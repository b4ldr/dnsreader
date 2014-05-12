#!/usr/bin/env python
import SocketServer
import struct
import socket
import argparse
import time
import yaml
import json
import os
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

#class DnsReaderServer(SocketServer.ThreadingUDPServer):
class DnsReaderServer(SocketServer.UDPServer):
    '''
    SocketServer.ThreadingUDPServer 

    Instance variables:
    
    - RequestHandlerClass
    '''
    def __init__(self,server_address,RequestHandlerClass, directory, 
            zabbix_server, filter_domain):
        #SocketServer.ThreadingUDPServer.__init__(self,server_address,RequestHandlerClass)
        SocketServer.UDPServer.__init__(self,server_address,RequestHandlerClass)
        if not os.path.exists(directory):
            os.makedirs(directory)
        self.directory = directory
        self.zabbix_server = zabbix_server
        self.filter_domain = filter_domain

class DnsReaderHanlder(SocketServer.BaseRequestHandler):
    '''
    Base Handeler class 
    '''

    message = None
    nsid = None
    serial = None
    data = None
    incoming = None
    node_name = None

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def set_node_name(self, nsid):
        if nsid == "None":
            #we can only identify the node if we get the node_name as the qname
            if self.filter_domain not in qname:
                return None
            else:
                return qname
        else:
            return nsid
       
    def format_qname (self, qname):
        if qname == '.':
            return 'root'
        else:
            return qname[:-1]

    def parse_dns(self):
        '''
        parse the data package into dns elements
        '''
        self.data = str(self.request[0]).strip()
        self.incoming = self.request[1]
        #incoming Data
        try:
            self.message = dns.message.from_wire(self.data)
        except dns.name.BadLabelType:
            #Error processing lable (bit flip?)
            return False 
        except dns.message.ShortHeader:
            #Recived junk
            return False
        else:
            current_time = int(time.time())
            self.qname = self.format_qname(self.message.question[0].name.to_text())
            for opt in self.message.options: 
                    if opt.otype == dns.edns.NSID: 
                        self.nsid = str(opt.data)
                        if '.' not in self.nsid:
                            self.nsid = self.nsid.decode("hex")
            self.node_name = self.set_node_name(self.nsid)
            for ans in self.message.answer:
                if ans.rdtype == dns.rdatatype.SOA:
                    self.serial =  ans[0].serial
            print "%s: %s %s @%s" % (self.nsid, self.qname, self.serial, current_time)
            return True

    def handle(self):
        '''
        RequestHandlerClass handle function
        handler listens for dns packets
        '''
        raise NotImplementedError('This needs to be implmented by a child class')

class DnsReaderHanlderZabbix(DnsReaderHanlder):
    '''
    Handeler class with zabbix output 
    '''
    def __init__(self, request, client_address, server):
        DnsReaderHanlder.__init__(self, request, client_address, server)
         
    def _zabbix_recv_all(self, sock):
        buf = ''
        zbx_hdr_size = 13
        while len(buf)<zbx_hdr_size:
            chunk = sock.recv(zbx_hdr_size-len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    def _send_to_zabbix(self, data):

        zbx_host, zbx_port = self.server.zabbix_server.split(':')
        try:
            zbx_sock = socket.socket()
            zbx_sock.connect((zbx_host, int(zbx_port)))
            zbx_sock.sendall(data)
        except (socket.gaierror, socket.error) as e:
            zbx_sock.close()
            raise Exception(e[1])
        else:
            zbx_srv_resp_hdr = self._zabbix_recv_all(zbx_sock)
            zbx_srv_resp_body_len = struct.unpack('<Q', zbx_srv_resp_hdr[5:])[0]
            zbx_srv_resp_body = zbx_sock.recv(zbx_srv_resp_body_len)
            zbx_sock.close()
        return json.loads(zbx_srv_resp_body)

    def send_zabbix_data(self, key, value):
        data = [{
            'host': self.node_name,
            'key': key,
            'value': value
            }]
        body = json.dumps({ 'request' : 'sender data', 'data' : data })
        message = 'ZBXD\1' + struct.pack('<Q',  len(body)) + body
        response = self._send_to_zabbix(message)
        print response['info']
    
    def handle(self):
        '''
        RequestHandlerClass handle function
        handler listens for dns packets
        '''
        if self.parse_dns():
            if self.node_name:
                if self.serial:
                    zabbix_key = 'spoof_{}_serial'.format(self.qname.replace('.','_'))
                    zabbix_value = self.serial
                else:
                    zabbix_key = 'spoof_nsid'
                    zabbix_value = self.nsid
                self.send_zabbix_data(zabbix_key, zabbix_value)

class DnsReaderHanlderYaml(DnsReaderHanlder):
    '''
    Handeler class with yaml output 
    '''
    node_file = None

    def __init__(self, request, client_address, server):
        DnsReaderHanlder.__init__(self, request, client_address, server)

    def write_yaml(self):
        '''
        write out yaml file for a specific node
        '''
        self.node_file = os.path.join(self.server.directory, "%s.yaml" % self.node_name)
        now = int(time.time())
        if os.path.exists(self.node_file):
            node_doc = file(self.node_file, 'r+')
        else:
            node_doc = file(self.node_file, 'w+')
        node = yaml.load(node_doc)
        if not node:
            node = { 'name': self.node_name, 'nsid': { 
                        'value': None, 
                        'updated': 0 },
                     'domains': { },
                    }
        node['nsid']['value'] = self.nsid
        if self.nsid:
            node['nsid']['updated'] = now
        if self.serial:
            try:
                node['domains'][self.qname]['serial'] = self.serial
                node['domains'][self.qname]['updated'] = now
            except KeyError:
                node['domains'][self.qname] = { 'serial' : self.serial, 'updated' : now }
        #rewrite the file
        node_doc.seek(0)
        yaml.dump(node, node_doc, indent=4, default_flow_style = False)
        node_doc.close()
    
    def handle(self):
        '''
        RequestHandlerClass handle function
        handler listens for dns packets
        '''
        if self.parse_dns():
            if self.node_name:
                self.write_yaml()


def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description='dns spoof monitoring script')
    parser.add_argument('-l', '--listen', metavar="0.0.0.0:6969", 
            default="0.0.0.0:6969", help='listen on address:port ')
    parser.add_argument('-z', '--zabbix-server', metavar="localhost:10051", 
            default="localhost:10051", help='Zabbix trapper server')
    parser.add_argument('-d', '--directory', metavar="/tmp/dnsdata/", 
            default="/tmp/dnsdata/", help='Directory to store node information')
    parser.add_argument('-f', '--filter-domain', required=True,
            help='domain name filter used to identify node if nsid is not set')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--yaml', action='store_true')
    group.add_argument('--zabbix', action='store_true')
    args = parser.parse_args()
    host, port = args.listen.split(":")
    if args.yaml:
        server = DnsReaderServer((host, int(port)), DnsReaderHanlderYaml, 
                args.directory, args.zabbix_server, args.filter_domain )
    elif args.zabbix:
        server = DnsReaderServer((host, int(port)), DnsReaderHanlderZabbix, 
                args.directory, args.zabbix_server, args.filter_domain )
    server.serve_forever()

if __name__ == "__main__":
    main()
