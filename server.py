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
    """
    SocketServer.ThreadingUDPServer 

    Instance variables:
    
    - RequestHandlerClass
    """
    def __init__(self,server_address,RequestHandlerClass, directory, zabbix_server):
        #SocketServer.ThreadingUDPServer.__init__(self,server_address,RequestHandlerClass)
        SocketServer.UDPServer.__init__(self,server_address,RequestHandlerClass)
        if not os.path.exists(directory):
            os.makedirs(directory)
        self.directory = directory
        self.zabbix_server = zabbix_server

class DnsReaderHanlder(SocketServer.BaseRequestHandler):
    """
    Handeler class 
    """
    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def set_node_name(self, nsid):
        if nsid == "None":
            #we can only identify the node if we get the node_name as the qname
            if 'l.root-servers.org' not in qname:
                return None
            else:
                return qname
        else:
            return nsid
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
            #try:
            zbx_srv_resp_hdr = self._zabbix_recv_all(zbx_sock)
            zbx_srv_resp_body_len = struct.unpack('<Q', zbx_srv_resp_hdr[5:])[0]
            zbx_srv_resp_body = zbx_sock.recv(zbx_srv_resp_body_len)
            zbx_sock.close()
            #except:
            #    zbx_sock.close()
            #    raise Exception("Error while sending data to Zabbix")

        return json.loads(zbx_srv_resp_body)

    def send_zabbix_data(self, host, key, value):
        data = [{
            'host': host,
            'key': key,
            'value': value
            }]
        body = json.dumps({ 'request' : 'sender data', 'data' : data })
        message = 'ZBXD\1' + struct.pack('<Q',  len(body)) + body
        response = self._send_to_zabbix(message)
        print response['info']
        

    def format_qname (self, qname):
        if qname == '.':
            return 'root'
        else:
            return qname[:-1]

    def write_yaml(self, node_name, nsid, qname, serial):

        now = int(time.time())

        node_file = os.path.join(self.server.directory, "%s.yaml" % node_name)

        if os.path.exists(node_file):
            node_doc = file(node_file, 'r+')
        else:
            node_doc = file(node_file, 'w+')

        node = yaml.load(node_doc)

        if not node:
            node = { 'name': node_name, 'nsid': { 
                        'value': None, 
                        'updated': 0 },
                     'domains': { },
                    }

        node['nsid']['value'] = nsid
        if nsid:
            node['nsid']['updated'] = now

        if serial:
            try:
                node['domains'][qname]['serial'] = serial
                node['domains'][qname]['updated'] = now
            except KeyError:
                node['domains'][qname] = { 'serial' : serial, 'updated' : now }
        #rewrite the file
        node_doc.seek(0)
        yaml.dump(node,node_doc, indent=4, default_flow_style = False)
        node_doc.close()



    def handle(self):
            """
            RequestHandlerClass handle function
            handler listens for dns packets
            """

            #incoming Data
            message = None
            nsid = None
            serial = None
            data = str(self.request[0]).strip()
            node_file = None
            #Sending machine
            incoming = self.request[1]
            try:
                message = dns.message.from_wire(data)
                current_time = int(time.time())
                qname = self.format_qname(message.question[0].name.to_text())
                for opt in message.options: 
                      if opt.otype == dns.edns.NSID: 
                          nsid = opt.data
                          if '.' not in nsid:
                              nsid = nsid.decode("hex")
                node_name = self.set_node_name(nsid)
                for ans in message.answer:
                    if ans.rdtype == dns.rdatatype.SOA:
                        serial =  ans[0].serial
                print "%s: %s %s @%s" % (nsid, qname, serial, current_time)
                if node_name:
                    if serial:
                        zabbix_key = 'spoof_{}_serial'.format(qname.replace('.','_'))
                        zabbix_value = serial
                    else:
                        zabbix_key = 'spoof_nsid'
                        zabbix_value = nsid
                    self.write_yaml(node_name, str(nsid), qname, serial)
                    self.send_zabbix_data(node_name, zabbix_key, zabbix_value)
                #if message.rcode() != dns.rcode.NOERROR:
                #    print "%s: %s %s @%s" % (nsid, qname, serial, current_time)
            except dns.name.BadLabelType:
                #Error processing lable (bit flip?)
                pass 
            except dns.message.ShortHeader:
                #Recived junk
                pass

def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description='dns spoof monitoring script')
    parser.add_argument('-l', '--listen', metavar="0.0.0.0:6969", default="0.0.0.0:6969", help='listen on address:port ')
    parser.add_argument('-z', '--zabbix-server', metavar="localhost:10051", default="localhost:10051", help='Zabbix trapper server')
    parser.add_argument('-d', '--directory', metavar="/tmp/dnsdata/", default="/tmp/dnsdata/", help='Directory to store node information')
    args = parser.parse_args()
    host, port = args.listen.split(":")
    server = DnsReaderServer((host, int(port)), DnsReaderHanlder, args.directory, args.zabbix_server )
    server.serve_forever()

if __name__ == "__main__":
    main()
