#!/usr/bin/env python
import SocketServer
import socket
import argparse
import time
import yaml
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
    def __init__(self,server_address,RequestHandlerClass, directory):
        #SocketServer.ThreadingUDPServer.__init__(self,server_address,RequestHandlerClass)
        SocketServer.UDPServer.__init__(self,server_address,RequestHandlerClass)
        if not os.path.exists(directory):
            os.makedirs(directory)
        self.directory = directory

class DnsReaderHanlder(SocketServer.BaseRequestHandler):
    """
    Handeler class 
    """
    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def write_yaml(self, nsid, qname, serial):

        now = int(time.time())
        if qname == '.':
            qname = 'root'
        else:
            #remove trailing dot
            qname = qname[:-1]

        #We didn't get an NSID
        if nsid == "None":
            #we can only identify the node if we get the node_name as the qname
            if 'l.root-servers.org' not in qname:
                return
            else:
                node_name = qname
        else:
            node_name = nsid

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
                qname = message.question[0].name
                for opt in message.options: 
                      if opt.otype == dns.edns.NSID: 
                          nsid = opt.data
                          if '.' not in nsid:
                              nsid = nsid.decode("hex")
                for ans in message.answer:
                    if ans.rdtype == dns.rdatatype.SOA:
                        serial =  ans[0].serial
                print "%s: %s %s @%s" % (nsid, qname, serial, current_time)
                self.write_yaml(str(nsid), qname.to_text(), serial)
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
    parser = argparse.ArgumentParser(description="Deployment script for atlas anchor")
    parser.add_argument('-l', '--listen', metavar="0.0.0.0:6969", default="0.0.0.0:6969", help='listen on address:port ')
    parser.add_argument('-d', '--directory', metavar="/tmp/dnsdata/", default="/tmp/dnsdata/", help='Directory to store node information')
    args = parser.parse_args()
    host, port = args.listen.split(":")
    server = DnsReaderServer((host, int(port)), DnsReaderHanlder, args.directory )
    server.serve_forever()

if __name__ == "__main__":
    main()
