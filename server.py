#!/usr/bin/env python2
import SocketServer
import socket
import argparse
import time
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

class DnsReaderServer(SocketServer.ThreadingUDPServer):
    """
    SocketServer.ThreadingUDPServer 

    Instance variables:
    
    - RequestHandlerClass
    """
    def __init__(self,server_address,RequestHandlerClass):
        SocketServer.ThreadingUDPServer.__init__(self,server_address,RequestHandlerClass)

class DnsReaderHanlder(SocketServer.BaseRequestHandler):
    """
    Handeler class 
    """
    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

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
                if message.rcode() != dns.rcode.NOERROR:
                    print "%s: %s %s @%s" % (nsid, qname, serial, current_time)
            except dns.name.BadLabelType:
                #Error processing lable (bit flip?)
                pass 
            except dns.message.ShortHeader:
                #Recived junk
                pass

def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description="Deployment script for atlas anchor")
    parser.add_argument('--listen', metavar="0.0.0.0:6969", default="0.0.0.0:6969", help='listen on address:port ')
    args = parser.parse_args()
    host, port = args.listen.split(":")
    server = DnsReaderServer((host, int(port)), DnsReaderHanlder )
    server.serve_forever()

if __name__ == "__main__":
    main()
