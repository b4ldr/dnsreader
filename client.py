#!/usr/bin/env python
import argparse
import socket
import dns.message
import dns.rdatatype
import dns.rdataclass
from impacket import ImpactPacket
def get_args():
    '''return argpars opject'''
    parser = argparse.ArgumentParser(description='dns spoof monitoring server')
    parser.add_argument('-s', '--source', help='Source address', required=True)
    parser.add_argument('-p', '--source-port', help='Source port', default=6969, type=int)
    parser.add_argument('-d', '--destination', help='Destination address', required=True)
    parser.add_argument('-P', '--destination-port', help='Destination port', default=53, type=int)
    parser.add_argument('-Q', '--qname', help='query name', required=True)
    parser.add_argument('-T', '--qtype', help='query type', default='SOA')
    parser.add_argument('-C', '--qclass', help='query class', default='IN')
    parser.add_argument('-n', '--nsid', help='set the NSID OPT bit', action='store_true')
    return parser.parse_args()
def main():
    '''main function for using as cli'''
    args = get_args()
    query = dns.message.make_query(args.qname,
        dns.rdatatype.from_text(args.qtype), dns.rdataclass.from_text(args.qclass))
    if args.nsid:
        query.use_edns(payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, '')])
    data = ImpactPacket.Data(query.to_wire())
    udp = ImpactPacket.UDP()
    udp.set_uh_sport(args.source_port)
    udp.set_uh_dport(args.destination_port)
    udp.contains(data)
    ip = ImpactPacket.IP()
    ip.set_ip_src(args.source)
    ip.set_ip_dst(args.destination)
    ip.contains(udp)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(ip.get_packet(), (args.destination,args.destination_port))

if __name__ == "__main__":
    main()
