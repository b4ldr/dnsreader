#!/usr/bin/env python
import argparse
import time
import yaml
import os
import glob
import dns.resolver


class NodeMessages(object):

    def __init__(self, node_name):
        self.messages = []
        self.name = node_name
        self.domain_messages = dict()

    def add_error(self, message):
        
        self.messages.append(message)

    def add_domain_error(self, domain, message):

        try:
            self.domain_messages[domain].append(message)
        except KeyError:
            self.domain_messages[domain] = [ message ]

    def print_error_report(self):
        h1_spacer = '======================================'
        h2_spacer = '--------------------------------------'
        if self.messages or self.domain_messages:
            print '%s:' % self.name
            print h1_spacer
            
        if self.messages:
            print 'Genral node errors'
            print h2_spacer
            for message in self.messages:
                print '\t%s' % message
            print '\n'
        if self.domain_messages:
            for domain, messages in self.domain_messages.items():
                print '%s:' % domain
                print h2_spacer
                for message in messages:
                    print '\t%s' % message
                print '\n'



def sec_to_human(seconds):
    for i in ['Secs', 'Mins']:
        if seconds < 60:
            return "%3.1f %s" % (seconds, i)
        seconds /= 60.0
    return "%3.1f %s" % (seconds, "Hours")

def check_updated(updated, alert_lag=86400):
    now = int(time.time())
    if updated < (now - alert_lag):
        return sec_to_human(now - updated)
    return None

def get_mname(domain):

    answer = None
    try:
        answer = dns.resolver.query(domain, 'SOA')
        return answer[0].mname
    except dns.resolver.NXDOMAIN:
        print 'unable to resolve %s' % domain

def get_serial(domain, master):

    answer = None
    resolver = dns.resolver.Resolver()
    try:
        
        master_ip = resolver.query(master, 'A')[0].address
    except dns.resolver.NXDOMAIN:
        print 'unable to resolve %s' % master

    resolver.nameservers = [master_ip]
    try:
        answer = resolver.query(domain, 'SOA')
        return answer[0].serial
    except dns.resolver.NXDOMAIN:
        print 'unable to resolve %s' % domain

def get_master_serial(domain):

    if domain == 'root':
        domain = '.'
    else:
        domain += '.'

    master = get_mname(domain)
    master_serial = get_serial(domain, master)
    return master_serial

def check_domain(node, domain, node_messages):

    updated = 0
    serial = 0
    alert_lag = 86400
    status = True
    try:
        updated = node['domains'][domain]['updated']
        serial = node['domains'][domain]['serial']
        lag = check_updated( updated, alert_lag)
        master_serial = get_master_serial(domain)

        if lag:
             node_messages.add_domain_error(domain, 'SOA not recived for %s' % (lag))
             status = False

        if master_serial != serial:
            node_messages.add_domain_error(domain, 'Node Serial (%s) does not match Master (%s)' % (serial, master_serial))
            status = False

    except KeyError:
        node_messages.add_domain_error(domain, 'SOA not recived')
        return False

    return status

def check_node(node_file, domains=['root', 'arpa', 'root-servers.net']):
    
    node_name = node_file.split('/')[-1].rstrip('.yaml')
    node_messages = NodeMessages(node_name)
    alert_lag = 86400
    if not os.path.exists(node_file):
        node_messages.add_error('No Data Recived from node')
        return node_messages 

    node_doc = open(node_file, 'r')
    node = yaml.load(node_doc)
    if not node['nsid']['value']:
        node_messages.add_error('No NSID recived')
    else:
        if node_name != node['nsid']['value']:
            node_messages.add_error('Incorrect NSID recived: %s' % node['nsid']['value'])

        lag = check_updated( node['nsid']['updated'], alert_lag)
        if lag:
             node_messages.add_domain_error(domain, 'NSID not recived for %s' % (lag))

    for domain in domains:
        check_domain(node, domain, node_messages)

    return node_messages

def check_nodes(nodes_directory, results_directory):
    messages = []
    for node_file in os.listdir(nodes_directory):
        if node_file.endswith('l.root-servers.org.yaml'):
            node_path = os.path.join(nodes_directory, node_file)

            node_doc = open(node_path, 'r')
            node = yaml.load(node_doc)

            if node['status']['operational']:
                node_result_path = os.path.join(results_directory, node_file)
            	messages.append(check_node(node_result_path))
    return messages

def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description="Deployment script for atlas anchor")
    parser.add_argument('-N', '--node-directory', metavar="/etc/hierdata/nodes/", default="/etc/hierdata/nodes/", help='Directory to store node information')
    parser.add_argument('-R', '--results-directory', metavar="/tmp/dnsdata/", default="/tmp/dnsdata/", help='Directory to store node information')
    args = parser.parse_args()
    messages = check_nodes(args.node_directory, args.results_directory)
    for message in messages:
        message.print_error_report()

if __name__ == "__main__":
    main()
