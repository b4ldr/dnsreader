#!/usr/bin/env python2
import argparse
import time
import yaml
import os


def sec_to_human(seconds):
    for i in ['Secs', 'Mins']:
        if seconds < 60:
            return "%3.1f %s" % (seconds, i)
        seconds /= 60.0
    return "%3.1f %s" % (seconds, "Hours")

def check_update(domain, update, alert_lag=86400):
    now = int(time.time())
    if update < (now - alert_lag):
        return False, sec_to_human(now - update)
    return True, None

def check_serial(domain, serial, master):
    master_serial = 0

def check_domain(node, domain):

    update = 0
    serial = 0
    alert_lag = 86400
    try:
        update = node['domains'][domain]['update']
        serial = node['domains'][domain]['serial']
        update_status, lag = check_update(domain, update, lag)
        if not update_status:
            return False, '%s (%s): No data recived for %s ' % (node['name'], domain, lag)

    except TypeError:
        return False,  '%s (%s): No data recived' % (node['name'], domain) 

    return True, None

def check_node(node_file, domains=['root', 'arpa', 'root-servers.net']):
    
    if not os.path.exists(node_file):
        return False, '%s: No data recived' % (node['name']) 

    node_doc = open(node_file, 'r')
    node = yaml.load(node_doc)

    for domain in domains:
        check_domain(node, domain)
    return True, None

def check_directoy(directory):
    errors = []
    return errors

def main():
    ''' main function for using on cli'''
    parser = argparse.ArgumentParser(description="Deployment script for atlas anchor")
    parser.add_argument('-d', '--directory', metavar="/tmp/dnsdata/", default="/tmp/dnsdata/", help='Directory to store node information')
    args = parser.parse_args()

if __name__ == "__main__":
    main()
