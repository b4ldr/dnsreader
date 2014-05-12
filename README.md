dnsreader
=========

These scripts are here to monitor dns anycast deployments.  There are three componets

    * client.py - this is used to send spoofed dns queries to an anycast address
    * server.py - this is expected to listen on spoofed address:port specifed in the client.  
        When a packet is recived some preocessing is preformed and results are either written 
        to zabbix or a yaml file
    * checker.py - this script reads the yaml files produced in the server.py script and prints 
        a rport to stdout (TODO: make this script compatible with nagios)

#Example

In the simplest example i have the following set up.

##Parametrs
###domain(s) to monitor
`example.com`
this is a list of domains we want to check
###domain-filter
`example.net`
this filter is used to filter out junk when we dont get an nsid (explained below)
###anycast address
`198.51.100.1`
this is the address we will send the spoffed queries to
###monitoring server
`192.0.2.1`
this is the server we are spoofing and therefore the one that will recive the response
###nodes list
`./nodes.txt`
this is a text file which should contain a list of all the anycast nodes you expect to be sending packets
        
##probes
    
###domain check: 
`./client.py --nsid -s 192.0.2.1 -d 198.51.100.1 -Q example.com`
this will send an soa query, with the nsid bit set, for example.com to 198.51.100.1.  the response will be sent to 192.0.2.1
###nsid check: 
`./client.py --nsid -s 192.0.2.1 -d 198.51.100.1 -Q $(hostname -f)`
We dont care what the response status of this query is, we just need the reponse to contain the original qname.  At the monitoring server we use this to ensure the qname matches the nsid.  without this the domain checks in the server will never work.  

##server
`./server.py --yaml -f example.net`
this will output yaml files for each dnspacket recived.  the filter option is used for the nsid check. if we recive a response that has no nsid and the qname ends with this filter then we will use this value to identify the node.  this allows us to identify nodes that can reach us but are not senting an nsid.

TODO: explain zabbix configuration

##checker
The checker is used to parse the yaml files preduced above and print a report to stdout if any errors are found, intended for a cronjob

`./checker.py -D 'example.com'`
        - 

#Yaml Output
anycastnode1.ams.example.net.yaml
```yaml
domains:
    example.com:
        serial: 2014051200
        updated: 1399898912
name: anycastnode1.ams.example.net
nsid:
    updated: 1399898917
    value: anycastnode1.ams.example.net
``` 

    * domains: hash of domains that have been recived.  the key is the domain name and each 
        value conatins
        - updated: unix time stamp when we last recived a serial for this domain
        - serial: the serial number from the soa we recived
    * name: this is what we have identified as the node name and relates to the --filter-domain 
        and the nsid check explaind above
    * nsid: this indicats the last nsid value we recived and when we recived it


