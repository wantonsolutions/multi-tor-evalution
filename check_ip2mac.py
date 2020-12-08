#!/usr/bin/env python3

file_prefix = "./onearm_lb/test-pmd/"
ip2mac_filename  = "ip_mac_aws.txt"
routing_filename = "routing_table_aws.txt" 

ip2mac_dict = {}
line_count=0
with open(file_prefix + ip2mac_filename, "r") as ip2mac_file:
    for line in ip2mac_file:
        parse_line=line.replace("\n","")
        if line_count == 0:
            line_count = line_count + 1
            continue
        splitline= parse_line.split(" ")
        ip_addr  = splitline[0]
        mac_addr = splitline[1]
        #print( '%s:%s' % (ip_addr, mac_addr))
        ip2mac_dict[ip_addr] = mac_addr
        line_count = line_count + 1

iplist=[]
line_count=0
with open(file_prefix + routing_filename, "r") as routing_file:
    for line in routing_file:
        parse_line=line.replace("\n","")
        if line_count == 0:
            line_count = line_count + 1
            continue
        splitline= parse_line.split(" ")
        iplist.append(splitline[0])
        iplist.append(splitline[1])
        #print(splitline[0])
        #print(splitline[1])
        line_count = line_count + 1

#check if all ip addresses in routing table are in the ip2mac table

for ip in iplist:
    #print(ip)
    ret = ip2mac_dict.get(ip)
    if ret == None:
        print('%s %s %s' % ("can't find key", ip , "in ip2mac_dict"))


