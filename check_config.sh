#! /bin/bash

# we read routing table to generate /tmp/local_ip_list.txt file
# the switch ip is the ip addr of eth1, the second NIC
gen_host_dep_config()
{
rm /tmp/switch_self_ip.txt
touch /tmp/switch_self_ip.txt
IP_ADDR=$(ifconfig eth1 | awk '$1 == "inet" {print $2}' | tee -a /tmp/switch_self_ip.txt)
#echo ${IP_ADDR}

rm /tmp/local_ip_list.txt
touch /tmp/local_ip_list.txt
read num_line < ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt > /dev/null
tail -n ${num_line} ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt | tee -a /tmp/routing_table.tmp > /dev/null
n=0
while read line; do # reading each line
        #echo $line
	line_arr=($line)
	#echo ${line_arr[0]}
	#echo ${line_arr[1]}
	if [ "${line_arr[1]}" == "${IP_ADDR}" ]; then
		#echo "ToR addr matched!"
		echo ${line_arr[0]} | tee -a /tmp/local_ip_list.txt > /dev/null
		n=$((n+1))
	fi

done < /tmp/routing_table.tmp
rm /tmp/routing_table.tmp
sed -i "1s/^/$n\n/" /tmp/local_ip_list.txt
}

check_host_dep_config()
{
if [ ! -f /tmp/local_ip_list.txt ];then
	echo "## ERROR: Missed file /tmp/local_ip_list.txt"
	return
else
	#wc -l /tmp/local_ip_list.txt
	read num_line < /tmp/local_ip_list.txt
	n=0
	while read line; do # reading each line
	#echo $line
	n=$((n+1))
	done < /tmp/local_ip_list.txt

	n=$((n-1)) #subtract out the first line
	if [ ${n} -ne ${num_line} ]; then
		echo "invlid file of /tmp/local_ip_list.txt"
		return 
	fi

fi

if [ ! -f /tmp/switch_self_ip.txt ];then
        echo "## ERROR: the switch doesn't have a file describing its own ip address"
        return
fi
}

check_routing_config()
{
if [ ! -f ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt ];then
        echo "## ERROR: Missed file ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt"
        return
else
	read num_line < ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt
	n=0
        while read line; do # reading each line
        #echo $line
        n=$((n+1))
        done < ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt

        n=$((n-1)) #subtract out the first line
        if [ ${n} -ne ${num_line} ]; then
                echo "invlid file of ~/multi-tor-evalution/onearm_lb/test-pmd/routing_table_aws.txt"
                return
        fi
fi
}

check_ip2mac_config(){
	python3 check_ip2mac.py	
}

gen_host_dep_config
check_host_dep_config
check_routing_config
check_ip2mac_config
