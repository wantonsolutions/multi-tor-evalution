
#ref: https://www.geeksforgeeks.org/array-basics-shell-scripting-set-1/
switch_ip_list=(172.31.46.203 172.31.36.20)


#TODO: disable host key checking
# ssh -o StrictHostKeyChecking=no yourHardenedHost.com
for i in "${switch_ip_list[@]}"
do
	echo "scp .log files to:"
	echo ${i}
	scp -i ~/.ssh/replica-selection-key-pair.pem ~/multi-tor-evalution/onearm_lb/test-pmd/*.log ec2-user@${i}:~/ 
done

#scp -i ~/.ssh/replica-selection-key-pair.pem ~/multi-tor-evalution/onearm_lb/test-pmd/*.c
