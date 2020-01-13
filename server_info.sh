#!/bin/bash 

IP_HONEYPOTS=(server ip addresses here with space between each ip)
HONEYPOT_LOC=(server location names here in same order as ip addresses)
PORT=2222

# this script will print all the relevant server information
# with the mhn honeypot framework project
for i in "${!IP_HONEYPOTS[@]}";
do
	echo "--------------------------------------------"
	echo "Information from "${HONEYPOT_LOC[$i]^}" honeypot"
	echo "--------------------------------------------"

	if [ "${HONEYPOT_LOC[$i]^}" == "MHN-SERVER" ];then 
		PORT=22;
		ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "
		echo "---- Hard drive space ----";df -h;
		echo "---- Available RAM"; free -h;
		echo "---- Size of log file ----"; ls -lh /var/log/mhn/mhn-splunk.*; 
		echo "---- Size of log file ----"; ls -lh /var/log/mhn/mhn.log*; 
		echo "---- The services running ----";supervisorctl status"
	else
		ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "
		echo "---- Hard drive space ----";df -h;
		echo "---- Available RAM"; free -h;
		echo "---- Size of log file ----"; ls -lh /opt/dionaea/var/log/dionaea/; 
		echo "---- Number of bistreams files ----";ls -lh /opt/dionaea/var/lib/dionaea/bistreams/*| wc -l;
		echo "---- Number of binaries ----"; ls -lh /opt/dionaea/var/lib/dionaea/binaries/ | wc -l;
		echo "---- The services running ----";supervisorctl status"
	fi
	
done
