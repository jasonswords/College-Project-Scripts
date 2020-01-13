#!/bin/bash 

IP_HONEYPOTS=(server ip addresses here with space between each ip)
HONEYPOT_LOC=(server location names here in same order as ip addresses)
PORT=2222

# This script will restart the services of honeypots or MHN server.
# This script can also fix the hpfeeds-broker error that happens on occasion

if [ $# -eq 0 ]; then
	#Display thre options if no parameter is passed
	echo "-- Please pass suitable arguments -- "
	echo "		1  =  Restart MHN and Honeypots"
	echo "		2  =  Restart Honeypots only   "
	echo "		3  =  Fix hpfeeds issue with MHN   "
	exit 1;

# Restart all the honeypot servers and the mhn server services
elif [[ "$1" == "1" ]]; then
	echo " ****** Restarting MHN and Honeypot services"
	echo " "
		for i in "${!IP_HONEYPOTS[@]}";
		do
			echo "--------------------------------------------"
			echo "Restarting "${HONEYPOT_LOC[$i]^}" honeypot"
			echo "--------------------------------------------"

			if [ "${HONEYPOT_LOC[$i]^}" == "MHN-SERVER"  ];then 
				PORT=22;
				ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "echo "---- Restarting services ----";supervisorctl restart all";
			else
				ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "echo "---- Restarting services ----";supervisorctl restart all";	
			fi
			
		done

# Restart all the honeypots
elif [[ "$1" == "2" ]]; then
	echo " ****** Restarting Honeypot services"
	echo " "

			for i in "${!IP_HONEYPOTS[@]}";
			do
				echo "--------------------------------------------"
				echo "Restarting "${HONEYPOT_LOC[$i]^}" honeypot"
				echo "--------------------------------------------"

				if [ "${HONEYPOT_LOC[$i]^}" == "MHN-SERVER" ];then 
					continue
				else
					ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "echo "---- Restarting services ----";supervisorctl restart all";	
				fi
				
			done

# Fix mhn server hpfeeds issue
elif [[ "$1" == "3" ]]; then
	echo " ****** Fixing MHN server *****"
	echo " "
	echo " ****** Restarting Mongodb ******"
	ssh root@"${IP_HONEYPOTS[3]}" "service mongodb start"
	echo "Waiting for service to start"
	sleep 10
	echo "Changing file ownership"
	ssh root@"${IP_HONEYPOTS[3]}" "chown www-data /var/log/mhn/mhn.log; echo "Restaring all sevices";supervisorctl restart all;sleep 5; supervisorctl status"

fi

			





# Prints out the running processes of each honeypot and mhn server
	for i in "${!IP_HONEYPOTS[@]}";
	do
		echo "--------------------------------------------"
		echo "Services from "${HONEYPOT_LOC[$i]^}" "
		echo "--------------------------------------------"

		if [ "${HONEYPOT_LOC[$i]^}" == "MHN-SERVER" ];then 
			PORT=22;
			ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "
			echo "---- The services running ----";supervisorctl status"
		else
			ssh -p $PORT root@"${IP_HONEYPOTS[$i]}" "
			echo "---- The services running ----";supervisorctl status"
		fi
	done
