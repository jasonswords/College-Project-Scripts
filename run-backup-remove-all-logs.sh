#!/bin/bash 

# this script was used to backup all files from honeypots and mhn server
# for analysis at a later time
# the script also removes bloating dionaea log files
d=$(date +%Y-%m-%d)
MHN="ip address of mhn server"
IP_HONEYPOTS=(server ip addresses here with space between each ip)
HONEYPOT_LOC=(server location names here in same order as ip addresses)

dionaea_log="/opt/dionaea/var/log/dionaea/dionaea.log"
files_path="/opt/dionaea/var/lib/dionaea"
local_path="/path/to/directory/locally"
local_bistream_path="/path/to/directory/"

# # This script will download the files in dionaea binaries
for i in "${!IP_HONEYPOTS[@]}";
do
	echo "--------------------------------------------"
	echo "Transferring files from "${HONEYPOT_LOC[$i]^}" honeypot"
	echo "--------------------------------------------"
	echo "The file will be saved to dionaea/"$d"/"${HONEYPOT_LOC[$i]}"-"$d".log"
	if [ ! -d "$local_path"/dionaea/"$d" ];then
		mkdir "$local_path"/dionaea/"$d"
	fi
	rsync --remove-source-files -z --progress -e "ssh -p 2222" root@"${IP_HONEYPOTS[$i]}":"$dionaea_log" "$local_path"/dionaea/"$d"/"${HONEYPOT_LOC[$i]}"-"$d".log 
	sleep 3
	
	echo "---------------------------------------------"
	echo "    Copying Binary files from "${HONEYPOT_LOC[$i]^}""
	echo "---------------------------------------------"
	
	#scp -o StrictHostKeyChecking=no -P 2222 root@"${IP_HONEYPOTS[$i]}":"$files_path"/binaries/* "$local_path"/other_logs/"${HONEYPOT_LOC[$i]}"/"$d" 
	rsync --remove-source-files -z --progress -e "ssh -p 2222" root@"${IP_HONEYPOTS[$i]}":"$files_path"/binaries/* "$local_path"/other_logs/"${HONEYPOT_LOC[$i]}"/


	echo "---------------------------------------------"
	echo "    Copying Bistreams folder from "${HONEYPOT_LOC[$i]^}""
	echo "---------------------------------------------"
	if [ ! -d "$local_bistream_path"/"${HONEYPOT_LOC[$i]}" ]; then
		mkdir "$local_bistream_path"/"${HONEYPOT_LOC[$i]}"
	fi 
	# scp -o StrictHostKeyChecking=no -r -P 2222 root@"${IP_HONEYPOTS[$i]}":"$files_path"/bistreams/* "$local_bistream_path"/"${HONEYPOT_LOC[$i]}"/
	rsync --remove-source-files -z -r --progress -e "ssh -p 2222" root@"${IP_HONEYPOTS[$i]}":"$files_path"/bistreams/* "$local_bistream_path"/"${HONEYPOT_LOC[$i]}"/
	echo "-------------------------------------"
	echo "         Removing the files"
	echo "-------------------------------------"

	ssh -o StrictHostKeyChecking=no -p 2222 root@"${IP_HONEYPOTS[$i]}" "find "$files_path"/bistreams/* -type f -exec rm -v {} \;"
	ssh -o StrictHostKeyChecking=no -p 2222 root@"${IP_HONEYPOTS[$i]}" "find "$files_path"/binaries/ -type f -exec rm -v {} \;"
	ssh -o StrictHostKeyChecking=no -p 2222 root@"${IP_HONEYPOTS[$i]}" "rm -rf "$files_path"/bistreams/*; > "$dionaea_log"; supervisorctl restart all"
done


# Backup the log file in MHN server
echo "---------------------------------------------"
echo "  *********************************          "
echo "Backing up files from MHN main server"
echo "---------------------------------------------"
echo "  *********************************          "

echo "The files are backed up to the path "$local_path"/splunk/mhn-splunk-log/"
rsync -z --progress root@"$MHN":/var/log/mhn/mhn-splunk.*  "$local_path"/splunk/mhn-splunk-log/
echo "The files are backed up to the path "$local_path"/splunk/mhn-log/"
rsync -z --progress root@"$MHN":/var/log/mhn/mhn.*  "$local_path"/splunk/mhn-log/


echo "----------------------------------------------"
echo "The MHN server has been backed up successfully"
echo "----------------------------------------------"
echo "   The process has completed without error"
echo "----------------------------------------------"

echo "-------------------------------------"
echo "     The files are now removed       "
echo "   All operations are succeddful     "
echo "-------------------------------------"

echo "Shutting down"
#shutdown +10
