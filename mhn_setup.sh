#!/bin/bash

apt update && apt apgrade -y

adduser mhn 

su - mhn 

cd /opt/

sudo apt install git

sudo git clone https://github.com/threatstream/mhn.git

# get mhn to generate splunk log files

cd mhn/scripts/

$ sudo ./install_hpfeeds-logger-splunk

# now log files will be outputted into mhn-splunk.log` in `/var/log/mhn/

# copy splunk .deb file onto remote server
# scp -i .ssh/id_rsa Downloads/splunk-7.3.1.1-7651b7244cf2-linux-2.6-amd64.deb root@ip:~/opt

#Transfer the splunk install files onto the server./
# scp -i ../.ssh/id_rsa splunk-7.3.1.1-7651b7244cf2-Linux-x86_64.tgz root@ip:/opt
cd /opt/
tar -zxvf SPLUNK_BINARY.tgz
cd /opt/splunk/bin/
./splunk start



# You basically just should avoid these

# combos:

# Choose one or modify to listen on different ports (listens on port 80):

#     conpot
#     glastopf
#     wordpot
#     shockpot

# Chose one or modify to listen on different ports (listens on windows ports 445, 139, etc):

#     Amun
#     Dionaea

# These can be run with each other and any of the others (no port conflicts):

#     kippo
#     snort
#     suricata
#     p0f
#     elastichoney

# Running Snort and Suricata together is generally not necessary though.

