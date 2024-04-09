#!/bin/bash
#Check if sudo
if [ $UID != 0 ]; then
    echo " use sudo and try again... "
    exit
fi
#Clean packages
echo "Cleaning packages"
apt-get update
apt-get autoremove -y
apt-get autoclean -y
apt-get update

read -p "Do you want to update packages? [y,n]" runupdates
if [ $runupdates == "y" ]
	then
		echo "UPDATING PACKAGES"
		apt-get upgrade -y
fi
#Automatic updates
apt-get install -y unattended-upgrades
dpkg-reconfigure unattended-upgrades

#pam dependencies
apt-get install -y libpam-cracklib


cp ./common-password /etc/pam.d/common-password
cp ./login.defs /etc/
apt-get install -y gufw
ufw enable
sysctl -n net.ipv4.tcp_syncookies
echo 'net.ipv6.conf.all.disable_ipv6 = 1' | tee -a /etc/sysctl.conf
echo 0 | tee /proc/sys/net/ipv4/ip_forward

# core dumps and max logins
bash -c 'echo "* hard core 0" >> /etc/security/limits.conf'
bash -c 'echo "* hard maxlogins 10" >> /etc/security/limits.conf'