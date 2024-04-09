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