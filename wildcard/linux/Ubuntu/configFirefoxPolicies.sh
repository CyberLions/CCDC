#!/bin/bash
#Check if sudo
if [ $UID != 0 ]; then
    echo " use sudo and try again... "
    exit
fi
# Firefox policy config - see user.js
cp ./user.js /etc/firefox/user.js