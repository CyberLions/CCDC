#!/bin/bash
#Check if sudo
if [ $UID != 0 ]; then
    echo " use sudo and try again... "
    exit
fi
# delete bad packages
for i in arp-scan braa dirb hashcat dnswalk faraday-server donna spampd ophcrack tmux snap pinta knocker nbtscan pompem crunch netcat lynis xprobe john zenmap binwalk sl john-data medusa hydra dsniff netcat-openbsd netcat-traditional traceroute telnet wireshark aircrack-ng pyrit zeitgeist nmap yersinia deluge httpry p0f dos2unix kismet transmission sendmail tightvncserver finger xinetd cain minetest tor moon-buggy dovecot rsh-server aisleriot hping3 freeciv darkstat nis sqlmap libaa-bin gdb skipfish extremetuxracer ninvaders freesweep nsnake bsdgames
do
    #faster than apt purge for every package
    if dpkg-query -W $i; then
        sudo apt purge -y $i 
    fi

done