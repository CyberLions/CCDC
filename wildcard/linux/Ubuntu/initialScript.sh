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

#system logging
systemctl enable rsyslog
systemctl start rsyslog

#### Set permissions of important files ####

sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow

#permissions
chmod 755 /bin/nano
chmod 644 /bin/bzip2
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
chmod 644 /etc/passwd 
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chmod 644 /etc/hosts.deny 
chmod 644 /etc/hosts.allow 
chmod 644 /etc/passwd /etc/group /etc/shells /etc/login.defs /etc/securetty /etc/hosts.deny /etc/hosts.allow
chown -R root /etc/*
chmod 0000 /etc/shadow /etc/gshadow
chmod 600 /etc/sysctl.conf
chmod 755 /etc
chmod 755 /bin/su
chmod 755 /bin/bash
chmod u+s /bin/sudo
chmod u+s /bin/su
chmod u+s /sbin/unix_chkpwd
chmod 755 /sbin/ifconfig
chmod 666 /dev/null /dev/tty /dev/console
chmod 600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
chmod 0700 /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/*