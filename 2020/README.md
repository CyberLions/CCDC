# CCDC 2020

Outline of this year's competition, responsibilities, and after action report.

### Upcoming Events
- Conference Call 3/20 (Friday) 7:30 - 9:30 PM E101. Questions to cover:
 - Will we have internet access from the VMs? How "wide"? **Yes**
 - Why do we need to have the hosts running? They don't have any pertinent services. **You don't. They aren't scored**
 - Services like fail2ban allowed? **No since reports have to be submitted before blocking**
 - Snapshots? **No**
 - Does the Palo Alto firewall come with an active WildFire or any other security subscription? **No updating the PA**

- Competetion 3/21 (Saturday) 3:00 - 8:00 PM E164 w/ an hour setup

### Machines

- Palo Alto F/W
- Phantom 4.1.94
- Debian 7.8
 - Service Required - MySQL
- Ubuntu 12.04
 - Service Required - DNS
- Win 2008 R2
 - Services Requried - AD, DNS, Exchange
- Win 8.1
- Win 10
- Splunk 7.2.0
- CentOS 6.0
 - Service Required - Ecomm
- Fedora 21
 - Services Required - Webmail and WebApps

### Services "Outlined"
- HTTP
- HTTPS
- SMTP
- POP3
- DNS

### Team Coverage
- Brant - Phantom 4.1.94 > Win 8.1 (> PA) **Giving up box to Namo/Petr to configure PA/Phantom**
- Petr - > Splunk
- Namo - PA > Win 2008
- Justin - CentOS w/ Ecomm > Debian
- Matt - Win 2008 > Win 10
- Mark - Ubuntu w/ DNS
- Jason - Debian w/ MySQL
- Evan - Fedora 21 w/ Webmail and WebApps

### After Action Report

#### Business Tasks (Injects)
- Create Acceptable Use Policy
- Create detailed list of machines on topology
- Create profiles on PA
- Create exec board incident briefing
- Create AD groups
- Create Incident Response report
- Create Nessus report
- Create authorized use notice upon login
- Create internal organization role chart
- Install Splunk
- Assign Splunk forwards to machines on topology

#### Phantom 4.1.94
Pre-Comp
Remove users
Check service
Secure Phantom

Comp
Change passwords (or lock unused accounts)
Change users / delete users
Update OS (not vulnerable to dirtycow)
Checked cron
Secured Phantom service

Post-Comp
-n/a stayed online no incidents.

#### Debian 7.8
Pre-Comp
- Check users that need to be on the system so I know whats weird
- Learn how mysql works so I can run the mysql_secure_installation thing to make it secure

Comp
- Change password on root and sysadmin
- iptables -F to flush in case there's dumb network rules
- Uninstall nc because netcat sucks
- Remove ssh auth keys
- Edit sshd_config file to disallow root login, change port to something other than 22 so its not obvious (we needed SSH to access the MySQL database from the web server)
- Add sysadmin to sudoers
- Check /etc/passwd for weird users, change all shells I dont need to /bin/false
- Check /etc/sudoers
- Check /etc/sudoers.d
- Edit the mysql tables to allow a specific user to have access to the frog table that we needed (on localhost, then the web server SSHes into it with -L to "pretend" like he's localhost accessing all of it)
- Upgrade system (change sources to archive.debian.org......)
- Check .bashrc for weird stuff
- Uninstall cron
- Uninstall/disable apache2
- Check home folder for suspicious things/files as hints to problems
- After all upgrades done, install ufw and deny everything (default deny in & out) except access to the web server on ONE port (SSH so he could access the MySQL)
 - If something was going on with the web server, I cut the ssh connection so it wouldnt spread to my system, then when he was ready to go again I re enabled it
 - When the competition was about to end and everyone's systems were dying I just denied everything and sat there staring at my screen while all the other systems died

Post-Comp
- n/a

#### Ubuntu 12.04
Pre-Comp
- verify that they are using Bind9 for DNS
- check open ports: FTP on 21, nc listener on 54
- see that there are a bunch of "user" directories that have no actual users associated with them
- directories contain company SSNs and CC#s

Comp
- kill nc and ftp
- change user and root password
- check sudoers: bad stuff in sudoers
- check cron
- check environment variables
- bind9 starts nc listener every time it is started
- block ports that are not DNS
- LDAP service went crazy for some reason killed it everytime machine restarted

Post-Comp
- rkhunter
- check processes more
- go through lockdown steps first then check out other interesting things on the environment
- better ways to document attacks and sources
- practice reporting 
- change password several times throughout the competition


#### Win 2008 R2
Pre-Comp


Comp


Post-Comp

#### Win 8.1
Pre-Comp


Comp


Post-Comp
- Local user accounts never checked (until the very end), we never ran antimalware on it :(
- Should've created local user accounts!

#### PaloAlto
Pre-Comp
- Checked and deleted bogus admin accounts and kicked red team admin sessions out
- Security policies tightened

Comp
- Red team somehow got admin access (shared password getting pwn'd?)

Post-Comp
- PaloAlto maintenance mode would not allow password reset, only full factory reset
- We should keep a backup of a "known-working" PA configuration ready to restore, if this happens


#### Splunk 7.2.0
Pre-Comp
Create new user
Lock default admin account
Update Splunk to latest version
Make sure all forwarders have their own keys and certificates. (test environment had SSL disabled)
Create deployment server for easy remote management.

Comp
Changed splunk user password
Created CyberLions user
removed SSH
Updated iptables
Locked root
deleted user "default" in splunk

Post-Comp
No incidents, but need to streamline forwarder deployment. Will work to organize a deployment plan with the team.

#### CentOS 6.0
Pre-Comp

- I found that google was a really good resource

Comp

- user logged in as _vmd, ran killall -u _vmd, disabled sshd, and deleted the user

- sit0 interface opened?

- 4:30 sshd service started. Killed sshd.
- 4:37 sshd service started again?
- 5:09 noticed a lot of python, killed using killall python

- 5:46 Noticed that ls shows a picture of a rabbit, my username has been changed to charminultrasoft
    - sudo yum install --disableexcludes=all update
    - finally running an update!
    - fixed by updating coreutils
    
- Removed nc, sshd
- 6:08 noticed crontab and php have a script that downloads and runs a backdoor

- 6:16 got e-commerce up after setting the DB, 

- 7:30 uninstalled cronie to finally remove all backdoors 
- 7:36 centos slowed to a halt and I needed to restart
- 7:4? centos is completely pwned  

Post-Comp

- I wish I looked into apache much earlier on
- I should've realized that I could find the php configuration file 

#### Fedora 21
Pre-Comp


Comp


Post-Comp
