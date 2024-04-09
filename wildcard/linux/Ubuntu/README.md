# Ubuntu Hardening
Several scripts for hardening ubuntu boxes
**YOU NEED TO CLONE THE WHOLE REPO BECAUSE THESE SCRIPTS PULL FROM FILES IN THIS FOLDER**

### initialScript.sh
* This script takes a while to run! 
* it will update all of the packages and clean them. 
    * You will need to confirm or deny changes (Like 2 times).
* It will update PAM dependencies
    * Password policy yippee!
* it will enable the firewall (UFW)
* core dumps and max logins
* enables system logging with `rsyslog`
* sets permissions on important files
* Sets government STIG banner because why not
* adds password age requirements

### removeBadPackages.sh
* This script removes known bad packages/software from the box
* **AUDIT THE PACKAGES LIST BEFORE RUNNING**    
    * Pretty please make sure that you do not accidently remove a required software!

### configFirefoxPolicies
* This script will update firefox policies so they aren't crap
* Firefox will need to be refreshed after this runs

### sysctl.conf
* This is not a script, so don't try to run it :D
* append these changes to the bottom of sysctl.conf