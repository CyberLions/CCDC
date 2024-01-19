#!/bin/bash
#search for users containing the string "GOBLIN" in /etc/passwd
matching_isers=$(grep -i "GOBLIN" /etc/passwd)

#Check if any matching users were found
if [ -n "$matching_users" ]; then
    #Use awk to extract and print the usernames (first field)
    echo "$matching_users" | awk -F: '{print $1}' | while read -r username; do
        echo "Removing home directory and account for user: $username"
        #Assuming home directories are under /home
        user_home="/home/$username"
        #Deletion section
        rm -rf "$user_home"
        userdel $username
    done
else
    echo "error"
fi
