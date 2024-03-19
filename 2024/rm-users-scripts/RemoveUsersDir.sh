#!/bin/bash
#use the command below to select line numbers (ex 57-60) and put them in badusers.txt
#sed -n '57,60p' /etc/passwd > badusers.txt

#File containing selected /etc/passwd entries
file_path="/path/to/badusers.txt"

#Check if any matching users were found
if [ -f "$file_path" ]; then
    #Use awk to extract and print the usernames (first field) from the selected file
    matching_users=$(awk -F: '{print $1}' "$file_path")

    # Check if any matching users were found
    if [ -n "$matching_users" ]; then
        echo "Removing home directory and account for user:"
        echo "$matching_users" | while read -r username; do
            echo "$username"

            #Assuming home directories are under /home
            user_home="/home/$username"

            #Deletion section
            rm -rf "$user_home"
            userdel $username
        done
    else
        echo "No matching users found in the selected file."
    fi
else
    echo "Error: File not found at $file_path"
fi