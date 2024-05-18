#!/bin/bash

# Run as root pls
if [ "$(/usr/bin/id -u)" -ne "0" ]; then
    echo "This must be run as root."
    exit 1
fi

echo "The following users are on the system:"
awk -F':' '{ print $1 }' /etc/passwd

read -p "Enter usernames to delete (separated by space) or press Enter to skip: " -a user_list

if [ ${#user_list[@]} -eq 0 ]; then
    echo "No users to delete. Continuing without deletion."
else
    # Iterate over each username provided
    for user in "${user_list[@]}"; do
        # Check if the user exists on the system
        if id "$user" &>/dev/null; then
            # Confirm deletion
            read -p "Are you sure you want to delete the user '$user'? (y/n): " confirm
            if [[ "$confirm" == [yY] ]]; then
                sudo userdel -r "$user"
                if [ $? -eq 0 ]; then
                    echo "User '$user' has been deleted."
                else
                    echo "Failed to delete user '$user'."
                fi
            else
                echo "Skipping deletion of user '$user'."
            fi
        else
            echo "User '$user' does not exist on the system."
        fi
    done
fi

echo "Users finished"

# Password minimum length

echo "Setting the password minimum length to 10"

COMMON_PASSWORD="/etc/pam.d/common-password"

if [ ! -f "$COMMON_PASSWORD" ]; then
    echo "File $COMMON_PASSWORD does not exist. Exiting."
    exit 1
fi

# Add/update minlen
if grep -q "pam_unix.so" "$COMMON_PASSWORD"; then
    sed -i '/pam_unix.so/s/$/ minlen=10/' "$COMMON_PASSWORD"
    echo "minlen=10 added to pam_unix.so line in $COMMON_PASSWORD."
else
    echo "pam_unix.so line not found in $COMMON_PASSWORD. womp womp"
    exit 1
fi

echo "Minimum password length finished."

echo "THIS JUST FINDS UNCOMMENTED LINES: MANUALLY CHECK, SPECIFICALLY FOR IPV4 IP FORWARD."

SYSCTL_CONF="/etc/sysctl.conf"

if [ ! -f "$SYSCTL_CONF" ]; then
    echo "File $SYSCTL_CONF does not exist. Exiting."
    exit 1
fi

while IFS= read -r line; do
    if [[ "$line" =~ ^[^#] ]]; then
        echo "Uncommented line found: $line"
    fi
done < "$SYSCTL_CONF"

sysctl -p

echo "SYSCTL finished."

echo "Checks if UFW is enabled or not, if it's not, enables it. Manually add rules."

UFW_STATUS=$(ufw status | grep "Status: active")

if [ -n "$ufw_status" ]; then
    echo "UFW is already enabled"
else
    echo "UFW is not enabled. Enabling..."
    ufw enable
    echo "UFW has been enabled."
fi

echo "UFW Enabled."

echo "Check for unnecessary services"

echo "Active services:"
systemctl --no-pager list-units --type=service --state=active

read -p "Enter the name of the service(s) you want to disable and remove (separated by space), or press Enter to skip: " -a services_to_remove

if [ ${#services_to_remove[@]} -eq 0 ]; then
    echo "No services selected for removal. Exiting."
    exit 0
fi

for service in "${services_to_remove[@]}"; do
    # Check if the service exists and is active
    if systemctl is-active "$service" &>/dev/null; then
        # Confirm disabling and removing the service
        read -p "Are you sure you want to disable and remove '$service'? (y/n): " confirm
        if [[ "$confirm" == [yY] ]]; then
            systemctl stop "$service"
            systemctl disable "$service"
            apt-get remove --purge "$service" -y
            apt-get autoremove -y
            echo "Service '$service' has been disabled and removed."
        else
            echo "Skipping disabling and removing of service '$service'."
        fi
    else
        echo "Service '$service' is not active or does not exist."
    fi
done

echo "Services done."

SOURCES_LIST="/etc/apt/sources.list"

if [ ! -f "$SOURCES_LIST" ]; then
    echo "File $SOURCES_LIST does not exist. Exiting."
    exit 1
fi

if grep -q "^#deb http://security.ubuntu.com/ubuntu/ jammy-security main" "$SOURCES_LIST"; then
    sed -i 's/^#deb http:\/\/security.ubuntu.com\/ubuntu\/ jammy-security main/deb http:\/\/security.ubuntu.com\/ubuntu\/ jammy-security main/' "$SOURCES_LIST"
    echo "Uncommented 'deb http://security.ubuntu.com/ubuntu/ jammy-security main'."
else
    echo "'deb http://security.ubuntu.com/ubuntu/ jammy-security main' is already uncommented or not found."
fi

cat "$SOURCES_LIST"

echo "Finished sources."

echo "Find suspicious files."
locate '*.mp3'
