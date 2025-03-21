#!/bin/bash

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use sudo."
    exit 1
fi

# Prompt for admin and user passwords securely
read -r -s -p "Enter password: " ADMIN_PASSWORD

declare -A USERS
USERS=(
    [root]="$ADMIN_PASSWORD"
    [sysadmin]="$ADMIN_PASSWORD"
)

# Change passwords for specified users
for USER in "${!USERS[@]}"; do
    if id "$USER" >/dev/null 2>&1; then
        echo "Changing password for user: $USER"
        echo -e "${USERS[$USER]}\n${USERS[$USER]}" | passwd "$USER" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "Password successfully changed for $USER."
        else
            echo "Failed to change password for $USER."
        fi
    else
        echo "User $USER does not exist. Skipping."
    fi
done

# Disable login for all other users
# note that whiteteam user must not be disabled
while IFS=: read -r username _ uid _; do
    if [ "$uid" -ge 1000 ] && [ -z "${USERS[$username]}" ] && [ "$username" != "whiteteam" ]; then
        echo "Disabling login for user: $username"
        usermod -s /usr/sbin/nologin "$username" >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "Login disabled for $username."
        else
            echo "Failed to disable login for $username."
        fi
    fi
done < /etc/passwd

echo "Process completed."

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use sudo."
    exit 1
fi

echo "Checking .bashrc files for all users..."

# Determine the editor (prefer vi, fallback to nano)
if command -v vi &>/dev/null; then
    EDITOR="vi"
elif command -v nano &>/dev/null; then
    EDITOR="nano"
else
    echo "Error: No suitable text editor (vi or nano) found."
    exit 1
fi

# Loop through all users with valid home directories
for user in $(cut -d: -f1 /etc/passwd); do
    home_dir=$(eval echo ~$user)

    # Skip if the home directory doesn't exist
    if [ ! -d "$home_dir" ]; then
        continue
    fi

    bashrc_file="$home_dir/.bashrc"

    # If the .bashrc file exists, open it
    if [ -f "$bashrc_file" ]; then
        echo "Opening user $user's .bashrc file with $EDITOR..."
        sleep 2
        $EDITOR "$bashrc_file"

        echo "Opening crontab for user $user..."
        sleep 2
        sudo crontab -e -u "$user"

    fi

done

echo "Checking bash.bashrc..."
sleep 2
$EDITOR /etc/bash.bashrc

echo "Check complete."
