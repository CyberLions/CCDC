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

echo "Starting Firewalls"
sleep 2
# Function to configure ufw
configure_ufw() {
    echo "UFW is installed. Setting up firewall rules..."
    # Reset existing UFW rules
    sudo ufw reset
    sudo ufw default deny incoming
    sudo ufw default deny outgoing

    #Prompt User to set SSH
    echo "Do you want to allow SSH (Y/N)?"
    read -r answer

    if [[ "${answer,,}" == "y" ]]; then
        echo "yes"
        sudo ufw allow ssh
    else
        echo "You chose NO. IF YOU MEANT TO SAY YES ADD PORT 22 ON REQUESTED PORTS!!!!"
    fi


    # Ask the user which ports to open
    echo "Enter the ports you want to open (space-separated):"
    read -r ports

    # check for ftp and open passive ports
    if [[ "$ports" =~  "21" ]]; then
        echo "add passive port 40000-50000"
        sudo ufw allow 40000:50000/tcp
    fi

    # Open the specified ports
    for port in $ports; do
        echo "Allowing traffic on port $port..."
	
	if [[ "$port" == "53" ]]; then
            echo "DNS is UDP"
            sudo ufw allow $port/udp
	else
	    sudo ufw allow $port/tcp
        fi

    done

    sudo ufw enable
    sudo ufw status verbose


    echo "If you need internet access run 'sudo ufw default allow outgoing' but understand it will allow ALL outgoing so don't keep it permanently"
}

# Function to configure iptables
configure_iptables() {
    echo "iptables is installed. Setting up firewall rules..."
    # Flush existing iptables rules
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -t nat -F
    sudo iptables -t mangle -F
    sudo iptables -F
    sudo iptables -X

    #Prompt User to set SSH
    echo "Do you want to allow SSH (Y/N)?"
    read -r answer

    if [[ "${answer,,}" == "y" ]]; then
	echo "yes"
	sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        sudo iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
    else
	echo "You chose NO. IF YOU MEANT TO SAY YES ADD PORT 22 ON REQUESTED PORTS!!!!"
    fi

    # Ask the user which ports to open
    echo "Enter the ports you want to open (space-separated):"
    read -r ports

    # check for ftp and open passive ports
    if [[ "$ports" =~  "21" ]]; then
        echo "add passive port 40000-50000"
        sudo iptables -A OUTPUT -p tcp --match multiport --sports 40000:50000 -j ACCEPT
	sudo iptables -A INPUT -p tcp --match multiport --dports 40000:50000 -j ACCEPT
    fi

    # Open the specified ports
    for port in $ports; do
        echo "Allowing traffic on port $port..."
        sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT
        sudo iptables -A OUTPUT -p tcp --sport $port -j ACCEPT
    done

    # Set default policies to deny incoming and outgoing traffic
    sudo iptables -P INPUT DROP
    sudo iptables -P OUTPUT DROP


    sudo iptables -L -v

}

#service iptables stop to kill

# Check if ufw is installed
if command -v ufw &> /dev/null; then
    configure_ufw
# If ufw is not installed, check for iptables
elif command -v iptables &> /dev/null; then
    configure_iptables
else
    echo "Neither ufw nor iptables are installed. Please install one of them to proceed."
    exit 1
fi

echo "Firewall configuration complete. Allow all outbound if you need internet connection. The default for this script is to deny all but the necessary outbound traffic."


echo "Starting crontab and bashrc checks"
sleep 2

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

echo "Starting backing up DNS"
sleep 2


echo "Copying /etc/bind to /etc/dns_backups"

#Define directories
SOURCE_DIR="/etc/bind"
BACKUP_DIR="/etc/dns_backup"

#Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

#Create a timestramped backup directory
BACKUP_DEST="$BACKUP_DIR/bind_backup"
mkdir -p "$BACKUP_DEST"

#Copy files instead of compressing
if cp -r "$SOURCE_DIR"/* "$BACKUP_DEST"/; then
	echo "Backup successful: $BACKUP_DEST"
else
	echo "Backup failed!" >&2
	exit 1
fi
