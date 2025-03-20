#!/bin/bash

### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

FILE="/var/www/html/prestashop/index.php"
LOGFILE="/root/prestashop_hash.log"
CRONJOB="*/3 * * * * /root/check_prestashop.sh"

# Function to check if cron job already exists
check_cronjob() {
    crontab -l 2>/dev/null | grep -F "$CRONJOB" >/dev/null
}

# Add cron job if not already present
if ! check_cronjob; then
    (crontab -l 2>/dev/null; echo "$CRONJOB") | crontab -
    echo "$(date) - Cron job added: $CRONJOB" >> "$LOGFILE"
fi

if [ -f "$FILE" ]; then
    sha256sum "$FILE" >> "$LOGFILE"
else
    echo "$(date) - ERROR: $FILE not found!" >> "$LOGFILE"
fi