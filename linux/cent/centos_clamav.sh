#!/bin/bash

### only run if machine has good resources
### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

FRESHCLAM_CONF="/etc/freshclam.conf"
LOG_DIR="/root/clamav"
CLAMSCAN_CMD='clamscan -r --exclude-dir="/usr/share|/usr/lib" /bin /etc /home /opt /mnt /root /sbin /srv /tmp /var /usr > "/root/clamav/clamav_scan_$(date +\%Y\%m\%d_\%H\%M\%S).log" 2>&1'
CRON_JOB="*/5 * * * * bash -c '$CLAMSCAN_CMD'"

mkdir -p "$LOG_DIR"

sed -i 's|^DatabaseMirror .*|DatabaseMirror http://database.clamav.net|' $FRESHCLAM_CONF

freshclam

(crontab -l 2>/dev/null | grep -Fq "$CLAMSCAN_CMD") || (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -

echo "done"