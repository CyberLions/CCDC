#!/bin/bash

### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

echo "Users with valid login shells on this system:"

users=$(awk -F: '$7 !~ /(\/sbin\/nologin|\/bin\/false|\/sbin\/shutdown|\/bin\/sync|\/sbin\/halt)/ {print $1}' /etc/passwd)

echo "$users"

### Change specific user's passwords

for user in $users; do
    read -p "Do you want to change the password for user '$user'? (y/n): " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        passwd "$user"
    fi
done

### Disable specific users

for user in $users; do
    read -p "Do you want to disable the account for user '$user'? (y/n): " disable_response
    if [[ "$disable_response" =~ ^[Yy]$ ]]; then
        usermod -L "$user"
        echo "User '$user' has been disabled."
    fi
done

### Stopping and Disabling SSH

read -p "Do you want to stop and disable SSH? (y/n): " ssh_response
if [[ "$ssh_response" =~ ^[Yy]$ ]]; then
    systemctl stop sshd
    systemctl disable sshd
    echo "SSH has been stopped and disabled."
else
    echo "SSH service was not changed."
fi

### Download tools before firewall

wget https://rpmfind.net/linux/epel/8/Everything/x86_64/Packages/i/inotify-tools-3.14-19.el8.x86_64.rpm --no-check-certificate
rpm -ivh inotify-tools-3.14-19.el8.x86_64.rpm

CENTOS_REPO_PATH="/etc/yum.repos.d/CentOS-Base.repo"
EPEL_REPO_PATH="/etc/yum.repos.d/epel.repo"

cp $CENTOS_REPO_PATH ${CENTOS_REPO_PATH}.bak
cp $EPEL_REPO_PATH ${EPEL_REPO_PATH}.bak 2>/dev/null

cat > $CENTOS_REPO_PATH <<EOF
# CentOS-EOL.repo
#
# This is an example config which can be used to deal with EOL RHEL
# You MUST look to mirroring this locally if you want long term access
#

[base]
name=CentOS-\$releasever - Base
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/os/\$basearch/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#released updates
[updates]
name=CentOS-\$releasever - Updates
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/updates/\$basearch/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that may be useful
[extras]
name=CentOS-\$releasever - Extras
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/extras/\$basearch/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-\$releasever - Plus
baseurl=http://archive.kernel.org/centos-vault/7.9.2009/centosplus/\$basearch/
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
EOF

echo "CentOS-Base.repo updated."

yum install -y epel-release

cat > $EPEL_REPO_PATH <<EOF
[epel]
name=Extra Packages for Enterprise Linux 7 - \$basearch
#baseurl=http://download.fedoraproject.org/pub/epel/7/\$basearch
baseurl=http://archives.fedoraproject.org/pub/archive/epel/7/\$basearch
#metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-7&arch=\$basearch
failovermethod=priority
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7

[epel-debuginfo]
name=Extra Packages for Enterprise Linux 7 - \$basearch - Debug
#baseurl=http://download.fedoraproject.org/pub/epel/7/\$basearch/debug
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-debug-7&arch=\$basearch
failovermethod=priority
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
gpgcheck=1

[epel-source]
name=Extra Packages for Enterprise Linux 7 - \$basearch - Source
#baseurl=http://download.fedoraproject.org/pub/epel/7/SRPMS
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-source-7&arch=\$basearch
failovermethod=priority
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7
gpgcheck=1
EOF

echo "EPEL repository updated."

yum install -y clamav

### Crontabs

echo "Enumerating cron jobs for each user..."

for crontab in /var/spool/cron/*; do
    user=$(basename "$crontab")

    # Check if the user has a crontab
    if [[ -f "$crontab" ]]; then
        echo "User: $user"
        echo "Crontab contents:"
        cat "$crontab"
        echo

        # Ask if the crontab should be cleared
        read -p "Do you want to clear the crontab for user '$user'? (y/n): " response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            > "$crontab"  # Clear the crontab by overwriting with an empty file
            echo "Crontab for user '$user' has been cleared."
        else
            echo "Crontab for user '$user' was not cleared."
        fi
    fi
done

### Start cron
systemctl start crond

### Services

KNOWN_GOOD_SERVICES=(
    "abrt-ccpp.service"
    "abrt-oops.service"
    "abrt-vmcore.service"
    "abrt-xorg.service"
    "abrtd.service"
    "accounts-daemon.service"
    "alsa-restore.service"
    "alsa-state.service"
    "alsa-store.service"
    "auditd.service"
    "avahi-daemon.service"
    "bluetooth.service"
    "brandbot.service"
    "chronyd.service"
    "colord.service"
    "cpupower.service"
    "cups.service"
    "dbus.service"
    "dm-event.service"
    "dmraid-activation.service"
    "dracut-shutdown.service"
    "ebtables.service"
    "emergency.service"
    "exim.service"
    "firewalld.service"
    "gdm.service"
    "getty@tty1.service"
    "getty@ttyUSB0.service"
    "hypervkvpd.service"
    "hypervvssd.service"
    "initial-setup-graphical.service"
    "initial-setup-text.service"
    "ip6tables.service"
    "iprdump.service"
    "iprinit.service"
    "iprupdate.service"
    "iptables.service"
    "irqbalance.service"
    "iscsi.service"
    "iscsid.service"
    "iscsiuio.service"
    "kdump.service"
    "kmod-static-nodes.service"
    "ksm.service"
    "ksmtuned.service"
    "libstoragemgmt.service"
    "libvirt-guests.service"
    "libvirtd.service"
    "livesys-late.service"
    "livesys.service"
    "lvm2-activation-early.service"
    "lvm2-activation.service"
    "lvm2-lvmetad.service"
    "lvm2-monitor.service"
    "microcode.service"
    "ModemManager.service"
    "multipathd.service"
    "named.service"
    "netconsole.service"
    "network.service"
    "NetworkManager-wait-online.service"
    "NetworkManager.service"
    "nfs-lock.service"
    "ntpd.service"
    "ntpdate.service"
    "plymouth-quit-wait.service"
    "plymouth-quit.service"
    "plymouth-read-write.service"
    "plymouth-start.service"
    "polkit.service"
    "postfix.service"
    "rc-local.service"
    "rescue.service"
    "rhel-autorelabel-mark.service"
    "rhel-autorelabel.service"
    "rhel-configure.service"
    "rhel-dmesg.service"
    "rhel-import-state.service"
    "rhel-loadmodules.service"
    "rhel-readonly.service"
    "rngd.service"
    "rpcbind.service"
    "rsyslog.service"
    "rtkit-daemon.service"
    "sendmail.service"
    "serial-getty@ttyAMA0.service"
    "serial-getty@ttymxc0.service"
    "serial-getty@ttymxc3.service"
    "serial-getty@ttyO0.service"
    "serial-getty@ttyO2.service"
    "serial-getty@ttyS0.service"
    "smartd.service"
    "sntp.service"
    "sshd.service"
    "syslog.service"
    "sysstat.service"
    "systemd-ask-password-console.service"
    "systemd-ask-password-plymouth.service"
    "systemd-ask-password-wall.service"
    "systemd-binfmt.service"
    "systemd-fsck-root.service"
    "systemd-initctl.service"
    "systemd-journal-flush.service"
    "systemd-journald.service"
    "systemd-logind.service"
    "systemd-modules-load.service"
    "systemd-random-seed-load.service"
    "systemd-random-seed.service"
    "systemd-readahead-collect.service"
    "systemd-readahead-done.service"
    "systemd-readahead-replay.service"
    "systemd-reboot.service"
    "systemd-remount-fs.service"
    "systemd-shutdownd.service"
    "systemd-sysctl.service"
    "systemd-tmpfiles-clean.service"
    "systemd-tmpfiles-setup-dev.service"
    "systemd-tmpfiles-setup.service"
    "systemd-udev-settle.service"
    "systemd-udev-trigger.service"
    "systemd-udevd.service"
    "systemd-update-utmp-runlevel.service"
    "systemd-update-utmp.service"
    "systemd-user-sessions.service"
    "systemd-vconsole-setup.service"
    "tuned.service"
    "udisks2.service"
    "upower.service"
    "vmtoolsd.service"
    "crond.service"
    "apache2.service"
)

active_services=$(systemctl list-units --type=service --all | awk '{print $1}' | tail -n +2)

echo "Checking active services..."

for service in $active_services; do
    if [[ ! " ${KNOWN_GOOD_SERVICES[@]} " =~ " ${service} " ]]; then
        echo "Unknown service running: $service"
    fi
done

echo "Service check completed."

### Backup files

mkdir /etc/balls
cp -r /var/www/html/* /etc/balls/

### Apache & PHP

## Remove phpmyadmin
rm -rf /var/www/html/prestashop/phpmyadmin*
rm -rf /var/www/html/prestashop/admin*
rm -rf /var/www/html/prestashop/config/config.inc.php
php_ini=$(php --ini | grep "Loaded Configuration" | awk '{print $4}' | sed 's/cli/apache2/')
if [ -z "$php_ini" ]; then
    echo "php.ini not found. womp"
    exit 1
fi

echo "Found php.ini at: $php_ini"
cp "$php_ini" "$php_ini.bak"
grep -q "disable_functions" "$php_ini" || echo "disable_functions =" >> "$php_ini"

sed -i '/disable_functions/ s/$/exec,shell_exec,system,passthru,popen,proc_open,curl_exec,curl_multi_exec/' "$php_ini"

echo "Restarting Apache"
systemctl restart apache2

mkdir /opt/backups
cp -r /var/www/html/* /opt/backups/

# chattr +i /var/www/html/prestashop/index.html

### Compare suid binaries

KNOWN_BINARIES=(
    "/usr/libexec/qemu-bridge-helper"
    "/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper"
    "/usr/libexec/pulse/proximity-helper"
    "/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/usr/sbin/mount.nfs"
    "/usr/sbin/usernetctl"
    "/usr/sbin/userhelper"
    "/usr/sbin/pam_timestamp_check"
    "/usr/sbin/unix_chkpwd"
    "/usr/lib64/dbus-1/dbus-daemon-launch-helper"
    "/usr/bin/chsh"
    "/usr/bin/newgrp"
    "/usr/bin/ksu"
    "/usr/bin/umount"
    "/usr/bin/su"
    "/usr/bin/sudo"
    "/usr/bin/Xorg"
    "/usr/bin/chage"
    "/usr/bin/chfn"
    "/usr/bin/mount"
    "/usr/bin/pkexec"
    "/usr/bin/gpasswd"
    "/usr/bin/staprun"
    "/usr/bin/fusermount"
    "/usr/bin/at"
    "/usr/bin/passwd"
    "/usr/bin/crontab"
)

CURRENT_BINARIES=$(find /usr /bin /home /etc /opt /root /sbin /srv /tmp -perm -4000 -type f 2>/dev/null)

SORTED_KNOWN=$(printf "%s\n" "${KNOWN_BINARIES[@]}" | sort)
SORTED_FOUND=$(printf "%s\n" $CURRENT_BINARIES | sort)

NEW_BINARIES=$(comm -13 <(echo "$SORTED_KNOWN") <(echo "$SORTED_FOUND"))

if [[ -n "$NEW_BINARIES" ]]; then
    echo "New setuid binaries detected:"
    echo "$NEW_BINARIES"
else
    echo "No new setuid binaries found."
fi

### Manual Investigation

## Processes

ps awfux > processes

## Network Connections

ss -peanut > netconn
netstat -tunp > netconnestab
netstat -tulnp > netconnlisten

## Sudoers

cat /etc/sudoers | grep -vE "#|Defaults" > sudoers

## SUID Binaries

find /usr /bin /home /etc /opt /root /sbin /srv /tmp -perm -4000 -type f 2>/dev/null > setuid
# rm /usr/sbin/ppppd

echo "Script completed."
