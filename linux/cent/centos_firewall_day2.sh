#!/bin/bash

### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

### Firewalls

echo "Resetting iptables rules..."
iptables -F
iptables -X
iptables -Z

echo "Allowing port 22/tcp in iptables..."
iptables -A INPUT -p tcp --dport "22" -j ACCEPT

iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "Setting default policies to DROP for incoming and forwarded traffic..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT -i lo -j ACCEPT

echo "done"
