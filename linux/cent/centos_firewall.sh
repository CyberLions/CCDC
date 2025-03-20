#!/bin/bash

### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

### Firewalls

read -p "Enter a list of ports to allow (comma separated, e.g., 22,80,443): " ports

IFS=',' read -r -a port_array <<< "$ports"

echo "Resetting iptables rules..."
iptables -F
iptables -X
iptables -Z

for port in "${port_array[@]}"; do
    echo "Allowing port $port/tcp in iptables..."
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
done

iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "Setting default policies to DROP for incoming and forwarded traffic..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT -i lo -j ACCEPT

echo "done"