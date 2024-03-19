#!/bin/bash

# Stop SSH service
sudo systemctl stop ssh

# Block SSH connections at firewall level
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
sudo iptables -A OUTPUT -p tcp --sport 22 -j DROP

# Ensure SSH-related processes are stopped
sudo pkill sshd
