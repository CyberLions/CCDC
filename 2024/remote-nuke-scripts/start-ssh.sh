#!/bin/bash

# Stop SSH service
sudo systemctl start ssh

# Remove SSH blocking rules from firewall
sudo iptables -D INPUT -p tcp --dport 22 -j DROP
sudo iptables -D OUTPUT -p tcp --sport 22 -j DROP

# Restart firewall to apply changes
sudo systemctl restart iptables

# Ensure SSH-related processes are running
sudo systemctl start sshd