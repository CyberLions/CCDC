@echo off
Rem These must match the names of the rules that blocked all traffic
netsh advfirewall firewall delete rule name="Block All Inbound"
netsh advfirewall firewall delete rule name="Block All Outbound"
