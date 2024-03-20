@echo off
netsh advfirewall firewall add rule name="Block All Inbound" dir=in action=block
netsh advfirewall firewall add rule name="Block All Outbound" dir=out action=block

