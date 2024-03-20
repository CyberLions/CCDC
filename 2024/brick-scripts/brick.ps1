New-NetFirewallRule -DisplayName "Block All Inbound Traffic" -Direction Inbound -Action Block
New-NetFirewallRule -DisplayName "Block All Outbound Traffic" -Direction Outbound -Action Block
