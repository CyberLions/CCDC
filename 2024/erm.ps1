# Enable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Defender
Install-WindowsFeature-Name Windows-Server-Antimalware
Get-Command -Module Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting 2​
