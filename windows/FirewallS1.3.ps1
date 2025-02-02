Set-ExecutionPolicy Bypass -Scope Process -Force

# Log file path
$logPath = "C:\FirewallScriptLog.txt"
$backupDir = "C:\FirewallBackups"

# Function to log actions
function Log-Action {
    param ([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "[$timestamp] $Message"
}

# Function to validate port number
function Validate-PortNumber {
    param ([int]$PortNumber)
    if ($PortNumber -lt 1 -or $PortNumber -gt 65535) {
        Write-Host "Invalid port number! Port must be between 1 and 65535." -ForegroundColor Red
        return $false
    }
    return $true
}

# Function to validate protocol
function Validate-Protocol {
    param ([string]$Protocol)
    if ($Protocol -notin @("TCP", "UDP")) {
        Write-Host "Invalid protocol! Protocol must be TCP or UDP." -ForegroundColor Red
        return $false
    }
    return $true
}

# Function to display all enabled firewall rules
function Show-FirewallRules {
    $firewallRules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" }

    Write-Host "`nCurrently Enabled Firewall Rules:`n" -ForegroundColor Cyan
    Write-Host ("{0,-30} {1,-12} {2,-10} {3,-8} {4}" -f "DisplayName", "Direction", "LocalPort", "Action", "Enabled")
    Write-Host "---------------------------------------------------------------------------"

    foreach ($rule in $firewallRules) {
        Write-Host ("{0,-30} {1,-12} {2,-10} {3,-8} {4}" -f `
            $rule.DisplayName, `
            $rule.Direction, `
            $rule.LocalPort, `
            $rule.Action, `
            $rule.Enabled)
    }
    Write-Host ""
}

# Function to backup firewall rules
function Backup-FirewallRules {
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir | Out-Null
    }
    $backupPath = "$backupDir\FirewallRulesBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"
    netsh advfirewall export $backupPath
    if (Test-Path $backupPath) {
        Write-Host "Backup successful! Rules saved at $backupPath"
        Log-Action "Backup created at $backupPath"
        return $backupPath
    } else {
        Write-Host "Backup failed!"
        Log-Action "Backup failed!"
        return $null
    }
}

# Function to restore firewall rules
function Restore-FirewallRules {
    $backupFiles = Get-ChildItem -Path $backupDir -Filter "FirewallRulesBackup*.wfw"
    if ($backupFiles.Count -eq 0) {
        Write-Host "No backups found in $backupDir!"
        return
    }
    Write-Host "Available Backups:"
    $backupFiles | ForEach-Object { Write-Host "$($_.Name)" }
    $selectedBackup = Read-Host "Enter the full name of the backup file to restore"
    $backupPath = "$backupDir\$selectedBackup"
    if (Test-Path $backupPath) {
        netsh advfirewall import $backupPath
        Write-Host "Firewall rules restored from $backupPath!"
        Log-Action "Firewall rules restored from $backupPath"
    } else {
        Write-Host "Backup file not found at $backupPath!"
        Log-Action "Failed to restore backup: $backupPath not found"
    }
}

# Function to block all ports and allow specific ones
function Block-All-And-Allow-Specific-Ports {
    # Confirm action
    $confirmation = Read-Host "This will block all ports except the ones you specify. Do you want to continue? (Y/N)"
    if ($confirmation -notmatch "^[Yy]$") {
        Write-Host "Action cancelled."
        return
    }

    # Backup existing rules
    $backupPath = Backup-FirewallRules
    if (-not $backupPath) {
        Write-Host "Backup failed! Exiting script to avoid losing existing rules." -ForegroundColor Red
        return
    }

    # Remove ALL existing rules
    Write-Host "Removing all existing firewall rules..."
    Get-NetFirewallRule | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue

    # Set default block policy
    Write-Host "Setting default inbound and outbound rules to block..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
    Log-Action "Set default inbound/outbound rules to block"

    # Define allowed ports and protocols
    $allowedPorts = @(
        @{Port=80; Protocol="TCP"; Name="HTTP"},
        @{Port=443; Protocol="TCP"; Name="HTTPS"},
        @{Port=53; Protocol="TCP"; Name="DNS-TCP"},
        @{Port=53; Protocol="UDP"; Name="DNS-UDP"},
        @{Port=123; Protocol="UDP"; Name="NTP"},
        @{Port=25; Protocol="TCP"; Name="SMTP"},
        @{Port=110; Protocol="TCP"; Name="POP3"},
        @{Port=389; Protocol="TCP"; Name="LDAP"},
        @{Port=389; Protocol="UDP"; Name="LDAP-UDP"},
        @{Port=636; Protocol="TCP"; Name="LDAPS"},
        @{Port=445; Protocol="TCP"; Name="SMB"},
        @{Port=3389; Protocol="TCP"; Name="RDP"},
        @{Port=8000; Protocol="TCP"; Name="Splunk-Web"},
        @{Port=9997; Protocol="TCP"; Name="Splunk-Logs"}
    )

    # Create ICMP rules
    Write-Host "Creating ICMP rules..."
    New-NetFirewallRule -DisplayName "Allow-ICMPv4-Inbound" -Protocol ICMPv4 -Direction Inbound -Action Allow -Profile Any
    New-NetFirewallRule -DisplayName "Allow-ICMPv4-Outbound" -Protocol ICMPv4 -Direction Outbound -Action Allow -Profile Any
    New-NetFirewallRule -DisplayName "Allow-ICMPv6-Inbound" -Protocol ICMPv6 -Direction Inbound -Action Allow -Profile Any
    New-NetFirewallRule -DisplayName "Allow-ICMPv6-Outbound" -Protocol ICMPv6 -Direction Outbound -Action Allow -Profile Any

    # Create rules for allowed ports
    Write-Host "Creating essential service rules..."
    foreach ($port in $allowedPorts) {
        $name = $port.Name
        $protocol = $port.Protocol
        $portNumber = $port.Port
        
        New-NetFirewallRule -DisplayName "Allow-Inbound-$name" -Direction Inbound -Protocol $protocol -LocalPort $portNumber -Action Allow -Profile Any
        New-NetFirewallRule -DisplayName "Allow-Outbound-$name" -Direction Outbound -Protocol $protocol -LocalPort $portNumber -Action Allow -Profile Any
    }

    # Allow DNS resolver
    New-NetFirewallRule -DisplayName "Allow-DNS-Resolver" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Profile Any

    Write-Host "Firewall configuration completed successfully!"
    Log-Action "Completed full firewall reset and essential rules creation"
}

# Function to allow a specific port
function Open-Port {
    param (
        [int]$PortNumber,
        [string]$Protocol = "TCP"
    )

    if (-not (Validate-PortNumber -PortNumber $PortNumber) -or -not (Validate-Protocol -Protocol $Protocol)) {
        return
    }

    Write-Host "Opening port $PortNumber for $Protocol traffic..."
    New-NetFirewallRule -DisplayName "Allow-Inbound-Port-$PortNumber" -Direction Inbound -Protocol $Protocol -LocalPort $PortNumber -Action Allow -Profile Any
    New-NetFirewallRule -DisplayName "Allow-Outbound-Port-$PortNumber" -Direction Outbound -Protocol $Protocol -LocalPort $PortNumber -Action Allow -Profile Any
    Log-Action "Opened port $PortNumber for $Protocol traffic"
}

# Function to block a specific port
function Block-Port {
    param (
        [int]$PortNumber,
        [string]$Protocol = "TCP"
    )

    if (-not (Validate-PortNumber -PortNumber $PortNumber) -or -not (Validate-Protocol -Protocol $Protocol)) {
        return
    }

    Write-Host "Blocking port $PortNumber for $Protocol traffic..."
    New-NetFirewallRule -DisplayName "Block-Inbound-Port-$PortNumber" -Direction Inbound -Protocol $Protocol -LocalPort $PortNumber -Action Block -Profile Any
    New-NetFirewallRule -DisplayName "Block-Outbound-Port-$PortNumber" -Direction Outbound -Protocol $Protocol -LocalPort $PortNumber -Action Block -Profile Any
    Log-Action "Blocked port $PortNumber for $Protocol traffic"
}

# Main menu
function Main-Menu {
    # Require admin privileges
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script requires Administrator privileges!`nPlease restart PowerShell as Administrator." -ForegroundColor Red
        exit
    }

    while ($true) {
        Show-FirewallRules

        Write-Host "Select an option:"
        Write-Host "1) Block all and allow essential ports"
        Write-Host "2) Backup firewall rules"
        Write-Host "3) Restore firewall rules"
        Write-Host "4) Open a specific port"
        Write-Host "5) Block a specific port"
        Write-Host "6) Exit"
        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            1 { Block-All-And-Allow-Specific-Ports }
            2 { Backup-FirewallRules }
            3 { Restore-FirewallRules }
            4 {
                $portNumber = Read-Host "Enter the port number to allow"
                $protocol = Read-Host "Enter the protocol (TCP/UDP)"
                Open-Port -PortNumber $portNumber -Protocol $protocol
            }
            5 {
                $portNumber = Read-Host "Enter the port number to block"
                $protocol = Read-Host "Enter the protocol (TCP/UDP)"
                Block-Port -PortNumber $portNumber -Protocol $protocol
            }
            6 {
                Write-Host "Exiting... Goodbye!" -ForegroundColor Green
                exit
            }
            default {
                Write-Host "Invalid choice! Please select a valid option." -ForegroundColor Red
            }
        }
    }
}

# Run the main menu
Main-Menu
