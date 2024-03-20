# Function to stop and disable a service
function Disable-Service {
    param (
        [string]$serviceName
    )
    # Stop the service
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    # Disable the service
    Set-Service -Name $serviceName -StartupType Disabled -ErrorAction SilentlyContinue
}

# Function to stop a process
function Stop-ProcessByName {
    param (
        [string]$processName
    )
    # Get the process(es) by name and stop them
    Get-Process -Name $processName -ErrorAction SilentlyContinue | Stop-Process -Force
}

# Function to add a firewall rule to block incoming connections on a specific port
function Block-IncomingPort {
    param (
        [int]$port
    )
    # Check if the rule already exists
    $existingRule = Get-NetFirewallRule -DisplayName "Block Port $port" -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        # Add a new firewall rule to block incoming connections on the specified port
        New-NetFirewallRule -DisplayName "Block Port $port" -Direction Inbound -Protocol TCP -LocalPort $port -Action Block -Enabled True
    }
}

# Stop & Disable OpenSSH Authentication Agent
Disable-Service -serviceName 'ssh-agent'

# Stop & Disable OpenSSH SSH Server
Disable-Service -serviceName 'sshd'

# Ensure ssh agent process is stopped
Stop-ProcessByName -processName 'ssh-agent'

# Ensure sshd proces is stopped
Stop-ProcessByName -processName 'sshd'

# Disable Remote Desktop Protocol (RDP) service
Disable-Service -serviceName 'TermService'

# Stop & Disable TightVNC service
Disable-Service -serviceName 'tvnserver'

# Stop all processes with vnc in name (will work with at least thinvnc)
Stop-ProcessByName -processName '*vnc*'

# Stop & Disable WinRM service
Disable-Service -serviceName 'WinRM'

# Disable PS-Remoting - Removed cause it scuffs out, disabling WinRM should be fine.
# Disable-PSRemoting

# Block OpenSSH port (default: 22)
Block-IncomingPort -port 22

# Block RDP port (default: 3389)
Block-IncomingPort -port 3389

# Block VNC port
Block-IncomingPort -port 5900

# Block WinRM http & https port 
Block-IncomingPort -port 5985
Block-IncomingPort -port 5986


