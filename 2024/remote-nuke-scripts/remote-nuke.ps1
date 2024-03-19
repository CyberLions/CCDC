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

# Disable OpenSSH service
Disable-Service -serviceName 'ssh-agent'

# Stop OpenSSH process
Stop-ProcessByName -processName 'sshd'

# Disable Remote Desktop Protocol (RDP) service
Disable-Service -serviceName 'TermService'

# Stop RDP processes
Stop-ProcessByName -processName 'rdp'

# Disable Virtual Network Computing (VNC) service
Disable-Service -serviceName 'vncserver'

# Stop VNC process (adjust the process name as per your VNC configuration)
Stop-ProcessByName -processName 'vnc'

# Block OpenSSH port (default: 22)
Block-IncomingPort -port 22

# Block RDP port (default: 3389)
Block-IncomingPort -port 3389

# Block VNC port (adjust the port number as per your VNC configuration)
Block-IncomingPort -port <your_vnc_port_number>

