# List of executable names to monitor and terminate
$exeNames = @("msedge", "wmiprvse", "calc", "notepad", "cmd", "GooseDesktop", "MEMZ")

while ($true) {
    foreach ($exeName in $exeNames) {
        # Check for the process
        $process = Get-Process -Name $exeName -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "Terminating $exeName process..."
            Stop-Process -Name $exeName -Force
        }
    }

    # Wait for 2.5 seconds before checking again
    Start-Sleep -Seconds 2.5
}

