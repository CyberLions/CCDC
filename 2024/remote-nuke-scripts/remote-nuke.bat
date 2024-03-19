@echo off

REM Function to stop and disable a service
:DisableService
sc stop %1
sc config %1 start= disabled
exit /b

REM Function to stop a process by name
:StopProcessByName
taskkill /F /IM %1.exe
exit /b

REM Function to add a firewall rule to block incoming connections on a specific port
:BlockIncomingPort
netsh advfirewall firewall add rule name="Block Port %1" dir=in action=block protocol=TCP localport=%1
exit /b

REM Disable OpenSSH service
call :DisableService ssh-agent

REM Stop OpenSSH process
call :StopProcessByName sshd

REM Disable Remote Desktop Protocol (RDP) service
call :DisableService TermService

REM Stop RDP processes
call :StopProcessByName rdp

REM Disable Virtual Network Computing (VNC) service
call :DisableService vncserver

REM Stop VNC process
REM Replace "vnc" with the actual process name
call :StopProcessByName vnc

REM Block OpenSSH port (default: 22)
call :BlockIncomingPort 22

REM Block RDP port (default: 3389)
call :BlockIncomingPort 3389

REM Block VNC port (adjust the port number as per your VNC configuration)
REM call :BlockIncomingPort <your_vnc_port_number>

echo Script execution completed.

