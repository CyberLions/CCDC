# Lovingly plagiarised and authored by @Lfgberg - https://lfgberg.org

# VARIABLES TO SET - READ THE README
$allowedUsers = @("TODO")
$allowedAdministrators = @("TODO")
$enableRemoteDesktop = $true # Change this to false if you don't want RDP

# VARIABLES TO IGNORE
$Error.Clear()
$ErrorActionPreference = "Continue"
$uberSecurePassword = ConvertTo-SecureString -String "BallsInYourFace69!" -AsPlainText -Force
$backupPath = "C:\backups"
$transcriptPath = "C:\virtual-viagara.log"

# DC detection
$isDomainController = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $isDomainController = $true
}


# Ensure script is running as administrator
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

Start-Transcript -Path $transcriptPath

# Ensure AD Module is installed and imported
if ($isDomainController -eq $true){
    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)){
        if (-not (Get-WindowsFeature -Name RSAT-AD-PowerShell)){
            Install-WindowsFeature RSAT-AD-PowerShell -IncludeAllSubFeature -IncludeManagementTools
        }
        Import-Module ActiveDirectory
    }
}

# Create backup directory we will try to use later
New-Item -Path "C:\backups" -ItemType Directory -Force

# user password settings
net accounts /minpwlen:10 /maxpwage:30 /minpwage:1 /uniquepw:24
net accounts /lockoutthreshold:6 /lockoutwindow:30 /lockoutduration:30

# set auditing
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

# Enable Windows Firewall for all profiles (Domain, Private, Public)
$isRecentConsumer = ($Global:operatingSystem -Like "*Windows 10*") -or ($Global:operatingSystem -Like "*Windows 8.1*") -or ($Global:operatingSystem -Like "*Windows 8 *")
$isRecentServer = ($Global:operatingSystem -Like "*Windows Server 2016*") -or ($Global:operatingSystem -Like "*Windows Server 2012 R2*") -or ($Global:operatingSystem -Like "*Windows Server 2012*")

$isOlderConsumer = ($Global:operatingSystem -Like "*Windows 7*") -or ($Global:operatingSystem -Like "*Windows Vista*")
$isOlderServer = ($Global:operatingSystem -Like "*Windows Server 2008 R2*") -or ($Global:operatingSystem -Like "*Windows Server* 2008*")

if ($isRecentConsumer -or $isRecentServer)
{
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True # enable all firewall profiles
}
elseif($isOlderConsumer -or $isOlderServer)
{
    Invoke-Expression "netsh advfirewall set allprofiles state on" # enable all firewall profiles
}

# Reset folder and file perms to default in /Users folder
icacls \Users /reset /t

# User management

## Local Users
$allLocalUsers = Get-LocalUser | Select-Object -ExpandProperty Name
$localUsersToRemove = $allLocalUsers | Where-Object { $_ -notin $allowedUsers -and $_ -notin $allowedAdministrators }

## Purge local users, remove their user folders
foreach ($user in $localUsersToRemove) {
    # Del user
    Remove-LocalUser -Name $user -Confirm:$false

    # Del user folderr
    $userFolderPath = "C:\Users\$user"
    if (Test-Path $userFolderPath -PathType Container) {
        Remove-Item -Path $userFolderPath -Recurse -Force
    }
}

## Set all local user passwords, ensure they expire
Get-LocalUser | ForEach-Object { $_ | Set-LocalUser -Password $uberSecurePassword -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires }

if ($isDomainController -eq $true){
    $allADUsers = Get-ADUser -Filter * -Property SamAccountName | Select-Object -ExpandProperty SamAccountName
    $adUsersToRemove = $allADUsers | Where-Object { $_ -notin $allowedUsers -and $_ -notin $allowedAdministrators }
    
    foreach ($user in $adUsersToRemove) {
        # Del user
        Remove-ADUser -Identity $user -Confirm:$false
    
        # Del user folderr
        $userFolderPath = "C:\Users\$user"
        if (Test-Path $userFolderPath -PathType Container) {
            Remove-Item -Path $userFolderPath -Recurse -Force
        }
    }
    
    ## Set all AD account passwords
    Get-ADUser -Filter * | ForEach-Object { Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $uberSecurePassword -Reset -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -PasswordNotRequired $false -AccountNotDelegated $true;Set-ADAccountControl -Identity $_.SamAccountName -DoesNotRequirePreAuth $false }
    
    ## Ensure all AD accounts have passwords that expire
    Get-ADUser -Filter * -Properties PasswordNeverExpires | ForEach-Object {
        if (-not $_.PasswordNeverExpires) {
            $_ | Set-ADUser -PasswordNeverExpires:$false
        }
    }
}

# Enable Windows auto update
if ($Global:operatingSystem -NotLike '*Windows 10*' -or $Global:operatingSystem -NotLike '*Windows Server 2016*'){
    $updateObject = (New-Object -com "Microsoft.Update.AutoUpdate").Settings # turn automatic updates on
    $updateObject.NotificationLevel = 4 # make sure recommended updates are included
    $updateObject.IncludeRecommendedUpdates = "true"
    $updateObject.save() # save the changes
} else {
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -regName DisableWindowsUpdateAccess -regValue 0 # windows update is enabled
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName NoAutoUpdate -regValue 0 # enable automatic updates
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName AUOptions -regValue 4 # auto download and schedule installation
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName ScheduledInstallDay -regValue 0 # scheduled install every day
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName ScheduledInstallTime -regValue 3 # scheduled install at 3-4ish in the morning (values start form 0 so I'm not 100% sure which it is)
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName RescheduleWaitTime -regValue 10 # wait up to 10 min after scheduled install time has passed
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName NoAutoRebootWithLoggedOnUsers -regValue 0 # auto reboot for updates enabled
    Set-RegKey -regPath HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -regName UseWUServer -regValue 0 # use Microsoft update servers instead of corporate update servers
}

# Disabling Windows Features
$featuresToDisable = @(
    "IIS-WebServerRole",
    "IIS-WebServer",
    "IIS-CommonHttpFeatures",
    "IIS-HttpErrors",
    "IIS-HttpRedirect",
    "IIS-ApplicationDevelopment",
    "NetFx4Extended-ASPNET45",
    "IIS-NetFxExtensibility45",
    "IIS-HealthAndDiagnostics",
    "IIS-HttpLogging",
    "IIS-LoggingLibraries",
    "IIS-RequestMonitor",
    "IIS-HttpTracing",
    "IIS-Security",
    "IIS-RequestFiltering",
    "IIS-Performance",
    "IIS-WebServerManagementTools",
    "IIS-IIS6ManagementCompatibility",
    "IIS-Metabase",
    "IIS-ManagementConsole",
    "IIS-BasicAuthentication",
    "IIS-WindowsAuthentication",
    "IIS-StaticContent",
    "IIS-DefaultDocument",
    "IIS-WebSockets",
    "IIS-ApplicationInit",
    "IIS-ISAPIExtensions",
    "IIS-ISAPIFilter",
    "IIS-HttpCompressionStatic",
    "IIS-ASPNET45",
    "WindowsMediaPlayer",
    "TelnetServer",
    "TelnetClient",
    "SMB1Protocol",
    "MicrosoftWindowsPowerShellV2",
    "MicrosoftWindowsPowerShellV2Root"
)

foreach ($feature in $featuresToDisable) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}

# Services

## Enable
$servicesToStart = @(
    "wuauserv",                 # Windows Update
    "EventLog",                 # Event Logger
    "mpssvc",                   # Windows Firewall
    "WinDefend",                # Windows Defender
    "wcmsvc"                   # Windows Connection Manager
)

foreach ($service in $servicesToStart) {
    Set-Service -Name $service -Status Running -StartupType Automatic
}

Set-Service -Name SecurityHealthService -Status Running -StartupType Manual # Windows Security Health Service

##Disable
$servicesToStop = @(
    "RemoteRegistry",
    "bthserv",
    "Browser",
    "MapsBroker",
    "lfsvc",
    "IISADMIN",
    "irmon",
    "SharedAccess",
    "lltdsvc",
    "MSiSCSI",
    "InstallService",
    "sshd",
    "PNRPsvc",
    "p2psvc",
    "p2pimsvcy",
    "PNRPAutoReg",
    "wercplsupport",
    "RpcLocator",
    "RemoteAccess",
    "lanmanserver",
    "simptcp",
    "SNMP",
    "SSDPSRV",
    "upnphost",
    "WMSvc",
    "WerSvc",
    "Wecsvc",
    "WMPNetworkSvc",
    "icssvc",
    "WpnService",
    "PushToInstall",
    "WinRM",
    "W3SVC",
    "XboxGipSvc",
    "XblAuthManager",
    "XblGameSave",
    "XboxNetApiSvc",
    "Fax",
    "iphlpsvc",
    "seclogon",
    "UmRdpService",
    "RasAuto",
    "NetTcpPortSharing",
    "Mcx2Svc",
    "HomeGroupProvider",
    "HomeGroupListener",
    "PeerDistSvc",
    "TlntSvr",
    "AJRouter",
    "BthHFSrv",
    "CDPSvc",
    "DiagTrack",
    "wlidsvc",
    "Netlogon",
    "NcdAutoSetup",
    "PhoneSvc",
    "RetailDemo",
    "TapiSrv",
    "workfolderssvc",
    "fdPHost",
    "FDResPub",
    "WMPNetworkSvc"
)

foreach ($service in $servicesToStop) {
    Set-Service -Name $service -Status Stopped -StartupType Disabled
}

# Enable User Account Control
Invoke-Expression 'reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f'

# RDP

## Disable if not needed

if ($enableRemoteDesktop -eq $false){
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
	Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
}

## Secure RDP

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 2 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f | Out-Null

# Internet Explorer Settings

## Do not track
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f'
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f'
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f'
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f'
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f'
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f'

## Disable password Caching
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f'

## Enable SmartScreen
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f'
Invoke-Expression 'reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f'

# Create a backup of the hosts file in "C:\hostsBackup", restore to defaults
if ($Global:operatingSystem -Like "*Windows 10*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin10`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows 8 *") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin8`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows 8.1*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin8`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows 7*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin7`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows Vista*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWinVista`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows Server 2012 R2*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin8`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows Server 2012*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin8`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows Server 2008 R2*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWin7`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
} elseif ($Global:operatingSystem -Like "*Windows Server* 2008*") {
    Invoke-Expression "copy `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`" `"$backupPath`""
    Invoke-Expression "copy `"$Global:scriptPath\dependencies\hosts\HostWinVista`" `"$env:SystemDrive\Windows\System32\drivers\etc\hosts`""
}

# Create windows god mode shortcut
Invoke-Expression "mkdir '$env:userprofile\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}'"

# Flush DNS cache
Invoke-Expression "ipconfig /flushdns"

# Enable ASLR
Invoke-Expression 'reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MitigationOptions /t REG_BINARY /d 00010100000000000000000000000000 /f' 

# Enable DEP
Invoke-Expression "bcdedit.exe /set nx AlwaysOn"

# Disable AutoLogin
$autoLoginCheck = Test-Path $Global:scriptPath\dependencies\registry\AutoLogon.reg
if ($autoLoginCheck -eq $True){
    Invoke-Expression "regedit /s dependencies\AutoLogon.reg"
}

# WinRM
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v AllowUnencryptedTraffic /t REG_DWORD /d 0 /f | Out-Null # Disable unencrypted traffic

# CVEs

## CVE-2021-36934 (HiveNightmare/SeriousSAM) - workaround (patch at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
icacls $env:windir\system32\config\*.* /inheritance:e | Out-Null

## CVE-2021-1675 and CVE 2021-34527 (PrintNightmare)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v CopyFilesPolicy /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /f | Out-Null

## CVE-2021-1678
reg add "HKLM\System\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 1 /f | Out-Null

# Credential Delegation settings

## Enabling support for Restricted Admin/Remote Credential Guard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f | Out-Null
## Enabling Restricted Admin mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f | Out-Null
## Disabling Restricted Admin Outbound Creds
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 1 /f | Out-Null
## Enabling Credential Delegation (Restrict Credential Delegation)
reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v RestrictedRemoteAdministration /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v RestrictedRemoteAdministrationType /t REG_DWORD /d 3 /f | Out-Null

# User Account Control (UAC)

## Enabling Restricted Admin mode
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ValidateAdminCodeSignatures /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f | Out-Null

## Applying UAC restrictions to local accounts on network logons
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null

# LSASS Protections

## Enabling LSA protection mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null

## Enabling LSASS audit mode
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v disabledomaincreds /t REG_DWORD /d 1 /f | Out-Null

## Restricting access from anonymous users (treating them seperate from Everyone group)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous /t REG_DWORD /d 0 /f | Out-Null

## Setting amount of time to clear logged-off users' credentials from memory (secs)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30 /f | Out-Null

## Restricting remote calls to SAM to just Administrators
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f | Out-Null

# Disabling WDigest, removing storing plain text passwords in LSASS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f | Out-Null

# Disabling autologon
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f | Out-Null

# Setting screen saver grace period
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f | Out-Null

# Caching logons
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount /t REG_SZ /d 0 /f | Out-Null

# NTLM Settings

## Could impact share access (configured to only send NTLMv2, refuse LM & NTLM) - CVE-2019-1040
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LMCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null

## Allowing Local System to use computer identity for NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f | Out-Null

## Preventing null session fallback for NTLM
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f | Out-Null

## Setting NTLM SSP server and client to require NTLMv2 and 128-bit encryption
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f | Out-Null

# System security 

## Disable loading of test signed kernel-drivers
bcdedit.exe /set TESTSIGNING OFF | Out-Null
bcdedit.exe /set loadoptions ENABLE_INTEGRITY_CHECKS | Out-Null

## Enabling driver signature enforcement
bcdedit.exe /set nointegritychecks off | Out-Null

## Enable DEP for all processes
bcdedit.exe /set "{current}" nx AlwaysOn | Out-Null

## Disabling crash dump generation
reg add "HKLM\SYSTEM\CurrentControlSet\control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f | Out-Null

## Enabling automatic reboot after system crash
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 1 /f | Out-Null

## Stopping Windows Installer from always installing w/elevated privileges
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f | Out-Null
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /d 0 /f | Out-Null

## Requiring a password on wakeup
powercfg -SETACVALUEINDEX SCHEME_BALANCED SUB_NONE CONSOLELOCK 1 | Out-Null

## Disable WPBT (Windows Platform Binary Table) functionality
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v DisableWpbtExecution /t REG_DWORD /d 1 /f | Out-Null

# Explorer/file settings

## Changing file associations to make sure they have to be executed manually
cmd /c ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype batfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
cmd /c ftype vbsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"

Stop-Transcript