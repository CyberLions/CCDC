# 1. Check admin rights ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "You must run this script as an administrator. Exiting..."
    exit 1
}

$ADModuleLoaded = $false
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $ADModuleLoaded = $true
    } catch {
        Write-Warning "Failed to import ActiveDirectory module: $($_.Exception.Message)"
    }
} else {
    Write-Warning "ActiveDirectory module not found. Domain accounts cannot be fetched or managed."
}

#local and domain accounts ---
Write-Host "Fetching local user accounts..."
$localUsers = @()
try {
    $localUsers = Get-LocalUser | Select-Object @{
        Name       = 'Name';
        Expression = { $_.Name }
    }, @{
        Name       = 'Enabled';
        Expression = { $_.Enabled }
    }, @{
        Name       = 'Type';
        Expression = { 'Local' }
    }
} catch {
    Write-Warning "Could not retrieve local users: $($_.Exception.Message)"
}

$domainUsers = @()
if ($ADModuleLoaded) {
    Write-Host "Fetching domain user accounts..."
    try {
        $domainUsers = Get-ADUser -Filter * -Properties Enabled | Select-Object `
            @{ Name = 'Name'; Expression = { $_.SamAccountName } },
            @{ Name = 'Enabled'; Expression = { $_.Enabled } },
            @{ Name = 'Type'; Expression = { 'Domain' } },
            @{ Name = 'SamAccountName'; Expression = { $_.SamAccountName } } 
    } catch {
        Write-Warning "Could not retrieve domain users: $($_.Exception.Message)"
    }
}

$allAccounts = $localUsers + $domainUsers

if ($allAccounts.Count -eq 0) {
    Write-Host "No accounts found. Exiting..."
    exit 0
}

#Show all
Write-Host "`n========== ALL FETCHED ACCOUNTS =========="
$index = 0
$allAccounts | ForEach-Object {
    # Show an index, then account info
    $status = if ($_.Enabled -eq $true) { 'Enabled' } else { 'Disabled' }
    Write-Host ("[{0}] {1} - {2} - Type: {3}" -f $index, $_.Name, $status, $_.Type)
    $index++
}

Write-Host "==========================================`n"

#Prompt
$selectedIndex = Read-Host "Enter the index of the account you want to manage"
if ($selectedIndex -notmatch '^\d+$' -or [int]$selectedIndex -lt 0 -or [int]$selectedIndex -ge $allAccounts.Count) {
    Write-Host "Invalid selection. Exiting..."
    exit 1
}

$selectedAccount = $allAccounts[$selectedIndex]
Write-Host "`nYou selected: $($selectedAccount.Name) (Type: $($selectedAccount.Type))"

# action ---
Write-Host "`nChoose an action for this account:"
Write-Host "1. Delete"
Write-Host "2. Change Password"
Write-Host "3. Disable (Deactivate)"
$actionChoice = Read-Host "Enter 1, 2, or 3"

switch ($actionChoice) {
    # DELETE
    "1" {
        if ($selectedAccount.Type -eq "Local") {
            try {
                Remove-LocalUser -Name $selectedAccount.Name
                Write-Host "Local user '$($selectedAccount.Name)' has been deleted."
            } catch {
                Write-Warning "Failed to delete local user: $($_.Exception.Message)"
            }
        } elseif ($selectedAccount.Type -eq "Domain") {
            if (-not $ADModuleLoaded) {
                Write-Warning "Cannot delete domain user because AD module is not loaded."
                break
            }
            try {
                Remove-ADUser -Identity $selectedAccount.SamAccountName -Confirm:$false
                Write-Host "Domain user '$($selectedAccount.Name)' has been deleted."
            } catch {
                Write-Warning "Failed to delete domain user: $($_.Exception.Message)"
            }
        }
    }

    #  CHANGE PASSWORD
    "2" {
        $newPassword = Read-Host "Enter the new password" -AsSecureString

        if ($selectedAccount.Type -eq "Local") {
            try {
                $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword)
                )

                Set-LocalUser -Name $selectedAccount.Name `
                              -Password (ConvertTo-SecureString $plainPassword -AsPlainText -Force)
                Write-Host "Password changed for local user '$($selectedAccount.Name)'."
            } catch {
                Write-Warning "Failed to change password for local user: $($_.Exception.Message)"
            }
        } elseif ($selectedAccount.Type -eq "Domain") {
            if (-not $ADModuleLoaded) {
                Write-Warning "Cannot change password for domain user because AD module is not loaded."
                break
            }
            try {
                Set-ADAccountPassword -Identity $selectedAccount.SamAccountName `
                                      -Reset `
                                      -NewPassword $newPassword `
                                      -Confirm:$false


                Write-Host "Password changed for domain user '$($selectedAccount.Name)'."
            } catch {
                Write-Warning "Failed to change password for domain user: $($_.Exception.Message)"
            }
        }
    }

    #  DISABLE (Deactivate)
    "3" {
        if ($selectedAccount.Type -eq "Local") {
            try {
                Disable-LocalUser -Name $selectedAccount.Name
                Write-Host "Local user '$($selectedAccount.Name)' has been disabled."
            } catch {
                Write-Warning "Failed to disable local user: $($_.Exception.Message)"
            }
        } elseif ($selectedAccount.Type -eq "Domain") {
            if (-not $ADModuleLoaded) {
                Write-Warning "Cannot disable domain user because AD module is not loaded."
                break
            }
            try {
                Disable-ADAccount -Identity $selectedAccount.SamAccountName
                Write-Host "Domain user '$($selectedAccount.Name)' has been disabled."
            } catch {
                Write-Warning "Failed to disable domain user: $($_.Exception.Message)"
            }
        }
    }

    default {
        Write-Host "Invalid action choice. Exiting...!"
    }
}

Write-Host "`nWindows Sucks."
