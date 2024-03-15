$NewPassword = Read-Host "Enter the new password" -AsSecureString; Get-LocalUser | ForEach-Object { $_ | Set-LocalUser -Password $NewPassword }
