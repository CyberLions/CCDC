Get-ADUser -Filter * | ForEach-Object { Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword (Read-Host "Enter the new password" -AsSecureString) -Reset }

