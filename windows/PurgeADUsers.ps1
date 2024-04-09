# List of users to keep
$usersToKeep = @("User1", "User2", "User3")

# Specify the AD domain
$domain = "yourdomain.com"

# Get all existing users from AD
$allUsers = Get-ADUser -Filter * -Property SamAccountName | Select-Object -ExpandProperty SamAccountName

# Users to remove
$usersToRemove = $allUsers | Where-Object { $_ -notin $usersToKeep }

# Remove users not in the array
foreach ($user in $usersToRemove) {
    Remove-ADUser -Identity $user -Confirm:$false
}

Write-Host "Users removed successfully."
