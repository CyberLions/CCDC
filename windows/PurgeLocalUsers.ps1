# List of users to keep
$usersToKeep = @("User1", "User2", "User3")

# Get all existing users
$allUsers = Get-LocalUser | Select-Object -ExpandProperty Name

# Users to remove
$usersToRemove = $allUsers | Where-Object { $_ -notin $usersToKeep }

# Remove users not in the array
foreach ($user in $usersToRemove) {
    Remove-LocalUser -Name $user -Confirm:$false
}

Write-Host "Users removed successfully."
