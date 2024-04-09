function CheckPublicReadWritePermissions {
    param (
        [string]$FilePath
    )

    $acl = Get-Acl -Path $FilePath

    foreach ($accessRule in $acl.Access) {
        if ($accessRule.IdentityReference -eq 'Everyone' -and $accessRule.FileSystemRights -match 'Read' -and $accessRule.FileSystemRights -match 'Write') {
            return $true
        }
    }

    return $false
}

# Specify the directory to search
$directoryToSearch = "C:\Path\To\Directory"

# Recursively search for files in the directory on Windows
$files = Get-ChildItem -Path $directoryToSearch -Recurse -File

# Iterate through each file and check permissions
foreach ($file in $files) {
    $isPublicReadWrite = CheckPublicReadWritePermissions -FilePath $file.FullName
    if ($isPublicReadWrite) {
        Write-Output "Public READ/WRITE file found: $($file.FullName)"
    }
}
