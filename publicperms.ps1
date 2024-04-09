function CheckPublicReadWritePermissions {
    param (
        [string]$FilePath
    )

    # Check permissions on Linux
    if ($IsLinux) {
        $permissions = (Get-Acl -Path $FilePath).Access
        $publicReadWrite = $false

        foreach ($permission in $permissions) {
            if ($permission.IdentityReference -eq 'Everyone' -and $permission.FileSystemRights -match 'Read' -and $permission.FileSystemRights -match 'Write') {
                $publicReadWrite = $true
                break
            }
        }

        return $publicReadWrite
    }

    # Check permissions on Windows
    else {
        $acl = Get-Acl -Path $FilePath

        foreach ($accessRule in $acl.Access) {
            if ($accessRule.IdentityReference -eq 'Everyone' -and $accessRule.FileSystemRights -match 'Read' -and $accessRule.FileSystemRights -match 'Write') {
                return $true
            }
        }

        return $false
    }
}

# Determine if running on Linux
$IsLinux = Test-Path "/proc/version"

# Specify the directory to search
$directoryToSearch = "C:\Path\To\Directory"

# Recursively search for files in the directory on Windows
if (-not $IsLinux) {
    $files = Get-ChildItem -Path $directoryToSearch -Recurse -File
}
# Recursively search for files in the directory on Linux
else {
    $files = Get-ChildItem -Path $directoryToSearch -Recurse | Where-Object { -not $_.PSIsContainer }
}

# Iterate through each file and check permissions
foreach ($file in $files) {
    $isPublicReadWrite = CheckPublicReadWritePermissions -FilePath $file.FullName
    if ($isPublicReadWrite) {
        Write-Output "Public READ/WRITE file found: $($file.FullName)"
    }
}

