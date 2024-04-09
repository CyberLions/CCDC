# Lovingly plagiarised and authored by @Lfgberg - https://lfgberg.org

# VARIABLES TO IGNORE
$transcriptPath = "C:\dementia.log"

# Network Shares
Write-Host "These are the current network shares"
[string[]]$output = Invoke-Expression "net share" # list shares

New-Item $Global:scriptPath\results\Shares.txt -type file | Out-Null
foreach ($str in $output)
{
    Add-Content $Global:scriptPath\results\Shares.txt $str
    Write-Host $str
}