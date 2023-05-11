#
# After installing an application, this can be run in the command line to locate the regkey from the application name. 
# The locations specified are the most common spots, but may not always work.
#

[string]$AppName = Read-Host "Input App name"
    

$regLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

$foundRegKeys = @()

foreach ($regLocation in $regLocations) {
    $regKeys = Get-ChildItem -Path $regLocation -ErrorAction SilentlyContinue

    foreach ($regKey in $regKeys) {
        $displayName = (Get-ItemProperty -Path $regKey.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName

        if ($displayName -like "*$AppName*") {
            $foundRegKeys += $regKey.PSPath
        }
    }
}

if ($foundRegKeys.Count -gt 0) {
    Write-Host "Found $($foundRegKeys.Count) registry key(s) for '$AppName':"
    foreach ($foundRegKey in $foundRegKeys) {
        Write-Host "  $foundRegKey"
    }
}
else {
    Write-Host "No registry keys found for '$AppName'"
}
