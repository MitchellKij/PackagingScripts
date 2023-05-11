# -----------------------------------------------------------------------------------------------------------------------
#                                       Generic Packaging functions                 
# -----------------------------------------------------------------------------------------------------------------------



function Write-Timestamp {
    return (Get-Date -Format yyyyMMdd-HHmm)
}

function Remove-FirewallRule {
    param(
        [string]$RuleName
    )

    Write-Host "Attempting to remove firewall rule"
    try {
        Remove-NetFirewallRule -DisplayName $RuleName
        Write-Host "Firewall rule removed"
    }
    catch {
        Write-Host "Issue removing firewall rule with name $RuleName"
    }
   
}

function New-FirewallRule {
    param(
        [string]$RuleName,
        [string]$ProgramPath,
        [string]$Direction = "Inbound",
        [string]$Action = "Allow",
        [string]$Protocol = "TCP",
        [int]$LocalPort
    )

    Write-Host "Creating new firewall rule"

    try {
        New-NetFirewallRule -DisplayName $RuleName -Direction $Direction -Program $ProgramPath -Action $Action -Protocol $Protocol -LocalPort $LocalPort
        Write-Host "Firewall rule has been successfully created"
    }
    catch {
        Write-Host "There was a problem creating the firewall rule"
    }
   
}

function New-RegistryKey {
    param(
        [string]$RegPath,
        [string]$RegKeyName,
        [string]$RegKeyValue,
        [string]$RegValueType = "String"
    )

    $RegKey = New-Item -Path $RegPath -Name $RegKeyName -Force -ErrorAction SilentlyContinue
    if ($null -ne $RegKey) {
        Write-Host "Creating Registry key"
        New-ItemProperty -Path $RegKey.PSPath -Name $RegKeyName -Value $RegKeyValue -PropertyType $RegValueType -Force
    } else {
        Write-Host "There was a problem creating the registry key"
    }
}

function Remove-RegistryKey {
    param(
        [string]$RegPath,
        [string]$RegKeyName
    )

    $RegKey = Get-Item -Path $RegPath -ErrorAction SilentlyContinue
    if ($null -ne $RegKey) {
        Write-Host "Removing registry key"
        Remove-ItemProperty -Path $RegKey.PSPath -Name $RegKeyName -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Registry key $RegKeyName not found at $RegPath"
    }
}

function New-Shortcut {
    param(
        [string]$ShortcutPath,
        [string]$TargetPath,
        [string]$IconLocation = ""
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)

    $shortcut.TargetPath = $TargetPath
    if (-not [string]::IsNullOrEmpty($IconLocation)) {
        $shortcut.IconLocation = $IconLocation
    } else {
        $shortcut.IconLocation = $TargetPath
    }
    $shortcut.Save()
}

function Remove-Shortcut {
    param(
        [string]$ShortcutPath
    )

    if (Test-Path $ShortcutPath) {
        Write-Host "Removing shortcut at $ShortcutPath"
        Remove-Item -Path $ShortcutPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Shortcut not found at $ShortcutPath"
    }
}

function Remove-Shortcuts {
    param(
        [array]$Shortcuts
    )

    Write-Host "Performing clean up actions..."

    ForEach ($Shortcut in $Shortcuts) {
        Start-Sleep 1
        if (Test-Path $Shortcut) {
            Remove-Item -Path $Shortcut -Force -ErrorAction Continue #add -Recurse for shortcut folders

            If (Test-Path -Path $Shortcut) {
                Write-Host "'$Shortcut' was still detected. Removal failed."
            }
            Else {
                Write-Host "'$Shortcut' was removed successfully."
            }
        }
        else {
            Write-Host "'$shortcut' doesn't exist, skipping..."
        }
    }
}

function Remove-Driver {
    param(
        [string]$DriverPath
    )

    Write-Host "Starting uninstall"
    $drivers = Get-WindowsDriver -Online

    $specificDriver = $drivers | Where-Object { $_.OriginalFileName -eq $DriverPath }
    $oemName = $specificDriver.Driver

    if ($null -ne $oemName) {
        $Result = Start-Process -FilePath pnputil.exe -ArgumentList "/delete-driver", $oemName -NoNewWindow -Wait -PassThru

        if ($Result.ExitCode -eq 0) {
            Write-Host "Driver '$DriverPath' uninstalled successfully."
        }
        else {
            Write-Host "An error occurred while uninstalling the driver '$DriverPath'. Exit code: $($Result.ExitCode)"
        }
    }
    else {
        Write-Host "No driver found with the path '$DriverPath'"
    }
}




# Recon 

function Find-SoftwareRegKey {
    param(
        [string]$AppName
    )

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
}

function Get-InstalledSoftware {
    # $installedSoftware = Get-InstalledSoftware
    # $installedSoftware | Format-Table -AutoSize
    $regLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $installedSoftware = @()

    foreach ($regLocation in $regLocations) {
        $regKeys = Get-ChildItem -Path $regLocation -ErrorAction SilentlyContinue

        foreach ($regKey in $regKeys) {
            $displayName = (Get-ItemProperty -Path $regKey.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            $displayVersion = (Get-ItemProperty -Path $regKey.PSPath -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
            $installLocation = (Get-ItemProperty -Path $regKey.PSPath -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation

            if ($null -ne $displayName) {
                $installedSoftware += New-Object -TypeName PSObject -Property @{
                    Name = $displayName
                    Version = $displayVersion
                    InstallLocation = $installLocation
                    RegPath = $regKey.PSPath
                }
            }
        }
    }

    return $installedSoftware
}

function Find-UninstallExe {
    param(
        [string]$AppName
    )

    $regLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($regLocation in $regLocations) {
        $regKeys = Get-ChildItem -Path $regLocation -ErrorAction SilentlyContinue

        foreach ($regKey in $regKeys) {
            $displayName = (Get-ItemProperty -Path $regKey.PSPath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
            $uninstallString = (Get-ItemProperty -Path $regKey.PSPath -Name UninstallString -ErrorAction SilentlyContinue).UninstallString

            if ($displayName -like "*$AppName*" -and $null -ne $uninstallString) {
                # Remove any command-line arguments from the uninstall string
                $uninstallExe = $uninstallString.Split(" ")[0]
                return $uninstallExe
            }
        }
    }

    Write-Host "Uninstall executable not found for '$AppName' in registry"
    return $null
}