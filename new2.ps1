# Ensure the script is running with Administrative Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "CRITICAL: You must run this script as an Administrator!"
    Exit
}

# Setup Auto-Logging
$ScriptDir = Split-Path -Parent -Path $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = $PWD.Path }
$LogFile = Join-Path -Path $ScriptDir -ChildPath "DNS_Lockdown.log"

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host "[$Type] $Message" -ForegroundColor $Color
}

Write-Log -Message "Experimental targeted script launched." -Type "SYSTEM" -Color Cyan

$Adapters = Get-NetAdapter -ErrorAction SilentlyContinue

$GpoPath = "HKCU:\Software\Policies\Microsoft\Windows\Network Connections"
# Target ONLY Admin and SYSTEM, leaving LocalService (DHCP) alone
$SidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")

function Get-DNSLockStatus {
    $AllLocked = $true
    $AnyLocked = $false
    
    Write-Host "Adapter Lockdown Status (Targeted SIDs):" -ForegroundColor Gray
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPath = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        $AdapterLocked = $false
        
        try {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                foreach ($Rule in $Acl.Access) {
                    try {
                        $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                        if (($RuleSid.Value -eq "S-1-5-32-544" -or $RuleSid.Value -eq "S-1-5-18") -and $Rule.AccessControlType -eq "Deny") {
                            $AdapterLocked = $true
                        }
                    } catch {}
                }
                $RegKey.Close()
            }
        } catch {}
        
        if ($AdapterLocked) {
            Write-Host "  [X] $($Adapter.Name) -> LOCKED (Admin/SYSTEM)" -ForegroundColor Red
            $AnyLocked = $true
        } else {
            Write-Host "  [ ] $($Adapter.Name) -> UNLOCKED" -ForegroundColor Green
            $AllLocked = $false
        }
    }
    Write-Host ""

    if ($AllLocked) { Write-Host "[STATUS] TARGETED DNS LOCK IS ACTIVE." -ForegroundColor White -BackgroundColor DarkRed } 
    else { Write-Host "[STATUS] TARGETED DNS LOCK IS INACTIVE." -ForegroundColor White -BackgroundColor DarkGreen }
    return $AllLocked
}

function Enable-DNSLock {
    Write-Log -Message "Initiating Targeted Lock (Admin/SYSTEM Only)..." -Type "ACTION" -Color Yellow
    
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPath = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        
        try {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                
                # Apply Deny rules specifically to Admin and SYSTEM
                $Rule1 = New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "SetValue", "Deny")
                $Rule2 = New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "SetValue", "Deny")
                
                $Acl.AddAccessRule($Rule1)
                $Acl.AddAccessRule($Rule2)
                
                $RegKey.SetAccessControl($Acl)
                $RegKey.Close()
                Write-Log -Message "Applied targeted lock for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green
            }
        } catch {
            Write-Log -Message "Failed to lock adapter $($Adapter.Name): $_" -Type "ERROR" -Color Red
        }
    }

    if (-not (Test-Path $GpoPath)) { New-Item -Path $GpoPath -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    Write-Log -Message "Enforcing GPO update (gpupdate /force)..." -Type "INFO" -Color Yellow
    C:\Windows\System32\gpupdate.exe /force | Out-Null
    Write-Log -Message "Protection deployed. Check if DHCP still works!" -Type "SUCCESS" -Color Green
}

function Disable-DNSLock {
    Write-Log -Message "Initiating Unlock..." -Type "ACTION" -Color Yellow
    
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPath = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
        
        try {
            $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
            if ($RegKey) {
                $Acl = $RegKey.GetAccessControl()
                $RulesToRemove = @()
                
                foreach ($Rule in $Acl.Access) {
                    try {
                        $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                        # Remove locks for Admin, SYSTEM, AND the old Everyone rule just in case it was left behind
                        if (($RuleSid.Value -eq "S-1-5-32-544" -or $RuleSid.Value -eq "S-1-5-18" -or $RuleSid.Value -eq "S-1-1-0") -and $Rule.AccessControlType -eq "Deny") {
                            $RulesToRemove += $Rule
                        }
                    } catch {}
                }
                
                if ($RulesToRemove.Count -gt 0) {
                    foreach ($Rule in $RulesToRemove) { $Acl.RemoveAccessRule($Rule) }
                    $RegKey.SetAccessControl($Acl)
                    Write-Log -Message "Unlocked Registry for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green
                }
                $RegKey.Close()
            }
        } catch {}
    }

    if (Test-Path $GpoPath) {
        Remove-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -ErrorAction SilentlyContinue
    }
    
    C:\Windows\System32\gpupdate.exe /force | Out-Null
    Write-Log -Message "System restored to default." -Type "SUCCESS" -Color Green
}

do {
    Clear-Host
    Write-Host "=========================================" -ForegroundColor Cyan
    Write-Host " EXPERIMENTAL TARGETED DNS LOCKOUT       " -ForegroundColor Cyan
    Write-Host "=========================================" -ForegroundColor Cyan
    $CurrentStatus = Get-DNSLockStatus
    Write-Host "-----------------------------------------"
    Write-Host "1. Enable Targeted Lock (Block Apps, Allow DHCP?)"
    Write-Host "2. Disable Total Lock (Ångra)"
    Write-Host "3. Refresh Status Check"
    Write-Host "4. Exit"
    Write-Host ""
    
    $Choice = Read-Host "Select an option (1-4)"
    
    switch ($Choice) {
        "1" { Enable-DNSLock; Start-Sleep -Seconds 4 }
        "2" { Disable-DNSLock; Start-Sleep -Seconds 4 }
        "3" { Start-Sleep -Milliseconds 500 }
        "4" { break }
        default { Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "4")