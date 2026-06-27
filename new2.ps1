<#
.SYNOPSIS
    Advanced DNS Hijack Protection & Diagnostics Tool (IPv4 & IPv6)
.DESCRIPTION
    A highly verbose, enterprise-grade PowerShell tool that enforces a Zero-Trust 
    Registry padlock on network interface DNS configurations. 
    
    ENGINEERING FEATURES:
    - DHCP Bypass: Targets S-1-5-32-544 (Admins) and S-1-5-18 (SYSTEM) to allow LocalService DHCP.
    - Dual-Stack Protection: Iterates through both Tcpip (IPv4) and Tcpip6 (IPv6) subkeys.
    - Cosmetic GPO Layer: Disables legacy Control Panel applets (ncpa.cpl).
    - Diagnostic Verbosity: Outputs RAW ACL Tables and raw .NET exceptions for IT auditing.
#>

# ============================================================================
# 1. PRE-FLIGHT CHECKS & ENVIRONMENT SETUP
# ============================================================================

# Ensure the script is running with Administrative Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "CRITICAL: You must run this script as an Administrator!"
    Start-Sleep -Seconds 3
    Exit
}

# Setup Auto-Logging in the same directory as the script
$ScriptDir = Split-Path -Parent -Path $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = $PWD.Path }
$LogFile = Join-Path -Path $ScriptDir -ChildPath "DNS_Lockdown_Verbose.log"

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host "[$Type] $Message" -ForegroundColor $Color
}

Write-Log -Message "Advanced Diagnostics Script Launched (IPv4 & IPv6)." -Type "SYSTEM" -Color Cyan

# Fetch all active and hidden network adapters
$Adapters = Get-NetAdapter -ErrorAction SilentlyContinue

# Define System Identifiers (SIDs)
# We avoid using "Everyone" (S-1-1-0) so we do not crash Windows DHCP services
$SidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$GpoPath = "HKCU:\Software\Policies\Microsoft\Windows\Network Connections"

# ============================================================================
# 2. STATUS CHECKER MODULE
# ============================================================================

function Get-DNSLockStatus {
    $AllLocked = $true
    $AnyLocked = $false

    Write-Host "`n--- Live Adapter Lockdown Status ---" -ForegroundColor Gray
    
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $AdapterLocked = $false

        # Build an array containing both IPv4 and IPv6 registry paths
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            try {
                # Open registry in Read-Only mode to check permissions
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            # If a Deny rule exists for Admin or SYSTEM, flag it as locked
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny") {
                                $AdapterLocked = $true
                            }
                        } catch {} # Catch orphaned/dead SIDs that cannot be translated
                    }
                    $RegKey.Close()
                }
            } catch {}
        }

        # Visual Output Logic
        if ($AdapterLocked) {
            Write-Host "  [X] $($Adapter.Name) -> LOCKED (IPv4 & IPv6 Protected)" -ForegroundColor Red
            $AnyLocked = $true
        } else {
            Write-Host "  [ ] $($Adapter.Name) -> UNLOCKED (Vulnerable)" -ForegroundColor Green
            $AllLocked = $false
        }
    }
    Write-Host ""

    if ($AllLocked) { Write-Host "[STATUS] ZERO-TRUST PADLOCK IS ACTIVE." -ForegroundColor White -BackgroundColor DarkRed } 
    else { Write-Host "[STATUS] SYSTEM IS CURRENTLY UNLOCKED." -ForegroundColor White -BackgroundColor DarkGreen }
    return $AllLocked
}

# ============================================================================
# 3. LOCKDOWN MODULE (ENABLE)
# ============================================================================

function Enable-DNSLock {
    Write-Log -Message "Initiating Targeted Lock (Admin/SYSTEM Only on IPv4 & IPv6)..." -Type "ACTION" -Color Yellow

    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }
            
            try {
                # Open registry with ChangePermissions rights
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()

                    # Create hard Deny rules specifically for Admin and SYSTEM
                    $Rule1 = New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "SetValue", "Deny")
                    $Rule2 = New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "SetValue", "Deny")

                    $Acl.AddAccessRule($Rule1)
                    $Acl.AddAccessRule($Rule2)

                    # Write the lock to the registry
                    $RegKey.SetAccessControl($Acl)
                    Write-Log -Message "Applied targeted lock ($Proto) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green
                    
                    # --- DIAGNOSTIC: RAW ACL OUTPUT ---
                    Write-Host "  > [RAW ACL DUMP FOR $($Adapter.Name) - $Proto]" -ForegroundColor DarkGray
                    $RegKey.GetAccessControl().Access | Where-Object { $_.AccessControlType -eq 'Deny' } | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize | Out-String | Write-Host -ForegroundColor DarkGray
                    
                    $RegKey.Close()
                }
            } catch {
                Write-Log -Message "Failed to lock $Proto adapter $($Adapter.Name)." -Type "ERROR" -Color Red
                
                # --- DIAGNOSTIC: RAW ERROR OUTPUT ---
                Write-Host "  > [RAW .NET EXCEPTION TRACE]" -ForegroundColor DarkRed
                Write-Output $_.Exception | Format-List * -Force | Out-String | Write-Host -ForegroundColor DarkRed
            }
        }
    }

    Write-Log -Message "Applying visual GPO restrictions..." -Type "INFO" -Color Yellow
    if (-not (Test-Path $GpoPath)) { New-Item -Path $GpoPath -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue

    # --- DIAGNOSTIC: VERBOSE GPO UPDATE ---
    Write-Log -Message "Enforcing Group Policy Update (gpupdate /force)..." -Type "INFO" -Color Yellow
    Write-Host "  > [RAW WINDOWS GPO OUTPUT]" -ForegroundColor DarkGray
    C:\Windows\System32\gpupdate.exe /force
    
    Write-Log -Message "Protection deployed successfully. Testing DHCP stability..." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 4. UNLOCK MODULE (DISABLE / ÅNGRA)
# ============================================================================

function Disable-DNSLock {
    Write-Log -Message "Initiating Total Unlock (Ångra)..." -Type "ACTION" -Color Yellow

    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }
            
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    $RulesToRemove = @()

                    # Hunt for active Deny rules tied to Admin, SYSTEM, or an old Everyone rule
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq "S-1-5-32-544" -or $RuleSid.Value -eq "S-1-5-18" -or $RuleSid.Value -eq "S-1-1-0") -and $Rule.AccessControlType -eq "Deny") {
                                $RulesToRemove += $Rule
                            }
                        } catch {}
                    }

                    if ($RulesToRemove.Count -gt 0) {
                        foreach ($Rule in $RulesToRemove) { $Acl.RemoveAccessRule($Rule) }
                        $RegKey.SetAccessControl($Acl)
                        Write-Log -Message "Stripped Deny rules ($Proto) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green
                    }
                    $RegKey.Close()
                }
            } catch {
                Write-Log -Message "Failed to read $Proto adapter $($Adapter.Name)." -Type "ERROR" -Color Red
            }
        }
    }

    Write-Log -Message "Removing visual GPO restrictions..." -Type "INFO" -Color Yellow
    if (Test-Path $GpoPath) {
        Remove-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -ErrorAction SilentlyContinue
    }

    # --- DIAGNOSTIC: VERBOSE GPO UPDATE ---
    Write-Host "  > [RAW WINDOWS GPO OUTPUT]" -ForegroundColor DarkGray
    C:\Windows\System32\gpupdate.exe /force
    
    Write-Log -Message "System restored to default Windows behaviors." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 5. MAIN INTERACTIVE MENU
# ============================================================================

do {
    Clear-Host
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "  EXPERIMENTAL TARGETED DNS LOCKOUT (VERBOSE MODE)   " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    
    $CurrentStatus = Get-DNSLockStatus
    
    Write-Host "-----------------------------------------------------"
    Write-Host "1. Enable Targeted Lock (Block Apps, Print Raw ACL)"
    Write-Host "2. Disable Total Lock (Ångra)"
    Write-Host "3. Refresh Interface Status"
    Write-Host "4. Exit"
    Write-Host ""

    $Choice = Read-Host "Select an administrative action (1-4)"

    switch ($Choice) {
        "1" { 
            Enable-DNSLock
            Write-Host "`nPress any key to return to the menu..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" { 
            Disable-DNSLock
            Write-Host "`nPress any key to return to the menu..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "3" { Start-Sleep -Milliseconds 200 }
        "4" { break }
        default { Start-Sleep -Milliseconds 500 }
    }
} while ($Choice -ne "4")
