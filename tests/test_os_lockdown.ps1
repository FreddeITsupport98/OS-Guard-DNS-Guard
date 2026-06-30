<#
.SYNOPSIS
    OS-Guard Regression Test Suite — read-only verification of lockdown state.
.DESCRIPTION
    Checks that the OS child lockdown and DNS protections are correctly applied.
    Does NOT modify any settings — purely asserts current state and reports failures.
    Run as Administrator for full access to HKLM and other user profiles.
#>

param([string]$ChildUser = "Child")

$FailedAssertions = @()

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = "")
    if (-not $Condition) {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkRed }
        $script:FailedAssertions += $Name
    } else {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
}

Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host " OS-GUARD REGRESSION TEST SUITE " -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
Write-Host "Child Account: $ChildUser" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "`n"

# --- 1. Child Account Existence & Membership ---
$ChildAccount = $null
try { $ChildAccount = Get-LocalUser -Name $ChildUser -ErrorAction Stop } catch {}
Assert-True -Name "ChildAccount_Exists" -Condition ($null -ne $ChildAccount) -Detail "Account '$ChildUser' not found"
if ($ChildAccount) {
    Assert-True -Name "ChildAccount_Enabled" -Condition ($ChildAccount.Enabled -eq $true) -Detail "Account is disabled"
    Assert-True -Name "ChildAccount_NotAdmin" -Condition ($ChildAccount.PrincipalSource -ne 'ActiveDirectory') -Detail "Check local admin membership manually"
    try {
        $AdminMembers = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Select-Object -ExpandProperty Name
        $IsAdmin = $AdminMembers -contains $ChildUser -or $AdminMembers -match "\\$ChildUser$"
        Assert-True -Name "ChildAccount_NoAdminGroup" -Condition (-not $IsAdmin) -Detail "Child is still in Administrators group"
    } catch {
        Assert-True -Name "ChildAccount_NoAdminGroup" -Condition $false -Detail "Could not query Administrators group: $_"
    }
}

# --- 2. Machine-Wide Policies (UAC + Store) ---
$UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$UacLUA = (Get-ItemProperty -Path $UacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
$UacAdmin = (Get-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$UacDesktop = (Get-ItemProperty -Path $UacPath -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop
Assert-True -Name "UAC_EnableLUA" -Condition ($UacLUA -eq 1) -Detail "EnableLUA = $UacLUA"
Assert-True -Name "UAC_ConsentPromptBehaviorAdmin" -Condition ($UacAdmin -eq 2) -Detail "ConsentPromptBehaviorAdmin = $UacAdmin"
Assert-True -Name "UAC_PromptOnSecureDesktop" -Condition ($UacDesktop -eq 1) -Detail "PromptOnSecureDesktop = $UacDesktop"

$StorePath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$StoreRemoved = (Get-ItemProperty -Path $StorePath -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue).RemoveWindowsStore
Assert-True -Name "Store_RemoveWindowsStore" -Condition ($StoreRemoved -eq 1) -Detail "RemoveWindowsStore = $StoreRemoved"

# --- 2b. Stricter Machine Policies (Installer, USB, WSH, SmartScreen, Fast User Switching, WU) ---
$MsiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$MsiDisabled = (Get-ItemProperty -Path $MsiPath -Name "DisableMSI" -ErrorAction SilentlyContinue).DisableMSI
Assert-True -Name "Installer_DisableMSI" -Condition ($MsiDisabled -eq 2) -Detail "DisableMSI = $MsiDisabled"

$UsbStart = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue).Start
Assert-True -Name "USBStorage_Disabled" -Condition ($UsbStart -eq 4) -Detail "USBSTOR Start = $UsbStart"

$WshEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
Assert-True -Name "WSH_Disabled" -Condition ($WshEnabled -eq 0) -Detail "WSH Enabled = $WshEnabled"

$SmartScreen = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue).EnableSmartScreen
Assert-True -Name "SmartScreen_Enforced" -Condition ($SmartScreen -eq 1) -Detail "EnableSmartScreen = $SmartScreen"

$FastSwitch = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -ErrorAction SilentlyContinue).HideFastUserSwitching
Assert-True -Name "FastUserSwitching_Disabled" -Condition ($FastSwitch -eq 1) -Detail "HideFastUserSwitching = $FastSwitch"

$WuBlocked = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue).DisableWindowsUpdateAccess
Assert-True -Name "WindowsUpdateUI_Blocked" -Condition ($WuBlocked -eq 1) -Detail "DisableWindowsUpdateAccess = $WuBlocked"

# --- 3. Child Hive Policies (if mountable) ---
$ChildProfile = $null
try {
    $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
} catch {}
if ($ChildProfile) {
    $NtUserDat = Join-Path $ChildProfile.LocalPath "NTUSER.DAT"
    if (Test-Path $NtUserDat) {
        $HiveMount = "OSGuardTestPolicy"
        # Unload if already mounted from a previous run
        if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
            reg.exe unload "HKU\$HiveMount" 2>&1 | Out-Null
        }
        $LoadResult = & reg.exe load "HKU\$HiveMount" "$NtUserDat" 2>&1
        if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
            $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
            $TaskMgr = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -ErrorAction SilentlyContinue).DisableTaskMgr
            $Regedit = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -ErrorAction SilentlyContinue).DisableRegistryTools
            $NoRun = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun" -ErrorAction SilentlyContinue).NoRun
            $NoControlPanel = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -ErrorAction SilentlyContinue).NoControlPanel

            Assert-True -Name "ChildHive_DisableTaskMgr" -Condition ($TaskMgr -eq 1) -Detail "DisableTaskMgr = $TaskMgr"
            Assert-True -Name "ChildHive_DisableRegistryTools" -Condition ($Regedit -eq 1) -Detail "DisableRegistryTools = $Regedit"
            Assert-True -Name "ChildHive_NoRun" -Condition ($NoRun -eq 1) -Detail "NoRun = $NoRun"
            Assert-True -Name "ChildHive_NoControlPanel" -Condition ($NoControlPanel -eq 1) -Detail "NoControlPanel = $NoControlPanel"

            $NoCtx = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoViewContextMenu" -ErrorAction SilentlyContinue).NoViewContextMenu
            $NoFolder = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoFolderOptions" -ErrorAction SilentlyContinue).NoFolderOptions
            $NoTaskbar = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSetTaskbar" -ErrorAction SilentlyContinue).NoSetTaskbar
            $NoAddPrinter = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAddPrinter" -ErrorAction SilentlyContinue).NoAddPrinter
            $NoDelPrinter = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDeletePrinter" -ErrorAction SilentlyContinue).NoDeletePrinter
            $NoThisPC = (Get-ItemProperty -Path "$HiveRoot\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue)."{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

            Assert-True -Name "ChildHive_NoViewContextMenu" -Condition ($NoCtx -eq 1) -Detail "NoViewContextMenu = $NoCtx"
            Assert-True -Name "ChildHive_NoFolderOptions" -Condition ($NoFolder -eq 1) -Detail "NoFolderOptions = $NoFolder"
            Assert-True -Name "ChildHive_NoSetTaskbar" -Condition ($NoTaskbar -eq 1) -Detail "NoSetTaskbar = $NoTaskbar"
            Assert-True -Name "ChildHive_NoAddPrinter" -Condition ($NoAddPrinter -eq 1) -Detail "NoAddPrinter = $NoAddPrinter"
            Assert-True -Name "ChildHive_NoDeletePrinter" -Condition ($NoDelPrinter -eq 1) -Detail "NoDeletePrinter = $NoDelPrinter"
            Assert-True -Name "ChildHive_HideThisPC" -Condition ($NoThisPC -eq 1) -Detail "ThisPC hidden = $NoThisPC"

            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
            reg.exe unload "HKU\$HiveMount" 2>&1 | Out-Null
        } else {
            Assert-True -Name "ChildHive_Mountable" -Condition $false -Detail "Could not mount NTUSER.DAT: $LoadResult"
        }
    } else {
        Assert-True -Name "ChildHive_NTUSERExists" -Condition $false -Detail "NTUSER.DAT not found at $NtUserDat"
    }
} else {
    Write-Host "[SKIP] ChildHive checks — profile not found (child may never have logged in)." -ForegroundColor Yellow
}

# --- 2c. Logout Shortcut ---
$ChildProfilePath = $null
try {
    $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
    if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
} catch {}
if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
$ShortcutPath = Join-Path $ChildProfilePath "Desktop\Log out.lnk"
Assert-True -Name "ChildLogoutShortcut_Exists" -Condition (Test-Path $ShortcutPath) -Detail "Logout shortcut not found at $ShortcutPath"

# --- 4. DNS Lock State (sample first adapter) ---
$Adapter = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Adapter) {
    $Guid = $Adapter.InterfaceGuid
    $SubKeyPath = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid"
    try {
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        if ($RegKey) {
            $Acl = $RegKey.GetAccessControl()
            $HasDeny = $false
            foreach ($Rule in $Acl.Access) {
                try {
                    $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                    if (($RuleSid.Value -eq "S-1-5-32-544" -or $RuleSid.Value -eq "S-1-5-18") -and $Rule.AccessControlType -eq "Deny" -and $Rule.RegistryRights -like "*SetValue*") {
                        $HasDeny = $true
                    }
                } catch {}
            }
            Assert-True -Name "DNS_AdapterLocked_IPv4" -Condition $HasDeny -Detail "No Deny SetValue ACL found for adapter $($Adapter.Name)"
            $RegKey.Close()
        } else {
            Assert-True -Name "DNS_AdapterLocked_IPv4" -Condition $false -Detail "Could not open registry key for adapter"
        }
    } catch {
        Assert-True -Name "DNS_AdapterLocked_IPv4" -Condition $false -Detail "Registry read error: $_"
    }
} else {
    Write-Host "[SKIP] DNS adapter checks — no network adapters found." -ForegroundColor Yellow
}

# --- 5. Browser DoH Policies ---
$EdgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ChromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$FirefoxPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
$EdgeDoH = (Get-ItemProperty -Path $EdgePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue).DnsOverHttpsMode
$ChromeDoH = (Get-ItemProperty -Path $ChromePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue).DnsOverHttpsMode
$FirefoxDoH = (Get-ItemProperty -Path $FirefoxPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
Assert-True -Name "DoH_EdgeDisabled" -Condition ($EdgeDoH -eq "off") -Detail "Edge DoH mode = $EdgeDoH"
Assert-True -Name "DoH_ChromeDisabled" -Condition ($ChromeDoH -eq "off") -Detail "Chrome DoH mode = $ChromeDoH"
Assert-True -Name "DoH_FirefoxDisabled" -Condition ($FirefoxDoH -eq 0) -Detail "Firefox DoH enabled = $FirefoxDoH"

# --- 6. Installation Artifacts ---
$InstallDir = "C:\ProgramData\OSGuard"
$CmdPath = "C:\Windows\oslock.cmd"
Assert-True -Name "InstallDir_Exists" -Condition (Test-Path $InstallDir) -Detail "Missing $InstallDir"
Assert-True -Name "GlobalCLI_Exists" -Condition (Test-Path $CmdPath) -Detail "Missing $CmdPath"

# --- 7. Scheduled Tasks ---
$TaskName = "OS-Guard-Protection"
$Guardian1 = "OSGuard-Guardian1"
$Guardian2 = "OSGuard-Guardian2"
$ChildLogon = "OSGuard-ChildLogon"
$ParentModeWatch = "OSGuard-ParentModeWatch"
Assert-True -Name "Task_MainExists" -Condition ([bool](Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) -Detail "Task $TaskName missing"
Assert-True -Name "Task_Guardian1Exists" -Condition ([bool](Get-ScheduledTask -TaskName $Guardian1 -ErrorAction SilentlyContinue)) -Detail "Task $Guardian1 missing"
Assert-True -Name "Task_Guardian2Exists" -Condition ([bool](Get-ScheduledTask -TaskName $Guardian2 -ErrorAction SilentlyContinue)) -Detail "Task $Guardian2 missing"
Assert-True -Name "Task_ParentModeWatchExists" -Condition ([bool](Get-ScheduledTask -TaskName $ParentModeWatch -ErrorAction SilentlyContinue)) -Detail "Task $ParentModeWatch missing"

# --- 8. Parent Mode Artifacts ---
$AdminProfile = $env:USERPROFILE
$AdminDesktop = Join-Path $AdminProfile "Desktop"
Assert-True -Name "ParentModeShortcut_Exists" -Condition (Test-Path (Join-Path $AdminDesktop "Parent Mode.lnk")) -Detail "Parent Mode.lnk missing on admin desktop"
Assert-True -Name "LockNowShortcut_Exists" -Condition (Test-Path (Join-Path $AdminDesktop "Lock Now.lnk")) -Detail "Lock Now.lnk missing on admin desktop"
Assert-True -Name "ContinueParentModeShortcut_Exists" -Condition (Test-Path (Join-Path $AdminDesktop "Continue Parent Mode.lnk")) -Detail "Continue Parent Mode.lnk missing on admin desktop"

$RequestDir = Join-Path "C:\ProgramData\OSGuard" "Requests"
Assert-True -Name "RequestsDir_Exists" -Condition (Test-Path $RequestDir) -Detail "Requests directory missing at $RequestDir"

$IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$ParentHash = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -ErrorAction SilentlyContinue).OSGuardParentPasswordHash
Assert-True -Name "ParentPasswordHash_Set" -Condition ($null -ne $ParentHash -and $ParentHash.Length -eq 64) -Detail "Parent password hash not set or wrong length"

$ParentModeActive = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue).OSGuardParentModeActive
$IsLocked = ($ParentModeActive -eq 0 -or $null -eq $ParentModeActive)
Assert-True -Name "ParentMode_NotActive" -Condition $IsLocked -Detail "ParentModeActive = $ParentModeActive (should be 0 or unset when not in use)"

# --- FAIL SUMMARY ---
Write-Host "`n=====================================================" -ForegroundColor DarkGray
Write-Host " REGRESSION RESULTS " -ForegroundColor White
Write-Host "=====================================================" -ForegroundColor DarkGray
if ($FailedAssertions.Count -gt 0) {
    Write-Host "FAIL SUMMARY ($($FailedAssertions.Count))" -ForegroundColor Red -BackgroundColor Black
    foreach ($Name in $FailedAssertions) { Write-Host "  - $Name" -ForegroundColor Red }
    exit 1
} else {
    Write-Host "[SUCCESS] ALL REGRESSION ASSERTIONS PASSED!" -ForegroundColor Green
    exit 0
}
