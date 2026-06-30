<#
.SYNOPSIS
    Enterprise OS Child Lockdown + DNS Hijack Protection Suite (IPv4 & IPv6 + DoH)
.DESCRIPTION
    A highly verbose, enterprise-grade PowerShell tool that enforces:
    1. Zero-Trust Registry padlock on network interface DNS configurations (IPv4 & IPv6)
    2. Browser DNS-over-HTTPS (DoH) loophole closure (Edge, Chrome, Firefox)
    3. STRICT child-safe OS lockdown on a dedicated standard user account
       - Auto-creates a PASSWORDLESS child account if missing
       - Blocks software installation, settings changes, CMD, Run, Control Panel, Regedit, TaskMgr
       - Maxes UAC so the child cannot turn it off
       - Removes Windows Store
       - Leaves the built-in Administrator account with FULL privileges to install/modify
    4. Self-healing background persistence (scheduled tasks + WMI) re-applies everything
       on boot, logon, network change, and every 5/10 minutes.

    NEW FEATURES:
    - Global CLI: Installs 'oslock' command to Windows PATH for easy cmd access.
    - Automated Installation: Scheduled Tasks re-apply locks on boot/network change/logon.
    - Background Guardians: Protects against Windows Updates and driver reinstalls.
    - Child Account Management: Auto-creates passwordless 'Child' standard user.
    - Advanced Auditing: UI tracks DNS locks, OS restrictions, and install status.
    - Payload Self-Defense: NTFS ACL hardening locks the install directory against tampering.
#>

param (
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Lock,
    [switch]$Unlock,
    [switch]$SilentLock,
    [switch]$ChildLock,
    [switch]$ParentMode,
    [switch]$SetParentPassword,
    [switch]$ChildGameRequest,
    [switch]$ContinueParentMode,
    [switch]$LockNow,
    [string]$ChildUser = "Child"
)

# ============================================================================
# 1. AUTO-ELEVATION & PRE-FLIGHT CHECKS
# ============================================================================

# Automatically relaunch as Administrator if not already elevated
$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$Role = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $Principal.IsInRole($Role)) {
    if ($Install -or $Uninstall -or $Lock -or $Unlock -or $SilentLock -or $ParentMode -or $SetParentPassword -or $LockNow) {
        Write-Warning "CRITICAL: Administrative privileges required for CLI commands. Access Denied."
        return
    }
    # ChildLock and ChildGameRequest write only to the current user's own HKCU, no elevation needed
    if (-not $ChildLock -and -not $ChildGameRequest) {
        Write-Warning "Administrative privileges required. Attempting auto-elevation..."
        Start-Sleep -Seconds 1
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "powershell.exe"

            # Forward any CLI flags (like -Uninstall) to the elevated process
            $ArgsString = ""
            if ($Install) { $ArgsString += " -Install" }
            if ($Uninstall) { $ArgsString += " -Uninstall" }
            if ($Lock) { $ArgsString += " -Lock" }
            if ($Unlock) { $ArgsString += " -Unlock" }
            if ($SilentLock) { $ArgsString += " -SilentLock" }
            if ($ChildLock) { $ArgsString += " -ChildLock" }
            if ($ParentMode) { $ArgsString += " -ParentMode" }
            if ($SetParentPassword) { $ArgsString += " -SetParentPassword" }
            if ($ChildGameRequest) { $ArgsString += " -ChildGameRequest" }
            if ($ContinueParentMode) { $ArgsString += " -ContinueParentMode" }
            if ($LockNow) { $ArgsString += " -LockNow" }
            if ($ChildUser -ne "Child") { $ArgsString += " -ChildUser `"$ChildUser`"" }

            $ProcessInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $ArgsString"
            $ProcessInfo.Verb = "runAs"
            [System.Diagnostics.Process]::Start($ProcessInfo) | Out-Null
            return
        } catch {
            Write-Error "Failed to elevate. Please right-click and 'Run as Administrator'."
            return
        }
    }
}

# ============================================================================
# 2. GLOBAL CONFIGURATION & PATHS
# ============================================================================

# Define Installation Paths (renamed from DNSGuard to OSGuard)
$InstallDir = "C:\ProgramData\OSGuard"
$InstallScript = Join-Path -Path $InstallDir -ChildPath "OS_Lockdown.ps1"
$CmdPath = "C:\Windows\oslock.cmd"
$TaskName = "OS-Guard-Protection"
$Guardian1Name = "OSGuard-Guardian1"
$Guardian2Name = "OSGuard-Guardian2"
$ChildLogonTaskName = "OSGuard-ChildLogon"
$WmiEventName = "OSGuardWmiHealth"
$ParentModeWatchName = "OSGuard-ParentModeWatch"
$IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"

# Setup Auto-Logging
$ScriptDir = Split-Path -Parent -Path $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = $PWD.Path }
# Log to a writable location (not the hardened install dir) so admin can still write
$LogFile = Join-Path -Path $env:TEMP -ChildPath "OS_Lockdown_Enterprise.log"

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try { "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}

    # Only print to screen if we are NOT running silently in the background
    if (-not $SilentLock) {
        Write-Host "[$Type] $Message" -ForegroundColor $Color
    }
}

if (-not $SilentLock -and -not $ChildLock) { Write-Log -Message "Enterprise OS+DNS Lockdown Suite Initialized." -Type "SYSTEM" -Color Cyan }

# ============================================================================
# 3. SYSTEM AUDIT & HARDWARE DISCOVERY
# ============================================================================

function Run-SystemAudit {
    Write-Log -Message "Running Pre-Flight System Audit..." -Type "AUDIT" -Color DarkGray
    $OS = Get-CimInstance Win32_OperatingSystem
    Write-Log -Message "OS Version: $($OS.Caption) (Build $($OS.BuildNumber))" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "PS Version: $($PSVersionTable.PSVersion)" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "Execution Path: $ScriptDir" -Type "AUDIT" -Color DarkGray
    Write-Log -Message "Target Child User: $ChildUser" -Type "AUDIT" -Color DarkGray
}

if (-not $SilentLock -and -not $ChildLock) { Run-SystemAudit }

# Fetch all network adapters (excluding hidden virtual ones if possible, but keeping all physical)
$Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue } # Fallback

$SidAdmin = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
# Network UI restrictions are USER policies (HKCU)
$GpoPath = "HKCU:\Software\Policies\Microsoft\Windows\Network Connections"

# Define Browser DoH GPO Paths
$EdgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ChromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$FirefoxPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"

# ============================================================================
# 3.1 OS LOCKDOWN POLICY DEFINITIONS
# ============================================================================

# Machine-wide (HKLM) policies. These apply to all users, but the built-in
# Administrator can elevate/bypass as needed. Standard users (child) are blocked.
$MachinePolicies = @(
    # UAC Maxed - child cannot turn off UAC
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableLUA"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; Value = 2 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "PromptOnSecureDesktop"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorUser"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "EnableInstallerDetection"; Value = 1 },
    # Block Windows Store so child cannot install apps
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "RemoveWindowsStore"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "AutoDownload"; Value = 2 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "DisableStoreApps"; Value = 1 },
    # Block Windows Installer for non-managed users (prevents .msi / .exe installer elevation)
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableMSI"; Value = 2 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableUserInstalls"; Value = 2 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableUserInstallsViaModifications"; Value = 1 },
    # Disable Windows Script Host (wscript.exe / cscript.exe)
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"; Name = "Enabled"; Value = 0 },
    # Disable USB storage (prevent installing software from USB)
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"; Name = "Start"; Value = 4 },
    # SmartScreen - block unknown apps and downloads
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableSmartScreen"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "ShellSmartScreenLevel"; Value = "Block" },
    # Block Windows Update UI for standard users
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"; Value = 1 },
    # Disable Fast User Switching (prevents switching to admin without logging out)
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "HideFastUserSwitching"; Value = 1 }
)

# Per-user (HKCU) policies applied to the child account only.
# SubPaths are relative to the user's hive root (no HKCU: prefix).
$ChildHivePolicies = @(
    # Disable Task Manager
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; Value = 1 },
    # Disable Registry Editor
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; Value = 1 },
    # Block password change
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableChangePassword"; Value = 1 },
    # Disable Themes tab
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "NoThemesTab"; Value = 1 },
    # Disable wallpaper change
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop"; Name = "NoChangingWallPaper"; Value = 1 },
    # Disable Run dialog
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoRun"; Value = 1 },
    # Disable Control Panel & Settings app
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoControlPanel"; Value = 1 },
    # Disable AutoPlay for all drive types
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDriveTypeAutoRun"; Value = 255 },
    # Hide Administrative Tools from start menu
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "StartMenuAdminTools"; Value = 0 },
    # Disable Add/Remove Programs (classic appwiz)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall"; Name = "NoAddRemovePrograms"; Value = 1 },
    # Disable Command Prompt
    @{ SubPath = "Software\Policies\Microsoft\Windows\System"; Name = "DisableCMD"; Value = 2 },
    # Disable Windows Update UI for the child
    @{ SubPath = "Software\Policies\Microsoft\Windows\WindowsUpdate"; Name = "NoWindowsUpdate"; Value = 1 },
    # Network Connections UI restrictions (also applied machine-wide by DNS module)
    @{ SubPath = "Software\Policies\Microsoft\Windows\Network Connections"; Name = "NC_LanProperties"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Network Connections"; Name = "NC_LanChangeProperties"; Value = 0 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Network Connections"; Name = "NC_AllowAdvancedTCPIPConfig"; Value = 0 },
    # Disable right-click context menu (prevents "Run as administrator", properties, etc.)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoViewContextMenu"; Value = 1 },
    # Hide Folder Options (prevent showing hidden/system files)
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoFolderOptions"; Value = 1 },
    # Block taskbar changes
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoSetTaskbar"; Value = 1 },
    # Block adding/removing printers
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoAddPrinter"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoDeletePrinter"; Value = 1 },
    # Hide "This PC" from desktop and start menu
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum"; Name = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"; Value = 1 }
)

# ============================================================================
# 4. CHILD ACCOUNT MANAGEMENT
# ============================================================================

function Get-ChildAccount {
    # Returns the LocalUser object for the child account, or $null
    try {
        return (Get-LocalUser -Name $ChildUser -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Get-ChildSid {
    $Acct = Get-ChildAccount
    if ($Acct) { return $Acct.SID.Value }
    return $null
}

function Get-ChildProfilePath {
    param([string]$ChildSidValue)
    if (-not $ChildSidValue) { $ChildSidValue = Get-ChildSid }
    if (-not $ChildSidValue) { return $null }
    try {
        $Profile = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -eq $ChildSidValue } | Select-Object -First 1
        if ($Profile) { return $Profile.LocalPath }
    } catch {}
    # Fallback: assume standard profile location
    $Guess = "C:\Users\$ChildUser"
    if (Test-Path $Guess) { return $Guess }
    return $null
}

function New-ChildAccount {
    <#
        Creates a PASSWORDLESS local standard user if it does not already exist.
        Ensures it is NOT a member of Administrators and IS a member of Users.
        Prevents the child from changing or setting a password.
    #>
    $Existing = Get-ChildAccount
    if ($Existing) {
        Write-Log -Message "Child account '$ChildUser' already exists. Ensuring standard-user membership." -Type "INFO" -Color Gray
        # Ensure NOT an administrator
        try {
            $AdminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" }
            if ($AdminGroup) {
                Remove-LocalGroupMember -Group "Administrators" -Member $ChildUser -ErrorAction SilentlyContinue
                Write-Log -Message "Removed '$ChildUser' from Administrators group." -Type "WARN" -Color Yellow
            }
        } catch {}
        # Ensure IS a member of Users
        try {
            Add-LocalGroupMember -Group "Users" -Member $ChildUser -ErrorAction Stop
        } catch {}
        # Prevent password change
        net user $ChildUser /passwordchg:no 2>&1 | Out-Null
        net user $ChildUser /passwordreq:no 2>&1 | Out-Null
        return $false  # not newly created
    }

    # Create passwordless account
    try {
        New-LocalUser -Name $ChildUser -NoPassword -Description "OS-Guard managed child account (passwordless)" -ErrorAction Stop | Out-Null
        Write-Log -Message "Created PASSWORDLESS child account '$ChildUser'." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to create child account '$ChildUser': $_" -Type "ERROR" -Color Red
        return $false
    }

    # Add to standard Users group
    try {
        Add-LocalGroupMember -Group "Users" -Member $ChildUser -ErrorAction Stop
        Write-Log -Message "Added '$ChildUser' to Users group." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Could not add '$ChildUser' to Users group: $_" -Type "WARN" -Color Yellow
    }

    # Prevent the child from changing or setting a password (lockdown reinforcement)
    net user $ChildUser /passwordchg:no 2>&1 | Out-Null
    net user $ChildUser /passwordreq:no 2>&1 | Out-Null
    Write-Log -Message "Password change disabled for '$ChildUser'." -Type "INFO" -Color Gray

    # Enable the account (in case it was created disabled)
    Enable-LocalUser -Name $ChildUser -ErrorAction SilentlyContinue

    return $true  # newly created
}

# ============================================================================
# 5. CHILD REGISTRY HIVE MOUNT/DISMOUNT
# ============================================================================

function Mount-ChildHive {
    <#
        Loads the child's NTUSER.DAT into HKEY_USERS\OSGuardChildPolicy so we can
        write per-user HKCU policies even when the child is not logged in.
        Returns the hive mount name, or $null on failure.
    #>
    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) {
        Write-Log -Message "Cannot mount child hive: child account '$ChildUser' not found." -Type "WARN" -Color Yellow
        return $null
    }
    $ProfilePath = Get-ChildProfilePath -ChildSidValue $ChildSidValue
    if (-not $ProfilePath) {
        Write-Log -Message "Cannot mount child hive: no profile path for '$ChildUser' (never logged in?)." -Type "WARN" -Color Yellow
        return $null
    }
    $NtUserDat = Join-Path $ProfilePath "NTUSER.DAT"
    if (-not (Test-Path $NtUserDat)) {
        Write-Log -Message "Cannot mount child hive: NTUSER.DAT missing at $NtUserDat." -Type "WARN" -Color Yellow
        return $null
    }

    $HiveMount = "OSGuardChildPolicy"
    # If already mounted (e.g. left over), unload first
    if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
        Dismount-ChildHive -HiveMount $HiveMount
    }

    $Output = & reg.exe load "HKU\$HiveMount" "$NtUserDat" 2>&1
    if (Test-Path "Registry::HKEY_USERS\$HiveMount") {
        Write-Log -Message "Child hive mounted at HKU\$HiveMount." -Type "INFO" -Color Gray
        return $HiveMount
    }
    Write-Log -Message "Failed to mount child hive: $Output" -Type "WARN" -Color Yellow
    return $null
}

function Dismount-ChildHive {
    param([string]$HiveMount = "OSGuardChildPolicy")
    # Release any open handles before unloading
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 300
    $Output = & reg.exe unload "HKU\$HiveMount" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log -Message "Child hive unload returned: $Output" -Type "AUDIT" -Color DarkGray
    }
}

# ============================================================================
# 6. OS LOCKDOWN MODULE (ENABLE)
# ============================================================================

function Apply-ChildHivePolicies {
    param([string]$HiveMount)
    if (-not $HiveMount) { return }
    $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
    foreach ($Policy in $ChildHivePolicies) {
        $KeyPath = "$HiveRoot\$($Policy.SubPath)"
        try {
            if (-not (Test-Path $KeyPath)) {
                New-Item -Path $KeyPath -Force -ErrorAction SilentlyContinue | Out-Null
            }
            New-ItemProperty -Path $KeyPath -Name $Policy.Name -Value $Policy.Value -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Log -Message "Failed to set child policy $($Policy.Name) at $($Policy.SubPath): $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ChildHivePolicies {
    param([string]$HiveMount)
    if (-not $HiveMount) { return }
    $HiveRoot = "Registry::HKEY_USERS\$HiveMount"
    foreach ($Policy in $ChildHivePolicies) {
        $KeyPath = "$HiveRoot\$($Policy.SubPath)"
        try {
            if (Test-Path $KeyPath) {
                Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

function Set-ChildLogoutShortcut {
    <#
        Creates a shortcut on the child's desktop that logs the user out.
        The shortcut is flagged to run as administrator, so the child sees a UAC prompt
        and cannot approve it without an admin password.
    #>
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) {
        New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    $ShortcutPath = Join-Path $DesktopPath "Log out.lnk"
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "C:\Windows\System32\shutdown.exe"
        $Shortcut.Arguments = "/l /t 0"
        $Shortcut.Description = "Log out (requires administrator approval)"
        $Shortcut.IconLocation = "shell32.dll,48"
        $Shortcut.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Write-Log -Message "Admin-approval logout shortcut created at '$ShortcutPath' for '$ChildUser'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create logout shortcut for '$ChildUser': $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildLogoutShortcut {
    <#
        Removes the admin-approval logout shortcut from the child's desktop.
    #>
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $ShortcutPath = Join-Path $ChildProfilePath "Desktop\Log out.lnk"
    if (Test-Path $ShortcutPath) {
        Remove-Item -Path $ShortcutPath -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed logout shortcut from '$ChildUser' desktop." -Type "INFO" -Color Gray
    }
}

function Harden-FileACL {
    <#
        Reusable ACL hardener for a single file (e.g., .lnk shortcuts).
        SYSTEM = FullControl, Admins/Users = ReadAndExecute + Deny Delete/ChangePermissions/TakeOwnership.
    #>
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $Acl = Get-Acl -Path $FilePath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "Delete", "None", "None", "Deny")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ChangePermissions", "None", "None", "Deny")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "TakeOwnership", "None", "None", "Deny")))
        Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to harden ACL for $FilePath`: $_" -Type "WARN" -Color Yellow
    }
}

function Set-ParentPassword {
    <#
        Prompts the admin to set (or change) the Parent Mode password.
        Stores a SHA256 hash in the protected registry key.
    #>
    $PwRegName = "OSGuardParentPasswordHash"
    Write-Host "`n[SET PARENT MODE PASSWORD]" -ForegroundColor Cyan
    $NewPw = Read-Host "Enter new Parent Mode password" -AsSecureString
    $ConfirmPw = Read-Host "Confirm new Parent Mode password" -AsSecureString
    $NewPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPw))
    $ConfirmPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPw))
    if ($NewPlain -ne $ConfirmPlain) {
        Write-Host "[ERROR] Passwords do not match. Password NOT changed." -ForegroundColor Red
        return
    }
    if ($NewPlain.Length -lt 4) {
        Write-Host "[ERROR] Password must be at least 4 characters." -ForegroundColor Red
        return
    }
    $Hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($NewPlain))
    $HashStr = ([System.BitConverter]::ToString($Hash) -replace "-", "").ToLower()
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name $PwRegName -Value $HashStr -Type String -Force -ErrorAction Stop
        # Harden the registry key so only SYSTEM can read the hash
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($RegKey) {
            $Acl = $RegKey.GetAccessControl()
            $Acl.SetAccessRuleProtection($true, $false)
            $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "FullControl", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "ReadKey", "Allow")))
            $RegKey.SetAccessControl($Acl)
            $RegKey.Close()
        }
        Write-Log -Message "Parent Mode password hash stored." -Type "SUCCESS" -Color Green
        Write-Host "[SUCCESS] Parent Mode password updated." -ForegroundColor Green
    } catch {
        Write-Log -Message "Failed to store parent password hash: $_" -Type "ERROR" -Color Red
        Write-Host "[ERROR] Could not store password hash." -ForegroundColor Red
    }
}

function Test-ParentPassword {
    <#
        Prompts for the Parent Mode password and returns $true if correct.
    #>
    $PwRegName = "OSGuardParentPasswordHash"
    $StoredHash = $null
    try { $StoredHash = (Get-ItemProperty -Path $IntegrityRegPath -Name $PwRegName -ErrorAction Stop).$PwRegName } catch {}
    if (-not $StoredHash) {
        Write-Host "[ERROR] No Parent Mode password set. Run 'oslock -SetParentPassword' first." -ForegroundColor Red
        return $false
    }
    $InputPw = Read-Host "Enter Parent Mode password" -AsSecureString
    $InputPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($InputPw))
    $InputHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputPlain))
    $InputHashStr = ([System.BitConverter]::ToString($InputHash) -replace "-", "").ToLower()
    if ($InputHashStr -eq $StoredHash) {
        return $true
    } else {
        Write-Host "[ERROR] Incorrect password." -ForegroundColor Red
        return $false
    }
}

function Enter-ParentMode {
    <#
        Unlocks the system for the admin after password verification.
        Sets a registry flag and timestamp so the AFK watcher can auto-lock.
    #>
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " ENTER PARENT MODE (ADMIN UNLOCK) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    if (-not (Test-ParentPassword)) { return }

    Write-Log -Message "Parent Mode activated by admin. Unlocking system..." -Type "ACTION" -Color Magenta

    # Temporarily unlock everything
    Disable-OSLock
    Disable-DNSLock

    # Remove child hive restrictions from live hive if child is currently logged in
    foreach ($Policy in $ChildHivePolicies) {
        $KeyPath = "HKCU:\$($Policy.SubPath)"
        try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
    }

    # Set parent mode flag and timestamp
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to set parent mode flag: $_" -Type "ERROR" -Color Red
    }

    Write-Host "`n[PARENT MODE ACTIVE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host "  System is UNLOCKED. You can now install, modify settings, or view the child account." -ForegroundColor Green
    Write-Host "  Auto-lock after 5 minutes of inactivity (AFK timer)." -ForegroundColor Yellow
    Write-Host "  Click 'Lock Now' on the admin desktop or run 'oslock -LockNow' to re-lock immediately." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Cyan
}

function Exit-ParentMode {
    <#
        Re-locks everything and clears the parent mode flag.
    #>
    Write-Log -Message "Exiting Parent Mode and re-locking system..." -Type "ACTION" -Color Magenta
    Enable-OSLock
    Enable-DNSLock
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}
    Write-Log -Message "Parent Mode ended. System re-locked." -Type "SUCCESS" -Color Green
    Write-Host "[LOCKED] System is secured again." -ForegroundColor Green
}

function New-ParentModeShortcut {
    <#
        Creates Parent Mode, Lock Now, and Continue shortcuts on the admin desktop.
    #>
    $AdminProfile = $env:USERPROFILE
    $AdminDesktop = Join-Path $AdminProfile "Desktop"
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }

    $Shortcuts = @(
        @{ Name = "Parent Mode.lnk"; Args = "-ParentMode"; Icon = "shell32.dll,48"; Desc = "Enter Parent Mode (unlock system)" },
        @{ Name = "Lock Now.lnk"; Args = "-LockNow"; Icon = "shell32.dll,47"; Desc = "Immediately re-lock the system" },
        @{ Name = "Continue Parent Mode.lnk"; Args = "-ContinueParentMode"; Icon = "shell32.dll,45"; Desc = "Reset AFK timer while in Parent Mode" }
    )

    foreach ($Sc in $Shortcuts) {
        $Path = Join-Path $AdminDesktop $Sc.Name
        try {
            $Wsh = New-Object -ComObject WScript.Shell
            $Lnk = $Wsh.CreateShortcut($Path)
            $Lnk.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallScript`" $($Sc.Args)"
            $Lnk.Description = $Sc.Desc
            $Lnk.IconLocation = $Sc.Icon
            $Lnk.Save()
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Path, $bytes)
            Harden-FileACL -FilePath $Path
            Write-Log -Message "Created admin shortcut: $($Sc.Name)" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to create admin shortcut $($Sc.Name): $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ParentModeShortcut {
    $AdminProfile = $env:USERPROFILE
    $AdminDesktop = Join-Path $AdminProfile "Desktop"
    foreach ($Name in @("Parent Mode.lnk", "Lock Now.lnk", "Continue Parent Mode.lnk")) {
        $Path = Join-Path $AdminDesktop $Name
        if (Test-Path $Path) {
            # Relax ACL first so we can delete it
            try {
                $Acl = Get-Acl -Path $Path
                $Acl.SetAccessRuleProtection($false, $false)
                Set-Acl -Path $Path -AclObject $Acl -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed admin shortcut: $Name" -Type "INFO" -Color Gray
        }
    }
}

function New-ChildGameRequestShortcut {
    <#
        Creates a "Request Game Install" shortcut on the child's desktop.
        The shortcut is ACL-hardened so the child cannot delete or modify it.
    #>
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $ShortcutPath = Join-Path $DesktopPath "Request Game Install.lnk"
    try {
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildGameRequest -ChildUser `"$ChildUser`""
        $Lnk.Description = "Request a game installation (requires admin approval)"
        $Lnk.IconLocation = "shell32.dll,15"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child game request shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create child game request shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-ChildGameRequestShortcut {
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $Path = Join-Path $ChildProfilePath "Desktop\Request Game Install.lnk"
    if (Test-Path $Path) {
        try {
            $Acl = Get-Acl -Path $Path
            $Acl.SetAccessRuleProtection($false, $false)
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction SilentlyContinue
        } catch {}
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed child game request shortcut." -Type "INFO" -Color Gray
    }
}

function Show-GameRequestDialog {
    <#
        Displays a simple input dialog for the child to request a game.
        Writes the request to a protected file in $InstallDir\Requests.
    #>
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $GameName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the game name you want to install:`n(Admin will review and approve)", "Game Install Request", "", -1, -1)
    if ([string]::IsNullOrWhiteSpace($GameName)) { return }
    $RequestDir = Join-Path $InstallDir "Requests"
    if (-not (Test-Path $RequestDir)) { New-Item -ItemType Directory -Path $RequestDir -Force -ErrorAction SilentlyContinue | Out-Null }
    $RequestFile = Join-Path $RequestDir "request_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $Content = @"
Game Install Request
--------------------
From user: $ChildUser
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Game name: $GameName

This request was submitted by the child user and requires administrator approval.
"@
    try {
        Set-Content -Path $RequestFile -Value $Content -Encoding UTF8 -Force -ErrorAction Stop
        Write-Log -Message "Game request saved to '$RequestFile'." -Type "INFO" -Color Gray
        [System.Windows.Forms.MessageBox]::Show("Your request for '$GameName' has been submitted to the administrator.`n`nThe admin will review and install it if approved.", "Request Sent", "OK", "Information") | Out-Null
    } catch {
        Write-Log -Message "Failed to save game request: $_" -Type "ERROR" -Color Red
    }
}

function Apply-MachinePolicies {
    Write-Log -Message "Applying machine-wide OS policies (UAC max, Store block, Installer block, USB disable, SmartScreen, Fast User Switching)..." -Type "INFO" -Color Yellow
    foreach ($Policy in $MachinePolicies) {
        try {
            if (-not (Test-Path $Policy.Path)) {
                New-Item -Path $Policy.Path -Force -ErrorAction SilentlyContinue | Out-Null
            }
            $PropType = if ($Policy.Value -is [string]) { "String" } else { "DWord" }
            Set-ItemProperty -Path $Policy.Path -Name $Policy.Name -Value $Policy.Value -Type $PropType -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to set machine policy $($Policy.Name) at $($Policy.Path): $_" -Type "WARN" -Color Yellow
        }
    }
    # Disable USB storage service immediately
    try {
        Stop-Service -Name "USBSTOR" -Force -ErrorAction SilentlyContinue
        Write-Log -Message "USB storage service stopped." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Could not stop USBSTOR service: $_" -Type "WARN" -Color Yellow
    }
    Write-Log -Message "Machine-wide OS policies enforced." -Type "SUCCESS" -Color Green
}

function Remove-MachinePolicies {
    Write-Log -Message "Removing machine-wide OS policies..." -Type "INFO" -Color Yellow
    foreach ($Policy in $MachinePolicies) {
        try {
            if (Test-Path $Policy.Path) {
                Remove-ItemProperty -Path $Policy.Path -Name $Policy.Name -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    # Restore UAC to a sane default (prompt for non-Windows binaries) instead of leaving blank
    try {
        $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $UacPath -Name "EnableLUA" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $UacPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}
    # Re-enable USB storage service
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 3 -Type DWord -Force -ErrorAction SilentlyContinue
        Start-Service -Name "USBSTOR" -ErrorAction SilentlyContinue
        Write-Log -Message "USB storage service restored to Manual (Start=3)." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Could not restore USBSTOR service: $_" -Type "WARN" -Color Yellow
    }
    Write-Log -Message "Machine-wide OS policies removed (UAC restored to default)." -Type "SUCCESS" -Color Green
}

function Enable-OSLock {
    Write-Log -Message "Initiating OS Child Lockdown..." -Type "ACTION" -Color Magenta

    # 1. Ensure child account exists and is a standard user (passwordless)
    New-ChildAccount | Out-Null

    # 2. Machine-wide policies (UAC maxed + Store removed)
    Apply-MachinePolicies

    # 3. Per-user policies on the child's hive
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Apply-ChildHivePolicies -HiveMount $HiveMount
        Write-Log -Message "Child hive policies applied to '$ChildUser'." -Type "SUCCESS" -Color Green
        Dismount-ChildHive -HiveMount $HiveMount
    } else {
        Write-Log -Message "Child hive not available - policies will apply at next child logon via ChildLogon task." -Type "WARN" -Color Yellow
    }

    # 4. Block password change at the account level (belt and suspenders)
    net user $ChildUser /passwordchg:no 2>&1 | Out-Null
    net user $ChildUser /passwordreq:no 2>&1 | Out-Null

    Set-ChildLogoutShortcut
    New-ChildGameRequestShortcut
    New-ParentModeShortcut

    Write-Log -Message "OS Child Lockdown deployed." -Type "SUCCESS" -Color Green

    # Verification
    $FailedCount = 0
    foreach ($Policy in $MachinePolicies) {
        try {
            $Val = (Get-ItemProperty -Path $Policy.Path -Name $Policy.Name -ErrorAction SilentlyContinue).$($Policy.Name)
            if ($Val -ne $Policy.Value) { $FailedCount++; Write-Log -Message "Machine policy $($Policy.Name) not enforced (got $Val)." -Type "ERROR" -Color Red }
        } catch { $FailedCount++ }
    }
    $ChildExists = Get-ChildAccount
    if (-not $ChildExists) { $FailedCount++; Write-Log -Message "Child account '$ChildUser' missing." -Type "ERROR" -Color Red }
    else {
        # Verify not an administrator
        try {
            $IsAdmin = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" }
            if ($IsAdmin) { $FailedCount++; Write-Log -Message "Child '$ChildUser' is still an administrator!" -Type "ERROR" -Color Red }
        } catch {}
    }
    # Verify logout shortcut
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    if (-not (Test-Path (Join-Path $ChildProfilePath "Desktop\Log out.lnk"))) { $FailedCount++; Write-Log -Message "Logout shortcut for '$ChildUser' not found." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        if (-not $SilentLock) { Write-Host "[SUCCESS] ALL OS LOCKS DEPLOYED!" -ForegroundColor Green }
    } else {
        if (-not $SilentLock) { Write-Host "[PARTIAL] OS LOCKS DEPLOYED WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow }
    }
}

function Disable-OSLock {
    Write-Log -Message "Initiating OS Child Lockdown removal..." -Type "ACTION" -Color Magenta

    # 1. Remove machine-wide policies
    Remove-MachinePolicies

    # 2. Remove per-user policies from the child's hive
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Remove-ChildHivePolicies -HiveMount $HiveMount
        Write-Log -Message "Child hive policies removed from '$ChildUser'." -Type "SUCCESS" -Color Green
        Dismount-ChildHive -HiveMount $HiveMount
    } else {
        Write-Log -Message "Child hive not available for cleanup - policies will clear at next logon if ChildLogon task removed." -Type "WARN" -Color Yellow
    }

    # 3. Re-enable password change capability
    net user $ChildUser /passwordchg:yes 2>&1 | Out-Null

    Remove-ChildLogoutShortcut

    Write-Log -Message "OS Child Lockdown removed." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 7. DNS LOCKDOWN MODULE (ENABLE) - PRESERVED FROM ORIGINAL
# ============================================================================

function Enable-DNSLock {
    Write-Log -Message "Initiating Targeted DNS Lock (Admin/SYSTEM Only on IPv4 & IPv6)..." -Type "ACTION" -Color Magenta

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

                    $Rule1 = New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "SetValue", "Deny")
                    $Rule2 = New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "SetValue", "Deny")

                    $Acl.AddAccessRule($Rule1)
                    $Acl.AddAccessRule($Rule2)

                    $RegKey.SetAccessControl($Acl)
                    Write-Log -Message "Applied DNS lock ($Proto) for adapter: $($Adapter.Name)" -Type "SUCCESS" -Color Green

                    if (-not $SilentLock) {
                        Write-Host "  > [RAW ACL DUMP FOR $($Adapter.Name) - $Proto]" -ForegroundColor DarkGray
                        $RegKey.GetAccessControl().Access | Where-Object { $_.AccessControlType -eq 'Deny' } | Format-Table IdentityReference, AccessControlType, RegistryRights -AutoSize | Out-String | Write-Host -ForegroundColor DarkGray
                    }
                    $RegKey.Close()
                }
            } catch {
                Write-Log -Message "Failed to lock $Proto adapter $($Adapter.Name)." -Type "ERROR" -Color Red
            }
        }
    }

    Write-Log -Message "Applying visual GPO restrictions (network UI)..." -Type "INFO" -Color Yellow
    if (-not (Test-Path $GpoPath)) { New-Item -Path $GpoPath -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -Value 0 -Force -ErrorAction SilentlyContinue

    Write-Log -Message "Enforcing Browser DoH Restrictions (Edge, Chrome, Firefox)..." -Type "INFO" -Color Yellow
    # Edge
    if (!(Test-Path $EdgePath)) { New-Item -Path $EdgePath -Force | Out-Null }
    Set-ItemProperty -Path $EdgePath -Name "DnsOverHttpsMode" -Value "off" -Force
    Set-ItemProperty -Path $EdgePath -Name "BuiltInDnsClientEnabled" -Value 0 -Force
    # Chrome
    if (!(Test-Path $ChromePath)) { New-Item -Path $ChromePath -Force | Out-Null }
    Set-ItemProperty -Path $ChromePath -Name "DnsOverHttpsMode" -Value "off" -Force
    # Firefox
    if (!(Test-Path $FirefoxPath)) { New-Item -Path $FirefoxPath -Force | Out-Null }
    Set-ItemProperty -Path $FirefoxPath -Name "Enabled" -Value 0 -Force

    Write-Log -Message "Resetting Network Stack..." -Type "INFO" -Color Yellow
    ipconfig /flushdns | Out-Null

    # Only force DHCP renewal during interactive runs; avoid network disruption in background task
    if (-not $SilentLock) {
        ipconfig /renew | Out-Null
        Write-Log -Message "DNS protection deployed. DHCP Lease Renewal Successful!" -Type "SUCCESS" -Color Green
    } else {
        Write-Log -Message "DNS protection deployed silently (no DHCP renewal in background task)." -Type "SUCCESS" -Color Green
    }

    # Final DNS status verification
    $FailedCount = 0
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )
        foreach ($SubKeyPath in $SubKeyPaths) {
            $Proto = if ($SubKeyPath -like "*Tcpip6*") { "IPv6" } else { "IPv4" }
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    $HasDeny = $false
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny" -and $Rule.RegistryRights -like "*SetValue*") { $HasDeny = $true }
                        } catch {}
                    }
                    if (-not $HasDeny) { $FailedCount++; Write-Log -Message "DNS lock missing for adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
                    $RegKey.Close()
                }
            } catch { $FailedCount++; Write-Log -Message "Could not verify DNS lock for adapter $($Adapter.Name) ($Proto)." -Type "ERROR" -Color Red }
        }
    }
    $NetConn = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue
    if (-not $NetConn -or $NetConn.NC_LanProperties -ne 0) { $FailedCount++; Write-Log -Message "GPO NC_LanProperties not enforced." -Type "ERROR" -Color Red }
    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $FailedCount++; Write-Log -Message "Edge DoH not disabled." -Type "ERROR" -Color Red }
    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $FailedCount++; Write-Log -Message "Chrome DoH not disabled." -Type "ERROR" -Color Red }
    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -ne 0) { $FailedCount++; Write-Log -Message "Firefox DoH not disabled." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        if (-not $SilentLock) { Write-Host "[SUCCESS] ALL DNS LOCKS DEPLOYED!" -ForegroundColor Green }
    } else {
        if (-not $SilentLock) { Write-Host "[PARTIAL] DNS LOCKS DEPLOYED WITH ERRORS! ($FailedCount items failed)" -ForegroundColor Yellow }
    }
}

# ============================================================================
# 8. DNS UNLOCK MODULE (DISABLE)
# ============================================================================

function Disable-DNSLock {
    Write-Log -Message "Initiating Total DNS Unlock..." -Type "ACTION" -Color Magenta

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

    Write-Log -Message "Removing Browser DoH Restrictions (Edge, Chrome, Firefox)..." -Type "INFO" -Color Yellow
    if (Test-Path $EdgePath) {
        Remove-ItemProperty -Path $EdgePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $EdgePath -Name "BuiltInDnsClientEnabled" -ErrorAction SilentlyContinue
    }
    if (Test-Path $ChromePath) { Remove-ItemProperty -Path $ChromePath -Name "DnsOverHttpsMode" -ErrorAction SilentlyContinue }
    if (Test-Path $FirefoxPath) { Remove-ItemProperty -Path $FirefoxPath -Name "Enabled" -ErrorAction SilentlyContinue }

    ipconfig /flushdns | Out-Null

    Write-Log -Message "DNS restored to default Windows behaviors." -Type "SUCCESS" -Color Green
}

# ============================================================================
# 9. COMBINED STATUS CHECKER (DNS + OS)
# ============================================================================

function Get-LockStatus {
    $DnsLocked = $true
    $AnyDnsLocked = $false
    $OsLocked = $true

    # Refresh adapter list each time (USB/Wi-Fi may change while menu is open)
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }

    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " LIVE HARDWARE ADAPTER STATUS (DNS) " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    # --- 1. CHECK HARDWARE ADAPTERS ---
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        $AdapterLocked = $false
        $StatusColor = if ($Adapter.Status -eq "Up") { "Green" } else { "DarkGray" }

        Write-Host ("  Hardware: {0,-25} | State: {1,-5} | MAC: {2}" -f $Adapter.Name, $Adapter.Status, $Adapter.MacAddress) -ForegroundColor $StatusColor

        $SubKeyPaths = @(
            "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid",
            "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid"
        )

        foreach ($SubKeyPath in $SubKeyPaths) {
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny") {
                                $AdapterLocked = $true
                            }
                        } catch {}
                    }
                    $RegKey.Close()
                }
            } catch {}
        }

        if ($AdapterLocked) {
            Write-Host "  `-> DNS Security: [X] LOCKED (IPv4/IPv6)" -ForegroundColor Red
            Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
            $AnyDnsLocked = $true
        } else {
            Write-Host "  `-> DNS Security: [ ] UNLOCKED (Vulnerable)" -ForegroundColor Green
            Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
            $DnsLocked = $false
        }
    }

    # --- 2. CHECK DNS SYSTEM POLICIES ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " DNS POLICIES (DoH) " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    $GpoEnforced = $true
    $NetConn = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue
    if (-not $NetConn -or $NetConn.NC_LanProperties -ne 0) { $GpoEnforced = $false }
    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -ne 0) { $GpoEnforced = $false }

    if ($GpoEnforced) {
        Write-Host "  [X] DNS GPO Restrictions -> ENFORCED (Browsers & GUI)" -ForegroundColor Red
    } else {
        Write-Host "  [ ] DNS GPO Restrictions -> NOT ENFORCED" -ForegroundColor Green
        $DnsLocked = $false
    }

    # --- 3. CHECK OS CHILD LOCKDOWN ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " OS CHILD LOCKDOWN " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray

    $ChildExists = Get-ChildAccount
    if (-not $ChildExists) {
        Write-Host "  [ ] Child Account      -> NOT CREATED ($ChildUser)" -ForegroundColor DarkGray
        $OsLocked = $false
    } else {
        $ChildEnabled = $ChildExists.Enabled
        Write-Host "  [X] Child Account      -> EXISTS ($ChildUser, Enabled=$ChildEnabled)" -ForegroundColor Cyan
        # Verify not an administrator
        try {
            $IsAdmin = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" }
            if ($IsAdmin) {
                Write-Host "  [!] Child is Admin     -> SHOULD BE STANDARD USER!" -ForegroundColor Yellow
                $OsLocked = $false
            } else {
                Write-Host "  [X] Child Membership   -> Standard User (not Admin)" -ForegroundColor Cyan
            }
        } catch {}

        # Check machine policies (UAC + Store)
        $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $UacLUA = (Get-ItemProperty -Path $UacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
        $UacAdmin = (Get-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $StoreRemoved = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue).RemoveWindowsStore
        if ($UacLUA -eq 1 -and $UacAdmin -eq 2) {
            Write-Host "  [X] UAC Maxed          -> ENFORCED (child cannot disable)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] UAC Maxed          -> NOT ENFORCED" -ForegroundColor Green
            $OsLocked = $false
        }
        if ($StoreRemoved -eq 1) {
            Write-Host "  [X] Windows Store      -> REMOVED (child cannot install)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Windows Store      -> AVAILABLE" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Windows Installer block
        $MsiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
        $MsiDisabled = (Get-ItemProperty -Path $MsiPath -Name "DisableMSI" -ErrorAction SilentlyContinue).DisableMSI
        if ($MsiDisabled -eq 2) {
            Write-Host "  [X] Windows Installer  -> BLOCKED for non-admin" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Windows Installer  -> AVAILABLE" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check USB storage
        $UsbStart = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue).Start
        if ($UsbStart -eq 4) {
            Write-Host "  [X] USB Storage        -> DISABLED (install from USB blocked)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] USB Storage        -> ENABLED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Windows Script Host
        $WshEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
        if ($WshEnabled -eq 0) {
            Write-Host "  [X] Windows Script Host -> DISABLED (wscript/cscript blocked)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Windows Script Host -> ENABLED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check SmartScreen
        $SmartScreen = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue).EnableSmartScreen
        if ($SmartScreen -eq 1) {
            Write-Host "  [X] SmartScreen        -> ENFORCED (unknown apps blocked)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] SmartScreen        -> NOT ENFORCED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Fast User Switching
        $FastSwitch = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -ErrorAction SilentlyContinue).HideFastUserSwitching
        if ($FastSwitch -eq 1) {
            Write-Host "  [X] Fast User Switching -> DISABLED (can't switch to admin)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Fast User Switching -> ENABLED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Windows Update UI block
        $WuBlocked = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue).DisableWindowsUpdateAccess
        if ($WuBlocked -eq 1) {
            Write-Host "  [X] Windows Update UI  -> BLOCKED for standard users" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Windows Update UI  -> AVAILABLE" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check child hive policies (mount + verify samples)
        $HiveMount = Mount-ChildHive
        if ($HiveMount) {
            $SamplePath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            $TaskMgrDisabled = (Get-ItemProperty -Path $SamplePath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue).DisableTaskMgr
            $RegDisabled = (Get-ItemProperty -Path $SamplePath -Name "DisableRegistryTools" -ErrorAction SilentlyContinue).DisableRegistryTools
            if ($TaskMgrDisabled -eq 1) {
                Write-Host "  [X] TaskMgr/Regedit    -> DISABLED for child" -ForegroundColor Red
            } else {
                Write-Host "  [ ] TaskMgr/Regedit    -> ENABLED for child" -ForegroundColor Green
                $OsLocked = $false
            }

            $ExplorerPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            $NoCtx = (Get-ItemProperty -Path $ExplorerPath -Name "NoViewContextMenu" -ErrorAction SilentlyContinue).NoViewContextMenu
            $NoFolder = (Get-ItemProperty -Path $ExplorerPath -Name "NoFolderOptions" -ErrorAction SilentlyContinue).NoFolderOptions
            $NoTaskbar = (Get-ItemProperty -Path $ExplorerPath -Name "NoSetTaskbar" -ErrorAction SilentlyContinue).NoSetTaskbar
            $NoAddPrinter = (Get-ItemProperty -Path $ExplorerPath -Name "NoAddPrinter" -ErrorAction SilentlyContinue).NoAddPrinter
            $NoDelPrinter = (Get-ItemProperty -Path $ExplorerPath -Name "NoDeletePrinter" -ErrorAction SilentlyContinue).NoDeletePrinter

            if ($NoCtx -eq 1) {
                Write-Host "  [X] Right-Click Menu   -> DISABLED for child" -ForegroundColor Red
            } else {
                Write-Host "  [ ] Right-Click Menu   -> ENABLED for child" -ForegroundColor Green
                $OsLocked = $false
            }
            if ($NoFolder -eq 1) {
                Write-Host "  [X] Folder Options     -> HIDDEN for child" -ForegroundColor Red
            } else {
                Write-Host "  [ ] Folder Options     -> VISIBLE for child" -ForegroundColor Green
                $OsLocked = $false
            }
            if ($NoTaskbar -eq 1) {
                Write-Host "  [X] Taskbar Changes    -> BLOCKED for child" -ForegroundColor Red
            } else {
                Write-Host "  [ ] Taskbar Changes    -> ALLOWED for child" -ForegroundColor Green
                $OsLocked = $false
            }
            if ($NoAddPrinter -eq 1 -and $NoDelPrinter -eq 1) {
                Write-Host "  [X] Printer Changes    -> BLOCKED for child" -ForegroundColor Red
            } else {
                Write-Host "  [ ] Printer Changes    -> ALLOWED for child" -ForegroundColor Green
                $OsLocked = $false
            }

            Dismount-ChildHive -HiveMount $HiveMount
        } else {
            Write-Host "  [~] Child Hive         -> Not mountable (will apply at logon)" -ForegroundColor DarkGray
        }

        # Check logout shortcut
        $ChildProfilePath = $null
        try {
            $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
            if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
        } catch {}
        if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
        $ShortcutPath = Join-Path $ChildProfilePath "Desktop\Log out.lnk"
        if (Test-Path $ShortcutPath) {
            Write-Host "  [X] Logout Shortcut    -> CREATED (requires admin approval)" -ForegroundColor Cyan
        } else {
            Write-Host "  [ ] Logout Shortcut    -> MISSING" -ForegroundColor DarkGray
            $OsLocked = $false
        }
    }

    # --- 4. CHECK INSTALLATION STATUS ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " PERSISTENCE & INSTALLATION " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $CmdExists = Test-Path $CmdPath
    if ($TaskExists -and $CmdExists) {
        Write-Host "  [X] Background Service -> INSTALLED ('oslock' active)" -ForegroundColor Cyan
    } else {
        Write-Host "  [ ] Background Service -> NOT INSTALLED" -ForegroundColor DarkGray
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # --- 5. INTEGRITY CHECK ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " INTEGRITY CHECK " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    if (Test-Path $InstallScript) {
        $ExpectedHash = $null
        try { $ExpectedHash = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings" -Name "OSGuardIntegrity" -ErrorAction Stop).OSGuardIntegrity } catch {}
        if (-not $ExpectedHash -and (Test-Path (Join-Path $InstallDir "integrity.sha256"))) {
            $ExpectedHash = Get-Content -Path (Join-Path $InstallDir "integrity.sha256") -Raw
        }
        if ($ExpectedHash) {
            $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
            if ($ExpectedHash.Trim() -eq $ActualHash.Trim()) {
                Write-Host "  [X] Script Integrity    -> VERIFIED" -ForegroundColor Green
            } else {
                Write-Host "  [ ] Script Integrity    -> TAMPER DETECTED" -ForegroundColor Red
                Write-Host "`n  >>> TAMPER DETECTED! ACTION REQUIRED <<<" -ForegroundColor Black -BackgroundColor Yellow
                Write-Host "  - Run a full antivirus scan immediately." -ForegroundColor Yellow
                Write-Host "  - Do NOT use options [1], [2], or [3] (they may run malicious code)." -ForegroundColor Yellow
                Write-Host "  - Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [ ] Script Integrity    -> NO BASELINE" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [ ] Script Integrity    -> NOT INSTALLED" -ForegroundColor DarkGray
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # Master Status Banner Logic
    if ($DnsLocked -and $OsLocked -and $GpoEnforced) {
        Write-Host " >>> SYSTEM FULLY LOCKED: DNS + OS CHILD PADLOCK ACTIVE <<< " -ForegroundColor White -BackgroundColor DarkRed
    } elseif ($AnyDnsLocked -or $GpoEnforced -or $OsLocked) {
        Write-Host " >>> SYSTEM PARTIALLY LOCKED: MIXED STATE <<< " -ForegroundColor Black -BackgroundColor Yellow
    } else {
        Write-Host " >>> SYSTEM UNLOCKED: NO PADLOCK ACTIVE <<< " -ForegroundColor White -BackgroundColor DarkGreen
    }

    return @{ Dns = $DnsLocked; Os = $OsLocked }
}

function Show-CategoryGrid {
    <#
        Prints a compact two-column category status grid at the top of the TUI.
        Reads key registry values directly so it is independent of Get-LockStatus.
    #>
    $Categories = [ordered]@{}

    # --- DNS ---
    $AnyDns = $false
    $Adapters = Get-NetAdapter -IncludeHidden:$false -ErrorAction SilentlyContinue
    if (-not $Adapters) { $Adapters = Get-NetAdapter -ErrorAction SilentlyContinue }
    foreach ($Adapter in $Adapters) {
        $Guid = $Adapter.InterfaceGuid
        foreach ($SubKeyPath in @("SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Guid", "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$Guid")) {
            try {
                $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($SubKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
                if ($RegKey) {
                    $Acl = $RegKey.GetAccessControl()
                    foreach ($Rule in $Acl.Access) {
                        try {
                            $RuleSid = $Rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                            if (($RuleSid.Value -eq $SidAdmin.Value -or $RuleSid.Value -eq $SidSystem.Value) -and $Rule.AccessControlType -eq "Deny") { $AnyDns = $true }
                        } catch {}
                    }
                    $RegKey.Close()
                }
            } catch {}
        }
    }
    $Categories["DNS Lock"] = $AnyDns

    $GpoEnforced = $true
    $NetConn = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue
    if (-not $NetConn -or $NetConn.NC_LanProperties -ne 0) { $GpoEnforced = $false }
    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -ne 0) { $GpoEnforced = $false }
    $Categories["DNS GPO/DoH"] = $GpoEnforced

    # --- OS Machine-wide ---
    $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $UacLUA = (Get-ItemProperty -Path $UacPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    $UacAdmin = (Get-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
    $Categories["UAC Max"] = ($UacLUA -eq 1 -and $UacAdmin -eq 2)

    $StoreRemoved = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue).RemoveWindowsStore
    $Categories["Windows Store"] = ($StoreRemoved -eq 1)

    $MsiDisabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "DisableMSI" -ErrorAction SilentlyContinue).DisableMSI
    $Categories["Windows Installer"] = ($MsiDisabled -eq 2)

    $UsbStart = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue).Start
    $Categories["USB Storage"] = ($UsbStart -eq 4)

    $WshEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    $Categories["WSH (cscript)"] = ($WshEnabled -eq 0)

    $SmartScreen = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue).EnableSmartScreen
    $Categories["SmartScreen"] = ($SmartScreen -eq 1)

    $FastSwitch = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -ErrorAction SilentlyContinue).HideFastUserSwitching
    $Categories["Fast User Switching"] = ($FastSwitch -eq 1)

    $WuBlocked = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue).DisableWindowsUpdateAccess
    $Categories["Windows Update UI"] = ($WuBlocked -eq 1)

    # --- Child Account ---
    $ChildAccount = $null
    try { $ChildAccount = Get-LocalUser -Name $ChildUser -ErrorAction Stop } catch {}
    $Categories["Child Account"] = ($null -ne $ChildAccount)

    # --- Child Hive (if mountable) ---
    $HiveMount = $null
    $ChildProfile = $null
    try { $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1 } catch {}
    if ($ChildProfile) {
        $NtUserDat = Join-Path $ChildProfile.LocalPath "NTUSER.DAT"
        if (Test-Path $NtUserDat) {
            if (Test-Path "Registry::HKEY_USERS\OSGuardChildPolicy") { reg.exe unload "HKU\OSGuardChildPolicy" 2>&1 | Out-Null }
            $Output = & reg.exe load "HKU\OSGuardChildPolicy" "$NtUserDat" 2>&1
            if (Test-Path "Registry::HKEY_USERS\OSGuardChildPolicy") { $HiveMount = "OSGuardChildPolicy" }
        }
    }

    if ($HiveMount) {
        $TaskMgr = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -ErrorAction SilentlyContinue).DisableTaskMgr
        $Regedit = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableRegistryTools" -ErrorAction SilentlyContinue).DisableRegistryTools
        $NoRun = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun" -ErrorAction SilentlyContinue).NoRun
        $NoControlPanel = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -ErrorAction SilentlyContinue).NoControlPanel
        $NoCtx = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoViewContextMenu" -ErrorAction SilentlyContinue).NoViewContextMenu
        $NoFolder = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoFolderOptions" -ErrorAction SilentlyContinue).NoFolderOptions
        $NoTaskbar = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoSetTaskbar" -ErrorAction SilentlyContinue).NoSetTaskbar
        $NoAddPrinter = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAddPrinter" -ErrorAction SilentlyContinue).NoAddPrinter
        $NoDelPrinter = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDeletePrinter" -ErrorAction SilentlyContinue).NoDeletePrinter
        $NoThemes = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoThemesTab" -ErrorAction SilentlyContinue).NoThemesTab
        $NoWallpaper = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -Name "NoChangingWallPaper" -ErrorAction SilentlyContinue).NoChangingWallPaper
        $NoAutoPlay = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
        $NoAdminTools = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "StartMenuAdminTools" -ErrorAction SilentlyContinue).StartMenuAdminTools
        $NoAddRemove = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -Name "NoAddRemovePrograms" -ErrorAction SilentlyContinue).NoAddRemovePrograms
        $NoPassChange = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableChangePassword" -ErrorAction SilentlyContinue).DisableChangePassword
        $NoNetUi = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Network Connections" -Name "NC_LanProperties" -ErrorAction SilentlyContinue).NC_LanProperties
        $NoThisPC = (Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue)."{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

        $Categories["Task Manager"] = ($TaskMgr -eq 1)
        $Categories["Registry Tools"] = ($Regedit -eq 1)
        $Categories["CMD / Run"] = ($NoRun -eq 1)
        $Categories["Control Panel"] = ($NoControlPanel -eq 1)
        $Categories["Right-Click Menu"] = ($NoCtx -eq 1)
        $Categories["Folder Options"] = ($NoFolder -eq 1)
        $Categories["Taskbar"] = ($NoTaskbar -eq 1)
        $Categories["Printers"] = ($NoAddPrinter -eq 1 -and $NoDelPrinter -eq 1)
        $Categories["Wallpaper/Themes"] = ($NoThemes -eq 1 -or $NoWallpaper -eq 1)
        $Categories["AutoPlay"] = ($NoAutoPlay -eq 255)
        $Categories["Admin Tools"] = ($NoAdminTools -eq 0)
        $Categories["Add/Remove Prog"] = ($NoAddRemove -eq 1)
        $Categories["Password Change"] = ($NoPassChange -eq 1)
        $Categories["Network UI"] = ($NoNetUi -eq 0)
        $Categories["This PC Hidden"] = ($NoThisPC -eq 1)

        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
        reg.exe unload "HKU\OSGuardChildPolicy" 2>&1 | Out-Null
    } else {
        $Categories["Task Manager"] = $null
        $Categories["Registry Tools"] = $null
        $Categories["CMD / Run"] = $null
        $Categories["Control Panel"] = $null
        $Categories["Right-Click Menu"] = $null
        $Categories["Folder Options"] = $null
        $Categories["Taskbar"] = $null
        $Categories["Printers"] = $null
        $Categories["Wallpaper/Themes"] = $null
        $Categories["AutoPlay"] = $null
        $Categories["Admin Tools"] = $null
        $Categories["Add/Remove Prog"] = $null
        $Categories["Password Change"] = $null
        $Categories["Network UI"] = $null
        $Categories["This PC Hidden"] = $null
    }

    # --- Logout Shortcut ---
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $Categories["Logout Shortcut"] = (Test-Path (Join-Path $ChildProfilePath "Desktop\Log out.lnk"))

    # --- Persistence ---
    $Categories["Background Service"] = ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -and (Test-Path $CmdPath))

    # --- Integrity ---
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    $IntegrityOk = $false
    if (Test-Path $InstallScript) {
        $ExpectedHash = $null
        try { $ExpectedHash = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop).OSGuardIntegrity } catch {}
        if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
        if ($ExpectedHash) {
            $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
            $IntegrityOk = ($ExpectedHash.Trim() -eq $ActualHash.Trim())
        }
    }
    $Categories["Integrity"] = $IntegrityOk

    # Print two-column grid
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " CATEGORY STATUS GRID " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $Keys = $Categories.Keys
    $i = 0
    while ($i -lt $Keys.Count) {
        $LeftKey = $Keys[$i]
        $LeftVal = $Categories[$LeftKey]
        $LeftStr = if ($LeftVal -eq $true) { "[ENABLED]  " } elseif ($LeftVal -eq $false) { "[DISABLED] " } else { "[UNKNOWN]  " }
        $LeftColor = if ($LeftVal -eq $true) { "Green" } elseif ($LeftVal -eq $false) { "DarkGray" } else { "Yellow" }

        if ($i + 1 -lt $Keys.Count) {
            $RightKey = $Keys[$i + 1]
            $RightVal = $Categories[$RightKey]
            $RightStr = if ($RightVal -eq $true) { "[ENABLED]  " } elseif ($RightVal -eq $false) { "[DISABLED] " } else { "[UNKNOWN]  " }
            Write-Host ("  {0}{1,-22}  {2}{3,-22}" -f $LeftStr, $LeftKey, $RightStr, $RightKey) -ForegroundColor $LeftColor
        } else {
            Write-Host ("  {0}{1,-22}" -f $LeftStr, $LeftKey) -ForegroundColor $LeftColor
        }
        $i += 2
    }
    Write-Host "=====================================================" -ForegroundColor DarkGray

    return $Categories
}

function Test-IntegrityStatus {
    # Returns $true if installed and hash matches; $false if tampered; $null if not installed
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    if (-not (Test-Path $InstallScript)) { return $null }
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop).OSGuardIntegrity } catch {}
    if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
    if (-not $ExpectedHash) { return $null }
    $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
    return ($ExpectedHash.Trim() -eq $ActualHash.Trim())
}

# ============================================================================
# 10. INSTALLER / PERSISTENCE MODULE (HARDENED)
# ============================================================================

function Install-Persistence {
    Write-Log -Message "Installing OS-Guard to System ($InstallDir)..." -Type "ACTION" -Color Yellow

    # 0. Installation Gate: Prevent overwriting existing installs
    if (Test-Path $InstallDir) {
        Write-Log -Message "Installation aborted: $InstallDir already exists." -Type "ERROR" -Color Red
        Write-Host "[ERROR] OS-Guard is already installed. Uninstall first." -ForegroundColor Red
        return
    }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Log -Message "Installation aborted: Scheduled task '$TaskName' already exists." -Type "ERROR" -Color Red
        Write-Host "[ERROR] OS-Guard is already installed. Uninstall first." -ForegroundColor Red
        return
    }

    # 1. Secure Copy
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $InstallScript -Force
    Write-Log -Message "Payload copied to $InstallScript." -Type "INFO" -Color Gray

    # Pre-build wrapper content and create all files inside $InstallDir BEFORE hardening ACLs
    $CmdBatContent = "@echo off`r`nC:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallScript`" %*"
    $CmdPathLocal = Join-Path $InstallDir "oslock.cmd"
    Out-File -FilePath $CmdPathLocal -InputObject $CmdBatContent -Encoding ASCII -Force
    Write-Log -Message "Local wrapper created at $CmdPathLocal." -Type "INFO" -Color Gray

    # Pre-calculate integrity hash and write backup file before hardening
    $ScriptHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    Set-Content -Path $IntegrityFile -Value $ScriptHash -Encoding UTF8 -Force
    Write-Log -Message "Self-integrity hash file written." -Type "INFO" -Color Gray

    # --- NTFS PAYLOAD SELF-DEFENSE ---
    Write-Log -Message "Hardening NTFS Permissions on installation directory and files..." -Type "INFO" -Color Yellow
    try {
        $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

        # Set owner to SYSTEM on directory and all existing files
        $DirAcl = Get-Acl -Path $InstallDir
        $DirAcl.SetOwner($SidSystem)
        Set-Acl -Path $InstallDir -AclObject $DirAcl
        Get-ChildItem -Path $InstallDir -File | ForEach-Object {
            $FileAcl = Get-Acl -Path $_.FullName
            $FileAcl.SetOwner($SidSystem)
            Set-Acl -Path $_.FullName -AclObject $FileAcl
        }

        # Harden directory ACL
        $DirAcl = Get-Acl -Path $InstallDir
        $DirAcl.SetAccessRuleProtection($true, $false)
        $DirAcl.Access | ForEach-Object { $DirAcl.RemoveAccessRule($_) | Out-Null }

        # SYSTEM: FullControl
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        # Admins: ReadAndExecute only (cannot delete, modify, or change permissions)
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")))
        # Authenticated Users: ReadAndExecute
        $DirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

        Set-Acl -Path $InstallDir -AclObject $DirAcl

        # Explicitly harden each file
        Get-ChildItem -Path $InstallDir -File | ForEach-Object {
            $FileAcl = Get-Acl -Path $_.FullName
            $FileAcl.SetAccessRuleProtection($true, $false)
            $FileAcl.Access | ForEach-Object { $FileAcl.RemoveAccessRule($_) | Out-Null }
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
            $FileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
            Set-Acl -Path $_.FullName -AclObject $FileAcl
        }

        Write-Log -Message "Installation directory and files locked. Owner=SYSTEM, Admins=ReadOnly+NoDelete." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to harden NTFS permissions: $_" -Type "ERROR" -Color Red
    }

    # 2. Build the Global CLI Command (oslock) in C:\Windows (ASCII encoding, no BOM)
    Out-File -FilePath $CmdPath -InputObject $CmdBatContent -Encoding ASCII -Force
    if (-not (Test-Path $CmdPath)) {
        Write-Log -Message "CRITICAL: Wrapper file was not created at $CmdPath!" -Type "ERROR" -Color Red
    } else {
        Write-Log -Message "Global CLI wrapper created at $CmdPath." -Type "SUCCESS" -Color Green
    }

    # 2.2 Add InstallDir to system PATH so oslock is discoverable from any shell
    Write-Log -Message "Adding $InstallDir to system PATH..." -Type "INFO" -Color Yellow
    try {
        $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($CurrentPath -notlike "*$InstallDir*") {
            $NewPath = $CurrentPath + ";" + $InstallDir
            [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
            Write-Log -Message "Added $InstallDir to system PATH." -Type "SUCCESS" -Color Green
        } else {
            Write-Log -Message "$InstallDir already in system PATH." -Type "INFO" -Color Gray
        }
    } catch {
        Write-Log -Message "Failed to update system PATH: $_" -Type "ERROR" -Color Red
    }

    # 2.3 Harden the wrapper files against tampering (but allow all users to execute them)
    Write-Log -Message "Hardening oslock wrapper files..." -Type "INFO" -Color Yellow
    $SidUsers = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
    foreach ($WrapperPath in @($CmdPath, $CmdPathLocal)) {
        if (Test-Path $WrapperPath) {
            try {
                $CmdAcl = Get-Acl -Path $WrapperPath
                $CmdAcl.SetOwner($SidSystem)
                $CmdAcl.SetAccessRuleProtection($true, $false)
                $CmdAcl.Access | ForEach-Object { $CmdAcl.RemoveAccessRule($_) | Out-Null }
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
                $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "None", "None", "Allow")))
                Set-Acl -Path $WrapperPath -AclObject $CmdAcl
            } catch {
                Write-Log -Message "Failed to harden wrapper ACLs for $WrapperPath`: $_" -Type "ERROR" -Color Red
            }
        }
    }
    Write-Log -Message "Wrapper files locked to SYSTEM (FullControl), Admins (ReadOnly+NoDelete), Users (ReadAndExecute)." -Type "SUCCESS" -Color Green

    Write-Log -Message "Registering self-healing background tasks..." -Type "INFO" -Color Yellow

    # 3. Main task: Run at System Startup, User Logon, and Event ID 10000 (Network Connected)
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $Trigger1 = New-ScheduledTaskTrigger -AtStartup
    $Trigger2 = New-ScheduledTaskTrigger -AtLogOn

    $CimClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace "Root/Microsoft/Windows/TaskScheduler"
    $Trigger3 = New-CimInstance -CimClass $CimClass -ClientOnly
    $Trigger3.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[EventID=10000]]</Select></Query></QueryList>"
    $Trigger3.Enabled = $True

    $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger2, $Trigger3) -Principal $PrincipalSettings -Force | Out-Null
    Write-Log -Message "Registered Main Task: auto-heal on Reboot & Network Change." -Type "INFO" -Color Gray

    # 4. Guardian 1: Monitors every 5 minutes and restores if tampered
    $GuardianAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $GuardianTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 9999)
    $GuardianPrincipal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Guardian1Name -Action $GuardianAction -Trigger $GuardianTrigger -Principal $GuardianPrincipal -Force | Out-Null
    Write-Log -Message "Guardian 1 '$Guardian1Name' registered (5-minute heartbeat)." -Type "INFO" -Color Gray

    # 4.1 Guardian 2: Additional watcher with a 10-minute interval
    $Guardian2Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
    $Guardian2Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 9999)
    $Guardian2Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $Guardian2Name -Action $Guardian2Action -Trigger $Guardian2Trigger -Principal $Guardian2Principal -Force | Out-Null
    Write-Log -Message "Guardian 2 '$Guardian2Name' registered (10-minute heartbeat)." -Type "INFO" -Color Gray

    # 4.2 Child Logon Task: Applies HKCU policies in the child's own session at logon.
    # Runs as the child user (no elevation) so it writes to the live HKCU hive.
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue) {
        try {
            $ChildAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildLock -ChildUser `"$ChildUser`""
            $ChildTrigger = New-ScheduledTaskTrigger -AtLogOn
            $ChildTrigger.UserId = $ChildUser
            $ChildPrincipalObj = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $ChildLogonTaskName -Action $ChildAction -Trigger $ChildTrigger -Principal $ChildPrincipalObj -Force | Out-Null
            Write-Log -Message "Child Logon Task '$ChildLogonTaskName' registered (applies HKCU at child logon)." -Type "SUCCESS" -Color Green
        } catch {
            Write-Log -Message "Failed to register child logon task: $_" -Type "WARN" -Color Yellow
        }
    } else {
        Write-Log -Message "Child account not yet created - child logon task will be created on next silent heal." -Type "WARN" -Color Yellow
    }

    # 4.3 WMI Event Subscription: Third hidden persistence layer
    Write-Log -Message "Registering WMI event subscription for persistence..." -Type "INFO" -Color Gray
    try {
        $WmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'Schedule'"
        $WmiConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; CommandLineTemplate="powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"; RunInteractively=$false} -ErrorAction Stop
        $WmiFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; EventNamespace="root\cimv2"; QueryLanguage="WQL"; Query=$WmiQuery} -ErrorAction Stop
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WmiFilter; Consumer=$WmiConsumer} -ErrorAction Stop | Out-Null
        Write-Log -Message "WMI subscription registered (triggers if Schedule service is modified)." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "WMI subscription registration failed: $_" -Type "WARN" -Color Yellow
    }

    # 5. Self-Integrity: Store SHA256 hash in a misleading registry key
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
    Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -Value $ScriptHash -Force -ErrorAction SilentlyContinue
    Write-Log -Message "Self-integrity hash stored in registry (backup file already written)." -Type "INFO" -Color Gray

    # 6. Apply ALL locks immediately (DNS + OS + child account)
    Enable-DNSLock
    Enable-OSLock
    Set-ChildLogoutShortcut
    New-ChildGameRequestShortcut
    New-ParentModeShortcut

    # 7. Set default Parent Mode password and create requests directory
    Write-Log -Message "Setting default Parent Mode password and creating requests directory..." -Type "INFO" -Color Yellow
    $DefaultPw = "admin123"
    $Hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($DefaultPw))
    $HashStr = ([System.BitConverter]::ToString($Hash) -replace "-", "").ToLower()
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -Value $HashStr -Type String -Force -ErrorAction Stop
        Write-Log -Message "Default Parent Mode password set (change it with 'oslock -SetParentPassword')." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to set default Parent Mode password: $_" -Type "WARN" -Color Yellow
    }
    $RequestDir = Join-Path $InstallDir "Requests"
    if (-not (Test-Path $RequestDir)) { New-Item -ItemType Directory -Path $RequestDir -Force -ErrorAction SilentlyContinue | Out-Null }
    try {
        $RequestsDirAcl = Get-Acl -Path $RequestDir
        $RequestsDirAcl.SetOwner($SidSystem)
        $RequestsDirAcl.SetAccessRuleProtection($true, $false)
        $RequestsDirAcl.Access | ForEach-Object { $RequestsDirAcl.RemoveAccessRule($_) | Out-Null }
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $RequestDir -AclObject $RequestsDirAcl -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to harden Requests directory ACL: $_" -Type "WARN" -Color Yellow
    }

    # 8. Register Parent Mode AFK Watcher (1-minute dead man's switch)
    Write-Log -Message "Registering Parent Mode AFK watcher (1-minute heartbeat) ..." -Type "INFO" -Color Yellow
    $WatchScriptPath = Join-Path $InstallDir "ParentModeWatch.ps1"
    $WatchScriptContent = '
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$Active = (Get-ItemProperty -Path $RegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue).OSGuardParentModeActive
if ($Active -ne 1) { return }

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class IdleTime {
    [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    [StructLayout(LayoutKind.Sequential)] struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    public static uint GetIdleTime() {
        LASTINPUTINFO lii = new LASTINPUTINFO(); lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
        GetLastInputInfo(ref lii);
        return (uint)Environment.TickCount - lii.dwTime;
    }
}
"@

$IdleMs = [IdleTime]::GetIdleTime()
$Timeout = 5 * 60 * 1000
if ($IdleMs -gt $Timeout) {
    & "C:\Windows\oslock.cmd" -LockNow
}
'
    Set-Content -Path $WatchScriptPath -Value $WatchScriptContent -Encoding UTF8 -Force
    $WatchAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WatchScriptPath`""
    $WatchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
    $WatchPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ParentModeWatchName -Action $WatchAction -Trigger $WatchTrigger -Principal $WatchPrincipal -Force | Out-Null
    Write-Log -Message "Parent Mode AFK watcher registered (1-minute heartbeat, 5-minute idle timeout)." -Type "INFO" -Color Gray

    Write-Log -Message "INSTALLATION COMPLETE! System is permanently protected." -Type "SUCCESS" -Color Green

    # Final status verification
    $FailedCount = 0
    if (-not (Test-Path $InstallDir)) { $FailedCount++; Write-Log -Message "Install directory $InstallDir missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $InstallScript)) { $FailedCount++; Write-Log -Message "Install script $InstallScript missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $CmdPath)) { $FailedCount++; Write-Log -Message "Global CLI wrapper $CmdPath missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path $IntegrityFile)) { $FailedCount++; Write-Log -Message "Integrity file $IntegrityFile missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Main task $TaskName missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $Guardian1Name -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian 1 $Guardian1Name missing." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $Guardian2Name -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Guardian 2 $Guardian2Name missing." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$InstallDir*") { $FailedCount++; Write-Log -Message "System PATH does not contain $InstallDir." -Type "ERROR" -Color Red }
    if (-not (Get-ChildAccount)) { $FailedCount++; Write-Log -Message "Child account '$ChildUser' not created." -Type "ERROR" -Color Red }
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    if (-not (Test-Path (Join-Path $ChildProfilePath "Desktop\Log out.lnk"))) { $FailedCount++; Write-Log -Message "Logout shortcut for '$ChildUser' not found." -Type "ERROR" -Color Red }
    if (-not (Test-Path (Join-Path $ChildProfilePath "Desktop\Request Game Install.lnk"))) { $FailedCount++; Write-Log -Message "Game request shortcut for '$ChildUser' not found." -Type "ERROR" -Color Red }
    $AdminProfile = $env:USERPROFILE
    $AdminDesktop = Join-Path $AdminProfile "Desktop"
    if (-not (Test-Path (Join-Path $AdminDesktop "Parent Mode.lnk"))) { $FailedCount++; Write-Log -Message "Parent Mode shortcut not found on admin desktop." -Type "ERROR" -Color Red }
    if (-not (Test-Path (Join-Path $AdminDesktop "Lock Now.lnk"))) { $FailedCount++; Write-Log -Message "Lock Now shortcut not found on admin desktop." -Type "ERROR" -Color Red }
    if (-not (Test-Path (Join-Path $AdminDesktop "Continue Parent Mode.lnk"))) { $FailedCount++; Write-Log -Message "Continue Parent Mode shortcut not found on admin desktop." -Type "ERROR" -Color Red }
    if (-not (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue)) { $FailedCount++; Write-Log -Message "Parent Mode watch task $ParentModeWatchName missing." -Type "ERROR" -Color Red }
    if (-not (Test-Path (Join-Path $InstallDir "Requests"))) { $FailedCount++; Write-Log -Message "Requests directory missing." -Type "ERROR" -Color Red }
    if ($FailedCount -eq 0) {
        Write-Host "[SUCCESS] INSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "[PARTIAL] INSTALLATION COMPLETE WITH ERRORS! ($FailedCount items missing)" -ForegroundColor Yellow
    }
}

function Invoke-AsSystem {
    param([string]$Command)
    $TempTaskName = "OSGuard-Uninstall-Helper"
    $CommonTemp = "C:\Windows\Temp"
    $ResultFile = "$CommonTemp\OSGuard_CleanupResult.txt"
    $TempScript = "$CommonTemp\OSGuard_Cleanup.ps1"
    Write-Log -Message "[DEBUG] Invoke-AsSystem called. CommonTemp=$CommonTemp" -Type "INFO" -Color Yellow
    try {
        # Ensure SYSTEM can write to the common temp directory
        $TempAcl = Get-Acl -Path $CommonTemp
        $SystemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $TempAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SystemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $CommonTemp -AclObject $TempAcl -ErrorAction SilentlyContinue
        # Write the cleanup command to a temporary script file with error capture
        $ScriptContent = "try { `$ErrorActionPreference = 'Stop'; $Command; 'SUCCESS' | Out-File -FilePath '$ResultFile' -Encoding UTF8 -Force } catch { `$_.Exception.Message | Out-File -FilePath '$ResultFile' -Encoding UTF8 -Force }"
        $ScriptContent | Out-File -FilePath $TempScript -Encoding UTF8 -Force
        Write-Log -Message "[DEBUG] Temp script written to $TempScript" -Type "INFO" -Color Yellow
        # Use full PowerShell path and execute the temp script
        $Action = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$TempScript`""
        $Principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TempTaskName -Action $Action -Principal $Principal -Force | Out-Null
        Start-ScheduledTask -TaskName $TempTaskName
        Write-Log -Message "[DEBUG] SYSTEM task started. Waiting for completion..." -Type "INFO" -Color Yellow
        # Wait up to 30 seconds
        $MaxWait = 30
        $Waited = 0
        while ($Waited -lt $MaxWait) {
            Start-Sleep -Seconds 2
            $Waited += 2
            $Task = Get-ScheduledTask -TaskName $TempTaskName -ErrorAction SilentlyContinue
            if (-not $Task) { break }
        }
        Unregister-ScheduledTask -TaskName $TempTaskName -Confirm:$false | Out-Null
        Write-Log -Message "[DEBUG] SYSTEM task completed and unregistered." -Type "INFO" -Color Yellow
        if (Test-Path $ResultFile) {
            $Result = Get-Content -Path $ResultFile -Raw
            Write-Log -Message "[DEBUG] SYSTEM task result: $Result" -Type "INFO" -Color Yellow
            Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "[DEBUG] No result file found at $ResultFile" -Type "ERROR" -Color Red
        }
        Remove-Item -Path $TempScript -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "SYSTEM helper task failed: $_" -Type "ERROR" -Color Red
    }
}

function Uninstall-Persistence {
    # Exit early if nothing is installed
    $IsInstalled = (Test-Path $InstallDir) -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)
    if (-not $IsInstalled) {
        Write-Host "[WARN] OS-Guard is not installed. Nothing to uninstall." -ForegroundColor Yellow
        return
    }

    Write-Log -Message "Uninstalling OS-Guard from System..." -Type "ACTION" -Color Yellow

    # Unlock everything FIRST (DNS + OS)
    Disable-DNSLock
    Disable-OSLock
    Remove-ChildLogoutShortcut
    Remove-ChildGameRequestShortcut
    Remove-ParentModeShortcut

    # Remove the Scheduled Tasks (including guardians, child logon, and parent mode watch)
    foreach ($TName in @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName)) {
        if (Get-ScheduledTask -TaskName $TName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TName -Confirm:$false | Out-Null
            Write-Log -Message "Removed task: $TName" -Type "INFO" -Color Gray
        }
    }

    # Remove WMI Event Subscription
    Write-Log -Message "Removing WMI event subscription..." -Type "INFO" -Color Gray
    try {
        Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
        Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue | Remove-WmiObject -ErrorAction SilentlyContinue
    } catch { Write-Log -Message "Failed to remove WMI subscription: $_" -Type "WARN" -Color Yellow }

    # Remove the integrity hash and parent password registry keys
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    if (Test-Path $IntegrityRegPath) {
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -ErrorAction SilentlyContinue
    }

    # Remove Global CLI Command (relax ACL first) - then delete via SYSTEM helper if needed
    if (Test-Path $CmdPath) {
        try {
            $CmdAcl = Get-Acl -Path $CmdPath
            $CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $CmdAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($CurrentUserSid, "FullControl", "None", "None", "Allow")))
            Set-Acl -Path $CmdPath -AclObject $CmdAcl -ErrorAction Stop
            Remove-Item -Path $CmdPath -Force -ErrorAction Stop
        } catch {
            Write-Log -Message "Direct deletion failed for $CmdPath. Spawning SYSTEM cleanup task..." -Type "INFO" -Color Yellow
            Invoke-AsSystem -Command "takeown.exe /F $CmdPath; icacls.exe $CmdPath /reset; Remove-Item -Path $CmdPath -Force -ErrorAction Stop"
        }
        if (Test-Path $CmdPath) {
            Write-Log -Message "Failed to remove 'oslock' CLI Alias at $CmdPath." -Type "ERROR" -Color Red
        } else {
            Write-Log -Message "Removed 'oslock' CLI Alias." -Type "INFO" -Color Gray
        }
    }

    # Remove local wrapper and PATH entry
    $CmdPathLocal = Join-Path $InstallDir "oslock.cmd"
    if (Test-Path $CmdPathLocal) { Remove-Item -Path $CmdPathLocal -Force -ErrorAction SilentlyContinue }
    try {
        $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
        if ($CurrentPath -like "*$InstallDir*") {
            $NewPath = ($CurrentPath -split ';' | Where-Object { $_ -ne $InstallDir }) -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
            Write-Log -Message "Removed $InstallDir from system PATH." -Type "INFO" -Color Gray
        }
    } catch {
        Write-Log -Message "Failed to clean system PATH: $_" -Type "ERROR" -Color Red
    }

    # Delete System Directory LAST - use SYSTEM helper if direct deletion fails (hardened ACLs)
    if (Test-Path $InstallDir) {
        Write-Log -Message "Removing hardened installation directory..." -Type "INFO" -Color Gray
        try {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
            Write-Log -Message "Installation directory removed." -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Direct deletion failed (hardened ACLs). Spawning SYSTEM cleanup task..." -Type "INFO" -Color Yellow
            Invoke-AsSystem -Command "takeown.exe /F $InstallDir /R /D Y; icacls.exe $InstallDir /reset /T; Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop"
            Start-Sleep -Seconds 3
            if (Test-Path $InstallDir) {
                Write-Log -Message "SYSTEM cleanup failed: $InstallDir still exists." -Type "ERROR" -Color Red
            } else {
                Write-Log -Message "Installation directory removed by SYSTEM. Goodbye!" -Type "INFO" -Color Gray
            }
        }
    }

    # Note: We do NOT delete the child account on uninstall - only remove restrictions.
    # This preserves any data the child has. To delete the account manually:
    #   Remove-LocalUser -Name $ChildUser
    Write-Host "`n[INFO] Child account '$ChildUser' was NOT deleted (data preserved)." -ForegroundColor Cyan
    Write-Host "       Restrictions removed. To delete the account entirely:" -ForegroundColor Cyan
    Write-Host "       Remove-LocalUser -Name '$ChildUser'" -ForegroundColor Cyan

    # Final status verification
    $FailedCount = 0
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $TaskName still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $Guardian1Name -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $Guardian1Name still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $Guardian2Name -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $Guardian2Name still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $ChildLogonTaskName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $ChildLogonTaskName still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $ParentModeWatchName still exists." -Type "ERROR" -Color Red }
    if (Test-Path $InstallDir) { $FailedCount++; Write-Log -Message "Install directory $InstallDir still exists." -Type "ERROR" -Color Red }
    if (Test-Path $CmdPath) { $FailedCount++; Write-Log -Message "Global CLI $CmdPath still exists." -Type "ERROR" -Color Red }
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -like "*$InstallDir*") { $FailedCount++; Write-Log -Message "System PATH still contains $InstallDir." -Type "ERROR" -Color Red }

    if ($FailedCount -eq 0) {
        Write-Host "`n[SUCCESS] UNINSTALLATION COMPLETE!" -ForegroundColor Green
    } else {
        Write-Host "`n[PARTIAL] UNINSTALLATION COMPLETE WITH ERRORS! ($FailedCount items failed to remove)" -ForegroundColor Yellow
    }
}

# ============================================================================
# 11. CLI EXECUTION HANDLER
# ============================================================================

# ChildLock: applies HKCU policies to the CURRENT user's session (no elevation needed).
# Used by the child logon task so the child's live hive gets the restrictions directly.
if ($ChildLock) {
    # Only apply if the current user IS the child (defense: don't lock an admin by accident)
    $CurrentUserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($CurrentUserName -notmatch "$ChildUser$") {
        return
    }
    foreach ($Policy in $ChildHivePolicies) {
        $KeyPath = "HKCU:\$($Policy.SubPath)"
        try {
            if (-not (Test-Path $KeyPath)) { New-Item -Path $KeyPath -Force -ErrorAction SilentlyContinue | Out-Null }
            Set-ItemProperty -Path $KeyPath -Name $Policy.Name -Value $Policy.Value -Type DWord -Force -ErrorAction SilentlyContinue
        } catch {}
    }
    # Also apply the network UI restrictions to HKCU
    if (-not (Test-Path $GpoPath)) { New-Item -Path $GpoPath -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-ItemProperty -Path $GpoPath -Name "NC_LanProperties" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_LanChangeProperties" -Value 0 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $GpoPath -Name "NC_AllowAdvancedTCPIPConfig" -Value 0 -Force -ErrorAction SilentlyContinue
    return
}

# SilentLock: background re-apply (used by guardian tasks). Verifies integrity first.
if ($SilentLock) {
    $IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
    $IntegrityFile = Join-Path $InstallDir "integrity.sha256"
    $HashCheckPassed = $true

    # Primary check: registry stored hash
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop).OSGuardIntegrity } catch {}

    if ($ExpectedHash) {
        $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: Registry hash mismatch!" -Type "SECURITY" -Color Red
            $HashCheckPassed = $false
        }
    } elseif (Test-Path $IntegrityFile) {
        $ExpectedHash = Get-Content -Path $IntegrityFile -Raw
        $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: File hash mismatch!" -Type "SECURITY" -Color Red
            $HashCheckPassed = $false
        }
    }

    # Even on integrity failure, re-apply locks to keep the child locked down.
    # Guardian: ensure main task still exists and recreate it if deleted
    $MainTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $MainTask) {
        Write-Log -Message "Main task '$TaskName' is missing! Recreating from guardian..." -Type "SECURITY" -Color Red
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"
        $Trigger1 = New-ScheduledTaskTrigger -AtStartup
        $Trigger2 = New-ScheduledTaskTrigger -AtLogOn
        $CimClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace "Root/Microsoft/Windows/TaskScheduler"
        $Trigger3 = New-CimInstance -CimClass $CimClass -ClientOnly
        $Trigger3.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[EventID=10000]]</Select></Query></QueryList>"
        $Trigger3.Enabled = $True
        $PrincipalSettings = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger2, $Trigger3) -Principal $PrincipalSettings -Force | Out-Null
    }

    # Re-apply the child logon task if missing
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and -not (Get-ScheduledTask -TaskName $ChildLogonTaskName -ErrorAction SilentlyContinue)) {
        try {
            $ChildAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ChildLock -ChildUser `"$ChildUser`""
            $ChildTrigger = New-ScheduledTaskTrigger -AtLogOn
            $ChildTrigger.UserId = $ChildUser
            $ChildPrincipalObj = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive -RunLevel Limited
            Register-ScheduledTask -TaskName $ChildLogonTaskName -Action $ChildAction -Trigger $ChildTrigger -Principal $ChildPrincipalObj -Force | Out-Null
        } catch {}
    }

    # Re-apply the parent mode watch task if missing
    if (-not (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue)) {
        try {
            $WatchScriptPath = Join-Path $InstallDir "ParentModeWatch.ps1"
            $WatchAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WatchScriptPath`""
            $WatchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
            $WatchPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $ParentModeWatchName -Action $WatchAction -Trigger $WatchTrigger -Principal $WatchPrincipal -Force | Out-Null
        } catch {}
    }

    # Ensure parent mode flag is cleared (defense: never leave unlocked after a silent heal)
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
    } catch {}

    Enable-DNSLock
    Enable-OSLock
    return
}

if ($Lock)       { Enable-DNSLock; Enable-OSLock; return }
if ($Unlock)     { Disable-DNSLock; Disable-OSLock; return }
if ($Install)    { Install-Persistence; return }
if ($ParentMode) { Enter-ParentMode; return }
if ($SetParentPassword) { Set-ParentPassword; return }
if ($ChildGameRequest) { Show-GameRequestDialog; return }
if ($ContinueParentMode) {
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
        Write-Log -Message "Parent Mode AFK timer reset by admin." -Type "INFO" -Color Green
    } catch {
        Write-Log -Message "Failed to reset Parent Mode AFK timer: $_" -Type "ERROR" -Color Red
    }
    return
}
if ($LockNow)    { Exit-ParentMode; return }
if ($Uninstall) {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $CurrentUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($CurrentUserSid.Value -ne "S-1-5-18") {
        Write-Host "[SECURITY] CLI Uninstall denied: Must run as SYSTEM. Current user: $CurrentUser" -ForegroundColor Red
        Write-Host "Run from a SYSTEM shell (e.g., psexec -s powershell.exe -File `"$InstallScript`" -Uninstall)" -ForegroundColor Yellow
        return
    }
    Uninstall-Persistence
    return
}

# ============================================================================
# 12. INTERACTIVE MENU
# ============================================================================

# If no flags are passed, load the Interactive Menu
do {
    Clear-Host
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host "    ENTERPRISE OS + DNS LOCKDOWN SUITE (INSTALLER)   " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    $CurrentStatus = Get-LockStatus
    $CategoryGrid = Show-CategoryGrid

    Write-Host "`n-----------------------------------------------------"
    Write-Host "[1] DEPLOY ALL LOCKS (DNS + OS Child Lockdown)" -ForegroundColor Cyan
    Write-Host "[2] REMOVE ALL LOCKS (Restore Access)" -ForegroundColor Yellow
    if (-not (Test-Path $InstallDir)) {
        Write-Host "[3] INSTALL SERVICE (Auto-Heal & Create 'oslock' command)" -ForegroundColor Green
    }
    Write-Host "[4] UNINSTALL SERVICE (Remove background tasks & Unlock)" -ForegroundColor Red
    Write-Host "[5] REFRESH SYSTEM STATUS" -ForegroundColor Gray
    Write-Host "[6] EXIT TERMINAL" -ForegroundColor Gray
    Write-Host "[7] ENTER PARENT MODE (Unlock with password)" -ForegroundColor Green
    Write-Host "[8] LOCK NOW (Re-lock immediately)" -ForegroundColor Cyan
    Write-Host "-----------------------------------------------------"

    $Choice = Read-Host "Select an administrative action (1-8)"
    $IntegrityStatus = Test-IntegrityStatus

    switch ($Choice) {
        "1" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [1] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Enable-DNSLock
                Enable-OSLock
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [2] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Disable-DNSLock
                Disable-OSLock
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "3" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [3] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } elseif (Test-Path $InstallDir) {
                Write-Warning "OS-Guard is already installed. Option [3] is unavailable."
            } else {
                Install-Persistence
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "4" { Uninstall-Persistence; Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") }
        "5" { Start-Sleep -Milliseconds 200 }
        "6" { Write-Host "Returning to terminal..." -ForegroundColor DarkGray; Start-Sleep -Milliseconds 500; break }
        "7" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [7] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Enter-ParentMode
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "8" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [8] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Exit-ParentMode
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        default { Write-Warning "Invalid Selection."; Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "6")
