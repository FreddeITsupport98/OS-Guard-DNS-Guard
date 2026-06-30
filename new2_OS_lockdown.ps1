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
    [switch]$ProgramScan,
    [switch]$SetScreenTime,
    [switch]$ScreenTimeStatus,
    [switch]$GrantBrowserTime,
    [switch]$ScreenTimeEnforce,
    [switch]$TamperLockout,
    [switch]$ApproveChildInstall,
    [switch]$RehardenChildInstall,
    [switch]$HealthCheck,
    [switch]$WhatIf,
    [switch]$ExportReport,
    [switch]$FirstRun,
    [string]$ChildUser = "Child",
    [string[]]$ChildUsers = @(),
    [string]$BrandingOrg = "OS-Guard",
    [string]$HomeSSID = ""
)

Set-StrictMode -Version Latest

# Validate $ChildUser parameter: must be non-empty and contain only valid Windows username characters
if ([string]::IsNullOrWhiteSpace($ChildUser) -or $ChildUser -match '[<>"/\|?*]' -or $ChildUser -match '^[\s\.]+$') {
    Write-Error 'Invalid ChildUser parameter: must be non-empty and not contain invalid characters (< > : " / \ | ? *).'
    exit 1
}

# ============================================================================
# 1. AUTO-ELEVATION & PRE-FLIGHT CHECKS
# ============================================================================

# Automatically relaunch as Administrator if not already elevated
$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$Role = [Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $Principal.IsInRole($Role)) {
    if ($Install -or $Uninstall -or $Lock -or $Unlock -or $SilentLock -or $ParentMode -or $SetParentPassword -or $LockNow -or $ProgramScan -or $SetScreenTime -or $ScreenTimeStatus -or $GrantBrowserTime -or $ScreenTimeEnforce -or $TamperLockout -or $ApproveChildInstall) {
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
            if ($ProgramScan) { $ArgsString += " -ProgramScan" }
            if ($SetScreenTime) { $ArgsString += " -SetScreenTime" }
            if ($ScreenTimeStatus) { $ArgsString += " -ScreenTimeStatus" }
            if ($GrantBrowserTime) { $ArgsString += " -GrantBrowserTime" }
            if ($ScreenTimeEnforce) { $ArgsString += " -ScreenTimeEnforce" }
            if ($TamperLockout) { $ArgsString += " -TamperLockout" }
            if ($ApproveChildInstall) { $ArgsString += " -ApproveChildInstall" }
            if ($RehardenChildInstall) { $ArgsString += " -RehardenChildInstall" }
            if ($HealthCheck) { $ArgsString += " -HealthCheck" }
            if ($WhatIf) { $ArgsString += " -WhatIf" }
            if ($ExportReport) { $ArgsString += " -ExportReport" }
            if ($FirstRun) { $ArgsString += " -FirstRun" }
            if ($ChildUser -ne "Child") { $ArgsString += " -ChildUser `"$ChildUser`"" }
            if ($ChildUsers.Count -gt 0) { $ArgsString += " -ChildUsers `"$($ChildUsers -join ',')`"" }
            if ($BrandingOrg -ne "OS-Guard") { $ArgsString += " -BrandingOrg `"$BrandingOrg`"" }
            if ($HomeSSID) { $ArgsString += " -HomeSSID `"$HomeSSID`"" }

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
$ProgramScannerName = "OSGuard-ProgramScanner"
$ScreenTimeTaskName = "OSGuard-ScreenTime"
$ScreenTimeConfigFile = Join-Path $InstallDir "ScreenTime.json"
$ScreenTimeTrackerFile = Join-Path $InstallDir "ScreenTimeTracker.json"
$BrowserLauncherPath = Join-Path $InstallDir "BrowserLauncher.ps1"
$TempUnlockTimerPath = Join-Path $InstallDir "TempUnlockTimer.ps1"
$TempUnlockTimerPidFile = Join-Path $InstallDir "TempUnlockTimer.pid"
$IntegrityRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$TamperDetectedRegName = "OSGuardTamperDetected"

# Parent Mode AFK Watch script embedded as Base64 (written fresh at install and every silent heal)
$ParentModeWatchB64 = "JFJlZ1BhdGggPSBIS0xNOlxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxXcG5QbGF0Zm9ybVxTZXR0aW5ncwp0cnkgeyAkUGFyZW50QWN0aXZlID0gKEdldC1JdGVtUHJvcGVydHlWYWx1ZSAtUGF0aCAkUmVnUGF0aCAtTmFtZSAiT1NHdWFyZFBhcmVudE1vZGVBY3RpdmUiIC1FcnJvckFjdGlvbiBTdG9wKSB9IGNhdGNoIHsgJFBhcmVudEFjdGl2ZSA9ICRudWxsIH0KdHJ5IHsgJFRlbXBBY3RpdmUgPSAoR2V0LUl0ZW1Qcm9wZXJ0eVZhbHVlIC1QYXRoICRSZWdQYXRoIC1OYW1lICJPU0d1YXJkVGVtcFVubG9ja0FjdGl2ZSIgLUVycm9yQWN0aW9uIFN0b3ApIH0gY2F0Y2ggeyAkVGVtcEFjdGl2ZSA9ICRudWxsIH0KaWYgKCRQYXJlbnRBY3RpdmUgLW5lIDEgLWFuZCAkVGVtcEFjdGl2ZSAtbmUgMSkgeyByZXR1cm4gfQoKQWRkLVR5cGUgQCIKdXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7CnB1YmxpYyBjbGFzcyBJZGxlVGltZSB7CiAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildIHN0YXRpYyBleHRlcm4gYm9vbCBHZXRMYXN0SW5wdXRJbmZvKHJlZiBMQVNUSU5QVVRJTkZPIHBsaWkpOwogICAgW1N0cnVjdExheW91dChMYXlvdXRLaW5kLlNlcXVlbnRpYWwpXSBzdHJ1Y3QgTEFTVElOUFVUSU5GTyB7IHB1YmxpYyB1aW50IGNiU2l6ZTsgcHVibGljIHVpbnQgZHdUaW1lOyB9CiAgICBwdWJsaWMgc3RhdGljIHVpbnQgR2V0SWRsZVRpbWUoKSB7CiAgICAgICAgTEFTVElOUFVUSU5GTyBsaWkgPSBuZXcgTEFTVElOUFVUSU5GTygpOyBsaWkuY2JTaXplID0gKHVpbnQpTWFyc2hhbC5TaXplT2YodHlwZW9mKExBU1RJTlBVVElORk8pKTsKICAgICAgICBHZXRMYXN0SW5wdXRJbmZvKHJlZiBsaWkpOwogICAgICAgIHJldHVybiAodWludClFbnZpcm9ubWVudC5UaWNrQ291bnQgLSBsaWkuZHdUaW1lOwogICAgfQp9CiJACgokSWRsZU1zID0gW0lkbGVUaW1lXTo6R2V0SWRsZVRpbWUoKQokVGltZW91dCA9IDEgKiA2MCAqIDEwMDAKaWYgKCRJZGxlTXMgLWd0ICRUaW1lb3V0KSB7CiAgICAmICJDOlxXaW5kb3dzXG9zbG9jay5jbWQiIC1Mb2NrTm93Cn0="

# Setup Auto-Logging
$ScriptDir = Split-Path -Parent -Path $PSCommandPath
if (-not $ScriptDir) { $ScriptDir = $PWD.Path }
# Log to a protected location (hardened install dir) so child cannot tamper with logs
$LogFile = Join-Path -Path $InstallDir -ChildPath "OS_Lockdown_Enterprise.log"

function Write-Log {
    param ([string]$Message, [string]$Type = "INFO", [ConsoleColor]$Color = "White")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
        "[$TimeStamp] [$Type] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
    } catch {}

    # Write to Windows Event Log for tamper-resistant auditing
    if ($Type -in @("SECURITY","ERROR","WARN","AUDIT","ACTION")) {
        try {
            $SourceName = "OS-Guard"
            $LogName = "Application"
            if (-not [System.Diagnostics.EventLog]::SourceExists($SourceName)) {
                # Requires elevation to create; silently ignore if not present
                try { New-EventLog -LogName $LogName -Source $SourceName -ErrorAction Stop } catch {}
            }
            $EntryType = switch ($Type) {
                "SECURITY"  { "Warning" }
                "ERROR"     { "Error" }
                "WARN"      { "Warning" }
                "AUDIT"     { "Information" }
                "ACTION"    { "Information" }
                default     { "Information" }
            }
            Write-EventLog -LogName $LogName -Source $SourceName -EventId 1001 -EntryType $EntryType -Message "[$script:Branding] $Message" -ErrorAction SilentlyContinue
        } catch {}
    }

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

# WhatIf/DryRun support: wrap modifying calls in a preview flag
$script:WhatIfPreference = $WhatIf.IsPresent
function Invoke-WhatIf {
    param([scriptblock]$Action, [string]$Description)
    if ($script:WhatIfPreference) {
        Write-Log -Message "[WhatIf] $Description" -Type "WhatIf" -Color Yellow
    } else {
        & $Action
    }
}

# Branding
$script:Branding = $BrandingOrg

# Home SSID for geofencing
$script:HomeSSID = $HomeSSID

# Multi-child support: build effective list
$script:EffectiveChildUsers = if ($ChildUsers.Count -gt 0) { $ChildUsers } else { @($ChildUser) }

# Canary file path
$CanaryFile = Join-Path $InstallDir ".osguard.canary"
$CanaryHashFile = Join-Path $InstallDir ".osguard.canary.sha256"

# Cache for expensive lookups
$script:CachedChildSid = @{}
$script:CachedChildProfilePath = @{}
$script:CacheTimestamp = $null

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
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "HideFastUserSwitching"; Value = 1 },
    # Disable Notification Center / Action Center globally
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; Value = 1 },
    # Disable Windows consumer features (suggested apps in Start Menu)
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1 }
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
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum"; Name = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"; Value = 1 },
    # Block exploit tools (Notepad, WordPad, Paint, Write) that can browse files via File -> Open
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisallowRun"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "1"; Value = "notepad.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "2"; Value = "wordpad.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "3"; Value = "mspaint.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "4"; Value = "write.exe" },
    # Disable "Open With" dialog to prevent file browsing via Choose Another App
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoOpenWith"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoInternetOpenWith"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoSecurityTab"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoHardwareTab"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoManageMyComputerVerb"; Value = 1 },
    # Start Menu hardening: lock pinning, drag-drop, context menus, and taskbar tray
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuPinnedList"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuDragDrop"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoTrayContextMenu"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoMovingBands"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoCloseDragDropBands"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuNetworkPlaces"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuEjectPC"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyGames"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyMusic"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyPictures"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuMyVideos"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuDownloads"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuDocuments"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuRecordings"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuHomegroup"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuFavorites"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuRecentDocs"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuRun"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuFind"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuHelp"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoStartMenuLogoff"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoBalloonTips"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "DisableContextMenusInStart"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\Explorer"; Name = "DisableNotificationCenter"; Value = 1 },
    @{ SubPath = "Software\Policies\Microsoft\Windows\CloudContent"; Name = "DisableWindowsConsumerFeatures"; Value = 1 },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "6"; Value = "powershell.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "7"; Value = "pwsh.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "8"; Value = "cmd.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "9"; Value = "wscript.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "10"; Value = "cscript.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "11"; Value = "mshta.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "12"; Value = "certutil.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "13"; Value = "bitsadmin.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "14"; Value = "wmic.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "15"; Value = "regsvr32.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "16"; Value = "rundll32.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "17"; Value = "msiexec.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "18"; Value = "msconfig.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "19"; Value = "mmc.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "20"; Value = "eventvwr.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "21"; Value = "fodhelper.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "22"; Value = "computerdefaults.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "23"; Value = "slui.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "24"; Value = "dccw.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "25"; Value = "xwizard.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "26"; Value = "taskkill.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "27"; Value = "ftp.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "28"; Value = "tftp.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "29"; Value = "telnet.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "30"; Value = "curl.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "31"; Value = "robocopy.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "32"; Value = "takeown.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "33"; Value = "icacls.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "34"; Value = "net.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "35"; Value = "net1.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "36"; Value = "schtasks.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "37"; Value = "at.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "38"; Value = "cleanmgr.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "39"; Value = "sdclt.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "40"; Value = "systempropertiesadvanced.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "41"; Value = "ms-settings.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "42"; Value = "control.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "43"; Value = "inetcpl.cpl" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "44"; Value = "appwiz.cpl" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "45"; Value = "compmgmt.msc" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "46"; Value = "diskmgmt.msc" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "47"; Value = "devmgmt.msc" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "48"; Value = "taskmgr.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "49"; Value = "regedit.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "50"; Value = "perfmon.exe" },
    # Block all alternative browsers so Edge is the only viable option
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "51"; Value = "chrome.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "52"; Value = "firefox.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "53"; Value = "brave.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "54"; Value = "opera.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "55"; Value = "vivaldi.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "56"; Value = "waterfox.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "57"; Value = "tor.exe" },
    @{ SubPath = "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"; Name = "58"; Value = "iexplore.exe" }
)

# ============================================================================
# 4. CHILD ACCOUNT MANAGEMENT
# ============================================================================

function Get-ChildAccount {
    param([string]$UserName = $ChildUser)
    # Returns the LocalUser object for the child account, or $null
    try {
        return (Get-LocalUser -Name $UserName -ErrorAction Stop)
    } catch {
        return $null
    }
}

function Get-ChildSid {
    param([string]$UserName = $ChildUser)
    # Check cache first
    if ($script:CachedChildSid.ContainsKey($UserName)) {
        return $script:CachedChildSid[$UserName]
    }
    $Acct = Get-ChildAccount -UserName $UserName
    $Result = $null
    if ($Acct) { $Result = $Acct.SID.Value }
    $script:CachedChildSid[$UserName] = $Result
    return $Result
}

function Get-ChildProfilePath {
    param([string]$UserName = $ChildUser, [string]$ChildSidValue)
    if ($script:CachedChildProfilePath.ContainsKey($UserName)) {
        return $script:CachedChildProfilePath[$UserName]
    }
    if (-not $ChildSidValue) { $ChildSidValue = Get-ChildSid -UserName $UserName }
    if (-not $ChildSidValue) { $script:CachedChildProfilePath[$UserName] = $null; return $null }
    try {
        $Profile = Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.SID -eq $ChildSidValue } | Select-Object -First 1
        if ($Profile) { $script:CachedChildProfilePath[$UserName] = $Profile.LocalPath; return $Profile.LocalPath }
    } catch {}
    # Fallback: assume standard profile location
    $Guess = "C:\Users\$UserName"
    if (Test-Path $Guess) { $script:CachedChildProfilePath[$UserName] = $Guess; return $Guess }
    $script:CachedChildProfilePath[$UserName] = $null
    return $null
}

function Clear-ChildCache {
    $script:CachedChildSid = @{}
    $script:CachedChildProfilePath = @{}
}

# PBKDF2 helpers
function New-PBKDF2Hash {
    param([string]$Password, [string]$SaltBase64, [int]$Iterations = 100000)
    $SaltBytes = [Convert]::FromBase64String($SaltBase64)
    $Derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $SaltBytes, $Iterations)
    $HashBytes = $Derive.GetBytes(32)
    $Derive.Dispose()
    return [Convert]::ToBase64String($HashBytes)
}

function Get-PBKDF2Salt {
    $Salt = [byte[]]::new(32)
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Rng.GetBytes($Salt)
    $Rng.Dispose()
    return [Convert]::ToBase64String($Salt)
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
        Clear-ChildCache
        return $false  # not newly created
    }

    # Create passwordless account
    $Created = $false
    try {
        New-LocalUser -Name $ChildUser -NoPassword -Description "OS-Guard managed child account (passwordless)" -ErrorAction Stop | Out-Null
        Write-Log -Message "Created PASSWORDLESS child account '$ChildUser'." -Type "SUCCESS" -Color Green
        $Created = $true
    } catch {
        Write-Log -Message "New-LocalUser failed for '$ChildUser': $_. Trying net user fallback..." -Type "WARN" -Color Yellow
        $netResult = net user $ChildUser /add /active:yes /passwordreq:no 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log -Message "Created child account '$ChildUser' via net user." -Type "SUCCESS" -Color Green
            $Created = $true
        } else {
            Write-Log -Message "Failed to create child account '$ChildUser' via net user: $netResult" -Type "ERROR" -Color Red
            return $false
        }
    }

    # Add to standard Users group
    try {
        Add-LocalGroupMember -Group "Users" -Member $ChildUser -ErrorAction Stop
        Write-Log -Message "Added '$ChildUser' to Users group." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Add-LocalGroupMember failed for Users: $_. Trying net localgroup fallback..." -Type "WARN" -Color Yellow
        net localgroup Users $ChildUser /add 2>&1 | Out-Null
    }

    # Prevent the child from changing or setting a password (lockdown reinforcement)
    net user $ChildUser /passwordchg:no 2>&1 | Out-Null
    net user $ChildUser /passwordreq:no 2>&1 | Out-Null
    Write-Log -Message "Password change disabled for '$ChildUser'." -Type "INFO" -Color Gray

    # Enable the account (in case it was created disabled)
    Enable-LocalUser -Name $ChildUser -ErrorAction SilentlyContinue

    Clear-ChildCache
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
            $PropType = if ($Policy.Value -is [string]) { "String" } else { "DWord" }
            New-ItemProperty -Path $KeyPath -Name $Policy.Name -Value $Policy.Value -PropertyType $PropType -Force -ErrorAction SilentlyContinue | Out-Null
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

function Apply-EdgePolicies {
    <#
        Applies deep lockdown policies to Microsoft Edge via HKLM.
        Disables bookmarks, settings, incognito, dev tools, extensions, downloads, etc.
    #>
    Write-Log -Message "Applying Edge deep lockdown policies..." -Type "INFO" -Color Yellow
    $EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $EdgePolicyPath)) { New-Item -Path $EdgePolicyPath -Force -ErrorAction SilentlyContinue | Out-Null }

    $Policies = @{
        "BookmarkBarEnabled" = 0
        "EdgeCollectionsEnabled" = 0
        "BrowserAddProfileEnabled" = 0
        "BrowserGuestModeEnabled" = 0
        "BrowserSignin" = 0
        "DeveloperToolsAvailability" = 2
        "HideFirstRunExperience" = 1
        "InPrivateModeAvailability" = 1
        "PasswordManagerEnabled" = 0
        "SyncDisabled" = 1
        "AllowDeleteBrowserHistory" = 0
        "ForceGoogleSafeSearch" = 1
        "ForceYouTubeRestrict" = 1
        "DownloadRestrictions" = 3
        "DefaultSearchProviderEnabled" = 1
        "DefaultSearchProviderName" = "Bing"
        "DefaultSearchProviderSearchURL" = "https://www.bing.com/search?q={searchTerms}"
        "HomepageLocation" = "https://www.bing.com"
        "NewTabPageLocation" = "https://www.bing.com"
        "ShowHomeButton" = 1
        "PreventSmartScreenPromptOverride" = 1
        "SmartScreenPuaEnabled" = 1
    }

    foreach ($Name in $Policies.Keys) {
        $Value = $Policies[$Name]
        $Type = if ($Value -is [string]) { "String" } else { "DWord" }
        try {
            Set-ItemProperty -Path $EdgePolicyPath -Name $Name -Value $Value -Type $Type -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to set Edge policy $Name`: $_" -Type "WARN" -Color Yellow
        }
    }

    # URL Blocklist (prevent access to internal settings pages)
    $UrlBlockPath = Join-Path $EdgePolicyPath "URLBlocklist"
    if (-not (Test-Path $UrlBlockPath)) { New-Item -Path $UrlBlockPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $BlockedUrls = @("edge://settings","edge://flags","edge://extensions","edge://downloads","edge://passwords","edge://history","edge://bookmarks","chrome://settings","chrome://flags","about:config")
    # Find highest existing numeric key so we append rather than overwrite existing blocklists
    $ExistingKeys = Get-ItemProperty -Path $UrlBlockPath -ErrorAction SilentlyContinue | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -match '^\d+$' } | Select-Object -ExpandProperty Name | ForEach-Object { [int]$_ } | Sort-Object -Descending
    $i = if ($ExistingKeys) { $ExistingKeys[0] + 1 } else { 1 }
    foreach ($Url in $BlockedUrls) {
        Set-ItemProperty -Path $UrlBlockPath -Name "$i" -Value $Url -Type String -Force -ErrorAction SilentlyContinue
        $i++
    }

    # Extension Install Blocklist (block all extensions)
    $ExtBlockPath = Join-Path $EdgePolicyPath "ExtensionInstallBlocklist"
    if (-not (Test-Path $ExtBlockPath)) { New-Item -Path $ExtBlockPath -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-ItemProperty -Path $ExtBlockPath -Name "1" -Value "*" -Type String -Force -ErrorAction SilentlyContinue

    Write-Log -Message "Edge deep lockdown policies applied." -Type "SUCCESS" -Color Green
}

function Remove-EdgePolicies {
    <#
        Removes Edge deep lockdown policies.
    #>
    Write-Log -Message "Removing Edge deep lockdown policies..." -Type "INFO" -Color Yellow
    $EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (Test-Path $EdgePolicyPath) {
        $Keys = @("BookmarkBarEnabled","EdgeCollectionsEnabled","BrowserAddProfileEnabled","BrowserGuestModeEnabled","BrowserSignin","DeveloperToolsAvailability","HideFirstRunExperience","InPrivateModeAvailability","PasswordManagerEnabled","SyncDisabled","AllowDeleteBrowserHistory","ForceGoogleSafeSearch","ForceYouTubeRestrict","DownloadRestrictions","DefaultSearchProviderEnabled","DefaultSearchProviderName","DefaultSearchProviderSearchURL","HomepageLocation","NewTabPageLocation","ShowHomeButton","PreventSmartScreenPromptOverride","SmartScreenPuaEnabled")
        foreach ($Key in $Keys) {
            Remove-ItemProperty -Path $EdgePolicyPath -Name $Key -ErrorAction SilentlyContinue
        }
        Remove-Item -Path (Join-Path $EdgePolicyPath "URLBlocklist") -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path (Join-Path $EdgePolicyPath "ExtensionInstallBlocklist") -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Message "Edge deep lockdown policies removed." -Type "SUCCESS" -Color Green
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
        Stores a PBKDF2 hash (100,000 iterations) in the protected registry key.
    #>
    $PwRegName = "OSGuardParentPasswordHash"
    $SaltRegName = "OSGuardParentPasswordSalt"
    $IterRegName = "OSGuardParentPasswordIterations"
    Write-Host "`n[SET PARENT MODE PASSWORD]" -ForegroundColor Cyan
    $NewPw = Read-Host "Enter new Parent Mode password" -AsSecureString
    $ConfirmPw = Read-Host "Confirm new Parent Mode password" -AsSecureString
    $NewPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPw))
    $ConfirmPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConfirmPw))
    if ($NewPlain -ne $ConfirmPlain) {
        Write-Host "[ERROR] Passwords do not match. Password NOT changed." -ForegroundColor Red
        return
    }
    if ($NewPlain.Length -lt 8) {
        Write-Host "[ERROR] Password must be at least 8 characters." -ForegroundColor Red
        return
    }
    $SaltStr = Get-PBKDF2Salt
    $HashStr = New-PBKDF2Hash -Password $NewPlain -SaltBase64 $SaltStr -Iterations 100000
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name $PwRegName -Value $HashStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name $SaltRegName -Value $SaltStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name $IterRegName -Value 100000 -Type DWord -Force -ErrorAction Stop
        # Harden the registry key so only SYSTEM can read the hash
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($RegKey) {
            $Acl = $RegKey.GetAccessControl()
            $Acl.SetAccessRuleProtection($true, $false)
            $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidSystem, "FullControl", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($SidAdmin, "WriteKey", "Allow")))
            $RegKey.SetAccessControl($Acl)
            $RegKey.Close()
        }
        # Also write a hardened hash file so the child session can verify during tamper lockout
        $HashFile = Join-Path $InstallDir "parent.hash"
        "$HashStr|$SaltStr|100000" | Set-Content -Path $HashFile -Encoding UTF8 -Force
        # Harden hash file ACL: only SYSTEM and Admin have access (child cannot read hash to brute-force)
        $HashAcl = Get-Acl -Path $HashFile
        $HashAcl.SetOwner($SidSystem)
        $HashAcl.SetAccessRuleProtection($true, $false)
        $HashAcl.Access | ForEach-Object { $HashAcl.RemoveAccessRule($_) | Out-Null }
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Delete", "None", "None", "Deny")))
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ChangePermissions", "None", "None", "Deny")))
        $HashAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "TakeOwnership", "None", "None", "Deny")))
        Set-Acl -Path $HashFile -AclObject $HashAcl -ErrorAction SilentlyContinue
        Write-Log -Message "Parent Mode PBKDF2 password hash stored (100k iterations)." -Type "SUCCESS" -Color Green
        Write-Host "[SUCCESS] Parent Mode password updated." -ForegroundColor Green
    } catch {
        Write-Log -Message "Failed to store parent password hash: $_" -Type "ERROR" -Color Red
        Write-Host "[ERROR] Could not store password hash." -ForegroundColor Red
    }
}

function Test-ParentPassword {
    <#
        Prompts for the Parent Mode password and returns $true if correct.
        Uses the stored PBKDF2 salt to compute the hash.
    #>
    $PwRegName = "OSGuardParentPasswordHash"
    $SaltRegName = "OSGuardParentPasswordSalt"
    $IterRegName = "OSGuardParentPasswordIterations"
    $StoredHash = $null
    $StoredSalt = $null
    $StoredIterations = 100000
    try { $StoredHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $PwRegName -ErrorAction Stop) } catch {}
    try { $StoredSalt = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $SaltRegName -ErrorAction Stop) } catch {}
    try { $StoredIterations = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $IterRegName -ErrorAction Stop) } catch {}
    if (-not $StoredHash -or -not $StoredSalt) {
        Write-Host "[ERROR] No Parent Mode password set. Run 'oslock -SetParentPassword' first." -ForegroundColor Red
        return $false
    }
    $InputPw = Read-Host "Enter Parent Mode password" -AsSecureString
    $InputPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($InputPw))
    $InputHash = New-PBKDF2Hash -Password $InputPlain -SaltBase64 $StoredSalt -Iterations $StoredIterations
    if ($InputHash -eq $StoredHash) {
        return $true
    } else {
        Write-Host "[ERROR] Incorrect password." -ForegroundColor Red
        return $false
    }
}

function Start-WindowGuard {
    <#
        Starts a background process that monitors for new windows during Parent Mode.
        If a new process with a visible window is detected, it prompts for the Parent Mode password.
        3 wrong passwords or Cancel triggers immediate lock.
    #>
    $GuardPath = Join-Path $InstallDir "WindowGuard.ps1"
    $GuardContent = @'
$ErrorActionPreference = "Stop"
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$Hash = $null
$Salt = $null
$Iterations = 100000
try { $Hash = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentPasswordHash" -ErrorAction Stop) } catch {}
try { $Salt = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentPasswordSalt" -ErrorAction Stop) } catch {}
try { $Iterations = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentPasswordIterations" -ErrorAction Stop) } catch {}
if (-not $Hash -or -not $Salt) { exit }

Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue

function New-PBKDF2Hash {
    param([string]$Password, [string]$SaltBase64, [int]$Iterations = 100000)
    $SaltBytes = [Convert]::FromBase64String($SaltBase64)
    $Derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $SaltBytes, $Iterations)
    $HashBytes = $Derive.GetBytes(32)
    $Derive.Dispose()
    return [Convert]::ToBase64String($HashBytes)
}

function Test-GuardPassword {
    param([string]$Prompt)
    $Pw = [Microsoft.VisualBasic.Interaction]::InputBox($Prompt, "Parent Mode Window Guard", "", -1, -1)
    if ([string]::IsNullOrWhiteSpace($Pw)) { return $false }
    $InputHash = New-PBKDF2Hash -Password $Pw -SaltBase64 $Salt -Iterations $Iterations
    return ($InputHash -eq $Hash)
}

$SystemProcs = @("explorer","SearchApp","SearchUI","ShellExperienceHost","TextInputHost","ApplicationFrameHost","sihost","RuntimeBroker","dllhost","StartMenuExperienceHost","SecurityHealthSystray","WpnUserService","Dwm","csrss","lsass","services","smss","wininit","winlogon","fontdrvhost","Memory Compression","System","Registry","Secure System","Idle")

$InitialProcs = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $SystemProcs -notcontains $_.ProcessName } | Select-Object -ExpandProperty Id
$KnownProcs = @($InitialProcs)
$FailureCount = 0

while ($true) {
    Start-Sleep -Seconds 5
    try {
        $Active = (Get-ItemPropertyValue -Path $RegPath -Name "OSGuardParentModeActive" -ErrorAction Stop)
    } catch { $Active = 0 }
    if ($Active -ne 1) { break }

    $CurrentProcs = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $SystemProcs -notcontains $_.ProcessName } | Select-Object Id, ProcessName
    $NewProcs = $CurrentProcs | Where-Object { $KnownProcs -notcontains $_.Id }

    if ($NewProcs.Count -gt 0) {
        $Names = ($NewProcs | Select-Object -ExpandProperty ProcessName -Unique) -join ", "
        $Result = Test-GuardPassword -Prompt "New window detected ($Names). Enter password to continue, or click Cancel to lock."
        if (-not $Result) {
            $FailureCount++
            if ($FailureCount -ge 3) {
                try { & "C:\Windows\oslock.cmd" -LockNow } catch { try { Stop-Process -Id $PID -Force } catch {} }
                break
            }
        } else {
            $FailureCount = 0
            $KnownProcs = @($CurrentProcs | Select-Object -ExpandProperty Id)
        }
    } else {
        $KnownProcs = @($CurrentProcs | Select-Object -ExpandProperty Id)
    }
}
'@
    try {
        Set-Content -Path $GuardPath -Value $GuardContent -Encoding UTF8 -Force
        $GuardAcl = Get-Acl -Path $GuardPath
        $GuardAcl.SetOwner($SidSystem)
        $GuardAcl.SetAccessRuleProtection($true, $false)
        $GuardAcl.Access | ForEach-Object { $GuardAcl.RemoveAccessRule($_) | Out-Null }
        $GuardAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $GuardAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $GuardPath -AclObject $GuardAcl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write WindowGuard script: $_" -Type "WARN" -Color Yellow
    }
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$GuardPath`"" -WindowStyle Hidden
        Write-Log -Message "Window Guard started for Parent Mode session." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to start Window Guard: $_" -Type "WARN" -Color Yellow
    }
}

function Stop-WindowGuard {
    try {
        $Procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -like "*WindowGuard.ps1*" }
        foreach ($Proc in $Procs) {
            Stop-Process -Id $Proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-Log -Message "Window Guard stopped." -Type "INFO" -Color Gray
    } catch {}
}

function Harden-ScreenTimeFile {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $Acl = Get-Acl -Path $FilePath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "Read", "None", "None", "Allow")))
        $ChildSidValue = Get-ChildSid
        if ($ChildSidValue) {
            $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "Read", "None", "None", "Allow")))
        }
        Set-Acl -Path $FilePath -AclObject $Acl -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to harden ScreenTime file $FilePath`: $_" -Type "WARN" -Color Yellow
    }
}

function Get-ScreenTimeConfig {
    if (Test-Path $ScreenTimeConfigFile) {
        try { return Get-Content -Path $ScreenTimeConfigFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch {
            Write-Log -Message "Failed to read ScreenTime config: $_" -Type "WARN" -Color Yellow
        }
    }
    return $null
}

function Set-ScreenTimeConfig {
    param(
        [string]$DailyStart = "08:00",
        [string]$DailyEnd = "20:00",
        [int]$DailyMaxMinutes = 120,
        [int]$BrowserMaxMinutes = 60,
        [int]$WeekendDailyMaxMinutes = 180,
        [int]$WeekendBrowserMaxMinutes = 90,
        [bool]$Enabled = $true
    )
    $Config = @{
        Enabled = $Enabled
        DailyStart = $DailyStart
        DailyEnd = $DailyEnd
        DailyMaxMinutes = $DailyMaxMinutes
        BrowserMaxMinutes = $BrowserMaxMinutes
        WeekendDailyMaxMinutes = $WeekendDailyMaxMinutes
        WeekendBrowserMaxMinutes = $WeekendBrowserMaxMinutes
    }
    try {
        $Config | ConvertTo-Json -Depth 3 | Set-Content -Path $ScreenTimeConfigFile -Encoding UTF8 -Force -ErrorAction Stop
        Harden-ScreenTimeFile -FilePath $ScreenTimeConfigFile
        Write-Log -Message "ScreenTime config saved." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to save ScreenTime config: $_" -Type "ERROR" -Color Red
    }
}

function Get-ScreenTimeTracker {
    if (Test-Path $ScreenTimeTrackerFile) {
        try { return Get-Content -Path $ScreenTimeTrackerFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch {}
    }
    return $null
}

function Update-ScreenTimeTracker {
    param([PSCustomObject]$Tracker)
    try {
        $Tracker | ConvertTo-Json -Depth 3 | Set-Content -Path $ScreenTimeTrackerFile -Encoding UTF8 -Force -ErrorAction Stop
        Harden-ScreenTimeFile -FilePath $ScreenTimeTrackerFile
    } catch {
        Write-Log -Message "Failed to update ScreenTime tracker: $_" -Type "WARN" -Color Yellow
    }
}

function Reset-ScreenTimeTrackerIfNewDay {
    $Tracker = Get-ScreenTimeTracker
    $Today = (Get-Date).ToString("yyyy-MM-dd")
    if (-not $Tracker -or $Tracker.LastDate -ne $Today) {
        $Tracker = @{
            LastDate = $Today
            DailySecondsUsed = 0
            BrowserSecondsUsed = 0
            LastResetTimestamp = (Get-Date -Format "o")
            BrowserAllowanceActive = $false
            BrowserAllowanceExpiry = $null
            BrowserAllowanceMinutes = 0
        }
        Update-ScreenTimeTracker -Tracker $Tracker
        Write-Log -Message "ScreenTime tracker reset for new day ($Today)." -Type "INFO" -Color Gray
    }
    return $Tracker
}

function Test-ScreenTimeLimit {
    $Config = Get-ScreenTimeConfig
    if (-not $Config -or -not $Config.Enabled) { return $false }
    $Now = Get-Date
    $Tracker = Reset-ScreenTimeTrackerIfNewDay

    # Check browser allowance first (admin-granted override)
    if ($Tracker.BrowserAllowanceActive -eq $true) {
        if ($Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt $Now) {
            return $false
        } else {
            $Tracker.BrowserAllowanceActive = $false
            Update-ScreenTimeTracker -Tracker $Tracker
        }
    }

    # Check daily hours
    try {
        $StartTime = [DateTime]::ParseExact($Config.DailyStart, "HH:mm", $null)
        $EndTime = [DateTime]::ParseExact($Config.DailyEnd, "HH:mm", $null)
        $StartToday = $Now.Date.Add($StartTime.TimeOfDay)
        $EndToday = $Now.Date.Add($EndTime.TimeOfDay)
        if ($StartToday -le $EndToday) {
            if ($Now -lt $StartToday -or $Now -gt $EndToday) { return $true }
        } else {
            if ($Now -gt $EndToday -and $Now -lt $StartToday) { return $true }
        }
    } catch {
        Write-Log -Message "ScreenTime config has invalid time format." -Type "WARN" -Color Yellow
    }

    # Check daily max minutes
    $DailyUsedMin = [math]::Floor($Tracker.DailySecondsUsed / 60)
    $IsWeekend = ($Now.DayOfWeek -eq 'Saturday') -or ($Now.DayOfWeek -eq 'Sunday')
    $DailyLimit = if ($IsWeekend -and $Config.WeekendDailyMaxMinutes) { $Config.WeekendDailyMaxMinutes } else { $Config.DailyMaxMinutes }
    if ($DailyUsedMin -ge $DailyLimit) { return $true }

    # Check browser max minutes (total daily)
    $BrowserUsedMin = [math]::Floor($Tracker.BrowserSecondsUsed / 60)
    $BrowserLimit = if ($IsWeekend -and $Config.WeekendBrowserMaxMinutes) { $Config.WeekendBrowserMaxMinutes } else { $Config.BrowserMaxMinutes }
    if ($BrowserUsedMin -ge $BrowserLimit) { return $true }

    return $false
}

function Invoke-ScreenTimeEnforcement {
    $Exceeded = Test-ScreenTimeLimit
    $BrowserProcs = @()
    $ChildSidValue = Get-ChildSid
    foreach ($BrowserName in @("msedge", "chrome", "firefox")) {
        $Procs = Get-Process -Name $BrowserName -ErrorAction SilentlyContinue | Where-Object {
            # Only target browsers owned by the child user (avoid killing admin browsers)
            if (-not $ChildSidValue) { return $true }
            try {
                $Owner = $_.GetOwner().User
                $OwnerSid = (New-Object System.Security.Principal.NTAccount($Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
                return ($OwnerSid -eq $ChildSidValue)
            } catch { return $false }
        }
        if ($Procs) { $BrowserProcs += $Procs }
    }
    if ($Exceeded -and $BrowserProcs) {
        foreach ($Proc in $BrowserProcs) {
            try { Stop-Process -Id $Proc.Id -Force -ErrorAction Stop } catch {}
        }
        Write-Log -Message "ScreenTime limit exceeded. Browsers terminated." -Type "SECURITY" -Color Red
        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            [System.Windows.Forms.MessageBox]::Show("Your browser time is up or outside allowed hours. Please ask your admin for more time.", "Browser Time Limit", "OK", "Warning") | Out-Null
        } catch {}
    }
    $Tracker = Get-ScreenTimeTracker
    if (-not $Tracker) { return }
    if ($BrowserProcs) {
        $Tracker.DailySecondsUsed += 60
        $Tracker.BrowserSecondsUsed += 60
        Update-ScreenTimeTracker -Tracker $Tracker
    }
}

function Show-SetScreenTimeDialog {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " SET SCREEN TIME (ADMIN ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not (Test-ParentPassword)) { return }
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $ExistingConfig = Get-ScreenTimeConfig
    $DefaultStart = if ($ExistingConfig -and $ExistingConfig.DailyStart) { $ExistingConfig.DailyStart } else { "08:00" }
    $DefaultEnd = if ($ExistingConfig -and $ExistingConfig.DailyEnd) { $ExistingConfig.DailyEnd } else { "20:00" }
    $DefaultDailyMax = if ($ExistingConfig -and $ExistingConfig.DailyMaxMinutes) { [string]$ExistingConfig.DailyMaxMinutes } else { "120" }
    $DefaultBrowserMax = if ($ExistingConfig -and $ExistingConfig.BrowserMaxMinutes) { [string]$ExistingConfig.BrowserMaxMinutes } else { "60" }
    $DefaultWeekendDailyMax = if ($ExistingConfig -and $ExistingConfig.WeekendDailyMaxMinutes) { [string]$ExistingConfig.WeekendDailyMaxMinutes } else { "180" }
    $DefaultWeekendBrowserMax = if ($ExistingConfig -and $ExistingConfig.WeekendBrowserMaxMinutes) { [string]$ExistingConfig.WeekendBrowserMaxMinutes } else { "90" }
    $Start = [Microsoft.VisualBasic.Interaction]::InputBox("Daily allowed start time (HH:mm):", "Screen Time", $DefaultStart, -1, -1)
    if ([string]::IsNullOrWhiteSpace($Start)) { return }
    $End = [Microsoft.VisualBasic.Interaction]::InputBox("Daily allowed end time (HH:mm):", "Screen Time", $DefaultEnd, -1, -1)
    if ([string]::IsNullOrWhiteSpace($End)) { return }
    try {
        [DateTime]::ParseExact($Start, "HH:mm", $null) | Out-Null
        [DateTime]::ParseExact($End, "HH:mm", $null) | Out-Null
    } catch {
        Write-Host "[ERROR] Invalid time format. Use HH:mm (e.g. 08:00)." -ForegroundColor Red
        return
    }
    $tmp = 0
    $DailyMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max computer minutes (weekday):", "Screen Time", $DefaultDailyMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($DailyMax) -or -not [int]::TryParse($DailyMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid daily max." -ForegroundColor Red; return }
    $BrowserMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max browser minutes (weekday):", "Screen Time", $DefaultBrowserMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($BrowserMax) -or -not [int]::TryParse($BrowserMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid browser max." -ForegroundColor Red; return }
    $WeekendDailyMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max computer minutes (weekend):", "Screen Time", $DefaultWeekendDailyMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($WeekendDailyMax) -or -not [int]::TryParse($WeekendDailyMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid weekend daily max." -ForegroundColor Red; return }
    $WeekendBrowserMax = [Microsoft.VisualBasic.Interaction]::InputBox("Daily max browser minutes (weekend):", "Screen Time", $DefaultWeekendBrowserMax, -1, -1)
    if ([string]::IsNullOrWhiteSpace($WeekendBrowserMax) -or -not [int]::TryParse($WeekendBrowserMax, [ref]$tmp)) { Write-Host "[ERROR] Invalid weekend browser max." -ForegroundColor Red; return }
    Set-ScreenTimeConfig -DailyStart $Start -DailyEnd $End -DailyMaxMinutes ([int]$DailyMax) -BrowserMaxMinutes ([int]$BrowserMax) -WeekendDailyMaxMinutes ([int]$WeekendDailyMax) -WeekendBrowserMaxMinutes ([int]$WeekendBrowserMax) -Enabled $true
    Write-Host "[SUCCESS] ScreenTime settings updated." -ForegroundColor Green
    Write-Log -Message "Admin updated ScreenTime settings." -Type "ACTION" -Color Magenta
}

function Show-ScreenTimeStatus {
    $Config = Get-ScreenTimeConfig
    $Tracker = Reset-ScreenTimeTrackerIfNewDay
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " SCREEN TIME STATUS " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not $Config -or -not $Config.Enabled) {
        Write-Host "  ScreenTime is not configured or disabled." -ForegroundColor Yellow
    } else {
        Write-Host "  Allowed hours: $($Config.DailyStart) - $($Config.DailyEnd)" -ForegroundColor Gray
        Write-Host "  Daily max: $($Config.DailyMaxMinutes) minutes" -ForegroundColor Gray
        Write-Host "  Browser max: $($Config.BrowserMaxMinutes) minutes" -ForegroundColor Gray
        $DailyUsed = [math]::Floor($Tracker.DailySecondsUsed / 60)
        $BrowserUsed = [math]::Floor($Tracker.BrowserSecondsUsed / 60)
        Write-Host "  Daily used: $DailyUsed minutes" -ForegroundColor Gray
        Write-Host "  Browser used: $BrowserUsed minutes" -ForegroundColor Gray
        if ($Tracker.BrowserAllowanceActive -eq $true -and $Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt (Get-Date)) {
            Write-Host "  Active browser allowance: expires at $([DateTime]::Parse($Tracker.BrowserAllowanceExpiry).ToString('HH:mm'))" -ForegroundColor Green
        } else {
            Write-Host "  No active browser allowance." -ForegroundColor Yellow
        }
    }
    Write-Host "=====================================================" -ForegroundColor Cyan
}

function Show-GrantBrowserTimeDialog {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " GRANT BROWSER TIME (ADMIN ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    if (-not (Test-ParentPassword)) { return }
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $Minutes = [Microsoft.VisualBasic.Interaction]::InputBox("Enter minutes to grant the child for browser access:`n(Presets: 15, 30, 60, 120)", "Grant Browser Time", "30", -1, -1)
    if ([string]::IsNullOrWhiteSpace($Minutes)) { return }
    $tmp = 0
    if (-not [int]::TryParse($Minutes, [ref]$tmp)) {
        Write-Host "[ERROR] Invalid number." -ForegroundColor Red
        return
    }
    $MinutesInt = [int]$Minutes
    if ($MinutesInt -le 0 -or $MinutesInt -gt 720) {
        Write-Host "[ERROR] Minutes must be between 1 and 720." -ForegroundColor Red
        return
    }
    $Tracker = Reset-ScreenTimeTrackerIfNewDay
    $Expiry = (Get-Date).AddMinutes($MinutesInt).ToString("o")
    $Tracker.BrowserAllowanceActive = $true
    $Tracker.BrowserAllowanceExpiry = $Expiry
    $Tracker.BrowserAllowanceMinutes = $MinutesInt
    Update-ScreenTimeTracker -Tracker $Tracker
    Write-Host "`n[SUCCESS] Browser time granted: $MinutesInt minutes (expires at $([DateTime]::Parse($Expiry).ToString('HH:mm')))." -ForegroundColor Green
    Write-Log -Message "Admin granted $MinutesInt minutes of browser time." -Type "ACTION" -Color Magenta
}

function New-BrowserLauncher {
    $LauncherContent = @'
param([switch]$Request)
$InstallDir = "C:\ProgramData\OSGuard"
$TrackerFile = Join-Path $InstallDir "ScreenTimeTracker.json"
$RequestsDir = Join-Path $InstallDir "Requests"
function Get-Tracker {
    if (Test-Path $TrackerFile) {
        try { return Get-Content -Path $TrackerFile -Raw -ErrorAction Stop | ConvertFrom-Json } catch {}
    }
    return $null
}
function Show-Info {
    param([string]$Message)
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show($Message, "Browser Access", "OK", "Information") | Out-Null
}
$Tracker = Get-Tracker
$Now = Get-Date
$Allowed = $false
if ($Tracker -and $Tracker.BrowserAllowanceActive -eq $true) {
    if ($Tracker.BrowserAllowanceExpiry -and ([DateTime]$Tracker.BrowserAllowanceExpiry) -gt $Now) {
        $Allowed = $true
    }
}
if ($Allowed) {
    Start-Process "msedge.exe" -ErrorAction SilentlyContinue
} else {
    Show-Info -Message "Browser is locked. Ask your admin to open 'Grant Browser Time' on their desktop to set a timer."
    if (-not (Test-Path $RequestsDir)) { New-Item -ItemType Directory -Path $RequestsDir -Force -ErrorAction SilentlyContinue | Out-Null }
    $ReqFile = Join-Path $RequestsDir ("browser_request_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")
    @"
Browser Access Request
----------------------
From: Child
Timestamp: $($Now.ToString("yyyy-MM-dd HH:mm:ss"))
Message: Child requested browser access but no active allowance exists.
"@ | Set-Content -Path $ReqFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
}
'@
    try {
        Set-Content -Path $BrowserLauncherPath -Value $LauncherContent -Encoding UTF8 -Force
        Harden-ScreenTimeFile -FilePath $BrowserLauncherPath
        Write-Log -Message "Browser launcher script written." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to write browser launcher: $_" -Type "WARN" -Color Yellow
    }
}

function New-BrowserRequestShortcut {
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $DesktopPath = Join-Path $ChildProfilePath "Desktop"
    if (-not (Test-Path $DesktopPath)) { New-Item -ItemType Directory -Path $DesktopPath -Force -ErrorAction SilentlyContinue | Out-Null }
    $ShortcutPath = Join-Path $DesktopPath "Browser Request.lnk"
    try {
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$BrowserLauncherPath`""
        $Lnk.Description = "Request browser access (requires admin approval)"
        $Lnk.IconLocation = "shell32.dll,14"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created child browser request shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create browser request shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-BrowserRequestShortcut {
    $ChildProfilePath = $null
    try {
        $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1
        if ($ChildProfile) { $ChildProfilePath = $ChildProfile.LocalPath }
    } catch {}
    if (-not $ChildProfilePath) { $ChildProfilePath = "C:\Users\$ChildUser" }
    $Path = Join-Path $ChildProfilePath "Desktop\Browser Request.lnk"
    if (Test-Path $Path) {
        try {
            $Acl = Get-Acl -Path $Path
            $Acl.SetAccessRuleProtection($false, $false)
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction SilentlyContinue
        } catch {}
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed browser request shortcut." -Type "INFO" -Color Gray
    }
}

function New-GrantBrowserTimeShortcut {
    $Wsh = New-Object -ComObject WScript.Shell
    $AdminDesktop = $Wsh.SpecialFolders("Desktop")
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }
    $ShortcutPath = Join-Path $AdminDesktop "Grant Browser Time.lnk"
    try {
        $Wsh = New-Object -ComObject WScript.Shell
        $Lnk = $Wsh.CreateShortcut($ShortcutPath)
        $Lnk.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $Lnk.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$InstallScript`" -GrantBrowserTime"
        $Lnk.Description = "Grant the child browser access time (password protected)"
        $Lnk.IconLocation = "shell32.dll,14"
        $Lnk.Save()
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)
        Harden-FileACL -FilePath $ShortcutPath
        Write-Log -Message "Created admin 'Grant Browser Time' shortcut at '$ShortcutPath'." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create Grant Browser Time shortcut: $_" -Type "WARN" -Color Yellow
    }
}

function Remove-GrantBrowserTimeShortcut {
    $Wsh = New-Object -ComObject WScript.Shell
    $AdminDesktop = $Wsh.SpecialFolders("Desktop")
    $Path = Join-Path $AdminDesktop "Grant Browser Time.lnk"
    if (Test-Path $Path) {
        try {
            $Acl = Get-Acl -Path $Path
            $Acl.SetAccessRuleProtection($false, $false)
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction SilentlyContinue
        } catch {}
        Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed Grant Browser Time shortcut." -Type "INFO" -Color Gray
    }
}

function Install-ScreenTimeWatcher {
    Write-Log -Message "Installing ScreenTime watcher task..." -Type "INFO" -Color Yellow
    try {
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ScreenTimeEnforce"
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $ScreenTimeTaskName -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
        Write-Log -Message "ScreenTime watcher '$ScreenTimeTaskName' registered (1-minute heartbeat)." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to register ScreenTime watcher: $_" -Type "ERROR" -Color Red
    }
}

function Remove-ScreenTimeWatcher {
    if (Get-ScheduledTask -TaskName $ScreenTimeTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $ScreenTimeTaskName -Confirm:$false | Out-Null
        Write-Log -Message "Removed ScreenTime watcher task." -Type "INFO" -Color Gray
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

    if (-not $SilentLock) {
        $IntegrityCheck = Test-IntegrityStatus
        if ($IntegrityCheck -eq $false) {
            Write-Log -Message "Action blocked: script integrity failure before Enter-ParentMode." -Type "SECURITY" -Color Red
            Write-Host "[BLOCKED] Tamper detected. Use uninstall and reinstall." -ForegroundColor Red -BackgroundColor Black
            return
        }
    }

    if (-not (Test-ParentPassword)) { return }

    Write-Log -Message "Parent Mode activated by admin. Unlocking system..." -Type "ACTION" -Color Magenta

    # Temporarily unlock everything (but keep installer policies and directory ACLs active)
    Disable-OSLock
    Disable-DNSLock

    # Re-apply installer policies so the child cannot install even during Parent Mode
    Apply-InstallerPolicies
    Harden-ChildInstallDirectories

    # Remove child hive restrictions from live hive if child is currently logged in, and offline hive if not
    $ChildSidValue = Get-ChildSid
    $LiveHive = $null
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $LiveHive = $ChildSidValue
    }
    $OfflineHive = $null
    if (-not $LiveHive) {
        $OfflineHive = Mount-ChildHive
    }
    foreach ($Policy in $ChildHivePolicies) {
        if ($LiveHive) {
            $KeyPath = "Registry::HKEY_USERS\$LiveHive\$($Policy.SubPath)"
            try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
        if ($OfflineHive) {
            $KeyPath = "Registry::HKEY_USERS\$OfflineHive\$($Policy.SubPath)"
            try { Remove-ItemProperty -Path $KeyPath -Name $Policy.Name -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    if ($OfflineHive) { Dismount-ChildHive -HiveMount $OfflineHive }

    # Refresh Windows UI so the unlock takes effect immediately (only current session, not system-wide)
    Write-Log -Message "Refreshing Windows UI after unlock..." -Type "INFO" -Color Gray
    try {
        $CurrentSessionId = (Get-Process -Id $PID).SessionId
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId } | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
        Start-Process "explorer" -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to restart explorer for UI refresh: $_" -Type "WARN" -Color Yellow
    }

    # Create Admin tool shortcuts for Parent Mode session
    New-ParentModeAdminTools

    # Set parent mode flag and timestamp
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 1 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to set parent mode flag: $_" -Type "ERROR" -Color Red
    }

    Write-Host "`n[PARENT MODE ACTIVE]" -ForegroundColor Green -BackgroundColor Black
    Write-Host "  System UI is UNLOCKED. You can modify settings or view the child account." -ForegroundColor Green
    Write-Host "  SOFTWARE INSTALLATION RESTRICTED: Installer policies and directory ACLs remain active." -ForegroundColor Yellow
    Write-Host "  To install software to the child account, use 'Approve Child Install' on the admin desktop." -ForegroundColor Yellow
    Write-Host "  Auto-lock after 5 minutes of inactivity (AFK timer)." -ForegroundColor Yellow
    Write-Host "  Click 'Lock Now' on the admin desktop or run 'oslock -LockNow' to re-lock immediately." -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Cyan

    # Start Window Guard to detect new windows and re-prompt for password
    Start-WindowGuard
}

function Exit-ParentMode {
    <#
        Re-locks everything and clears the parent mode flag.
    #>
    Write-Log -Message "Exiting Parent Mode and re-locking system..." -Type "ACTION" -Color Magenta
    Stop-WindowGuard
    Stop-TempUnlockTimer
    Remove-ParentModeAdminTools
    Enable-OSLock
    Enable-DNSLock

    # Refresh Windows UI so the lock takes effect immediately (only current session, not system-wide)
    Write-Log -Message "Refreshing Windows UI after re-lock..." -Type "INFO" -Color Gray
    try {
        $CurrentSessionId = (Get-Process -Id $PID).SessionId
        Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId } | ForEach-Object {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
        Start-Process "explorer" -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to restart explorer for UI refresh: $_" -Type "WARN" -Color Yellow
    }

    # Program Guardian: immediately scan and harden any newly installed programs after Parent Mode
    Scan-And-Harden-ChildPrograms

    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}
    Write-Log -Message "Parent Mode ended. System re-locked." -Type "SUCCESS" -Color Green
    Write-Host "[LOCKED] System is secured again." -ForegroundColor Green
}

function Invoke-OSGuardFirewall {
    <#
        Creates or removes Windows Firewall rules via netsh advfirewall to block
        child-specific processes from outbound internet unless whitelisted.
    #>
    param([switch]$Enable, [switch]$Disable)
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }
    # Common child game/program directories
    $ProgramDirs = Get-ChildInstallDirectories
    $RulePrefix = "OSGuard-BlockOutbound"
    # Remove old rules first
    $ExistingRules = netsh advfirewall firewall show rule name=all dir=out | Select-String "^Rule Name:\s+($RulePrefix.*)" | ForEach-Object { ($_ -split "\s+", 3)[2].Trim() }
    foreach ($Rule in $ExistingRules) {
        if ($Disable) {
            try { netsh advfirewall firewall delete rule name="$Rule" | Out-Null } catch {}
        }
    }
    if ($Enable) {
        foreach ($Dir in $ProgramDirs) {
            $ExeFiles = Get-ChildItem -Path $Dir -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
            foreach ($Exe in $ExeFiles) {
                $RuleName = "$RulePrefix-$([System.IO.Path]::GetFileNameWithoutExtension($Exe))"
                try {
                    netsh advfirewall firewall add rule name="$RuleName" dir=out action=block program="$Exe" enable=yes | Out-Null
                    Write-Log -Message "Firewall outbound block added for $Exe" -Type "INFO" -Color Gray
                } catch {}
            }
        }
        # Also block common child browsers that are not Edge (already disallowed via DisallowRun)
        $BlockExes = @("chrome.exe","firefox.exe","opera.exe","brave.exe","vivaldi.exe")
        foreach ($ExeName in $BlockExes) {
            $RuleName = "$RulePrefix-$ExeName"
            try { netsh advfirewall firewall add rule name="$RuleName" dir=out action=block program="$ExeName" enable=yes | Out-Null } catch {}
        }
    }
}

function Test-HomeNetwork {
    <#
        Returns $true if the PC is connected to the home SSID (or if no HomeSSID is configured).
        Returns $false if connected to a different network, triggering stricter lockdown.
    #>
    if ([string]::IsNullOrWhiteSpace($script:HomeSSID)) { return $true }
    try {
        $ConnectedSSID = (netsh wlan show interfaces | Select-String "^\s+SSID\s+:" | ForEach-Object { ($_ -split ":\s+")[1].Trim() } | Select-Object -First 1)
        if ($ConnectedSSID -and $ConnectedSSID -eq $script:HomeSSID) { return $true }
    } catch {}
    return $false
}

function Invoke-GeofenceLockdown {
    <#
        If not on the home network, enforces stricter lockdown by killing browsers and games
        and temporarily adding extra firewall rules. Called during SilentLock and health check.
    #>
    if (Test-HomeNetwork) { return }
    Write-Log -Message "Geofence: Not connected to home network '$script:HomeSSID'. Enforcing stricter lockdown." -Type "SECURITY" -Color Red
    # Kill non-Edge browsers and games
    $BlockList = @("chrome","firefox","opera","brave","vivaldi","steam","epicgameslauncher","origin","uplay")
    foreach ($ProcName in $BlockList) {
        Get-Process -Name $ProcName -ErrorAction SilentlyContinue | ForEach-Object {
            try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
        }
    }
    # Add emergency firewall blocks
    Invoke-OSGuardFirewall -Enable
}

function Show-HealthCheck {
    <#
        Read-only drift audit. Reports all missing tasks, wrong registry values,
        missing ACLs, and policy drift without fixing anything. Perfect for MSP audits.
    #>
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " OS-GUARD HEALTH CHECK (READ-ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    $Drift = [System.Collections.Generic.List[string]]::new()

    # Check persistence tasks
    $Tasks = @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName, $ProgramScannerName, $ScreenTimeTaskName)
    foreach ($T in $Tasks) {
        if (-not (Get-ScheduledTask -TaskName $T -ErrorAction SilentlyContinue)) {
            $Drift.Add("MISSING TASK: $T")
        }
    }
    # Check canary
    if (-not (Test-Canary)) { $Drift.Add("CANARY MISSING OR TAMPERED") }
    # Check install dir
    if (-not (Test-Path $InstallDir)) { $Drift.Add("INSTALL DIR MISSING: $InstallDir") }
    if (-not (Test-Path $InstallScript)) { $Drift.Add("INSTALL SCRIPT MISSING: $InstallScript") }
    # Check wrapper
    if (-not (Test-Path $CmdPath)) { $Drift.Add("GLOBAL CLI MISSING: $CmdPath") }
    # Check PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    if ($CurrentPath -notlike "*$InstallDir*") { $Drift.Add("PATH MISSING: $InstallDir") }
    # Check machine policies (sample)
    $UacLUA = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableLUA" -ErrorAction SilentlyContinue
    if ($UacLUA -ne 1) { $Drift.Add("UAC LUA NOT ENFORCED") }
    $Store = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "RemoveWindowsStore" -ErrorAction SilentlyContinue
    if ($Store -ne 1) { $Drift.Add("STORE NOT REMOVED") }
    # Check child account
    if (-not (Get-ChildAccount)) { $Drift.Add("CHILD ACCOUNT MISSING: $ChildUser") }
    # Check geofence
    if (-not (Test-HomeNetwork)) { $Drift.Add("GEOFENCE: NOT ON HOME NETWORK ($script:HomeSSID)") }

    if ($Drift.Count -eq 0) {
        Write-Host "  [HEALTHY] No drift detected." -ForegroundColor Green
    } else {
        Write-Host "  [DRIFT] $($Drift.Count) issues found:" -ForegroundColor Red
        foreach ($Item in $Drift) { Write-Host "    - $Item" -ForegroundColor Yellow }
    }
    Write-Host "=====================================================" -ForegroundColor Cyan
    return $Drift
}

function Export-OSGuardReport {
    <#
        Exports a CSV report for admin/MSP review including:
        lock status, last tamper event, screen time usage, installed programs, policy drift.
    #>
    param([string]$OutputPath = (Join-Path $InstallDir "OSGuard_Report.csv"))
    $Drift = Show-HealthCheck
    $Tracker = Get-ScreenTimeTracker
    $Config = Get-ScreenTimeConfig
    $InstalledPrograms = Get-ChildInstallDirectories
    $TamperActive = Test-TamperDetected
    $LastTamper = "N/A"
    try { $LastTamper = Get-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $TamperDetectedRegName -ErrorAction SilentlyContinue } catch {}

    $Report = [PSCustomObject]@{
        Timestamp         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Branding          = $script:Branding
        ChildUser         = $ChildUser
        TamperActive      = $TamperActive
        PolicyDriftCount  = $Drift.Count
        ScreenTimeEnabled = if ($Config) { $Config.Enabled } else { $false }
        DailyUsedMin      = if ($Tracker) { [math]::Floor($Tracker.DailySecondsUsed / 60) } else { 0 }
        BrowserUsedMin    = if ($Tracker) { [math]::Floor($Tracker.BrowserSecondsUsed / 60) } else { 0 }
        InstalledPrograms = ($InstalledPrograms -join ";")
        HomeNetwork       = (Test-HomeNetwork)
    }
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
        $Report | Export-Csv -Path $OutputPath -NoTypeInformation -Force -Encoding UTF8
        Write-Log -Message "Report exported to $OutputPath" -Type "INFO" -Color Gray
        Write-Host "[INFO] Report exported to $OutputPath" -ForegroundColor Green
    } catch {
        Write-Log -Message "Failed to export report to $OutputPath`: $_" -Type "ERROR" -Color Red
        Write-Host "[ERROR] Failed to export report: $_" -ForegroundColor Red
    }
}

function Show-SetupWizard {
    <#
        First-Run Wizard: WinForms dialog that asks for child username, daily screen time,
        weekend limit, then auto-deploys everything. Removes the "read the menu" barrier.
    #>
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$script:Branding - First Run Wizard"
    $form.Size = New-Object System.Drawing.Size(500, 420)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false

    $y = 20
    $labels = @(
        @("Child username:", "Child"),
        @("Daily start time (HH:mm):", "08:00"),
        @("Daily end time (HH:mm):", "20:00"),
        @("Daily max minutes (weekday):", "120"),
        @("Browser max minutes (weekday):", "60"),
        @("Weekend daily max minutes:", "180"),
        @("Weekend browser max minutes:", "90")
    )
    $controls = @()
    foreach ($pair in $labels) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = $pair[0]
        $lbl.Location = New-Object System.Drawing.Point(20, $y)
        $lbl.Size = New-Object System.Drawing.Size(200, 20)
        $form.Controls.Add($lbl)
        $txt = New-Object System.Windows.Forms.TextBox
        $txt.Text = $pair[1]
        $txt.Location = New-Object System.Drawing.Point(230, $y)
        $txt.Size = New-Object System.Drawing.Size(220, 20)
        $form.Controls.Add($txt)
        $controls += $txt
        $y += 35
    }

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "DEPLOY"
    $btn.Location = New-Object System.Drawing.Point(180, $y + 10)
    $btn.Size = New-Object System.Drawing.Size(120, 30)
    $btn.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($btn)
    $form.AcceptButton = $btn

    [void]$form.ShowDialog()
    if ($form.DialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $ChildUser = $controls[0].Text
        $DailyStart = $controls[1].Text
        $DailyEnd = $controls[2].Text
        $DailyMax = [int]$controls[3].Text
        $BrowserMax = [int]$controls[4].Text
        $WeekendDailyMax = [int]$controls[5].Text
        $WeekendBrowserMax = [int]$controls[6].Text
        Set-ScreenTimeConfig -DailyStart $DailyStart -DailyEnd $DailyEnd -DailyMaxMinutes $DailyMax -BrowserMaxMinutes $BrowserMax -WeekendDailyMaxMinutes $WeekendDailyMax -WeekendBrowserMaxMinutes $WeekendBrowserMax -Enabled $true
        Write-Log -Message "First Run Wizard configured for '$ChildUser'. Deploying locks..." -Type "ACTION" -Color Magenta
        Install-Persistence
    }
}

function New-ParentModeShortcut {
    <#
        Creates Parent Mode, Lock Now, and Continue shortcuts on the admin desktop.
    #>
    $Wsh = New-Object -ComObject WScript.Shell
    $AdminDesktop = $Wsh.SpecialFolders("Desktop")
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }

    $Shortcuts = @(
        @{ Name = "Parent Mode.lnk"; Args = "-ParentMode"; Icon = "shell32.dll,48"; Desc = "Enter Parent Mode (unlock system)" },
        @{ Name = "Lock Now.lnk"; Args = "-LockNow"; Icon = "shell32.dll,47"; Desc = "Immediately re-lock the system" },
        @{ Name = "Continue Parent Mode.lnk"; Args = "-ContinueParentMode"; Icon = "shell32.dll,45"; Desc = "Reset AFK timer while in Parent Mode" },
        @{ Name = "Approve Child Install.lnk"; Args = "-ApproveChildInstall"; Icon = "shell32.dll,44"; Desc = "Temporarily allow software install to child account (15 min)" }
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
    $Wsh = New-Object -ComObject WScript.Shell
    $AdminDesktop = $Wsh.SpecialFolders("Desktop")
    foreach ($Name in @("Parent Mode.lnk", "Lock Now.lnk", "Continue Parent Mode.lnk", "Admin CMD.lnk", "Admin PowerShell.lnk")) {
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

function New-ParentModeAdminTools {
    <#
        Creates Admin CMD and Admin PowerShell shortcuts on the admin desktop
        during Parent Mode so the admin can quickly open elevated terminals.
    #>
    $Wsh = New-Object -ComObject WScript.Shell
    $AdminDesktop = $Wsh.SpecialFolders("Desktop")
    if (-not (Test-Path $AdminDesktop)) { New-Item -ItemType Directory -Path $AdminDesktop -Force -ErrorAction SilentlyContinue | Out-Null }

    $Tools = @(
        @{ Name = "Admin CMD.lnk"; Target = "C:\Windows\System32\cmd.exe"; Args = "/k cd %USERPROFILE%"; Icon = "cmd.exe,0"; Desc = "Admin Command Prompt (Parent Mode)" },
        @{ Name = "Admin PowerShell.lnk"; Target = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"; Args = "-NoExit -Command `"Set-Location ~`""; Icon = "powershell.exe,0"; Desc = "Admin PowerShell (Parent Mode)" }
    )

    foreach ($T in $Tools) {
        $Path = Join-Path $AdminDesktop $T.Name
        try {
            $Wsh = New-Object -ComObject WScript.Shell
            $Lnk = $Wsh.CreateShortcut($Path)
            $Lnk.TargetPath = $T.Target
            $Lnk.Arguments = $T.Args
            $Lnk.Description = $T.Desc
            $Lnk.IconLocation = $T.Icon
            $Lnk.Save()
            $bytes = [System.IO.File]::ReadAllBytes($Path)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Path, $bytes)
            Harden-FileACL -FilePath $Path
            Write-Log -Message "Created Parent Mode admin tool: $($T.Name)" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to create admin tool $($T.Name): $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ParentModeAdminTools {
    <#
        Removes the Admin CMD and Admin PowerShell shortcuts from the admin desktop.
    #>
    $Wsh = New-Object -ComObject WScript.Shell
    $AdminDesktop = $Wsh.SpecialFolders("Desktop")
    foreach ($Name in @("Admin CMD.lnk", "Admin PowerShell.lnk", "Approve Child Install.lnk")) {
        $Path = Join-Path $AdminDesktop $Name
        if (Test-Path $Path) {
            try {
                $Acl = Get-Acl -Path $Path
                $Acl.SetAccessRuleProtection($false, $false)
                Set-Acl -Path $Path -AclObject $Acl -ErrorAction SilentlyContinue
            } catch {}
            Remove-Item -Path $Path -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Removed admin tool: $Name" -Type "INFO" -Color Gray
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
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        [System.Windows.Forms.MessageBox]::Show("Your request for '$GameName' has been submitted to the administrator.`n`nThe admin will review and install it if approved.", "Request Sent", "OK", "Information") | Out-Null
    } catch {
        Write-Log -Message "Failed to save game request: $_" -Type "ERROR" -Color Red
    }
}

function Get-ChildInstallDirectories {
    <#
        Discovers program install directories and shortcuts within the child profile.
        Scans Desktop, Start Menu, AppData\Local\Programs, and AppData\Roaming.
        Uses [System.IO.Directory]::EnumerateDirectories for performance.
        Returns an array of unique directory paths.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return @() }

    $Dirs = [System.Collections.Generic.List[string]]::new()

    # --- Scan common user install locations ---
    $ScanPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs"),
        (Join-Path $ChildProfilePath "AppData\Local"),
        (Join-Path $ChildProfilePath "AppData\Roaming"),
        (Join-Path $ChildProfilePath "Desktop"),
        (Join-Path $ChildProfilePath "Documents")
    )

    foreach ($ScanPath in $ScanPaths) {
        if (-not (Test-Path $ScanPath)) { continue }
        try {
            $Candidates = [System.IO.Directory]::EnumerateDirectories($ScanPath) | Where-Object {
                $Name = [System.IO.Path]::GetFileName($_)
                # Skip Windows system folders that are not user-installed programs
                if ($Name -match "^(Microsoft|Windows|Temp|Packages|Temp\w*|Media\w*)$") { return $false }
                # Heuristic: contains .exe or .dll files, or looks like a program folder
                $HasFiles = $false
                try {
                    $SubDirs = [System.IO.Directory]::EnumerateDirectories($_, "*", [System.IO.SearchOption]::AllDirectories)
                    foreach ($SubDir in $SubDirs) {
                        if ([System.IO.Directory]::GetFiles($SubDir, "*.exe").Count -gt 0 -or
                            [System.IO.Directory]::GetFiles($SubDir, "*.dll").Count -gt 0 -or
                            [System.IO.Directory]::GetFiles($SubDir, "*.json").Count -gt 0) {
                            $HasFiles = $true
                            break
                        }
                    }
                } catch { $HasFiles = $false }
                $HasFiles
            }
            foreach ($Candidate in $Candidates) {
                if (-not $Dirs.Contains($Candidate)) { $Dirs.Add($Candidate) }
            }
        } catch {}
    }

    # --- Scan Start Menu shortcuts to discover program targets ---
    $StartMenuPaths = @(
        (Join-Path $ChildProfilePath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
    )
    foreach ($StartMenu in $StartMenuPaths) {
        if (-not (Test-Path $StartMenu)) { continue }
        try {
            $Shortcuts = Get-ChildItem -Path $StartMenu -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
            foreach ($Shortcut in $Shortcuts) {
                try {
                    $Wsh = New-Object -ComObject WScript.Shell
                    $Lnk = $Wsh.CreateShortcut($Shortcut.FullName)
                    $Target = $Lnk.TargetPath
                    if ($Target -and (Test-Path $Target) -and $Target -match "\.exe$") {
                        $TargetDir = Split-Path -Parent $Target
                        if ($TargetDir -and $TargetDir -notlike "*\Windows\*" -and $TargetDir -notlike "*\Program Files\*" -and $TargetDir -notlike "*\System32\*" -and $TargetDir -notlike "*\SysWOW64\*") {
                            if (-not $Dirs.Contains($TargetDir)) { $Dirs.Add($TargetDir) }
                        }
                    }
                } catch {}
            }
        } catch {}
    }

    return $Dirs.ToArray()
}

function Harden-ProgramDirectory {
    <#
        Hardens a program directory so the child can execute files but cannot:
        - Modify, delete, or rename files/folders
        - Change permissions or take ownership
        - Write new files
        The child retains ReadAndExecute (can run the game/program).
    #>
    param([string]$DirPath)
    if (-not (Test-Path $DirPath)) { return }

    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)

    try {
        $Acl = Get-Acl -Path $DirPath
        $Acl.SetOwner($SidSystem)
        $Acl.SetAccessRuleProtection($true, $false)

        # Remove any existing child-specific rules
        $Acl.Access | Where-Object {
            try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $ChildSidValue } catch { $false }
        } | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }

        # SYSTEM and Admin: FullControl so the directory remains accessible to admin after scan/reharden
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $SidAdmin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

        # Child: ReadAndExecute on files (can run programs), but Deny Modify/Delete/Write on folder+files
        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "Modify", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "WriteData", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "AppendData", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "ChangePermissions", "ContainerInherit,ObjectInherit", "None", "Deny")))

        $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $ChildSidObj, "TakeOwnership", "ContainerInherit,ObjectInherit", "None", "Deny")))

        Set-Acl -Path $DirPath -AclObject $Acl -ErrorAction Stop
        Write-Log -Message "Program directory hardened: $DirPath" -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to harden program directory $DirPath`: $_" -Type "WARN" -Color Yellow
    }
}

function Harden-ProgramShortcuts {
    <#
        Hardens all .lnk shortcuts in the child profile Desktop and Start Menu
        so the child cannot delete, modify, or rename them.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }

    $ShortcutPaths = @(
        (Join-Path $ChildProfilePath "Desktop"),
        (Join-Path $ChildProfilePath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs")
    )

    foreach ($BasePath in $ShortcutPaths) {
        if (-not (Test-Path $BasePath)) { continue }
        try {
            $Shortcuts = Get-ChildItem -Path $BasePath -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
            foreach ($Sc in $Shortcuts) {
                try {
                    Harden-FileACL -FilePath $Sc.FullName
                } catch {
                    Write-Log -Message "Failed to harden shortcut $($Sc.FullName): $_" -Type "WARN" -Color Yellow
                }
            }
        } catch {}
    }
}

function Scan-And-Harden-ChildPrograms {
    <#
        Main Program Guardian scan routine.
        Discovers newly installed programs in the child profile and hardens them.
        Also hardens all shortcuts.
        Skips expensive scan if the child is not currently logged in.
    #>
    # Performance: skip scan if child is not logged in
    $ChildIsLoggedIn = $false
    try {
        $LoggedOn = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match "Name=`"$ChildUser`"" }
        if ($LoggedOn) { $ChildIsLoggedIn = $true }
    } catch { $ChildIsLoggedIn = $true }
    if (-not $ChildIsLoggedIn) {
        Write-Log -Message "Program Guardian: child '$ChildUser' is not logged in. Skipping scan." -Type "INFO" -Color Gray
        return
    }

    Write-Log -Message "Program Guardian: scanning child profile for installed programs..." -Type "ACTION" -Color Cyan

    $DiscoveredDirs = Get-ChildInstallDirectories
    if ($DiscoveredDirs.Count -eq 0) {
        Write-Log -Message "Program Guardian: no user-installed programs found in child profile." -Type "INFO" -Color Gray
    } else {
        Write-Log -Message "Program Guardian: discovered $($DiscoveredDirs.Count) program directories." -Type "INFO" -Color Gray
        foreach ($Dir in $DiscoveredDirs) {
            Harden-ProgramDirectory -DirPath $Dir
        }
    }

    Harden-ProgramShortcuts
    Write-Log -Message "Program Guardian: scan complete." -Type "SUCCESS" -Color Green
}

function Harden-ChildInstallDirectories {
    <#
        Proactively hardens per-user install directories in the child profile
        so the child cannot install software even when Parent Mode is active.
        Hardens AppData\Local\Programs with ReadAndExecute only for the child.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }

    $InstallPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs")
    )

    $ChildSidValue = Get-ChildSid
    if (-not $ChildSidValue) { return }
    $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)

    foreach ($Path in $InstallPaths) {
        if (-not (Test-Path $Path)) {
            try { New-Item -ItemType Directory -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null } catch { continue }
        }
        try {
            $Acl = Get-Acl -Path $Path
            $Acl.SetOwner($SidSystem)
            $Acl.SetAccessRuleProtection($true, $false)

            $Acl.Access | ForEach-Object { $Acl.RemoveAccessRule($_) | Out-Null }

            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $SidSystem, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $SidAdmin, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "Modify", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "Write", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $Acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $ChildSidObj, "CreateFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))

            Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
            Write-Log -Message "Child install directory hardened: $Path" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to harden child install directory $Path`: $_" -Type "WARN" -Color Yellow
        }
    }
}

function Remove-ChildInstallDirectoryHardening {
    <#
        Resets ACLs on the child's per-user install directories back to inherited defaults.
        Used during Disable-OSLock / Uninstall.
    #>
    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) { return }

    $InstallPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs")
    )

    foreach ($Path in $InstallPaths) {
        if (-not (Test-Path $Path)) { continue }
        try {
            & icacls.exe $Path /reset /T /C 2>&1 | Out-Null
            Write-Log -Message "Child install directory ACLs reset: $Path" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to reset ACLs on $Path`: $_" -Type "WARN" -Color Yellow
        }
    }
}

function Apply-InstallerPolicies {
    <#
        Re-applies only the installer and store-related machine policies.
        Used during Parent Mode to keep software installation blocked even while unlocked.
    #>
    Write-Log -Message "Re-applying installer policies (MSI, Store, USB) during Parent Mode..." -Type "INFO" -Color Yellow
    $InstallerPolicies = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableMSI"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableUserInstalls"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name = "DisableUserInstallsViaModifications"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "RemoveWindowsStore"; Value = 1 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "AutoDownload"; Value = 2 },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"; Name = "DisableStoreApps"; Value = 1 },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"; Name = "Start"; Value = 4 }
    )
    foreach ($Policy in $InstallerPolicies) {
        try {
            if (-not (Test-Path $Policy.Path)) { New-Item -Path $Policy.Path -Force -ErrorAction SilentlyContinue | Out-Null }
            Set-ItemProperty -Path $Policy.Path -Name $Policy.Name -Value $Policy.Value -Type DWord -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Log -Message "Failed to re-apply installer policy $($Policy.Name): $_" -Type "WARN" -Color Yellow
        }
    }
    try { Stop-Service -Name "USBSTOR" -Force -ErrorAction SilentlyContinue } catch {}
    Write-Log -Message "Installer policies re-applied (MSI blocked, Store removed, USB disabled)." -Type "SUCCESS" -Color Green
}

function Approve-ChildInstall {
    <#
        Prompts for the Parent Mode password and temporarily relaxes ACLs on the
        child's per-user install directories so the admin can install software.
        After 15 minutes, a scheduled task re-hardens the directories.
    #>
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " APPROVE CHILD SOFTWARE INSTALL (ADMIN ONLY) " -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan

    if (-not (Test-ParentPassword)) { return }

    Write-Log -Message "Admin approved child software installation. Relaxing install directory ACLs..." -Type "ACTION" -Color Magenta

    $ChildProfilePath = Get-ChildProfilePath
    if (-not $ChildProfilePath) {
        Write-Host "[ERROR] Could not locate child profile path." -ForegroundColor Red
        return
    }

    $InstallPaths = @(
        (Join-Path $ChildProfilePath "AppData\Local\Programs")
    )

    foreach ($Path in $InstallPaths) {
        if (-not (Test-Path $Path)) { continue }
        try {
            $Acl = Get-Acl -Path $Path
            $ChildSidValue = Get-ChildSid
            if ($ChildSidValue) {
                $RulesToRemove = $Acl.Access | Where-Object {
                    try {
                        $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                        $sid.Value -eq $ChildSidValue -and $_.AccessControlType -eq "Deny"
                    } catch { $false }
                }
                foreach ($Rule in $RulesToRemove) { $Acl.RemoveAccessRule($Rule) | Out-Null }
            }
            $Acl.SetOwner($SidAdmin)
            Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
            Write-Log -Message "Relaxed install directory ACLs: $Path" -Type "INFO" -Color Gray
        } catch {
            Write-Log -Message "Failed to relax ACLs on $Path`: $_" -Type "WARN" -Color Yellow
        }
    }

    try {
        $RehardenAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -RehardenChildInstall"
        $RehardenTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15)
        $RehardenPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "OSGuard-ApproveInstallReharden" -Action $RehardenAction -Trigger $RehardenTrigger -Principal $RehardenPrincipal -Force | Out-Null
        Write-Log -Message "Scheduled re-hardening task for 15 minutes from now." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to schedule re-hardening task: $_" -Type "WARN" -Color Yellow
    }

    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    [System.Windows.Forms.MessageBox]::Show("Install approval active for 15 minutes.`n`nYou can now install software to the child account.`n`nACLs will be automatically re-hardened after 15 minutes.", "Install Approval", "OK", "Information") | Out-Null
    Write-Host "[SUCCESS] Install approval active for 15 minutes." -ForegroundColor Green
}

function Invoke-ChildInstallReharden {
    <#
        Re-hardens child install directories after an approval period.
        Called by the scheduled task created by Approve-ChildInstall.
    #>
    Write-Log -Message "Re-hardening child install directories after approval period..." -Type "ACTION" -Color Magenta
    Harden-ChildInstallDirectories
    Scan-And-Harden-ChildPrograms

    # LOCKBACK: If Parent Mode is still active, force re-lock the system
    $ParentModeActive = $false
    try { $ParentModeActive = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardParentModeActive" -ErrorAction SilentlyContinue -eq 1 } catch {}
    if ($ParentModeActive) {
        Write-Log -Message "Lockback triggered: Install approval window expired. Re-locking system..." -Type "SECURITY" -Color Red
        try { Stop-WindowGuard } catch { Write-Log -Message "Stop-WindowGuard failed during lockback: $_" -Type "WARN" -Color Yellow }
        Remove-ParentModeAdminTools
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
        } catch {}
        Enable-OSLock
        Enable-DNSLock

        # Restart explorer in user sessions to apply restrictions immediately
        # Do NOT start explorer from SYSTEM context - let Windows auto-restart it
        try {
            Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 } | ForEach-Object {
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log -Message "Explorer restart during lockback failed: $_" -Type "WARN" -Color Yellow
        }

        Write-Log -Message "Lockback complete: System re-locked after install approval expired." -Type "SUCCESS" -Color Green
    }

    if (Get-ScheduledTask -TaskName "OSGuard-ApproveInstallReharden" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "OSGuard-ApproveInstallReharden" -Confirm:$false | Out-Null
        Write-Log -Message "Removed re-hardening scheduled task." -Type "INFO" -Color Gray
    }
}

function Install-ProgramGuardian {
    <#
        Installs the OSGuard-ProgramScanner scheduled task (10-minute heartbeat).
        This task scans the child profile for new programs and hardens them automatically.
    #>
    Write-Log -Message "Installing Program Guardian scheduled task..." -Type "INFO" -Color Yellow
    try {
        $ScanAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -ProgramScan"
        $ScanTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 9999)
        $ScanPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $ProgramScannerName -Action $ScanAction -Trigger $ScanTrigger -Principal $ScanPrincipal -Force | Out-Null
        Write-Log -Message "Program Guardian '$ProgramScannerName' registered (10-minute heartbeat)." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to register Program Guardian task: $_" -Type "ERROR" -Color Red
    }
}

function Remove-ProgramGuardian {
    if (Get-ScheduledTask -TaskName $ProgramScannerName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $ProgramScannerName -Confirm:$false | Out-Null
        Write-Log -Message "Removed Program Guardian task: $ProgramScannerName" -Type "INFO" -Color Gray
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

    if (-not $SilentLock) {
        $IntegrityCheck = Test-IntegrityStatus
        if ($IntegrityCheck -eq $false) {
            Write-Log -Message "Action blocked: script integrity failure before Enable-OSLock." -Type "SECURITY" -Color Red
            Write-Host "[BLOCKED] Tamper detected. Use uninstall and reinstall." -ForegroundColor Red -BackgroundColor Black
            return
        }
    }

    # Clear any temporary unlock flags when re-locking
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}

    Stop-TempUnlockTimer

    # 1. Ensure child account exists and is a standard user (passwordless)
    New-ChildAccount | Out-Null

    # 2. Machine-wide policies (UAC maxed + Store removed)
    Apply-MachinePolicies

    # 3. Per-user policies on the child's offline hive
    $HiveMount = Mount-ChildHive
    if ($HiveMount) {
        Apply-ChildHivePolicies -HiveMount $HiveMount
        Write-Log -Message "Child hive policies applied to '$ChildUser' (offline)." -Type "SUCCESS" -Color Green
        Dismount-ChildHive -HiveMount $HiveMount
    } else {
        Write-Log -Message "Child hive not available - policies will apply at next child logon via ChildLogon task." -Type "WARN" -Color Yellow
    }
    # Also apply to live session if child is currently logged in
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        Apply-ChildHivePolicies -HiveMount $ChildSidValue
        Write-Log -Message "Child hive policies applied to '$ChildUser' (live session)." -Type "SUCCESS" -Color Green
    }

    # 4. Block password change at the account level (belt and suspenders)
    net user $ChildUser /passwordchg:no 2>&1 | Out-Null
    net user $ChildUser /passwordreq:no 2>&1 | Out-Null

    Set-ChildLogoutShortcut
    New-ChildGameRequestShortcut
    # Skip re-creating Parent Mode shortcuts if Parent Mode is currently active
    $ParentModeActive = $false
    try { $ParentModeActive = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardParentModeActive" -ErrorAction SilentlyContinue -eq 1 } catch {}
    if (-not $ParentModeActive) { New-ParentModeShortcut }
    New-BrowserLauncher
    New-BrowserRequestShortcut
    New-GrantBrowserTimeShortcut
    Apply-EdgePolicies

    # Program Guardian: scan and harden any newly installed programs immediately
    Scan-And-Harden-ChildPrograms

    # Harden per-user install directories so child cannot install even in Parent Mode
    Harden-ChildInstallDirectories

    Write-Log -Message "OS Child Lockdown deployed." -Type "SUCCESS" -Color Green

    # Verification
    $FailedCount = 0
    foreach ($Policy in $MachinePolicies) {
        try {
            $Val = Get-ItemProperty -Path $Policy.Path -Name $Policy.Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Policy.Name -ErrorAction SilentlyContinue
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
    param(
        [switch]$KeepChildAccount,
        [switch]$SetTempUnlockFlag
    )
    Write-Log -Message "Initiating OS Child Lockdown removal..." -Type "ACTION" -Color Magenta

    if (-not $SilentLock) {
        $IntegrityCheck = Test-IntegrityStatus
        if ($IntegrityCheck -eq $false) {
            Write-Log -Message "Action blocked: script integrity failure before Disable-OSLock." -Type "SECURITY" -Color Red
            Write-Host "[BLOCKED] Tamper detected. Use uninstall and reinstall." -ForegroundColor Red -BackgroundColor Black
            return
        }
    }

    # 1. Remove machine-wide policies
    Remove-MachinePolicies

    # Warn that guardian tasks will re-apply locks unless uninstalled
    if (-not $SilentLock) {
        Write-Host "[WARNING] Guardian tasks (5/10 min heartbeat) will re-apply locks soon." -ForegroundColor Yellow
        Write-Host "          Use option [4] UNINSTALL to permanently remove protection." -ForegroundColor Yellow
    }

    # Clear Parent Mode flags so the AFK watcher doesn't trigger after unlock
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}

    # Set temporary unlock flag if requested (prevents guardian re-lock)
    if ($SetTempUnlockFlag -and -not $SilentLock) {
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value (Get-Date -Format "o") -Type String -Force -ErrorAction Stop
        } catch {
            Write-Log -Message "Failed to set temp unlock flag: $_" -Type "WARN" -Color Yellow
        }
    }

    if (-not $KeepChildAccount) {
        # 2. Remove per-user policies from the child's live and offline hives
        $ChildSidValue = Get-ChildSid
        $LiveHive = $null
        if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
            $LiveHive = $ChildSidValue
        }
        $OfflineHive = $null
        if (-not $LiveHive) {
            $OfflineHive = Mount-ChildHive
        }
        if ($LiveHive) {
            Remove-ChildHivePolicies -HiveMount $LiveHive
            Write-Log -Message "Child hive policies removed from '$ChildUser' (live session)." -Type "SUCCESS" -Color Green
        }
        if ($OfflineHive) {
            Remove-ChildHivePolicies -HiveMount $OfflineHive
            Write-Log -Message "Child hive policies removed from '$ChildUser' (offline)." -Type "SUCCESS" -Color Green
            Dismount-ChildHive -HiveMount $OfflineHive
        }
        if (-not $LiveHive -and -not $OfflineHive) {
            Write-Log -Message "Child hive not available for cleanup - policies will clear at next logon if ChildLogon task removed." -Type "WARN" -Color Yellow
        }

        # 3. Re-enable password change capability
        net user $ChildUser /passwordchg:yes 2>&1 | Out-Null

        Remove-ChildLogoutShortcut
        Remove-ChildGameRequestShortcut
        Remove-BrowserRequestShortcut
        Remove-EdgePolicies
        Remove-ScreenTimeWatcher
        Remove-ChildInstallDirectoryHardening
    } else {
        Write-Log -Message "KeepChildAccount specified: child account policies, shortcuts, screen time, and install directory hardening are preserved." -Type "INFO" -Color Gray
    }

    Remove-ParentModeShortcut
    Remove-ParentModeAdminTools
    Remove-GrantBrowserTimeShortcut

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
    # Check child hive for network UI policies (admin HKCU is not the target)
    $ChildNetConn = $null
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue\Software\Policies\Microsoft\Windows\Network Connections")) {
        $ChildNetConn = Get-ItemProperty -Path "Registry::HKEY_USERS\$ChildSidValue\Software\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue
    } else {
        $HiveMount = Mount-ChildHive
        if ($HiveMount) {
            $ChildNetConn = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue
            Dismount-ChildHive -HiveMount $HiveMount
        }
    }
    if (-not $ChildNetConn -or $ChildNetConn.NC_LanProperties -ne 0) { $GpoEnforced = $false }
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
        $UacLUA = Get-ItemProperty -Path $UacPath -Name "EnableLUA" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableLUA" -ErrorAction SilentlyContinue
        $UacAdmin = Get-ItemProperty -Path $UacPath -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
        $StoreRemoved = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "RemoveWindowsStore" -ErrorAction SilentlyContinue
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
        $MsiDisabled = Get-ItemProperty -Path $MsiPath -Name "DisableMSI" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableMSI" -ErrorAction SilentlyContinue
        if ($MsiDisabled -eq 2) {
            Write-Host "  [X] Windows Installer  -> BLOCKED for non-admin" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Windows Installer  -> AVAILABLE" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check USB storage
        $UsbStart = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Start" -ErrorAction SilentlyContinue
        if ($UsbStart -eq 4) {
            Write-Host "  [X] USB Storage        -> DISABLED (install from USB blocked)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] USB Storage        -> ENABLED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Windows Script Host
        $WshEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Enabled" -ErrorAction SilentlyContinue
        if ($WshEnabled -eq 0) {
            Write-Host "  [X] Windows Script Host -> DISABLED (wscript/cscript blocked)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Windows Script Host -> ENABLED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check SmartScreen
        $SmartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableSmartScreen" -ErrorAction SilentlyContinue
        if ($SmartScreen -eq 1) {
            Write-Host "  [X] SmartScreen        -> ENFORCED (unknown apps blocked)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] SmartScreen        -> NOT ENFORCED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Fast User Switching
        $FastSwitch = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "HideFastUserSwitching" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "HideFastUserSwitching" -ErrorAction SilentlyContinue
        if ($FastSwitch -eq 1) {
            Write-Host "  [X] Fast User Switching -> DISABLED (can't switch to admin)" -ForegroundColor Red
        } else {
            Write-Host "  [ ] Fast User Switching -> ENABLED" -ForegroundColor Green
            $OsLocked = $false
        }

        # Check Windows Update UI block
        $WuBlocked = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
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
            $TaskMgrDisabled = Get-ItemProperty -Path $SamplePath -Name "DisableTaskMgr" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableTaskMgr" -ErrorAction SilentlyContinue
            $RegDisabled = Get-ItemProperty -Path $SamplePath -Name "DisableRegistryTools" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableRegistryTools" -ErrorAction SilentlyContinue
            if ($TaskMgrDisabled -eq 1) {
                Write-Host "  [X] TaskMgr/Regedit    -> DISABLED for child" -ForegroundColor Red
            } else {
                Write-Host "  [ ] TaskMgr/Regedit    -> ENABLED for child" -ForegroundColor Green
                $OsLocked = $false
            }

            $ExplorerPath = "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            $NoCtx = Get-ItemProperty -Path $ExplorerPath -Name "NoViewContextMenu" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoViewContextMenu" -ErrorAction SilentlyContinue
            $NoFolder = Get-ItemProperty -Path $ExplorerPath -Name "NoFolderOptions" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoFolderOptions" -ErrorAction SilentlyContinue
            $NoTaskbar = Get-ItemProperty -Path $ExplorerPath -Name "NoSetTaskbar" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoSetTaskbar" -ErrorAction SilentlyContinue
            $NoAddPrinter = Get-ItemProperty -Path $ExplorerPath -Name "NoAddPrinter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoAddPrinter" -ErrorAction SilentlyContinue
            $NoDelPrinter = Get-ItemProperty -Path $ExplorerPath -Name "NoDeletePrinter" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoDeletePrinter" -ErrorAction SilentlyContinue

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
    $TamperFlag = $false
    if (Test-Path $InstallScript) {
        $ExpectedHash = $null
        try { $ExpectedHash = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings" -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}
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
                $TamperFlag = $true
            }
        } else {
            Write-Host "  [ ] Script Integrity    -> NO BASELINE" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [ ] Script Integrity    -> NOT INSTALLED" -ForegroundColor DarkGray
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # --- 5.1 TAMPER LOCKOUT STATUS ---
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " SCRIPT TAMPER DETECTION " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $TamperLockoutActive = $false
    try { $TamperLockoutActive = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings" -Name $TamperDetectedRegName -ErrorAction Stop) -eq 1 } catch {}
    if ($TamperLockoutActive) {
        Write-Host "  [X] Tamper Lockout      -> ACTIVE (Child session locked)" -ForegroundColor Red
        Write-Host "  >>> Child session is locked due to script tampering. <<<" -ForegroundColor Black -BackgroundColor Red
        Write-Host "  Admin password required to unlock the child session." -ForegroundColor Yellow
    } else {
        Write-Host "  [ ] Tamper Lockout      -> NOT ACTIVE" -ForegroundColor Green
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # Master Status Banner Logic
    if ($TamperLockoutActive) {
        Write-Host " >>> TAMPER LOCKOUT ACTIVE: CHILD SESSION LOCKED <<< " -ForegroundColor White -BackgroundColor DarkRed
    } elseif ($DnsLocked -and $OsLocked -and $GpoEnforced) {
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
    $NetConnLan = if ($NetConn) { $NetConn.NC_LanProperties } else { $null }
    if ($NetConnLan -ne 0) { $GpoEnforced = $false }
    $Edge = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue
    if ($Edge -and $Edge.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
    $Chrome = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue
    if ($Chrome -and $Chrome.DnsOverHttpsMode -ne "off") { $GpoEnforced = $false }
    $Firefox = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue
    if ($Firefox -and $Firefox.Enabled -ne 0) { $GpoEnforced = $false }
    $Categories["DNS GPO/DoH"] = $GpoEnforced

    # --- OS Machine-wide ---
    $UacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $UacLUA = Get-ItemProperty -Path $UacPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableLUA" -ErrorAction SilentlyContinue
    $UacAdmin = Get-ItemProperty -Path $UacPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    $Categories["UAC Max"] = ($UacLUA -eq 1 -and $UacAdmin -eq 2)

    $StoreRemoved = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "RemoveWindowsStore" -ErrorAction SilentlyContinue
    $Categories["Windows Store"] = ($StoreRemoved -eq 1)

    $MsiDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableMSI" -ErrorAction SilentlyContinue
    $Categories["Windows Installer"] = ($MsiDisabled -eq 2)

    $UsbStart = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Start" -ErrorAction SilentlyContinue
    $Categories["USB Storage"] = ($UsbStart -eq 4)

    $WshEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Enabled" -ErrorAction SilentlyContinue
    $Categories["WSH (cscript)"] = ($WshEnabled -eq 0)

    $SmartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "EnableSmartScreen" -ErrorAction SilentlyContinue
    $Categories["SmartScreen"] = ($SmartScreen -eq 1)

    $FastSwitch = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "HideFastUserSwitching" -ErrorAction SilentlyContinue
    $Categories["Fast User Switching"] = ($FastSwitch -eq 1)

    $WuBlocked = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
    $Categories["Windows Update UI"] = ($WuBlocked -eq 1)

    # --- Child Account ---
    $Categories["Child Account"] = ($null -ne (Get-ChildAccount))

    # --- Child Hive: prefer live session if child is logged in ---
    $HiveMount = $null
    $HiveLoaded = $false
    $ChildSidValue = Get-ChildSid
    if ($ChildSidValue -and (Test-Path "Registry::HKEY_USERS\$ChildSidValue")) {
        $HiveMount = $ChildSidValue
    } else {
        $ChildProfile = $null
        try { $ChildProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { $_.LocalPath -like "*\$ChildUser" } | Select-Object -First 1 } catch {}
        if ($ChildProfile) {
            $NtUserDat = Join-Path $ChildProfile.LocalPath "NTUSER.DAT"
            if (Test-Path $NtUserDat) {
                if (Test-Path "Registry::HKEY_USERS\OSGuardChildPolicy") { reg.exe unload "HKU\OSGuardChildPolicy" 2>&1 | Out-Null }
                $Output = & reg.exe load "HKU\OSGuardChildPolicy" "$NtUserDat" 2>&1
                if (Test-Path "Registry::HKEY_USERS\OSGuardChildPolicy") { $HiveMount = "OSGuardChildPolicy"; $HiveLoaded = $true }
            }
        }
    }

    if ($HiveMount) {
        $TaskMgr = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableTaskMgr" -ErrorAction SilentlyContinue
        $Regedit = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableRegistryTools" -ErrorAction SilentlyContinue
        $NoRun = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoRun" -ErrorAction SilentlyContinue
        $NoControlPanel = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoControlPanel" -ErrorAction SilentlyContinue
        $NoCtx = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoViewContextMenu" -ErrorAction SilentlyContinue
        $NoFolder = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoFolderOptions" -ErrorAction SilentlyContinue
        $NoTaskbar = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoSetTaskbar" -ErrorAction SilentlyContinue
        $NoAddPrinter = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoAddPrinter" -ErrorAction SilentlyContinue
        $NoDelPrinter = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoDeletePrinter" -ErrorAction SilentlyContinue
        $NoThemes = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoThemesTab" -ErrorAction SilentlyContinue
        $NoWallpaper = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoChangingWallPaper" -ErrorAction SilentlyContinue
        $NoAutoPlay = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        $NoAdminTools = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "StartMenuAdminTools" -ErrorAction SilentlyContinue
        $NoAddRemove = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Uninstall" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NoAddRemovePrograms" -ErrorAction SilentlyContinue
        $NoPassChange = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableChangePassword" -ErrorAction SilentlyContinue
        $NoNetUi = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NC_LanProperties" -ErrorAction SilentlyContinue
        $NoThisPC = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue

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
        $DisallowRun = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisallowRun" -ErrorAction SilentlyContinue
        $ChromeDisallowed = Get-ItemProperty -Path "Registry::HKEY_USERS\$HiveMount\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "51" -ErrorAction SilentlyContinue
        $Categories["Alt Browser Block"] = ($DisallowRun -eq 1 -and $ChromeDisallowed -eq "chrome.exe")

        if ($HiveLoaded) {
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); Start-Sleep -Milliseconds 300
            reg.exe unload "HKU\OSGuardChildPolicy" 2>&1 | Out-Null
        }
    } else {
        $Categories["Task Manager"] = $false
        $Categories["Registry Tools"] = $false
        $Categories["CMD / Run"] = $false
        $Categories["Control Panel"] = $false
        $Categories["Right-Click Menu"] = $false
        $Categories["Folder Options"] = $false
        $Categories["Taskbar"] = $false
        $Categories["Printers"] = $false
        $Categories["Wallpaper/Themes"] = $false
        $Categories["AutoPlay"] = $false
        $Categories["Admin Tools"] = $false
        $Categories["Add/Remove Prog"] = $false
        $Categories["Password Change"] = $false
        $Categories["Network UI"] = $false
        $Categories["This PC Hidden"] = $false
        $Categories["Alt Browser Block"] = $false
    }

    # --- Browser Lockdown (Edge-Only) ---
    $EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $EdgeGuest = Get-ItemProperty -Path $EdgePolicyPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "BrowserGuestModeEnabled" -ErrorAction SilentlyContinue
    $EdgeAddProfile = Get-ItemProperty -Path $EdgePolicyPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "BrowserAddProfileEnabled" -ErrorAction SilentlyContinue
    $Categories["Edge-Only Browser"] = ($EdgeGuest -eq 0 -and $EdgeAddProfile -eq 0)

    # --- Screen Time ---
    $ScreenTimeEnabled = $false
    $ScreenTimeTask = Get-ScheduledTask -TaskName $ScreenTimeTaskName -ErrorAction SilentlyContinue
    if (Test-Path $ScreenTimeConfigFile) {
        $STConfig = Get-ScreenTimeConfig
        if ($STConfig -and $STConfig.Enabled) { $ScreenTimeEnabled = $true }
    }
    $Categories["Screen Time"] = ($ScreenTimeEnabled -and $null -ne $ScreenTimeTask)

    # --- Program Guardian ---
    $ProgGuard = Get-ScheduledTask -TaskName $ProgramScannerName -ErrorAction SilentlyContinue
    $Categories["Program Guardian"] = ($null -ne $ProgGuard)

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
        try { $ExpectedHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}
        if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
        if ($ExpectedHash) {
            $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
            $IntegrityOk = ($ExpectedHash.Trim() -eq $ActualHash.Trim())
        }
    }
    $Categories["Integrity"] = $IntegrityOk

    # --- Script Tamper Lockout ---
    $TamperFlag = $false
    try { $TamperFlag = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction Stop) -eq 1 } catch {}
    $Categories["Script Tamper Lockout"] = $TamperFlag

    # --- Canary File ---
    $Categories["Canary File"] = (Test-Canary)

    # --- Task Scheduler (OS-Guard Tasks Installed) ---
    $Categories["Task Scheduler"] = ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue))

    # --- Firewall Rules ---
    $FwRules = $null
    try { $FwRules = netsh advfirewall firewall show rule name=all dir=out | Select-String "^Rule Name:\s+(OSGuard-BlockOutbound.*)" } catch {}
    $Categories["Firewall Rules"] = ($null -ne $FwRules -and $FwRules.Count -gt 0)

    # --- Geofencing (Stricter Lockdown Active) ---
    if ([string]::IsNullOrWhiteSpace($script:HomeSSID)) {
        $Categories["Geofencing"] = $false
    } else {
        $Categories["Geofencing"] = -not (Test-HomeNetwork)
    }

    # --- Parent Mode Active ---
    $ParentModeActive = $false
    try { $ParentModeActive = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction Stop) -eq 1 } catch {}
    $Categories["Parent Mode Active"] = $ParentModeActive

    # --- Child Logon Task ---
    $Categories["Child Logon Task"] = ($null -ne (Get-ScheduledTask -TaskName $ChildLogonTaskName -ErrorAction SilentlyContinue))

    # --- Parent Mode Watch ---
    $Categories["Parent Mode Watch"] = ($null -ne (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue))

    # --- WMI Subscription ---
    $WmiFilterExists = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiConsumerExists = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiBindingExists = Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue
    $Categories["WMI Subscription"] = ($null -ne $WmiFilterExists -and $null -ne $WmiConsumerExists -and $null -ne $WmiBindingExists)

    # --- Browser Launcher ---
    $Categories["Browser Launcher"] = (Test-Path $BrowserLauncherPath)

    # --- Requests Directory ---
    $Categories["Requests Dir"] = (Test-Path (Join-Path $InstallDir "Requests"))

    # --- Install Directory ---
    $Categories["Install Dir"] = (Test-Path $InstallDir)

    # --- PATH Entry ---
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $Categories["PATH Entry"] = ($CurrentPath -like "*$InstallDir*")

    # --- Edge URL Blocklist ---
    $EdgeUrlBlock = Test-Path (Join-Path $EdgePath "URLBlocklist")
    $Categories["Edge URL Block"] = $EdgeUrlBlock

    # --- Edge Extension Blocklist ---
    $EdgeExtBlock = Test-Path (Join-Path $EdgePath "ExtensionInstallBlocklist")
    $Categories["Edge Ext Block"] = $EdgeExtBlock

    # --- Chrome DoH ---
    $ChromeDoH = Get-ItemProperty -Path $ChromePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DnsOverHttpsMode" -ErrorAction SilentlyContinue
    $Categories["Chrome DoH"] = ($ChromeDoH -eq "off")

    # --- Firefox DoH ---
    $FirefoxDoH = Get-ItemProperty -Path $FirefoxPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Enabled" -ErrorAction SilentlyContinue
    $Categories["Firefox DoH"] = ($FirefoxDoH -eq 0)

    # --- Network Change GPO ---
    $NetChange = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NC_LanChangeProperties" -ErrorAction SilentlyContinue
    $Categories["Net Change GPO"] = ($NetChange -eq 0)

    # --- Advanced TCP/IP GPO ---
    $NetAdv = Get-ItemProperty -Path $GpoPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "NC_AllowAdvancedTCPIPConfig" -ErrorAction SilentlyContinue
    $Categories["Net Adv GPO"] = ($NetAdv -eq 0)

    # --- Disable Consumer Features ---
    $ConsumerFeat = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue
    $Categories["Consumer Features"] = ($ConsumerFeat -eq 1)

    # --- Disable Notification Center ---
    $NotifCenter = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DisableNotificationCenter" -ErrorAction SilentlyContinue
    $Categories["Notification Center"] = ($NotifCenter -eq 1)

    # --- Child Is Standard User ---
    $ChildIsAdmin = $false
    try { $ChildIsAdmin = ($null -ne (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.Name -match "$ChildUser$" })) } catch {}
    $Categories["Child Not Admin"] = (-not $ChildIsAdmin)

    # --- Password Change Disabled ---
    $ChildAcct = $null
    try { $ChildAcct = Get-LocalUser -Name $ChildUser -ErrorAction Stop } catch {}
    $Categories["Password Locked"] = ($ChildAcct -and $ChildAcct.PasswordChangeableDate -eq $null)

    # --- Edge Incognito ---
    $EdgeIncognito = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "InPrivateModeAvailability" -ErrorAction SilentlyContinue
    $Categories["Edge Incognito"] = ($EdgeIncognito -eq 1)

    # --- Edge DevTools ---
    $EdgeDevTools = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DeveloperToolsAvailability" -ErrorAction SilentlyContinue
    $Categories["Edge DevTools"] = ($EdgeDevTools -eq 2)

    # --- Edge Downloads ---
    $EdgeDownloads = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "DownloadRestrictions" -ErrorAction SilentlyContinue
    $Categories["Edge Downloads"] = ($EdgeDownloads -eq 3)

    # --- Edge Sync ---
    $EdgeSync = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "SyncDisabled" -ErrorAction SilentlyContinue
    $Categories["Edge Sync"] = ($EdgeSync -eq 1)

    # --- Edge SafeSearch ---
    $EdgeSafeSearch = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "ForceGoogleSafeSearch" -ErrorAction SilentlyContinue
    $Categories["Edge SafeSearch"] = ($EdgeSafeSearch -eq 1)

    # --- Edge Guest Mode ---
    $EdgeGuestMode = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "BrowserGuestModeEnabled" -ErrorAction SilentlyContinue
    $Categories["Edge Guest Mode"] = ($EdgeGuestMode -eq 0)

    # --- Edge Bookmark Bar ---
    $EdgeBookmark = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "BookmarkBarEnabled" -ErrorAction SilentlyContinue
    $Categories["Edge Bookmark Bar"] = ($EdgeBookmark -eq 0)

    # --- Edge Password Manager ---
    $EdgePassMgr = Get-ItemProperty -Path $EdgePath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "PasswordManagerEnabled" -ErrorAction SilentlyContinue
    $Categories["Edge Password Mgr"] = ($EdgePassMgr -eq 0)

    # Print two-column grid
    Write-Host "`n=====================================================" -ForegroundColor DarkGray
    Write-Host " CATEGORY STATUS GRID " -ForegroundColor White
    Write-Host "=====================================================" -ForegroundColor DarkGray
    $Keys = @($Categories.Keys)
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
            $RightColor = if ($RightVal -eq $true) { "Green" } elseif ($RightVal -eq $false) { "DarkGray" } else { "Yellow" }
            Write-Host "  $LeftStr" -NoNewline -ForegroundColor $LeftColor
            Write-Host ("{0,-22}  " -f $LeftKey) -NoNewline -ForegroundColor $LeftColor
            Write-Host "$RightStr" -NoNewline -ForegroundColor $RightColor
            Write-Host ("{0,-22}" -f $RightKey) -ForegroundColor $RightColor
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
    try { $ExpectedHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}
    if (-not $ExpectedHash -and (Test-Path $IntegrityFile)) { $ExpectedHash = Get-Content -Path $IntegrityFile -Raw }
    if (-not $ExpectedHash) { return $null }
    $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
    return ($ExpectedHash.Trim() -eq $ActualHash.Trim())
}

function Test-Canary {
    <#
        Checks for the presence and integrity of the canary file.
        If the canary file is missing or its hash does not match, tampering is detected.
    #>
    if (-not (Test-Path $CanaryFile)) { return $false }
    if (-not (Test-Path $CanaryHashFile)) { return $false }
    try {
        $ExpectedHash = (Get-Content -Path $CanaryHashFile -Raw -ErrorAction Stop).Trim()
        $ActualHash = (Get-FileHash -Path $CanaryFile -Algorithm SHA256).Hash
        return ($ExpectedHash -eq $ActualHash)
    } catch { return $false }
}

function Set-Canary {
    <#
        Creates a hidden canary file with random content and stores its hash.
    #>
    try {
        $RandomBytes = [byte[]]::new(64)
        $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $Rng.GetBytes($RandomBytes)
        $Rng.Dispose()
        [System.IO.File]::WriteAllBytes($CanaryFile, $RandomBytes)
        (Get-Item $CanaryFile).Attributes = 'Hidden'
        $CanaryHash = (Get-FileHash -Path $CanaryFile -Algorithm SHA256).Hash
        Set-Content -Path $CanaryHashFile -Value $CanaryHash -Encoding UTF8 -Force -ErrorAction Stop
        # Harden canary files so they can't be tampered with by child
        Harden-FileACL -FilePath $CanaryFile
        Harden-FileACL -FilePath $CanaryHashFile
        Write-Log -Message "Canary file created and hardened." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to create canary file: $_" -Type "WARN" -Color Yellow
    }
}

function Test-TaskSchedulerTamper {
    <#
        Detects if the Task Scheduler (Schedule) service has been tampered with (disabled).
        Returns $true if tampered, $false otherwise.
    #>
    try {
        $Svc = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Schedule" -Name "Start" -ErrorAction Stop
        if ($Svc.Start -eq 4) {
            Write-Log -Message "Task Scheduler service has been disabled (Start=4). Tamper detected!" -Type "SECURITY" -Color Red
            return $true
        }
    } catch {}
    return $false
}

function Test-TamperDetected {
    try {
        return (Get-ItemPropertyValue -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction Stop) -eq 1
    } catch { return $false }
}

function Set-TamperDetected {
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "Tamper detected flag SET in registry." -Type "SECURITY" -Color Red
    } catch {
        Write-Log -Message "Failed to set tamper detected flag: $_" -Type "ERROR" -Color Red
    }
}

function Clear-TamperDetected {
    try {
        Set-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "Tamper detected flag CLEARED." -Type "SUCCESS" -Color Green
    } catch {
        Write-Log -Message "Failed to clear tamper detected flag: $_" -Type "ERROR" -Color Red
    }
}

function Show-TamperLockoutScreen {
    <#
        Full-screen lockout that appears when tampering is detected.
        Kills explorer to hide the taskbar, shows a single always-on-top window
        with a red warning. Admin must enter the Parent Mode password to unlock.
        Also provides a button to view the last 50 log lines.
    #>
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

    # Hide taskbar / desktop by killing explorer for the current session only
    try {
        $CurrentSessionId = (Get-Process -Id $PID).SessionId
        $MyExplorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId }
        if ($MyExplorer) { Stop-Process -Id $MyExplorer.Id -Force -ErrorAction SilentlyContinue }
    } catch {}

    $script:TamperUnlockSuccess = $false

    $form = New-Object System.Windows.Forms.Form
    $form.WindowState = 'Maximized'
    $form.FormBorderStyle = 'None'
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::Black
    $form.StartPosition = 'CenterScreen'
    $form.KeyPreview = $true

    # Block Alt+F4 and Escape
    $form.Add_KeyDown({
        param($sender, $e)
        if ($e.Alt -and $e.KeyCode -eq [System.Windows.Forms.Keys]::F4) {
            $e.Handled = $true
            $e.SuppressKeyPress = $true
        }
        if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            $e.Handled = $true
            $e.SuppressKeyPress = $true
        }
    })

    # Prevent closing unless the correct password was entered
    $form.Add_FormClosing({
        if ($script:TamperUnlockSuccess -ne $true) {
            $_.Cancel = $true
        }
    })

    $label = New-Object System.Windows.Forms.Label
    $label.Text = "TAMPERING DETECTED`n`nADMIN REVIEW REQUIRED`n`n[$script:Branding] This system has been locked due to unauthorized modification.`nOnly an administrator can unlock this session."
    $label.ForeColor = [System.Drawing.Color]::Red
    $label.Font = New-Object System.Drawing.Font("Consolas", 24, [System.Drawing.FontStyle]::Bold)
    $label.AutoSize = $false
    $label.TextAlign = 'MiddleCenter'
    $label.Dock = 'Fill'
    $form.Controls.Add($label)

    $pwPanel = New-Object System.Windows.Forms.Panel
    $pwPanel.Dock = 'Bottom'
    $pwPanel.Height = 120
    $pwPanel.BackColor = [System.Drawing.Color]::DarkRed

    $pwLabel = New-Object System.Windows.Forms.Label
    $pwLabel.Text = "Admin Password:"
    $pwLabel.ForeColor = [System.Drawing.Color]::White
    $pwLabel.Font = New-Object System.Drawing.Font("Consolas", 16)
    $pwLabel.AutoSize = $true
    $pwLabel.Location = New-Object System.Drawing.Point(50, 30)

    $pwBox = New-Object System.Windows.Forms.TextBox
    $pwBox.PasswordChar = '*'
    $pwBox.Font = New-Object System.Drawing.Font("Consolas", 16)
    $pwBox.Width = 350
    $pwBox.Location = New-Object System.Drawing.Point(300, 28)

    $unlockBtn = New-Object System.Windows.Forms.Button
    $unlockBtn.Text = "UNLOCK"
    $unlockBtn.Font = New-Object System.Drawing.Font("Consolas", 16, [System.Drawing.FontStyle]::Bold)
    $unlockBtn.BackColor = [System.Drawing.Color]::Black
    $unlockBtn.ForeColor = [System.Drawing.Color]::Red
    $unlockBtn.Size = New-Object System.Drawing.Size(150, 40)
    $unlockBtn.Location = New-Object System.Drawing.Point(680, 25)
    $unlockBtn.Add_Click({
        $pw = $pwBox.Text
        $StoredHash = $null
        $StoredSalt = $null
        # Child session cannot read the hardened registry key, so read from the hardened hash file instead
        $HashFile = Join-Path $InstallDir "parent.hash"
        if (Test-Path $HashFile) {
        $Content = Get-Content -Path $HashFile -Raw -ErrorAction SilentlyContinue
            if ($Content) {
                $Parts = $Content.Trim() -split '\|'
                if ($Parts.Count -ge 2) { $StoredHash = $Parts[0]; $StoredSalt = $Parts[1] }
                if ($Parts.Count -ge 3) { $StoredIterations = [int]$Parts[2] } else { $StoredIterations = 100000 }
            }
        }
        # Fallback to registry if file is missing (admin session)
        if (-not $StoredHash -or -not $StoredSalt) {
            try { $StoredHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -ErrorAction Stop) } catch {}
            try { $StoredSalt = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentPasswordSalt" -ErrorAction Stop) } catch {}
            try { $StoredIterations = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardParentPasswordIterations" -ErrorAction Stop) } catch {}
        }
        if ($StoredHash -and $StoredSalt) {
            # Inline PBKDF2 for the lockout screen (self-contained)
            $SaltBytes = [Convert]::FromBase64String($StoredSalt)
            $Derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($pw, $SaltBytes, $StoredIterations)
            $HashBytes = $Derive.GetBytes(32)
            $Derive.Dispose()
            $InputHash = [Convert]::ToBase64String($HashBytes)
            if ($InputHash -eq $StoredHash) {
                Clear-TamperDetected
                # Clean up the scheduled task that triggered this lockout
                if (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName "OSGuard-TamperLockout" -Confirm:$false | Out-Null
                }
                [System.Windows.Forms.MessageBox]::Show("Tamper lockout cleared. Restarting Windows UI...", "Unlocked", "OK", "Information") | Out-Null
                try {
                    $CurrentSessionId = (Get-Process -Id $PID).SessionId
                    $MyExplorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId }
                    if ($MyExplorer) { Stop-Process -Id $MyExplorer.Id -Force -ErrorAction SilentlyContinue }
                } catch {}
                Start-Sleep -Seconds 1
                Start-Process "explorer" -ErrorAction SilentlyContinue
                $script:TamperUnlockSuccess = $true
                $form.Close()
            } else {
                [System.Windows.Forms.MessageBox]::Show("Incorrect password. Tamper lockout remains active.", "Access Denied", "OK", "Error") | Out-Null
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("No admin password configured. Unlock from admin account using 'oslock -ParentMode'.", "Access Denied", "OK", "Error") | Out-Null
        }
    })

    $logsBtn = New-Object System.Windows.Forms.Button
    $logsBtn.Text = "VIEW LOGS"
    $logsBtn.Font = New-Object System.Drawing.Font("Consolas", 16)
    $logsBtn.BackColor = [System.Drawing.Color]::Black
    $logsBtn.ForeColor = [System.Drawing.Color]::White
    $logsBtn.Size = New-Object System.Drawing.Size(150, 40)
    $logsBtn.Location = New-Object System.Drawing.Point(850, 25)
    $logsBtn.Add_Click({
        if (Test-Path $LogFile) {
            $logs = Get-Content -Path $LogFile -Tail 50 -Raw
            [System.Windows.Forms.MessageBox]::Show($logs, "OS-Guard Logs (Last 50 Lines)", "OK", "Information") | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show("No log file found at $LogFile", "Logs", "OK", "Warning") | Out-Null
        }
    })

    $pwPanel.Controls.Add($pwLabel)
    $pwPanel.Controls.Add($pwBox)
    $pwPanel.Controls.Add($unlockBtn)
    $pwPanel.Controls.Add($logsBtn)
    $form.Controls.Add($pwPanel)

    $form.Add_Shown({ $form.Activate(); $form.TopMost = $true })

    [void]$form.ShowDialog()

    # Clean up the temporary scheduled task that triggered this lockout
    if (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName "OSGuard-TamperLockout" -Confirm:$false | Out-Null
    }

    # SAFE LOCK FALLBACK: If the form closed without a successful unlock,
    # forcibly re-lock the system to prevent a child from exploiting an accidental close.
    if ($script:TamperUnlockSuccess -ne $true) {
        Write-Log -Message "Tamper lockout screen closed without unlock. Initiating safe re-lock..." -Type "SECURITY" -Color Red
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
        } catch {}
        try { Stop-WindowGuard } catch {}
        try { Enable-OSLock } catch {}
        try { Enable-DNSLock } catch {}
        try {
            $CurrentSessionId = (Get-Process -Id $PID).SessionId
            $MyExplorer = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq $CurrentSessionId }
            if ($MyExplorer) { Stop-Process -Id $MyExplorer.Id -Force -ErrorAction SilentlyContinue }
        } catch {}
        Start-Sleep -Seconds 1
    }

    # Ensure explorer is running (restarted after unlock or after safe re-lock)
    Start-Process "explorer" -ErrorAction SilentlyContinue
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

    # 4.3 Program Guardian: scans and hardens newly installed programs every 10 minutes
    Install-ProgramGuardian

    # 4.4 WMI Event Subscription: Third hidden persistence layer
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

    # 6.0 Child Logon Task: Applies HKCU policies in the child's own session at logon.
    # Runs as the child user (no elevation) so it writes to the live HKCU hive.
    # NOTE: Moved here so the child account is created by Enable-OSLock before we register the task.
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
        Write-Log -Message "Child account not available after Enable-OSLock - child logon task will be created on next silent heal." -Type "WARN" -Color Yellow
    }

    # 6.1 Initialize ScreenTime config and watcher if not already present
    if (-not (Test-Path $ScreenTimeConfigFile)) {
        Set-ScreenTimeConfig -DailyStart "08:00" -DailyEnd "20:00" -DailyMaxMinutes 120 -BrowserMaxMinutes 60 -WeekendDailyMaxMinutes 180 -WeekendBrowserMaxMinutes 90 -Enabled $true
    }
    Install-ScreenTimeWatcher

    # 7. Set default Parent Mode password and create requests directory
    Write-Log -Message "Setting default Parent Mode password and creating requests directory..." -Type "INFO" -Color Yellow
    $DefaultPw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ })
    Write-Host "`n[IMPORTANT] Your default Parent Mode password is: $DefaultPw" -ForegroundColor Yellow
    Write-Host "            Please write it down. You will need it to enter Parent Mode and approve installations." -ForegroundColor Yellow
    $SaltStr = Get-PBKDF2Salt
    $HashStr = New-PBKDF2Hash -Password $DefaultPw -SaltBase64 $SaltStr -Iterations 100000
    try {
        if (-not (Test-Path $IntegrityRegPath)) { New-Item -Path $IntegrityRegPath -Force | Out-Null }
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordHash" -Value $HashStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordSalt" -Value $SaltStr -Type String -Force -ErrorAction Stop
        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordIterations" -Value 100000 -Type DWord -Force -ErrorAction Stop
        Write-Log -Message "Default Parent Mode password set (change it with 'oslock -SetParentPassword')." -Type "INFO" -Color Gray
    } catch {
        Write-Log -Message "Failed to set default Parent Mode password: $_" -Type "WARN" -Color Yellow
    }

    # 7.1 Create Canary file for tamper detection
    Write-Log -Message "Creating canary file for tamper detection..." -Type "INFO" -Color Yellow
    Set-Canary
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
        # Child user: WriteData only (can create request files, cannot read/list/delete)
        $ChildSidValue = Get-ChildSid
        if ($ChildSidValue) {
            $ChildSidObj = New-Object System.Security.Principal.SecurityIdentifier($ChildSidValue)
            $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "WriteData, AppendData", "ContainerInherit,ObjectInherit", "None", "Allow")))
            $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "Delete", "ContainerInherit,ObjectInherit", "None", "Deny")))
            $RequestsDirAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($ChildSidObj, "DeleteSubdirectoriesAndFiles", "ContainerInherit,ObjectInherit", "None", "Deny")))
        }
        Set-Acl -Path $RequestDir -AclObject $RequestsDirAcl -ErrorAction Stop
    } catch {
        Write-Log -Message "Failed to harden Requests directory ACL: $_" -Type "WARN" -Color Yellow
    }

    # 8. Register Parent Mode AFK Watcher (1-minute dead man's switch)
    Write-Log -Message "Registering Parent Mode AFK watcher (1-minute heartbeat) ..." -Type "INFO" -Color Yellow
    $WatchScriptPath = Join-Path $InstallDir "ParentModeWatch.ps1"
    try {
        $WatchScriptContent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ParentModeWatchB64))
        Set-Content -Path $WatchScriptPath -Value $WatchScriptContent -Encoding UTF8 -Force
        $WatchAcl = Get-Acl -Path $WatchScriptPath
        $WatchAcl.SetOwner($SidSystem)
        $WatchAcl.SetAccessRuleProtection($true, $false)
        $WatchAcl.Access | ForEach-Object { $WatchAcl.RemoveAccessRule($_) | Out-Null }
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $WatchScriptPath -AclObject $WatchAcl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write ParentModeWatch script: $_" -Type "WARN" -Color Yellow
    }
    $WatchAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WatchScriptPath`""
    $WatchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
    $WatchPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $ParentModeWatchName -Action $WatchAction -Trigger $WatchTrigger -Principal $WatchPrincipal -Force | Out-Null
    Write-Log -Message "Parent Mode AFK watcher registered (1-minute heartbeat, 1-minute idle timeout)." -Type "INFO" -Color Gray

    # 8.1 Create Temp Unlock Timer script
    New-TempUnlockTimerScript

    # --- NTFS PAYLOAD SELF-DEFENSE (runs after all files are written) ---
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
    if (-not (Test-Path (Join-Path $AdminDesktop "Approve Child Install.lnk"))) { $FailedCount++; Write-Log -Message "Approve Child Install shortcut not found on admin desktop." -Type "ERROR" -Color Red }
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
        Remove-Item -Path $ResultFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $TempScript -Force -ErrorAction SilentlyContinue
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

    # Stop any running Window Guard process
    Stop-WindowGuard
    Stop-TempUnlockTimer

    # Unlock everything FIRST (DNS + OS)
    Disable-DNSLock
    Disable-OSLock
    # Remove child-facing shortcuts and admin tools (Disable-OSLock already handles most of these)
    Remove-ChildGameRequestShortcut
    Remove-ParentModeShortcut
    Remove-ParentModeAdminTools

    # Remove ScreenTime files
    foreach ($STFile in @($ScreenTimeConfigFile, $ScreenTimeTrackerFile, $BrowserLauncherPath)) {
        if (Test-Path $STFile) { Remove-Item -Path $STFile -Force -ErrorAction SilentlyContinue }
    }

    # Remove Canary files
    foreach ($CFile in @($CanaryFile, $CanaryHashFile)) {
        if (Test-Path $CFile) { Remove-Item -Path $CFile -Force -ErrorAction SilentlyContinue }
    }

    # Remove firewall rules
    Write-Log -Message "Removing OS-Guard firewall rules..." -Type "INFO" -Color Gray
    try {
        $FwRules = netsh advfirewall firewall show rule name=all dir=out | Select-String "^Rule Name:\s+(OSGuard-BlockOutbound.*)" | ForEach-Object { ($_ -split "\s+", 3)[2].Trim() }
        foreach ($Rule in $FwRules) {
            try { netsh advfirewall firewall delete rule name="$Rule" | Out-Null } catch {}
        }
    } catch { Write-Log -Message "Failed to remove firewall rules: $_" -Type "WARN" -Color Yellow }

    # Remove the Scheduled Tasks (including guardians, child logon, parent mode watch, program scanner, screen time, tamper lockout, and install re-harden)
    foreach ($TName in @($TaskName, $Guardian1Name, $Guardian2Name, $ChildLogonTaskName, $ParentModeWatchName, $ProgramScannerName, $ScreenTimeTaskName, "OSGuard-TamperLockout", "OSGuard-ApproveInstallReharden")) {
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
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordSalt" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentPasswordIterations" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeTimestamp" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $IntegrityRegPath -Name $TamperDetectedRegName -ErrorAction SilentlyContinue
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
    if (Get-ScheduledTask -TaskName $ProgramScannerName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $ProgramScannerName still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName $ScreenTimeTaskName -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task $ScreenTimeTaskName still exists." -Type "ERROR" -Color Red }
    if (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue) { $FailedCount++; Write-Log -Message "Task OSGuard-TamperLockout still exists." -Type "ERROR" -Color Red }
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
    # If tamper lockout is active, show the lockout screen instead of normal policies
    if (Test-TamperDetected) {
        Show-TamperLockoutScreen
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

    # --- Canary check (catches deletion before script hash check) ---
    if (-not (Test-Canary)) {
        Write-Log -Message "CANARY FAILURE: Canary file missing or tampered! Tamper lockout activated." -Type "SECURITY" -Color Red
        Set-TamperDetected
        $HashCheckPassed = $false
    }

    # --- Task Scheduler tamper check ---
    if (Test-TaskSchedulerTamper) {
        Set-TamperDetected
        $HashCheckPassed = $false
    }

    # Primary check: registry stored hash
    $ExpectedHash = $null
    try { $ExpectedHash = (Get-ItemPropertyValue -Path $IntegrityRegPath -Name "OSGuardIntegrity" -ErrorAction Stop) } catch {}

    if ($ExpectedHash) {
        $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: Registry hash mismatch! Tamper lockout activated." -Type "SECURITY" -Color Red
            Set-TamperDetected
            # Trigger immediate lockout if child is currently logged in
            $ChildSession = $null
            try { $ChildSession = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match "Name=`"$ChildUser`"" } | Select-Object -First 1 } catch {}
            if ($ChildSession -and -not (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue)) {
                Write-Log -Message "Child session detected. Scheduling immediate tamper lockout..." -Type "SECURITY" -Color Red
                try {
                    $TamperAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -TamperLockout"
                    $TamperTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
                    $TamperPrincipal = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive
                    Register-ScheduledTask -TaskName "OSGuard-TamperLockout" -Action $TamperAction -Trigger $TamperTrigger -Principal $TamperPrincipal -Force | Out-Null
                    Start-ScheduledTask -TaskName "OSGuard-TamperLockout"
                } catch {
                    Write-Log -Message "Failed to schedule immediate tamper lockout: $_" -Type "WARN" -Color Yellow
                }
            }
            $HashCheckPassed = $false
        }
    } elseif (Test-Path $IntegrityFile) {
        $ExpectedHash = Get-Content -Path $IntegrityFile -Raw
        $ActualHash = (Get-FileHash -Path $InstallScript -Algorithm SHA256).Hash
        if ($ExpectedHash.Trim() -ne $ActualHash.Trim()) {
            Write-Log -Message "INTEGRITY FAILURE: File hash mismatch! Tamper lockout activated." -Type "SECURITY" -Color Red
            Set-TamperDetected
            $ChildSession = $null
            try { $ChildSession = Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | Where-Object { $_.Antecedent -match "Name=`"$ChildUser`"" } | Select-Object -First 1 } catch {}
            if ($ChildSession -and -not (Get-ScheduledTask -TaskName "OSGuard-TamperLockout" -ErrorAction SilentlyContinue)) {
                Write-Log -Message "Child session detected. Scheduling immediate tamper lockout..." -Type "SECURITY" -Color Red
                try {
                    $TamperAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -TamperLockout"
                    $TamperTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
                    $TamperPrincipal = New-ScheduledTaskPrincipal -UserId $ChildUser -LogonType Interactive
                    Register-ScheduledTask -TaskName "OSGuard-TamperLockout" -Action $TamperAction -Trigger $TamperTrigger -Principal $TamperPrincipal -Force | Out-Null
                    Start-ScheduledTask -TaskName "OSGuard-TamperLockout"
                } catch {
                    Write-Log -Message "Failed to schedule immediate tamper lockout: $_" -Type "WARN" -Color Yellow
                }
            }
            $HashCheckPassed = $false
        }
    }

    # Geofence: enforce stricter lockdown if not on home network
    Invoke-GeofenceLockdown

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

    # Re-write ParentModeWatch script from embedded Base64 (fresh every heal) and re-register task if missing
    $WatchScriptPath = Join-Path $InstallDir "ParentModeWatch.ps1"
    try {
        $WatchScriptContent = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ParentModeWatchB64))
        Set-Content -Path $WatchScriptPath -Value $WatchScriptContent -Encoding UTF8 -Force
        $WatchAcl = Get-Acl -Path $WatchScriptPath
        $WatchAcl.SetOwner($SidSystem)
        $WatchAcl.SetAccessRuleProtection($true, $false)
        $WatchAcl.Access | ForEach-Object { $WatchAcl.RemoveAccessRule($_) | Out-Null }
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidSystem, "FullControl", "None", "None", "Allow")))
        $WatchAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidAdmin, "ReadAndExecute", "None", "None", "Allow")))
        Set-Acl -Path $WatchScriptPath -AclObject $WatchAcl -ErrorAction SilentlyContinue
    } catch {
        Write-Log -Message "Failed to write ParentModeWatch script during silent heal: $_" -Type "WARN" -Color Yellow
    }
    if (-not (Get-ScheduledTask -TaskName $ParentModeWatchName -ErrorAction SilentlyContinue)) {
        try {
            $WatchAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WatchScriptPath`""
            $WatchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
            $WatchPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $ParentModeWatchName -Action $WatchAction -Trigger $WatchTrigger -Principal $WatchPrincipal -Force | Out-Null
        } catch {}
    }

    # Re-apply Program Guardian task if missing
    if (-not (Get-ScheduledTask -TaskName $ProgramScannerName -ErrorAction SilentlyContinue)) {
        try {
            Install-ProgramGuardian
        } catch {
            Write-Log -Message "Failed to re-register Program Guardian task during silent heal: $_" -Type "WARN" -Color Yellow
        }
    }

    # Re-apply ScreenTime watcher if missing
    if (-not (Get-ScheduledTask -TaskName $ScreenTimeTaskName -ErrorAction SilentlyContinue)) {
        try {
            Install-ScreenTimeWatcher
        } catch {
            Write-Log -Message "Failed to re-register ScreenTime watcher during silent heal: $_" -Type "WARN" -Color Yellow
        }
    }

    # Enforce ScreenTime limits immediately during silent heal
    Invoke-ScreenTimeEnforcement

    # Program Guardian: scan and harden any newly installed programs
    Scan-And-Harden-ChildPrograms

    # Check WMI subscription health and re-register if missing or corrupted
    $WmiFilterExists = Get-WmiObject -Class __EventFilter -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiConsumerExists = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" -Filter "Name='$WmiEventName'" -ErrorAction SilentlyContinue
    $WmiBindingExists = Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" -Filter "__PATH LIKE '%$WmiEventName%'" -ErrorAction SilentlyContinue
    if (-not $WmiFilterExists -or -not $WmiConsumerExists -or -not $WmiBindingExists) {
        Write-Log -Message "WMI subscription missing or corrupted during silent heal. Re-registering..." -Type "SECURITY" -Color Red
        try {
            $WmiQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 600 WHERE TargetInstance ISA 'Win32_Service' AND TargetInstance.Name = 'Schedule'"
            $WmiConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; CommandLineTemplate="powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$InstallScript`" -SilentLock"; RunInteractively=$false} -ErrorAction Stop
            $WmiFilter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{Name=$WmiEventName; EventNamespace="root\cimv2"; QueryLanguage="WQL"; Query=$WmiQuery} -ErrorAction Stop
            Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$WmiFilter; Consumer=$WmiConsumer} -ErrorAction Stop | Out-Null
            Write-Log -Message "WMI subscription re-registered successfully." -Type "SUCCESS" -Color Green
        } catch {
            Write-Log -Message "Failed to re-register WMI subscription during silent heal: $_" -Type "WARN" -Color Yellow
        }
    }

    # Check Task Scheduler service and auto-start if stopped
    $ScheduleService = Get-Service -Name "Schedule" -ErrorAction SilentlyContinue
    if ($ScheduleService -and $ScheduleService.Status -ne "Running") {
        Write-Log -Message "Task Scheduler service is stopped! Starting it..." -Type "SECURITY" -Color Red
        try {
            Start-Service -Name "Schedule" -ErrorAction Stop
            Write-Log -Message "Task Scheduler service started." -Type "SUCCESS" -Color Green
        } catch {
            Write-Log -Message "Failed to start Task Scheduler service: $_" -Type "ERROR" -Color Red
        }
    }

    # Only clear Parent Mode and re-apply locks if Parent Mode is NOT active
    $ParentModeActive = $false
    try { $ParentModeActive = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardParentModeActive" -ErrorAction SilentlyContinue -eq 1 } catch {}
    $TempUnlockActive = $false
    try { $TempUnlockActive = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue -eq 1 } catch {}
    if (-not $ParentModeActive -and -not $TempUnlockActive) {
        try {
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardParentModeActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        } catch {}

        Enable-DNSLock
        Enable-OSLock
    }
    return
}

function New-TempUnlockTimerScript {
    $TimerContent = @'
# TempUnlockTimer.ps1 - Live countdown for OS-Guard Temporary Unlock
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WpnPlatform\Settings"
$InstallDir = "C:\ProgramData\OSGuard"
$PidFile = Join-Path $InstallDir "TempUnlockTimer.pid"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "OS-Guard Temp Unlock Timer"
$form.Size = New-Object System.Drawing.Size(420, 160)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$label = New-Object System.Windows.Forms.Label
$label.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$label.TextAlign = "MiddleCenter"
$label.Dock = "Fill"
$form.Controls.Add($label)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000

$timer.Add_Tick({
    $TempActive = 0
    try { $TempActive = Get-ItemPropertyValue -Path $RegPath -Name "OSGuardTempUnlockActive" -ErrorAction Stop } catch { $TempActive = 0 }
    if ($TempActive -ne 1) {
        $timer.Stop()
        $form.Close()
        return
    }
    $TimestampStr = $null
    try { $TimestampStr = Get-ItemPropertyValue -Path $RegPath -Name "OSGuardTempUnlockTimestamp" -ErrorAction Stop } catch { $TimestampStr = $null }
    $Elapsed = [timespan]::Zero
    if ($TimestampStr) {
        try { $Elapsed = (Get-Date) - [datetime]::Parse($TimestampStr) } catch { $Elapsed = [timespan]::Zero }
    }
    $Remaining = [timespan]::FromMinutes(1) - $Elapsed
    if ($Remaining.TotalSeconds -le 0) {
        $label.Text = "LOCKING NOW..."
        $timer.Stop()
        Start-Sleep -Milliseconds 500
        & "C:\Windows\oslock.cmd" -LockNow
        $form.Close()
    } else {
        $label.Text = ("Temp Unlock: {0:mm\:ss}" -f $Remaining)
    }
})

$form.Add_FormClosing({
    $timer.Stop()
    $TempActive = 0
    try { $TempActive = Get-ItemPropertyValue -Path $RegPath -Name "OSGuardTempUnlockActive" -ErrorAction Stop } catch { $TempActive = 0 }
    if ($TempActive -eq 1) {
        & "C:\Windows\oslock.cmd" -LockNow
    }
    if (Test-Path $PidFile) { Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue }
})

$form.Add_Shown({
    $PID | Out-File -FilePath $PidFile -Encoding UTF8 -Force
    $timer.Start()
})

[void][System.Windows.Forms.Application]::EnableVisualStyles()
[void]$form.ShowDialog()
'@
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
    Set-Content -Path $TempUnlockTimerPath -Value $TimerContent -Encoding UTF8 -Force
}

function Start-TempUnlockTimer {
    if (-not (Test-Path $TempUnlockTimerPath)) {
        New-TempUnlockTimerScript
    }
    Stop-TempUnlockTimer
    try {
        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force -ErrorAction SilentlyContinue | Out-Null }
        $Process = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$TempUnlockTimerPath`"" -WindowStyle Normal -PassThru
        $Process.Id | Out-File -FilePath $TempUnlockTimerPidFile -Encoding UTF8 -Force
    } catch {
        Write-Log -Message "Failed to start temp unlock timer: $_" -Type "WARN" -Color Yellow
    }
}

function Stop-TempUnlockTimer {
    if (Test-Path $TempUnlockTimerPidFile) {
        try {
            $PidValue = Get-Content -Path $TempUnlockTimerPidFile -Raw -ErrorAction Stop
            $TimerPid = [int]$PidValue
            if ($TimerPid -gt 0) {
                Stop-Process -Id $TimerPid -Force -ErrorAction SilentlyContinue
            }
        } catch {}
        Remove-Item -Path $TempUnlockTimerPidFile -Force -ErrorAction SilentlyContinue
    }
    try {
        Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq "OS-Guard Temp Unlock Timer" } | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {}
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
if ($TamperLockout) { Show-TamperLockoutScreen; return }
if ($ProgramScan) { Scan-And-Harden-ChildPrograms; return }
if ($SetScreenTime) { Show-SetScreenTimeDialog; return }
if ($ScreenTimeStatus) { Show-ScreenTimeStatus; return }
if ($GrantBrowserTime) { Show-GrantBrowserTimeDialog; return }
if ($ScreenTimeEnforce) { Invoke-ScreenTimeEnforcement; return }
if ($ApproveChildInstall) { Approve-ChildInstall; return }
if ($RehardenChildInstall) { Invoke-ChildInstallReharden; return }
if ($HealthCheck) { Show-HealthCheck; return }
if ($WhatIf) { $script:WhatIfPreference = $true; Install-Persistence; return }
if ($ExportReport) { Export-OSGuardReport; return }
if ($FirstRun) { Show-SetupWizard; return }
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

    $TempUnlockActive = $false
    try { $TempUnlockActive = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardTempUnlockActive" -ErrorAction SilentlyContinue -eq 1 } catch {}

    Write-Host "`n-----------------------------------------------------"
    if ($TempUnlockActive) {
        $TempUnlockTimestamp = $null
        try { $TempUnlockTimestamp = Get-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "OSGuardTempUnlockTimestamp" -ErrorAction SilentlyContinue } catch {}
        $Elapsed = [timespan]::Zero
        if ($TempUnlockTimestamp) {
            try { $Elapsed = (Get-Date) - [datetime]::Parse($TempUnlockTimestamp) } catch {}
        }
        $Remaining = [timespan]::FromMinutes(1) - $Elapsed
        if ($Remaining.TotalSeconds -lt 0) { $Remaining = [timespan]::Zero }
        $CountdownStr = "{0:mm\:ss}" -f $Remaining
        Write-Host ">>> TEMP UNLOCK ACTIVE - Countdown: $CountdownStr remaining (auto-locks after 1 min idle) <<<" -ForegroundColor Yellow -BackgroundColor Black
    }
    Write-Host "[1] DEPLOY ALL LOCKS (DNS + OS Child Lockdown)" -ForegroundColor Cyan
    if ($TempUnlockActive) {
        Write-Host "[2] RE-LOCK SYSTEM (End Temporary Unlock)" -ForegroundColor Cyan
    } else {
        Write-Host "[2] TEMPORARY UNLOCK (Restore Access)" -ForegroundColor Yellow
    }
    if (-not (Test-Path $InstallDir)) {
        Write-Host "[3] INSTALL SERVICE (Auto-Heal & Create 'oslock' command)" -ForegroundColor Green
    }
    Write-Host "[4] UNINSTALL SERVICE (Remove background tasks & Unlock)" -ForegroundColor Red
    Write-Host "[5] REFRESH SYSTEM STATUS" -ForegroundColor Gray
    Write-Host "[6] EXIT TERMINAL" -ForegroundColor Gray
    Write-Host "[7] ENTER PARENT MODE (Unlock with password)" -ForegroundColor Green
    Write-Host "[8] LOCK NOW (Re-lock immediately)" -ForegroundColor Cyan
    Write-Host "[9] SET SCREEN TIME" -ForegroundColor Cyan
    Write-Host "[10] SCREEN TIME STATUS" -ForegroundColor Cyan
    Write-Host "[11] GRANT BROWSER TIME" -ForegroundColor Cyan
    Write-Host "[14] SET PARENT MODE PASSWORD" -ForegroundColor Green
    Write-Host "[15] APPROVE CHILD INSTALL (15-min window)" -ForegroundColor Green
    Write-Host "[16] FIRST RUN WIZARD" -ForegroundColor Green
    Write-Host "[17] EXPORT REPORT (CSV)" -ForegroundColor Green
    Write-Host "[18] HEALTH CHECK (DRIFT AUDIT)" -ForegroundColor Green
    Write-Host "-----------------------------------------------------"

    $Choice = Read-Host "Select an administrative action (1-18)"
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
                if ($TempUnlockActive) {
                    # Re-lock system
                    try {
                        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockActive" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $IntegrityRegPath -Name "OSGuardTempUnlockTimestamp" -Value "" -Type String -Force -ErrorAction SilentlyContinue
                    } catch {}
                    Stop-TempUnlockTimer
                    Enable-DNSLock
                    Enable-OSLock
                    Write-Host "`n[LOCKED] System re-locked. Temporary unlock ended." -ForegroundColor Green
                } else {
                    Disable-DNSLock
                    Disable-OSLock -KeepChildAccount -SetTempUnlockFlag
                    Start-TempUnlockTimer
                    Write-Host "`n[UNLOCKED] Temporary admin unlock active. Guardians suppressed." -ForegroundColor Yellow
                    Write-Host "  Press [2] again to re-lock, or use [8] LOCK NOW." -ForegroundColor Yellow
                    Write-Host "  Auto-locks after 1 minute of inactivity." -ForegroundColor Yellow
                }
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
        "9" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [9] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-SetScreenTimeDialog
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "10" {
            Show-ScreenTimeStatus
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "11" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [11] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-GrantBrowserTimeDialog
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "12" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [12] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Set-ParentPassword
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "13" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [13] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Approve-ChildInstall
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "16" {
            if ($IntegrityStatus -eq $false) {
                Write-Host "`n[BLOCKED] Option [16] is disabled because the script has been tampered with." -ForegroundColor Red -BackgroundColor Black
                Write-Host "Use option [4] to uninstall, then reinstall from a clean source." -ForegroundColor Yellow
            } else {
                Show-SetupWizard
            }
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "17" {
            Export-OSGuardReport
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "18" {
            Show-HealthCheck
            Write-Host "`n[ PRESS ANY KEY TO RETURN TO MENU ]" -ForegroundColor DarkGray; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        default { Write-Warning "Invalid Selection."; Start-Sleep -Seconds 1 }
    }
} while ($Choice -ne "6")
