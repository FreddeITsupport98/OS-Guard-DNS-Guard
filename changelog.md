# Changelog

All notable changes to this project are documented in this file. Dates are in ISO 8601 format (UTC).

## [Unreleased]

- OS Child Lockdown: auto-creates passwordless `Child` standard user account, enforces strict machine-wide and per-user policies (TaskMgr, Regedit, CMD, Run, Control Panel, Windows Store, UAC max, etc.).
- Global CLI renamed from `dnslock` to `oslock`.
- Install directory moved from `C:\ProgramData\DNSGuard` to `C:\ProgramData\OSGuard`.
- Task names renamed from `DNS-Hijack-Guard` to `OS-Guard-Protection` and associated guardians.
- Added `ChildLogon` scheduled task that applies HKCU restrictions directly in the child's session at every logon.
- Added `Mount-ChildHive` / `Dismount-ChildHive` helper functions to load and edit the child's `NTUSER.DAT` offline.
- `New-LocalUser -NoPassword` used for passwordless child account creation with `net user /passwordchg:no /passwordreq:no` hardening.
- Added `Enable-OSLock` and `Disable-OSLock` functions alongside preserved `Enable-DNSLock` / `Disable-DNSLock`.
- Interactive menu now shows DNS status, OS child lockdown status, and installation integrity in a single unified dashboard.
- WMI event subscription renamed to `OSGuardWmiHealth`.
- Integrity hash registry key renamed from `PushConfigBackoffInterval` to `OSGuardIntegrity`.
- Added regression test suite in `tests/` folder with `syntax_check.ps1` and `test_os_lockdown.ps1`.
- **Stricter OS Lockdown** (2026-06-30T04:12:00Z): Windows Installer blocked (`DisableMSI=2`), USB storage disabled (`USBSTOR Start=4`), Windows Script Host disabled (`Enabled=0`), SmartScreen enforced (`Block` level), Fast User Switching disabled, Windows Update UI blocked for standard users, right-click context menu disabled, Folder Options hidden, taskbar changes blocked, printer add/remove blocked, and "This PC" hidden from desktop/start menu.
- **Admin-Approval Logout Shortcut** placed on the child's desktop. Clicking it triggers a UAC elevation prompt; the child cannot log out without an administrator entering credentials.
|- **Interactive TUI Category Status Grid** added: a compact two-column grid shows all 25+ lock categories (DNS, UAC, Store, Installer, USB, WSH, SmartScreen, Fast User Switching, Windows Update, Child Account, Task Manager, Registry Tools, CMD/Run, Control Panel, Wallpaper/Themes, AutoPlay, Admin Tools, Add/Remove Programs, Network UI, Password Change, Right-Click, Folder Options, Taskbar, Printers, This PC, Logout Shortcut, Background Service, Integrity) with [ENABLED] / [DISABLED] / [UNKNOWN] indicators so you can see every enabled and disabled category at a glance.
|- **Parent Mode, Game Request, AFK Timer & Shortcut Guardian** (2026-06-30T04:39:00Z): Parent Mode allows temporary password-protected admin unlock for installing software or viewing the child account. Three admin desktop shortcuts (`Parent Mode`, `Lock Now`, `Continue Parent Mode`) are created and guarded by the auto-heal system. Child has a `Request Game Install` shortcut that opens a simple game request dialog. A 1-minute AFK watcher (`OSGuard-ParentModeWatch`) monitors idle time and auto-triggers `oslock -LockNow` after 5 minutes of inactivity. Menu options `[7]` and `[8]` added. Default Parent Mode password is `admin123` (change via `oslock -SetParentPassword`). `Requests` directory created at `C:\ProgramData\OSGuard\Requests` with hardened ACLs.

## 2026-06-29T04:11:00Z

- Initial release: DNS Hijack Protection Suite with registry ACL locks, browser DoH block, auto-healing scheduled tasks, and NTFS self-defense.
