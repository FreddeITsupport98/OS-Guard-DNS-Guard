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

## 2026-06-29T04:11:00Z

- Initial release: DNS Hijack Protection Suite with registry ACL locks, browser DoH block, auto-healing scheduled tasks, and NTFS self-defense.
