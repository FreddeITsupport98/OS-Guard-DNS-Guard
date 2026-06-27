# dnshijack-protection

# Multi-Layer DNS Vault & UI Lockdown Script

A robust, enterprise-grade PowerShell security tool designed to permanently lock down endpoint DNS configurations. By combining Group Policy Object (GPO) registry overrides with a hyper-targeted Access Control List (ACL) security descriptor, this script physically bars users, administrative accounts, and third-party software from tampering with upstream DNS configurations (such as Control D or NextDNS) while gracefully preserving dynamic DHCP networking functions.

## Features

* **UI Hardening (GPO Layer):** Dynamically applies Group Policy registry tweaks to gray out and completely disable network adapter property modifications inside the Windows Settings app and legacy Control Panel (`ncpa.cpl`).
* **Zero-Trust Registry Padlock:** Injects explicit `Deny` rules directly onto the adapter's active interfaces subkeys (`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`).
* **Intelligent Account Targeting (DHCP Bypass):** Avoids sweeping "Deny Everyone" rules which crash DHCP. Instead, it specifically targets `Administrators` and `SYSTEM` groups. This prevents malicious privilege escalation and app-level tampering while allowing the `NT AUTHORITY\LocalService` account to dynamically renew local router IP leases.
* **Robust Exception Management:** Features integrated translation filters that step over orphaned or "ghost" Security Identifiers (SIDs) left behind by Windows Updates, preventing execution crashes during directory scans.
* **Comprehensive Logging:** Outputs timestamped operational actions, system policies, and errors directly to a local transaction log file (`DNS_Lockdown.log`) for auditing.

---

## Technical Security Mechanics

| Security Vector | Standard Windows Behavior | Behavior with This Script Active |
| :--- | :--- | :--- |
| **Malware & Trojan Hijacking** | Elevated scripts rewrite `NameServer` values to redirect web traffic to phishing infrastructure. | Banned. Even with `SYSTEM` or administrative privileges, registry writes return a hard "Access Denied." |
| **Human Error / Interface Tampering** | Users modify adapter properties to bypass DNS filtering or troubleshoot manually. | Completely restricted. The Network Connections GUI elements are disabled or grayed out via GPO. |
| **Filter Bypassing** | Users or background processes switch DNS servers to standard open resolvers (e.g., `8.8.8.8`). | Blocked. The static upstream security perimeter remains locked to your preferred secure DNS provider. |
| **DHCP IP Allocation** | Standard registry locking drops the adapter into an APIPA (`169.254.x.x`) failure state. | Maintained. The targeted block list permits `LocalService` to fetch and update local network IPs smoothly. |

---

## Deployment & Usage

### Prerequisites
* Windows 10 or Windows 11.
* PowerShell 5.1 or PowerShell Core running with **Administrative Privileges**.
* Pre-configured DNS addresses (the script locks whatever values are active on your network card at the time of execution).

### How to Run
1. Right-click your PowerShell console and select **Run as Administrator**.
2. Execute the script:
   ```powershell
   .\DNS_Lockdown.ps1
   

### Understanding `Set-ExecutionPolicy RemoteSigned`

By default, Windows has a strict security mechanism enabled (called `Restricted`) that prevents *any* PowerShell scripts from running, even the ones you write yourself. This command changes that rule to a much more practical, balanced security setting.


Here is the exact command:

```powershell
Set-ExecutionPolicy RemoteSigned


### Trade-Offs & Known Limitations

While this script provides a high-security perimeter for your network configuration, deploying a "Zero Trust" registry lock introduces some friction into daily operations. Please be aware of the following scenarios before deployment:

* **Captive Portals (Public Wi-Fi):**
  Hotels, airports, and public networks use captive portals that require your device to temporarily use their local DNS to load the login/terms page. Because this script hard-locks your upstream DNS, captive portals will fail to route properly. 
  * **Workaround:** Run the script, select `Option 2` (Unlock), connect to the network and log in, then run `Option 1` (Lock) to re-secure the connection.

* **Corporate VPN Conflicts:**
  Traditional work VPNs (e.g., Cisco AnyConnect, Fortinet) often rewrite your local adapter's DNS to resolve internal company domains (like `intranet.local`). The registry lock will block this injection, which may cause the VPN software to crash or fail to route internal traffic. *(Note: WFP-based apps like Proton VPN are unaffected but require manual DNS entry in the app's own settings).*

* **Single Point of Failure:**
  By removing Windows' ability to fall back to a local ISP's automatic DNS, an outage at your chosen upstream DNS provider will result in a total loss of web resolution. Furthermore, if you use aggressive privacy filters and a legitimate service breaks, there is no quick GUI bypass available.

* **Administrative Friction:**
  The Group Policy UI restrictions apply system-wide. If you need to perform standard network troubleshooting or change a static IP address months from now, you will encounter grayed-out menus and "Access Denied" registry errors. You must keep the script accessible to temporarily unlock the system (`Option 2`) before performing maintenance.
