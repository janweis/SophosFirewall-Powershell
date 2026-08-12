# Sophos Firewall PowerShell Module Suite

PowerShell module collection for Sophos XGS/SFOS firewall management. Eleven modules with 471
cmdlets are shipped; roughly nine further areas of the API are still open.

## Quick Start

```powershell
# 1. Install from the PowerShell Gallery (SophosFirewall.Core is pulled in automatically)
Install-Module SophosFirewall.HostsAndServices -Repository PSGallery -Scope CurrentUser

# 2. Connect to firewall
$cred = Get-Credential
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential $cred -SkipCertificateCheck

# 3. Use modules
Get-SfosIPHost
New-SfosIPHost -Name "Server1" -HostType IP -IPAddress "10.0.0.5"
```

## Available Modules

### Shipped

| Module | Functions | Purpose |
|--------|-----------|---------|
| **SophosFirewall.Core** | 7 | Session management, API, XML security |
| **SophosFirewall.HostsAndServices** | 53 | Host and service management |
| **SophosFirewall.Web** | 52 | Web protection: URL groups, categories, file types, filter policies and exceptions, quotas, settings |
| **SophosFirewall.Firewall** | 21 | Firewall rules and rule groups, NAT rules, SSL/TLS inspection |
| **SophosFirewall.Network** | 100 | Interfaces, VLANs, zones, gateways, DNS, DHCP, ARP, tunnels |
| **SophosFirewall.Authentication** | 97 | Authentication servers, users and groups, guest and clientless users, one-time passwords, firewall/admin/VPN/web authentication, captive portal, Azure AD SSO, STAS, live users |
| **SophosFirewall.Routing** | 31 | Gateways and health checks, SD-WAN profiles and policy routes, static (unicast) and multicast routes, PIM |
| **SophosFirewall.VPN** | 51 | IPsec connections and profiles, SSL VPN (policies, bookmarks, site-to-site), L2TP, PPTP, failover groups |
| **SophosFirewall.IntrusionPrevention** | 29 | IPS policies and rules, custom signatures, IPS switch, DoS settings and bypass rules, spoof prevention, trusted MACs |
| **SophosFirewall.ActiveThreatResponse** | 10 | Sophos X-Ops threat feeds (ATP) with host/threat exceptions, third-party threat feeds |
| **SophosFirewall.Applications** | 20 | Application filter policies and rules, application objects, categories with QoS assignment, classification assignments |

471 cmdlets in total. Every one of them was called against a live SFOS 22.0 appliance, not
only against mocks — the firmware behaviour that differs from the vendor documentation is
recorded in the `.NOTES` of the affected function and summarised in each module README.

**Firmware note:** all measured behaviour — status paths, append-only lists, silent
no-ops, unsatisfiable operations — was established on SFOS 22.0. A firmware upgrade can
change any of it; re-verify against a lab appliance before trusting the measured notes on
a newer release. Cmdlets that can lock you out of the appliance or cause irreversible
state carry `ConfirmImpact = 'High'` and prompt unless `-Confirm:$false` is passed.

## Documentation

- [SophosFirewall.Core README](Modules/SophosFirewall.Core/README.md) - Foundation module details
- [SophosFirewall.HostsAndServices README](Modules/SophosFirewall.HostsAndServices/README.md) - Host/service management
- [SophosFirewall.Web README](Modules/SophosFirewall.Web/README.md) - Web protection, including the firmware limitations found on SFOS 22.0
- [SophosFirewall.Firewall README](Modules/SophosFirewall.Firewall/README.md) - Firewall, NAT and TLS inspection rules; read the safety notes before using the write cmdlets
- [SophosFirewall.Network README](Modules/SophosFirewall.Network/README.md) - Interfaces, zones, gateways, DNS and DHCP; a wrong write here can cut off the API path used to fix it
- [SophosFirewall.Authentication README](Modules/SophosFirewall.Authentication/README.md) - Who may log in and how; read the known limitations before using the write cmdlets
- [SophosFirewall.Routing README](Modules/SophosFirewall.Routing/README.md) - Gateways, SD-WAN and static routes (the API calls them UnicastRoute); a wrong route can cut off the management path
- [SophosFirewall.VPN README](Modules/SophosFirewall.VPN/README.md) - IPsec, SSL VPN, L2TP and PPTP; read the known limitations, several add operations are not satisfiable through the XML API
- [SophosFirewall.IntrusionPrevention README](Modules/SophosFirewall.IntrusionPrevention/README.md) - IPS, DoS and spoof prevention; enabling spoof prevention on the management zone can lock you out, read the warning first
- [SophosFirewall.ActiveThreatResponse README](Modules/SophosFirewall.ActiveThreatResponse/README.md) - ATP / Sophos X-Ops threat feeds and third-party feeds; note the measured remove/update quirks
- [SophosFirewall.Applications README](Modules/SophosFirewall.Applications/README.md) - Application control; several rule-list fields are computed server-side, read the known behaviour section first

## Key Features

- 471 functions covering eleven of roughly twenty API areas
- PowerShell 5.1 and 7.x
- Session management: connect once, use every module
- Pipeline support between cmdlets
- WhatIf/Confirm on all write operations
- Automatic XML escaping of user input
- Self-signed certificate support for test environments

## Requirements

- PowerShell 5.1 or higher
- HTTPS network access to firewall (port 4444)
- Valid firewall admin account
- SFOS 21.5, 22.0+

## Examples

### Host Management
```powershell
# List all hosts
Get-SfosIPHost

# Create host
New-SfosIPHost -Name "WebServer" -HostType IP -IPAddress "10.0.0.5" -Description "Web server"

# Update host
Set-SfosIPHost -Name "WebServer" -HostType IP -IPAddress "10.0.0.5" -Description "Updated"

# Delete host
Remove-SfosIPHost -Name "WebServer" -Confirm
```

### Service Management
```powershell
# Create service
New-SfosService -Name "CustomHTTPS" -Protocol TCP -DstPort "8443" -SrcPort "1:65535"

# List services
Get-SfosService | Format-Table -AutoSize
```

## Module Organization

One module per area of the SFOS web admin, named after that area.

| Web admin menu | Modules |
|---|---|
| Configure | Network, Routing, Authentication, SystemServices, VPN |
| Protect | RulesAndPolicies, IntrusionPrevention, Web, Applications, Wireless, Email, WebServer, ActiveThreatResponse |
| System | SophosCentral, Profiles, HostsAndServices, Administration, BackupAndFirmware, Certificates |
| Monitor & analyze | ZeroDayProtection, Diagnostics |

## Architecture

- **CRUD Operations**: Get, New, Set, Remove for all objects
- **Consistent Parameters**: Reusable connection across modules
- **Pipeline Support**: Objects flow between cmdlets
- **Safety**: WhatIf/Confirm on write operations
- **Error Handling**: Descriptive error messages

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection fails | Check IP/port, verify network connectivity |
| SSL error | Use `-SkipCertificateCheck` parameter |
| Auth fails (502) | Verify admin credentials |
| "No active connection" | Run `Connect-SfosFirewall` first |

## License

MIT License - Copyright (c) 2025 Jan Weis

## Version

1.0.0 - Production Release (January 2026)

---

For API details, see [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/).
