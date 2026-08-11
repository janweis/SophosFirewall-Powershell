# Sophos Firewall PowerShell Module Suite

Comprehensive PowerShell module collection for Sophos XGS/SFOS firewall management. 21 modules with 474+ cmdlets for complete API coverage.

## Quick Start

```powershell
# 1. Install from PowerShell Gallery
Install-Module SophosFirewall.Core -Repository PSGallery -Scope CurrentUser
Install-Module SophosFirewall.HostsAndServices -Repository PSGallery -Scope CurrentUser

# 2. Connect to firewall
$cred = Get-Credential
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential $cred -SkipCertificateCheck

# 3. Use modules
Get-SfosIPHost
New-SfosIPHost -Name "Server1" -HostType IP -IPAddress "10.0.0.5"
```

## Available Modules

### Published (v1.0.0)

| Module | Functions | Purpose |
|--------|-----------|---------|
| **SophosFirewall.Core** | 7 | Session management, API, XML security |
| **SophosFirewall.HostsAndServices** | 53 | Host and service management |
| **SophosFirewall.Web** | 52 | Web protection: URL groups, categories, file types, filter policies and exceptions, quotas, settings |
| **SophosFirewall.Firewall** | 21 | Firewall rules and rule groups, NAT rules, SSL/TLS inspection |
| **SophosFirewall.Network** | 100 | Interfaces, VLANs, zones, gateways, DNS, DHCP, ARP, tunnels |

### Planned

Module names follow the area names of the SFOS web admin, verbatim — with one exception
noted below. Only areas that actually have API entities are listed; see "Not planned".

**Configure**: Routing, Authentication, SystemServices, VPN\*
**Protect**: IntrusionPrevention, Applications, Wireless, Email, WebServer, ActiveThreatResponse
**System**: SophosCentral, Profiles, Administration, BackupAndFirmware, Certificates
**Monitor & analyze**: ZeroDayProtection, Diagnostics

\* The web admin splits VPN into *Remote access VPN* and *Site-to-site VPN*, while the API
reference keeps a single `VPN` category covering both. Which split the module follows is
still open; the documentation does not map entities to the two UI areas.

`SophosFirewall.Firewall` is the one place where the module name follows the API reference
rather than the web admin. The reference groups these entities under `PROTECT/Firewall`,
while the web admin calls the same area *Rules and policies*. The entity names follow the
API too — `FirewallRule`, `FirewallRuleGroup`, `NATRule` — so naming the module after the
UI would have left it the odd one out against its own contents.

**Not planned** — these areas exist in the web admin but have no API entities, so no module
can be built for them: Control center, Current activities, Reports, Sophos Firewall Config
Studio, Object usage, Logs, Advanced services, Services and ports, Certifications.

## Documentation

- [SophosFirewall.Core README](Modules/SophosFirewall.Core/README.md) - Foundation module details
- [SophosFirewall.HostsAndServices README](Modules/SophosFirewall.HostsAndServices/README.md) - Host/service management
- [SophosFirewall.Web README](Modules/SophosFirewall.Web/README.md) - Web protection, including the firmware limitations found on SFOS 22.0
- [SophosFirewall.Firewall README](Modules/SophosFirewall.Firewall/README.md) - Firewall, NAT and TLS inspection rules; read the safety notes before using the write cmdlets
- [SophosFirewall.Network README](Modules/SophosFirewall.Network/README.md) - Interfaces, zones, gateways, DNS and DHCP; a wrong write here can cut off the API path used to fix it

## Key Features

- ✅ **474+ Functions** - Complete Sophos Firewall API coverage
- ✅ **PowerShell 5.1+** - Full version compatibility
- ✅ **Session Management** - One connection for all modules
- ✅ **Pipeline Support** - Fluent cmdlet chaining
- ✅ **Safety Features** - WhatIf/Confirm for write operations
- ✅ **XML Security** - Automatic injection prevention
- ✅ **Self-Signed Certs** - Test environment support

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
