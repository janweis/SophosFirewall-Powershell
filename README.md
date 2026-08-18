# Sophos Firewall PowerShell Module Suite

A PowerShell module collection for managing Sophos XGS/SFOS firewalls through their XML
management API. Sixteen modules ship 577 cmdlets, covering sixteen of the API's areas.

## Quick Start

```powershell
# 1. Install from the PowerShell Gallery (SophosFirewall.Core is pulled in automatically)
Install-Module SophosFirewall.HostsAndServices -Repository PSGallery -Scope CurrentUser

# 2. Connect to the firewall
$cred = Get-Credential
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential $cred -SkipCertificateCheck

# 3. Use the cmdlets
Get-SfosIPHost
New-SfosIPHost -Name 'Server1' -HostType IP -IPAddress '192.0.2.50'
```

### Multiple firewalls at once

Every cmdlet accepts `-Session` - a session object returned by `Connect-SfosFirewall`, or
the name of a session registered with `-Name`. That makes moving objects between two
firewalls a one-liner:

```powershell
$fw1 = Connect-SfosFirewall -Firewall '192.0.2.10' -Credential $cred1 -Name fw1
$fw2 = Connect-SfosFirewall -Firewall '192.0.2.20' -Credential $cred2 -Name fw2 -NoDefault

Get-SfosIPHost -Session $fw1 -NameLike 'Server1' | ForEach-Object {
    New-SfosIPHost -Name $_.Name -HostType $_.HostType -IPAddress $_.IPAddress -Session $fw2
}

Get-SfosSession                  # list registered sessions (IsDefault marks the ambient one)
Disconnect-SfosFirewall -All     # drop everything
```

Cmdlets called without `-Session` use the ambient default session set by
`Connect-SfosFirewall`.

## Modules

| Module | Cmdlets | Purpose |
|---|---|---|
| [SophosFirewall.Core](Modules/SophosFirewall.Core/README.md) | 8 | Connection management, API transport, XML escaping |
| [SophosFirewall.HostsAndServices](Modules/SophosFirewall.HostsAndServices/README.md) | 53 | IP/FQDN/MAC hosts, country groups, services and their groups |
| [SophosFirewall.Web](Modules/SophosFirewall.Web/README.md) | 54 | URL groups, web categories, file types, filter policies and exceptions, surfing quotas |
| [SophosFirewall.Firewall](Modules/SophosFirewall.Firewall/README.md) | 21 | Firewall rules and rule groups, NAT rules, SSL/TLS inspection |
| [SophosFirewall.Network](Modules/SophosFirewall.Network/README.md) | 100 | Interfaces, VLANs, zones, gateways, DNS, DHCP, ARP, tunnels |
| [SophosFirewall.Authentication](Modules/SophosFirewall.Authentication/README.md) | 97 | Authentication servers, users and groups, guest/clientless users, OTP, admin/VPN/web authentication, captive portal, Azure AD SSO, STAS, live users |
| [SophosFirewall.Routing](Modules/SophosFirewall.Routing/README.md) | 31 | Gateways and health checks, SD-WAN, static and multicast routes, PIM |
| [SophosFirewall.VPN](Modules/SophosFirewall.VPN/README.md) | 51 | IPsec connections and profiles, SSL VPN, L2TP, PPTP, failover groups |
| [SophosFirewall.IntrusionPrevention](Modules/SophosFirewall.IntrusionPrevention/README.md) | 30 | IPS policies and rules, custom signatures, DoS settings, spoof prevention, trusted MACs |
| [SophosFirewall.ActiveThreatResponse](Modules/SophosFirewall.ActiveThreatResponse/README.md) | 10 | ATP threat feeds, host/threat exceptions, third-party threat feeds |
| [SophosFirewall.Applications](Modules/SophosFirewall.Applications/README.md) | 20 | Application filter policies and rules, application objects, categories, classification |
| [SophosFirewall.SystemServices](Modules/SophosFirewall.SystemServices/README.md) | 21 | QoS policies, syslog servers, the system service daemon manager, High Availability, RED |
| [SophosFirewall.Administration](Modules/SophosFirewall.Administration/README.md) | 32 | Notification, SNMP, appliance access, admin/web-admin settings, time, messages, Netflow, local service ACL |
| [SophosFirewall.Profiles](Modules/SophosFirewall.Profiles/README.md) | 20 | Schedules, access time policies, data transfer policies, decryption profiles, administration profiles |
| [SophosFirewall.WebServer](Modules/SophosFirewall.WebServer/README.md) | 18 | Web server publishing (WAF), protection policies, authentication policies and templates, slow HTTP protection |
| [SophosFirewall.Certificates](Modules/SophosFirewall.Certificates/README.md) | 11 | Certificates, certificate authorities, revocation lists |

577 cmdlets in total. Every module follows the same connection model and shares the
`SophosFirewall.Core` transport layer.

Several cmdlets change settings that the current management session itself depends on -
appliance access, admin authentication, interfaces and zones, spoof prevention, HA. A wrong
value there can end the session with no way to reconnect. Every write cmdlet in the suite
supports `-WhatIf`; each module's README names the cmdlets that carry this risk and how to
use them safely.

## Requirements

- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API (default port 4444)
- A firewall account with API access

## Architecture

Two layers:

- **`SophosFirewall.Core`** owns the connection, the HTTP transport, XML escaping and status
  evaluation. It has no knowledge of any specific object type.
- **Domain modules** (everything else) build the inner request XML for their own object
  types, parse the response, and expose the `Get-`/`New-`/`Set-`/`Remove-` cmdlets. They
  never call the firewall directly; they go through `SophosFirewall.Core`.

Every write cmdlet supports `-WhatIf`/`-Confirm`. Every value taken from a caller is
XML-escaped before being sent. `Get-*` cmdlets accept pipeline output from other `Get-*`
cmdlets so objects can be copied between firewalls with `Get-* -Session $fw1 | New-* -Session $fw2`.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
