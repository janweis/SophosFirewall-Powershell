# SophosFirewall.Routing

`SophosFirewall.Routing` manages the Routing area of a Sophos Firewall: gateway objects and
health check profiles, SD-WAN profiles and policy routes, static (unicast) routes, and
multicast routing with PIM. It is for administrators who script routing changes instead of
maintaining them in the web admin.

These cmdlets change how the appliance forwards traffic. A wrong route or a removed gateway
decides whether packets reach their destination, and a change that cuts off the management
path also cuts off the API used to repair it. Every write cmdlet supports `-WhatIf`; use it
before running an unfamiliar call against a production firewall, especially one that removes
a gateway or an SD-WAN profile that other objects may still reference.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.Routing -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

New-SfosGatewayHost -Name 'ISP1' -IPFamily IPv4 -GatewayIP '192.0.2.1' -Interface 'Port1'
Get-SfosGatewayHost | Format-Table Name, GatewayIP, Interface
Set-SfosGatewayHost -Name 'ISP1' -MailNotification ON
Remove-SfosGatewayHost -Name 'ISP1' -WhatIf
```

### SD-WAN and static routes

```powershell
New-SfosSDWANProfile -Name 'Branch-Profile' -GatewayName 'ISP1' -EnableSLA OFF -HealthCheckProfileName 'Default-Health-Check'
New-SfosSDWANPolicyRoute -Name 'Branch-Route' -DestinationNetwork 'Branch-Net' -LinkSelection SelectSDWANProfile -SDWANProfileName 'Branch-Profile'

# Check for dependent routes before removing a profile
Get-SfosSDWANPolicyRoute | Where-Object { $_.SDWANProfileName -eq 'Branch-Profile' }
Remove-SfosSDWANPolicyRoute -Name 'Branch-Route'
Remove-SfosSDWANProfile -Name 'Branch-Profile'

New-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Interface 'Port1' -Status OFF -Description 'Test route'
Get-SfosUnicastRoute | Format-Table DestinationIP, Netmask, Gateway, Status
Remove-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0'
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosGatewayHost` | Retrieves gateway objects. |
| `New-SfosGatewayHost` | Creates a gateway object. |
| `Set-SfosGatewayHost` | Updates a gateway object. |
| `Remove-SfosGatewayHost` | Removes a gateway object. |
| `Get-SfosHealthCheckProfile` | Retrieves health check profiles. |
| `New-SfosHealthCheckProfile` | Creates a health check profile. |
| `Set-SfosHealthCheckProfile` | Updates a health check profile. |
| `Remove-SfosHealthCheckProfile` | Removes a health check profile. |
| `Get-SfosHealthCheckProfileStatus` | Reads the on/off state of a health check. |
| `Set-SfosHealthCheckProfileStatus` | Switches a health check on or off. |
| `Get-SfosSDWANProfile` | Retrieves SD-WAN profiles. |
| `New-SfosSDWANProfile` | Creates an SD-WAN profile. |
| `Set-SfosSDWANProfile` | Updates an SD-WAN profile. |
| `Remove-SfosSDWANProfile` | Removes an SD-WAN profile. |
| `Get-SfosSDWANPolicyRoute` | Retrieves SD-WAN policy routes. |
| `New-SfosSDWANPolicyRoute` | Creates an SD-WAN policy route. |
| `Set-SfosSDWANPolicyRoute` | Updates an SD-WAN policy route. |
| `Remove-SfosSDWANPolicyRoute` | Removes an SD-WAN policy route. |
| `Get-SfosSDWANPolicyRouteStatus` | Reads the enable/disable status of an SD-WAN policy route. |
| `Set-SfosSDWANPolicyRouteStatus` | Enables or disables an SD-WAN policy route. |
| `Get-SfosUnicastRoute` | Retrieves static routes. |
| `New-SfosUnicastRoute` | Creates a static route. |
| `Set-SfosUnicastRoute` | Updates a static route. |
| `Remove-SfosUnicastRoute` | Removes a static route. |
| `Get-SfosMulticastRoute` | Retrieves multicast routes. |
| `New-SfosMulticastRoute` | Creates a multicast route. |
| `Set-SfosMulticastRoute` | Updates a multicast route. |
| `Remove-SfosMulticastRoute` | Removes a multicast route. |
| `Get-SfosMulticastConfiguration` | Reads the device-wide multicast forwarding setting. |
| `Get-SfosPIMDynamicRouting` | Reads the device-wide PIM dynamic routing configuration. |
| `Set-SfosPIMDynamicRouting` | Updates the device-wide PIM dynamic routing configuration. |

## Limitations

A standalone health check profile does not appear in `Get-SfosHealthCheckProfile` until it
is attached to a gateway or an SD-WAN profile; use `Get-SfosHealthCheckProfileStatus` to
confirm it exists in the meantime.

`Set-SfosUnicastRoute` removes and recreates the route instead of updating it in place,
because an in-place update is refused by this firmware; there is a brief window where the
route does not exist. `New-SfosUnicastRoute` checks for an existing route with the same
destination and netmask first, because the firewall itself allows duplicates.

Removing an SD-WAN profile that a policy route still references deletes the referencing
route as well, without a separate confirmation. Check
`Get-SfosSDWANPolicyRoute | Where-Object { $_.SDWANProfileName -eq $Name }` before removing
a profile that may still be in use.

`Set-SfosHealthCheckProfileStatus` and `Set-SfosSDWANPolicyRouteStatus` read the object back
after the call and throw if the name was not found or the status was not applied, because
the firewall answers success for a name that does not exist.

Creating or updating a multicast route is not confirmed to succeed on this firmware.
`Get-SfosMulticastConfiguration` has no matching `Set-*` cmdlet; it is read-only in this
module. `Set-SfosPIMDynamicRouting` applies to the whole device and was verified only at the
level of the generated request, not against a live change.

Enabled/disabled state is represented differently across entities in this module:
`HealthCheckProfile.Status` is `1`/`0`, `HealthCheckProfileStatus.Status` and
`UnicastRoute.Status` are `ON`/`OFF`, and `SDWANPolicyRoute.Status` is `1`/`0` text. Each
cmdlet passes the value through exactly as the firewall uses it; one entity's spelling does
not apply to another.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
