# SophosFirewall.Routing Module

> **Security warning.** These cmdlets change how a live firewall forwards traffic. A wrong
> route or a removed gateway decides whether packets reach their destination at all, and a
> change that cuts off the management path also cuts off the API used to repair it. Every
> write cmdlet in this module supports `-WhatIf`; use it before running an unfamiliar call
> against a production firewall, especially anything that removes a gateway or an SD-WAN
> profile that other objects may still reference.

## Overview

The **Routing** module provides PowerShell cmdlets for the **CONFIGURE > Routing** area of
the Sophos XGS / SFOS 22.0 API documentation. With 31 exported functions, it manages gateway
objects and health check profiles (including their status toggle), SD-WAN profiles and SD-WAN
policy routes (including their status toggle), unicast (static) routes, and multicast routes,
the multicast forwarding setting and PIM dynamic routing. Requires `SophosFirewall.Core`
(minimum version 1.1.0).

## Features

- **Gateways and Health Checks**: `GatewayHost` objects with an optional attached health
  check, standalone `HealthCheckProfile` objects, and the `HealthCheckProfileStatus` on/off
  toggle
- **SD-WAN**: `SDWANProfile` gateway-selection profiles and `SDWANPolicyRoute` traffic-steering
  routes, plus the `SDWANPolicyRouteStatus` enable/disable toggle
- **Unicast Routing**: Static `UnicastRoute` objects, identified by destination and netmask
- **Multicast Routing**: `MulticastRoute` objects, the read-only `MulticastConfiguration`
  singleton, and `PIMDynamicRouting`, the device-wide PIM-SM configuration
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Install-Module -Name SophosFirewall.Routing
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.Routing.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module, version 1.1.0 or higher (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### Multi-Session Usage

```powershell
# Register two connections without disturbing the default session
Connect-SfosFirewall -Firewall "fw1.example.test" -Credential (Get-Credential) -Name "fw1"
Connect-SfosFirewall -Firewall "fw2.example.test" -Credential (Get-Credential) -Name "fw2" -NoDefault

# Read a gateway's mail-notification setting from fw1 and apply it to the same-named
# gateway on fw2, without touching the ambient default session
Get-SfosGatewayHost -Session "fw1" -NameLike "ISP1" |
    Set-SfosGatewayHost -Session "fw2" -MailNotification ON
```

### Gateway and Health Check Management

```powershell
# List every gateway with its health state
Get-SfosGatewayHost | Format-Table Name, GatewayIP, Interface

# Create a gateway with health-check monitoring disabled (the default)
New-SfosGatewayHost -Name "ISP1" -IPFamily IPv4 -GatewayIP "192.168.1.1" -Interface "Port1"

# Create one with health-check monitoring enabled
$rule = [PSCustomObject]@{ Protocol = "PING"; IPAddress = "192.168.1.1"; Port = "*" }
New-SfosGatewayHost -Name "ISP2" -IPFamily IPv4 -GatewayIP "192.168.1.2" -Interface "Port2" `
    -Healthcheck ON -Interval 60 -Timeout 5 -FailureRetries 3 -MonitoringCondition $rule

# Turn on mail notification only; every other field is preserved
Set-SfosGatewayHost -Name "ISP1" -MailNotification ON

# Preview removal
Remove-SfosGatewayHost -Name "ISP1" -WhatIf
```

```powershell
# A standalone health check profile - see Known limitations, Get-SfosHealthCheckProfile
# does not list a profile until it is attached to a gateway or SD-WAN profile
$target = [PSCustomObject]@{ monitormethod = "PING"; monitorip = "192.168.1.1"; port = "0"; operator = "|" }
New-SfosHealthCheckProfile -Name "WAN-Probe" -IPFamily IPv4 -ProbeTarget $target

# Read the on/off state of every health check, including ones not visible via Get-SfosHealthCheckProfile
Get-SfosHealthCheckProfileStatus

# Disable the health check attached to a gateway - see Known limitations for the risk here
Set-SfosHealthCheckProfileStatus -Name "HealthCheckObject_GW_ISP1" -Status OFF
```

### SD-WAN Management

```powershell
# Create a minimal SD-WAN profile with a single gateway, SLA off
New-SfosSDWANProfile -Name "Branch-Profile" -GatewayName "Branch-Gateway" -EnableSLA OFF -HealthCheckProfileName "HealthCheckObject_Branch"

# Update the description only; gateway preferences and every other field are preserved
Set-SfosSDWANProfile -Name "Branch-Profile" -Description "Updated branch office profile"

# Create a route that defers gateway selection to the profile above
New-SfosSDWANPolicyRoute -Name "Branch-Route" -DestinationNetwork "Branch-Net" -LinkSelection SelectSDWANProfile -SDWANProfileName "Branch-Profile"

# Read the routes and their state
Get-SfosSDWANPolicyRoute | Format-Table Name, IPFamily
Get-SfosSDWANPolicyRouteStatus

# Disable a route right after creating it
Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName "Branch-Route" -Status OFF

# Check for dependent routes before removing a profile - see Known limitations
Get-SfosSDWANPolicyRoute | Where-Object { $_.SDWANProfileName -eq "Branch-Profile" }
Remove-SfosSDWANPolicyRoute -Name "Branch-Route"
Remove-SfosSDWANProfile -Name "Branch-Profile"
```

### Unicast (Static) Route Management

```powershell
# Create a disabled static route via Port1
New-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0" -Interface "Port1" -Status OFF -Description "Lab segment via Port1"

# Enable it later - see Known limitations, this removes and recreates the route
Set-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0" -Status ON

# List every static route
Get-SfosUnicastRoute | Format-Table DestinationIP, Netmask, Gateway, Status

# Remove a test route
Remove-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0"
```

### Multicast Route and PIM Management

```powershell
# See Known limitations - creation is documentation-faithful but unconfirmed on this firmware
New-SfosMulticastRoute -SourceIPAddress "203.0.113.10" -MulticastAddress "239.255.255.10" -DestinationInterface "Port1" -DestinationTunnelType "SystemInterface" -WhatIf

# List existing multicast routes
Get-SfosMulticastRoute

# Check whether multicast forwarding is enabled device-wide (read-only, see Known limitations)
Get-SfosMulticastConfiguration

# Check whether dynamic PIM routing is enabled device-wide
Get-SfosPIMDynamicRouting

# Preview enabling PIM on Port1 - see Known limitations, the write path is unconfirmed
Set-SfosPIMDynamicRouting -ManagePIM Enable -InterfaceList "Port1" -WhatIf
```

## Available Cmdlets (31 total)

### Gateways and Health Checks (10 functions)
- `Get-SfosGatewayHost` - Retrieves GatewayHost objects from the Sophos Firewall.
- `New-SfosGatewayHost` - Creates a new GatewayHost object on the Sophos Firewall.
- `Set-SfosGatewayHost` - Updates an existing GatewayHost object on the Sophos Firewall.
- `Remove-SfosGatewayHost` - Removes a GatewayHost object from the Sophos Firewall.
- `Get-SfosHealthCheckProfile` - Retrieves HealthCheckProfile objects from the Sophos Firewall.
- `New-SfosHealthCheckProfile` - Creates a new HealthCheckProfile object on the Sophos Firewall.
- `Set-SfosHealthCheckProfile` - Updates an existing HealthCheckProfile object on the Sophos Firewall.
- `Remove-SfosHealthCheckProfile` - Removes a HealthCheckProfile object from the Sophos Firewall.
- `Get-SfosHealthCheckProfileStatus` - Retrieves HealthCheckProfileStatus records from the Sophos Firewall.
- `Set-SfosHealthCheckProfileStatus` - Turns a HealthCheckProfileStatus record on or off.

### SD-WAN (10 functions)
- `Get-SfosSDWANProfile` - Retrieves SD-WAN profiles from the Sophos Firewall.
- `New-SfosSDWANProfile` - Creates a new SD-WAN profile on the Sophos Firewall.
- `Set-SfosSDWANProfile` - Updates an SD-WAN profile on the Sophos Firewall.
- `Remove-SfosSDWANProfile` - Removes an SD-WAN profile from the Sophos Firewall.
- `Get-SfosSDWANPolicyRoute` - Retrieves SD-WAN policy routes from the Sophos Firewall.
- `New-SfosSDWANPolicyRoute` - Creates a new SD-WAN policy route on the Sophos Firewall.
- `Set-SfosSDWANPolicyRoute` - Updates an SD-WAN policy route on the Sophos Firewall.
- `Remove-SfosSDWANPolicyRoute` - Removes an SD-WAN policy route from the Sophos Firewall.
- `Get-SfosSDWANPolicyRouteStatus` - Retrieves SD-WAN policy route enable/disable status from the Sophos Firewall.
- `Set-SfosSDWANPolicyRouteStatus` - Enables or disables an SD-WAN policy route on the Sophos Firewall.

### Unicast, Multicast and PIM Routing (11 functions)
- `Get-SfosUnicastRoute` - Retrieves UnicastRoute (static route) objects from the Sophos Firewall.
- `New-SfosUnicastRoute` - Creates a new UnicastRoute (static route) object on the Sophos Firewall.
- `Set-SfosUnicastRoute` - Replaces an existing UnicastRoute object on the Sophos Firewall.
- `Remove-SfosUnicastRoute` - Removes a UnicastRoute object from the Sophos Firewall.
- `Get-SfosMulticastRoute` - Retrieves MulticastRoute objects from the Sophos Firewall.
- `New-SfosMulticastRoute` - Creates a new MulticastRoute object on the Sophos Firewall.
- `Set-SfosMulticastRoute` - Updates an existing MulticastRoute object on the Sophos Firewall.
- `Remove-SfosMulticastRoute` - Removes a MulticastRoute object from the Sophos Firewall.
- `Get-SfosMulticastConfiguration` - Retrieves the MulticastConfiguration settings from the Sophos Firewall.
- `Get-SfosPIMDynamicRouting` - Retrieves the PIMDynamicRouting settings from the Sophos Firewall.
- `Set-SfosPIMDynamicRouting` - Updates the PIMDynamicRouting settings on the Sophos Firewall.

## Known limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance. Every read-modify-write `Set-*` in this module
exists because of the general finding that an update replaces the whole entity - see the
points below for the exceptions and additional defects found on top of that.

- **`UnicastRoute` has no working update.** `operation="update"` answers code `500` for every
  field combination tried, including a true no-op. `Set-SfosUnicastRoute` therefore removes
  and recreates the route, with a brief window where it is absent; if the recreate step fails,
  the route is left removed rather than silently reverted. The firewall also does not enforce
  `DestinationIP`+`Netmask` as a unique key - creating a duplicate answers `200` and produces
  two indistinguishable records - so `New-SfosUnicastRoute` checks for an existing match first
  and throws rather than silently creating an ambiguous duplicate.
- **Removing an SD-WAN profile that a policy route still references cascades silently.**
  `Remove-SfosSDWANProfile` on a profile named by an existing `SDWANPolicyRoute.SDWANProfileName`
  answers `200 Configuration applied successfully` and deletes the referencing route along with
  the profile, with no warning of any kind. Check for dependent routes with
  `Get-SfosSDWANPolicyRoute | Where-Object { $_.SDWANProfileName -eq $Name }` before removing a
  profile that may be in use.
- **The status toggles answer 200 for names that do not exist, without changing anything.**
  Both `Set-SfosSDWANPolicyRouteStatus` and the underlying health-check mechanics are subject
  to this false-positive-success class. `Set-SfosSDWANPolicyRouteStatus` reads the status back
  after a successful-looking write and throws if the route was not found or the status does not
  match what was requested, rather than reporting a silent no-op as success.
- **`MulticastRoute` write paths are unconfirmed.** Every documented-shape variant of
  `New-SfosMulticastRoute` tried against the lab firewall - with and without `SourceInterface`,
  with and without `TunnelType`, with and without the `DestinationInterfaceList` wrapper, the
  exact sample field order - answered code `500 Operation could not be performed on Entity`.
  The lab firewall's `MulticastConfiguration` singleton reads
  `MulticastForwardingSetting = Disable`, which is the most likely gate, but that could not be
  confirmed - see the next point. `New-`/`Set-`/`Remove-SfosMulticastRoute` are implemented
  documentation-faithful and verified at the XML-generation level only; nothing about them
  should be assumed to work. `Get-SfosMulticastRoute` is confirmed live.
- **`MulticastConfiguration` has no `Set-*` cmdlet.** The vendor documentation page for this
  entity has an empty Description and an empty Operations section - no operation, not even
  Get, is documented for it at all. The `Get-` in this module works despite that (measured),
  but with no documented write path this entity stays read-only, per the existing
  `Set-SfosGuestUser` precedent (no cmdlet for an undocumented write).
- **`Set-SfosPIMDynamicRouting` is verified structurally only.** `ManagePIM` switches dynamic
  multicast routing on or off for the entire device, so this cmdlet was implemented and checked
  via its generated XML (e.g. `-WhatIf`) but never executed against the lab firewall. The
  nesting and field names are inferred from the documented sample XML.
- **Enabled state is represented inconsistently across entities.** `HealthCheckProfile.Status`
  is an integer (`1`/`0`); `HealthCheckProfileStatus.Status`, `UnicastRoute.Status` and
  `SDWANPolicyRouteStatus.Status` are text (`ON`/`OFF`); `SDWANPolicyRoute.Status` (the route's
  own enabled flag, separate from `SDWANPolicyRouteStatus`) is text (`1`/`0`). Every cmdlet in
  this module passes these values through exactly as the firewall delivers them - nothing is
  normalised - so do not assume one entity's "enabled" spelling applies to another.
- **The Multicast documentation area is effectively empty**, and seven of the ten entities in
  this module use a wire element name that differs from the documentation folder name:
  `PolicyRoute` is `SDWANPolicyRoute`, `PolicyRouteStatus` is `SDWANPolicyRouteStatus`,
  `MonitorObject` is `HealthCheckProfile`, `MonitorObjectStatus` is `HealthCheckProfileStatus`,
  and `GatewayObject` is `GatewayHost`, on the wire. Building a request from the documentation
  folder name alone fails with `529 Input request module is Invalid`.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific gateway with error handling
    $gateway = Get-SfosGatewayHost -NameLike "ISP1" -ErrorAction Stop
    Write-Output "Found gateway: $($gateway.Name) - GatewayIP: $($gateway.GatewayIP)"
} catch {
    Write-Error "Failed to retrieve gateway: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosGatewayHost | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are entity-specific (GatewayHost, HealthCheckProfile, SDWANProfile, SDWANPolicyRoute, UnicastRoute, MulticastRoute, ...)
- **A newly created HealthCheckProfile does not show up in `Get-SfosHealthCheckProfile`**: See Known limitations - a standalone profile only becomes visible there once attached to a gateway or SD-WAN profile; use `Get-SfosHealthCheckProfileStatus` to confirm it exists in the meantime
- **`Set-SfosUnicastRoute` briefly shows the route as missing**: See Known limitations - this cmdlet removes and recreates the route because `operation="update"` fails for this entity
- **A profile removal also deleted a route you did not name**: See Known limitations - `Remove-SfosSDWANProfile` cascades to referencing `SDWANPolicyRoute` objects silently
- **`New-SfosMulticastRoute` fails with 500**: See Known limitations - this is a known, unconfirmed firmware limitation, not a module defect

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.Routing) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License
