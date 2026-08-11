# SophosFirewall.Network Module

> **Security warning.** These cmdlets change the network configuration of a live appliance:
> interfaces, VLANs, zones, gateways, DNS, DHCP, ARP and tunnels. A wrong IP address, a zone
> assigned to the wrong interface, or a gateway change that severs the path back to the
> management interface can make the appliance unreachable - and once that happens, the API you
> would use to undo it is unreachable too. There is no confirmation beyond `ShouldProcess`.
> Every write cmdlet in this module supports `-WhatIf`; use it before running an unfamiliar
> call against a production firewall, and keep a second, independent path to the device
> (console, out-of-band management) available before touching `Interface`, `Zone`,
> `GatewayConfiguration` or anything that carries the session's own management traffic.

## Overview

The **Network** module provides PowerShell cmdlets for the **CONFIGURE > Network** area of
the Sophos XGS / SFOS 22.0 API documentation; the SFOS web admin presents the same area as
**Network**. With 100 functions, it manages interfaces, VLANs, link aggregation groups, bridge
pairs and aliases, zones, the gateway configuration, DNS (resolver settings, host entries,
request routes, dynamic DNS), DHCP (servers, relays, IPv6, the server on/off switch), static
ARP and router advertisements, and tunnels (IP tunnels, GRE tunnels and routes, TAP interfaces,
RED devices, WiFi 6 interfaces and the cellular WAN). Requires `SophosFirewall.Core`.

## Features

- **Interfaces, VLANs, LAG, BridgePair, Alias**: Physical and logical Layer 2/3 building
  blocks, including IPv4/IPv6/MSS configuration builders
- **Zones**: Named security zones with the ApplianceAccess service groups
- **Gateway Configuration**: The device-wide gateway list and failover timeout (singleton)
- **DNS**: Resolver settings, static host entries with multiple addresses, request routes,
  dynamic DNS
- **DHCP**: IPv4/IPv6 DHCP servers, relays, and the server on/off switch
- **ARP and Router Advertisement**: The ARP cache configuration, static ARP entries, IPv6
  router advertisement
- **Tunnels**: IP tunnels, GRE tunnels and routes, TAP interfaces, RED devices, WiFi 6
  interfaces, cellular WAN
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Import-Module -Name SophosFirewall.Network
```

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.Network.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### Interfaces

Physical ports cannot be created or removed through this API - only `Get-` and `Set-` exist.
`Set-SfosInterface` reads the current interface first and resends every field it was not
explicitly given, IPv4/IPv6/MSS configuration included as complete objects.

```powershell
# List interfaces with their current IPv4 assignment
Get-SfosInterface | Format-Table Name, Hardware, NetworkZone, InterfaceStatus

# Preview an MTU change - IP assignment, zone and MSS are resent unchanged
Set-SfosInterface -Hardware "Port1" -MTU 9000 -WhatIf
```

### VLAN Management

```powershell
# Create a VLAN sub-interface, disabled review with -WhatIf first
New-SfosVLAN -Name "DMZ-VLAN" -Interface "Port1" -VLANID 100 -Zone "DMZ" -IPv4Assignment Static -IPAddress "10.10.10.1" -Netmask "255.255.255.0" -WhatIf

# Update only the zone - Interface and VLANID identify the object, everything else is preserved
Set-SfosVLAN -Interface "Port1" -VLANID 100 -Zone "DMZ"

# Remove it - see Known Firmware Limitations: removal is keyed on the firewall-computed
# Hardware value, not Name, so this resolves Hardware first and verifies deletion afterwards
Remove-SfosVLAN -Interface "Port1" -VLANID 100 -WhatIf
```

### Alias

An interface alias has no caller-chosen name - the firewall derives one as
`<Interface>:<Index>`, so `New-SfosAlias` has no `-Name` parameter at all; use `Get-SfosAlias`
to find the generated name for a later `Set-`/`Remove-`.

```powershell
New-SfosAlias -Interface "Port1" -IPFamily IPv4 -IPAddress "10.0.1.1" -Netmask "255.255.255.0" -WhatIf

# The generated Name, e.g. "Port1:0", is what Set-/Remove- key on
Get-SfosAlias -NameLike "Port1" | Set-SfosAlias -Netmask "255.255.0.0" -WhatIf
```

### Zones

```powershell
New-SfosZone -Name "Extranet" -Type DMZ -Description "Partner extranet" -WhatIf

# Inspect the ApplianceAccess sub-object before changing anything else on the zone
(Get-SfosZone -NameLike "LAN").ApplianceAccess

# Only Description changes - ApplianceAccess and every other field is read back and resent
Set-SfosZone -Name "Extranet" -Description "Updated partner extranet" -WhatIf
```

### Static ARP

```powershell
New-SfosStaticARP -IPAddress "192.0.2.10" -MACAddress "00:11:22:33:44:55" -Interface "Port1" -WhatIf

# See Known Firmware Limitations: there is no update for this entity - this cmdlet removes
# and recreates the entry, with a brief gap between the two calls
Set-SfosStaticARP -IPAddress "192.0.2.10" -MACAddress "00:11:22:33:44:66" -WhatIf

Remove-SfosStaticARP -IPAddress "192.0.2.10" -WhatIf
```

### DNS Host Entries

```powershell
# Build one or more addresses, then create the entry
$address = New-SfosDNSHostEntryAddress -EntryType Manual -IPFamily IPv4 -IPAddress "10.0.0.10"
New-SfosDNSHostEntry -HostName "server.example.com" -Address $address -WhatIf

# Add a second address without disturbing the first (member cmdlets read-merge-write)
$second = New-SfosDNSHostEntryAddress -EntryType Manual -IPFamily IPv4 -IPAddress "10.0.0.11"
Add-SfosDNSHostEntryMember -HostName "server.example.com" -Address $second -WhatIf
```

### DNS Request Routes

See Known Firmware Limitations: despite the documentation, `-TargetServer` does not accept a
raw IP address - it must name an existing `IPHost` object of type `IP` (from
`SophosFirewall.HostsAndServices`).

```powershell
New-SfosDNSRequestRoute -DomainName "internal.example" -TargetServer "Internal-DNS-Server" -WhatIf

Set-SfosDNSRequestRoute -DomainName "internal.example" -TargetServer "Internal-DNS-Server", "Internal-DNS-Server-2" -WhatIf
```

### Gateway Configuration

A singleton: only `Get-`/`Set-` exist, no `New-`/`Remove-` (see Known Firmware Limitations).
`Set-SfosGatewayConfiguration` reads the current gateway list first, so a field left unset is
preserved rather than cleared.

```powershell
Get-SfosGatewayConfiguration

# Change only the failover timeout - the existing gateway list is resent unchanged
Set-SfosGatewayConfiguration -GatewayFailoverTimeout 30 -WhatIf
```

### Tunnels

`New-SfosIPTunnel` requires `-Hardware`; removal is keyed on `-Name` and (if not supplied,
resolved automatically via a lookup) `-Hardware`.

```powershell
New-SfosIPTunnel -Name "IPv6-Tunnel" -Hardware "Port2" -TunnelType 6in4 -Zone "WAN" `
    -LocalEndPoint "203.0.113.1" -RemoteEndPoint "203.0.113.2" -WhatIf

Remove-SfosIPTunnel -Name "IPv6-Tunnel" -WhatIf
```

`GreTunnel`, `GreRoute` and `TAP` are documentation-faithful but unverified against hardware
(see below); `-HostAddress` (alias `-Host`) is deliberately not `-Host`, which would shadow
PowerShell's automatic `$Host` variable.

```powershell
New-SfosGreRoute -HostAddress "198.51.100.0" -Netmask "255.255.255.0" -TunnelName "GRE1" -WhatIf

New-SfosTAP -Hardware "Port3" -WhatIf
```

## Available Cmdlets (100 total)

### Interface (5 functions)
- `Get-SfosInterface` - Retrieve Interface objects
- `Set-SfosInterface` - Update a physical interface (no New-/Remove-, ports are fixed hardware)
- `New-SfosInterfaceIPv4Configuration` - Build an IPv4Configuration object for Set-SfosInterface (no API call)
- `New-SfosInterfaceIPv6Configuration` - Build an IPv6Configuration object for Set-SfosInterface (no API call)
- `New-SfosInterfaceMSSConfiguration` - Build an MSS object for Set-SfosInterface (no API call)

### VLAN (4 functions)
- `Get-SfosVLAN` - Retrieve VLAN objects
- `New-SfosVLAN` - Create a new VLAN sub-interface
- `Set-SfosVLAN` - Update an existing VLAN
- `Remove-SfosVLAN` - Delete a VLAN (resolves the Hardware value first, see below)

### LAG (5 functions, not verified against hardware)
- `Get-SfosLAG` - Retrieve LAG objects
- `New-SfosLAG` - Create a new link aggregation group
- `Set-SfosLAG` - Update an existing LAG
- `Remove-SfosLAG` - Delete a LAG
- `New-SfosLAGMSSConfiguration` - Build an MSS object for LAG cmdlets (no API call)

### BridgePair (5 functions, not verified against hardware)
- `Get-SfosBridgePair` - Retrieve BridgePair objects
- `New-SfosBridgePair` - Create a new bridge pair
- `Set-SfosBridgePair` - Update an existing bridge pair
- `Remove-SfosBridgePair` - Delete a bridge pair
- `New-SfosBridgePairMSSConfiguration` - Build an MSS object for BridgePair cmdlets (no API call, `-Override` not `-OverrideMSS`, see below)

### Alias (4 functions)
- `Get-SfosAlias` - Retrieve Alias objects
- `New-SfosAlias` - Create a new interface alias (no `-Name`, see below)
- `Set-SfosAlias` - Update an existing alias
- `Remove-SfosAlias` - Delete an alias

### CellularWAN (2 functions, 1 Get/Set pair)
- `Get-SfosCellularWAN` / `Set-SfosCellularWAN` - Cellular WAN modem action state (singleton)

### IPTunnel (4 functions)
- `Get-SfosIPTunnel` - Retrieve IPTunnel objects
- `New-SfosIPTunnel` - Create a new IP tunnel (`-Hardware` mandatory)
- `Set-SfosIPTunnel` - Update an existing IP tunnel
- `Remove-SfosIPTunnel` - Delete an IP tunnel (keyed on Name and Hardware, see below)

### GreTunnel (4 functions, not verified against hardware)
- `Get-SfosGreTunnel` - Retrieve GreTunnel objects
- `New-SfosGreTunnel` - Create a new GRE tunnel
- `Set-SfosGreTunnel` - Update an existing GRE tunnel
- `Remove-SfosGreTunnel` - Delete a GRE tunnel (no delete operation is documented for this entity)

### GreRoute (4 functions, not verified against hardware)
- `Get-SfosGreRoute` - Retrieve GreRoute objects
- `New-SfosGreRoute` - Create a new GRE route (`-HostAddress`, alias `-Host`, see below)
- `Set-SfosGreRoute` - Replace an existing GRE route (remove-then-add, no documented update operation)
- `Remove-SfosGreRoute` - Delete a GRE route

### TAP (4 functions, not verified against hardware)
- `Get-SfosTAP` - Retrieve TAP objects
- `New-SfosTAP` - Configure a TAP interface (an unknown `-Hardware` answers 200 and creates nothing, see below)
- `Set-SfosTAP` - Update an existing TAP interface
- `Remove-SfosTAP` - Remove a TAP interface configuration

### REDDevice (4 functions, not verified against hardware)
- `Get-SfosREDDevice` - Retrieve REDDevice objects
- `New-SfosREDDevice` - Create a new RED device
- `Set-SfosREDDevice` - Update an existing RED device
- `Remove-SfosREDDevice` - Delete a RED device

### WiFi6Interface (4 functions, not verified against hardware)
- `Get-SfosWiFi6Interface` - Retrieve WiFi6Interface objects
- `New-SfosWiFi6Interface` - Create a new WiFi 6 interface
- `Set-SfosWiFi6Interface` - Update an existing WiFi 6 interface
- `Remove-SfosWiFi6Interface` - Delete a WiFi 6 interface

### Zone (4 functions, write paths not verified against hardware)
- `Get-SfosZone` - Retrieve Zone objects (`-TypeLike` is filtered client-side, see below)
- `New-SfosZone` - Create a new zone
- `Set-SfosZone` - Update an existing zone
- `Remove-SfosZone` - Delete a zone

### GatewayConfiguration (3 functions, write path not verified against hardware)
- `Get-SfosGatewayConfiguration` - Retrieve the GatewayConfiguration singleton
- `Set-SfosGatewayConfiguration` - Update the GatewayConfiguration singleton (no New-/Remove-, see below)
- `New-SfosGatewayConfigurationGateway` - Build a Gateway entry for Set-SfosGatewayConfiguration (no API call)

### ARPConfiguration (2 functions, 1 Get/Set pair)
- `Get-SfosARPConfiguration` / `Set-SfosARPConfiguration` - ARP cache configuration (singleton)

### StaticARP (4 functions)
- `Get-SfosStaticARP` - Retrieve StaticARP objects
- `New-SfosStaticARP` - Create a new static ARP entry
- `Set-SfosStaticARP` - "Update" a static ARP entry (remove-then-add, see below)
- `Remove-SfosStaticARP` - Delete a static ARP entry

### RouterAdvertisement (4 functions, write paths not verified against hardware)
- `Get-SfosRouterAdvertisement` - Retrieve RouterAdvertisement objects
- `New-SfosRouterAdvertisement` - Create a new router advertisement configuration
- `Set-SfosRouterAdvertisement` - Update an existing router advertisement configuration
- `Remove-SfosRouterAdvertisement` - Delete a router advertisement configuration

### DNS (4 functions, write path not verified against hardware)
- `Get-SfosDNS` - Retrieve the DNS resolver settings singleton
- `Set-SfosDNS` - Update the DNS resolver settings singleton
- `New-SfosDNSIPv4Settings` - Build the IPv4Settings object for Set-SfosDNS (no API call)
- `New-SfosDNSIPv6Settings` - Build the IPv6Settings object for Set-SfosDNS (no API call)

### DNSHostEntry (7 functions)
- `Get-SfosDNSHostEntry` - Retrieve DNSHostEntry objects
- `New-SfosDNSHostEntry` - Create a new DNS host entry
- `Set-SfosDNSHostEntry` - Update an existing DNS host entry
- `Remove-SfosDNSHostEntry` - Delete a DNS host entry
- `New-SfosDNSHostEntryAddress` - Build an Address entry for DNSHostEntry cmdlets (no API call)
- `Add-SfosDNSHostEntryMember` - Add an address to an existing DNS host entry
- `Remove-SfosDNSHostEntryMember` - Remove an address from an existing DNS host entry

### DNSRequestRoute (6 functions)
- `Get-SfosDNSRequestRoute` - Retrieve DNSRequestRoute objects
- `New-SfosDNSRequestRoute` - Create a new DNS request route (`-TargetServer` needs IPHost names, see below)
- `Set-SfosDNSRequestRoute` - Update an existing DNS request route
- `Remove-SfosDNSRequestRoute` - Delete a DNS request route
- `Add-SfosDNSRequestRouteMember` - Add a target server to an existing route
- `Remove-SfosDNSRequestRouteMember` - Remove a target server from an existing route

### DynamicDNS (4 functions, write paths not verified against hardware)
- `Get-SfosDynamicDNS` - Retrieve DynamicDNS objects
- `New-SfosDynamicDNS` - Create a new dynamic DNS configuration
- `Set-SfosDynamicDNS` - Update an existing dynamic DNS configuration
- `Remove-SfosDynamicDNS` - Delete a dynamic DNS configuration

### DHCPServer (4 functions, write paths not verified against hardware)
- `Get-SfosDHCPServer` - Retrieve DHCPServer objects
- `New-SfosDHCPServer` - Create a new DHCP server
- `Set-SfosDHCPServer` - Update an existing DHCP server
- `Remove-SfosDHCPServer` - Delete a DHCP server

### DHCPServerStatus (1 function, not verified against hardware)
- `Set-SfosDHCPServerStatus` - Switch an existing DHCP server ON or OFF (no separate Get-, status is read via Get-SfosDHCPServer)

### DHCPServerIpv6 (4 functions, write paths not verified against hardware)
- `Get-SfosDHCPServerIpv6` - Retrieve DHCPServerIpv6 objects
- `New-SfosDHCPServerIpv6` - Create a new IPv6 DHCP server
- `Set-SfosDHCPServerIpv6` - Update an existing IPv6 DHCP server
- `Remove-SfosDHCPServerIpv6` - Delete an IPv6 DHCP server

### DHCPRelay (4 functions, write paths not verified against hardware)
- `Get-SfosDHCPRelay` - Retrieve DHCPRelay objects
- `New-SfosDHCPRelay` - Create a new DHCP relay
- `Set-SfosDHCPRelay` - Update an existing DHCP relay
- `Remove-SfosDHCPRelay` - Delete a DHCP relay

## Known Firmware Limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance unless marked `[doc]`. Every read-modify-write
`Set-*` in this module exists because of the general finding that an update replaces the
whole entity - see the points below for the exceptions and additional defects found on top
of that.

- **Eight documentation folders carry a different XML element name than their folder name.**
  `WWAN` (folder) is `CellularWAN` (element), `ARPNeighbour` is `ARPConfiguration`, `ARP` is
  `StaticARP`, `Gateway` is `GatewayConfiguration`, `DHCPIPV6Server` is `DHCPServerIpv6`,
  `TapInterfaceConfiguration` is `TAP`, `GRETunnel` is `GreTunnel`, `GRERoute` is `GreRoute`.
  The last two differ only in capitalisation - sending the folder's spelling for the root
  element answers `529 Input request module is Invalid`.
- **`Remove-SfosVLAN` by `Name` answers 200 and deletes nothing.** Only the firewall-computed
  `Hardware` value (`<Interface>.<VLANID>`) identifies a VLAN for removal. The cmdlet resolves
  `Hardware` from `Interface`/`VLANID` first, sends the delete keyed on `Hardware`, and
  re-reads the object afterwards to confirm it is actually gone rather than trusting the
  status code.
- **An Alias has no caller-supplied name.** The firewall derives it as `<Interface>:<Index>`;
  `New-SfosAlias` therefore has no `-Name` parameter, and `Set-`/`Remove-SfosAlias` identify
  the object by the generated name returned from `Get-SfosAlias`.
- **`DNSRequestRoute` target servers must name an existing `IPHost` object of type `IP`.** A
  raw IP address, a resolvable-looking host name, and an `IPHost` of `HostType Network` were
  all rejected identically. The documentation states the opposite.
- **`New-SfosTAP` with an unknown `-Hardware` answers 200 and creates nothing.** There is no
  distinguishing error; the only way to notice is that a subsequent `Get-SfosTAP` does not
  show the object.
- **`StaticARP` does not support `<Set operation="update">` at all.** Every attempt answers
  `500 - Operation could not be performed on Entity`, including a byte-for-byte resend of a
  preceding `Get`. `Set-SfosStaticARP` removes the existing entry and recreates it instead,
  with a brief gap in which the mapping does not exist; if the recreate fails after the
  remove succeeds, the original entry is gone until restored manually.
- **`IPTunnel` needs `-Hardware` on create and both `Name` and `Hardware` on remove.** The
  server-side filter on this entity answers `Transaction fail` rather than a normal result,
  so `Get-SfosIPTunnel` filters client-side only; `Remove-SfosIPTunnel` resolves `Hardware`
  automatically via `Get-SfosIPTunnel` when the caller does not supply it.
- **`BridgePair`'s MSS child element is `<Override>`, not `<OverrideMSS>`.** `Interface`,
  `VLAN` and `LAG` all use `<OverrideMSS>`; `New-SfosBridgePairMSSConfiguration` uses
  `-Override` to match the wire element actually used by this entity `[doc]`.
- **`GatewayConfiguration` documents only an update operation.** There is no add or delete for
  this entity, so this module ships no `New-`/`Remove-SfosGatewayConfiguration` `[doc]`.
- **`Zone`'s server-side filter on `Type` returns zero matches instead of every zone.**
  `Get-SfosZone -TypeLike` is therefore applied client-side only, same as every other
  unsupported filter key (the project build rules, section 6).
- **`New-`/`Set-SfosGreRoute` use `-HostAddress` (alias `-Host`).** `$Host` is an automatic
  PowerShell variable holding the console host; a parameter literally named `-Host` would
  shadow it inside the function. The wire element stays `<Host>`.

## Not verified against hardware

The following are implemented strictly to the documented request shape and checked at the
XML level (request captured and inspected, in several cases via `-WhatIf`), but never executed
against a live appliance:

- **`LAG`, `BridgePair`** - no write test was run; a LAG would absorb a member port and dissolve
  its IP configuration, and the only lab interfaces available carry live session traffic.
- **`WiFi6Interface`** - the lab appliance reports `IS_WIFI6="0"`; there is no WiFi 6 hardware
  to test against.
- **`REDDevice`, `GreTunnel`, `GreRoute`, `TAP`** - no matching hardware/peer was available in
  the lab; `GreTunnel` requires a `LocalGateway` naming an existing local interface, which
  could not be satisfied.
- **Every write path (`New-`/`Set-`/`Remove-`) of `Interface`, `Zone`, `GatewayConfiguration`,
  `DNS`, `DHCPServer`, `DHCPServerStatus`, `DHCPServerIpv6`, `DHCPRelay`,
  `RouterAdvertisement` and `DynamicDNS`** - these carry the management path, DNS resolution
  or DHCP service of the lab appliance itself; a wrong write risked losing the only access
  path to the device, so they were deliberately not exercised. `Get-*` for all of these was
  run live and works.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific VLAN with error handling
    $vlan = Get-SfosVLAN -NameLike "DMZ-VLAN" -ErrorAction Stop
    Write-Output "Found VLAN: $($vlan.Name) - Interface: $($vlan.Interface), VLANID: $($vlan.VLANID)"
} catch {
    Write-Error "Failed to retrieve VLAN: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosInterface`/`Get-SfosVLAN`/`Get-SfosZone` etc. to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are entity-specific (Interface, VLAN, Zone, DNSHostEntry, ...)
- **`Remove-SfosVLAN` appears to succeed but the VLAN is still there**: See Known Firmware Limitations - removal by `Name` alone does nothing; the cmdlet resolves and verifies `Hardware` internally, so calling it with `-Interface`/`-VLANID` as documented is required
- **`New-SfosAlias` has no `-Name` parameter**: See Known Firmware Limitations - the firewall assigns the name; read it back with `Get-SfosAlias`
- **`New-SfosDNSRequestRoute`/`Set-SfosDNSRequestRoute` rejects a target server**: See Known Firmware Limitations - pass an existing `IPHost` object name, not an IP address
- **`New-SfosTAP` reports success but nothing appears**: See Known Firmware Limitations - an unrecognised `-Hardware` value is silently ignored by the firewall

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.Network) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License
