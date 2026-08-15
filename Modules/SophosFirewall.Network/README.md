# SophosFirewall.Network

`SophosFirewall.Network` manages the Network area of a Sophos Firewall: interfaces, VLANs,
link aggregation groups, bridge pairs and aliases, zones, the gateway configuration, DNS
(resolver settings, host entries, request routes, dynamic DNS), DHCP (servers, relays, IPv6,
the server on/off switch), static ARP and router advertisements, and tunnels (IP tunnels,
GRE tunnels and routes, TAP interfaces, RED devices, WiFi 6 interfaces and the cellular
WAN). It is for administrators who script network configuration instead of using the web
admin.

These cmdlets change the network configuration of a live appliance. A wrong IP address, a
zone assigned to the wrong interface, or a gateway change that severs the path back to the
management interface can make the appliance unreachable - and once that happens, the API you
would use to undo it is unreachable too. Every write cmdlet supports `-WhatIf`; use it before
running an unfamiliar call against a production firewall, and keep a second, independent
path to the device available before touching `Interface`, `Zone`, `GatewayConfiguration` or
anything that carries the session's own management traffic.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.Network -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosInterface | Format-Table Name, Hardware, NetworkZone, InterfaceStatus
Set-SfosInterface -Hardware 'Port1' -MTU 9000 -WhatIf
```

### VLANs and zones

```powershell
New-SfosVLAN -Name 'DMZ-VLAN' -Interface 'Port1' -VLANID 100 -Zone 'DMZ' -IPv4Assignment Static -IPAddress '198.51.100.1' -Netmask '255.255.255.0' -WhatIf
Set-SfosVLAN -Interface 'Port1' -VLANID 100 -Zone 'DMZ'
Remove-SfosVLAN -Interface 'Port1' -VLANID 100 -WhatIf

New-SfosZone -Name 'Extranet' -Type DMZ -Description 'Partner extranet' -WhatIf
(Get-SfosZone -NameLike 'LAN').ApplianceAccess
```

### DNS host entries and request routes

```powershell
$address = New-SfosDNSHostEntryAddress -EntryType Manual -IPFamily IPv4 -IPAddress '198.51.100.10'
New-SfosDNSHostEntry -HostName 'server.example.com' -Address $address -WhatIf

New-SfosDNSRequestRoute -DomainName 'internal.example.com' -TargetServer 'Internal-DNS-Server' -WhatIf
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosInterface` | Retrieves interface objects. |
| `Set-SfosInterface` | Updates a physical interface. |
| `New-SfosInterfaceIPv4Configuration` | Builds an IPv4 configuration for `Set-SfosInterface`. |
| `New-SfosInterfaceIPv6Configuration` | Builds an IPv6 configuration for `Set-SfosInterface`. |
| `New-SfosInterfaceMSSConfiguration` | Builds an MSS configuration for `Set-SfosInterface`. |
| `Get-SfosVLAN` | Retrieves VLAN objects. |
| `New-SfosVLAN` | Creates a VLAN sub-interface. |
| `Set-SfosVLAN` | Updates a VLAN. |
| `Remove-SfosVLAN` | Removes a VLAN. |
| `Get-SfosLAG` | Retrieves link aggregation group objects. |
| `New-SfosLAG` | Creates a link aggregation group. |
| `Set-SfosLAG` | Updates a link aggregation group. |
| `Remove-SfosLAG` | Removes a link aggregation group. |
| `New-SfosLAGMSSConfiguration` | Builds an MSS configuration for LAG cmdlets. |
| `Get-SfosBridgePair` | Retrieves bridge pair objects. |
| `New-SfosBridgePair` | Creates a bridge pair. |
| `Set-SfosBridgePair` | Updates a bridge pair. |
| `Remove-SfosBridgePair` | Removes a bridge pair. |
| `New-SfosBridgePairMSSConfiguration` | Builds an MSS configuration for bridge pair cmdlets. |
| `Get-SfosAlias` | Retrieves interface alias objects. |
| `New-SfosAlias` | Creates an interface alias. |
| `Set-SfosAlias` | Updates an interface alias. |
| `Remove-SfosAlias` | Removes an interface alias. |
| `Get-SfosCellularWAN` | Reads the cellular WAN modem state. |
| `Set-SfosCellularWAN` | Updates the cellular WAN modem state. |
| `Get-SfosIPTunnel` | Retrieves IP tunnel objects. |
| `New-SfosIPTunnel` | Creates an IP tunnel. |
| `Set-SfosIPTunnel` | Updates an IP tunnel. |
| `Remove-SfosIPTunnel` | Removes an IP tunnel. |
| `Get-SfosGreTunnel` | Retrieves GRE tunnel objects. |
| `New-SfosGreTunnel` | Creates a GRE tunnel. |
| `Set-SfosGreTunnel` | Updates a GRE tunnel. |
| `Remove-SfosGreTunnel` | Removes a GRE tunnel. |
| `Get-SfosGreRoute` | Retrieves GRE route objects. |
| `New-SfosGreRoute` | Creates a GRE route. |
| `Set-SfosGreRoute` | Updates a GRE route. |
| `Remove-SfosGreRoute` | Removes a GRE route. |
| `Get-SfosTAP` | Retrieves TAP interface objects. |
| `New-SfosTAP` | Configures a TAP interface. |
| `Set-SfosTAP` | Updates a TAP interface. |
| `Remove-SfosTAP` | Removes a TAP interface configuration. |
| `Get-SfosREDDevice` | Retrieves RED device objects. |
| `New-SfosREDDevice` | Creates a RED device. |
| `Set-SfosREDDevice` | Updates a RED device. |
| `Remove-SfosREDDevice` | Removes a RED device. |
| `Get-SfosWiFi6Interface` | Retrieves WiFi 6 interface objects. |
| `New-SfosWiFi6Interface` | Creates a WiFi 6 interface. |
| `Set-SfosWiFi6Interface` | Updates a WiFi 6 interface. |
| `Remove-SfosWiFi6Interface` | Removes a WiFi 6 interface. |
| `Get-SfosZone` | Retrieves zone objects. |
| `New-SfosZone` | Creates a zone. |
| `Set-SfosZone` | Updates a zone. |
| `Remove-SfosZone` | Removes a zone. |
| `Get-SfosGatewayConfiguration` | Reads the device-wide gateway configuration. |
| `Set-SfosGatewayConfiguration` | Updates the device-wide gateway configuration. |
| `New-SfosGatewayConfigurationGateway` | Builds a gateway entry for `Set-SfosGatewayConfiguration`. |
| `Get-SfosARPConfiguration` | Reads the ARP cache configuration. |
| `Set-SfosARPConfiguration` | Updates the ARP cache configuration. |
| `Get-SfosStaticARP` | Retrieves static ARP entries. |
| `New-SfosStaticARP` | Creates a static ARP entry. |
| `Set-SfosStaticARP` | Updates a static ARP entry. |
| `Remove-SfosStaticARP` | Removes a static ARP entry. |
| `Get-SfosRouterAdvertisement` | Retrieves router advertisement configurations. |
| `New-SfosRouterAdvertisement` | Creates a router advertisement configuration. |
| `Set-SfosRouterAdvertisement` | Updates a router advertisement configuration. |
| `Remove-SfosRouterAdvertisement` | Removes a router advertisement configuration. |
| `Get-SfosDNS` | Reads the DNS resolver settings. |
| `Set-SfosDNS` | Updates the DNS resolver settings. |
| `New-SfosDNSIPv4Settings` | Builds the IPv4 settings object for `Set-SfosDNS`. |
| `New-SfosDNSIPv6Settings` | Builds the IPv6 settings object for `Set-SfosDNS`. |
| `Get-SfosDNSHostEntry` | Retrieves DNS host entries. |
| `New-SfosDNSHostEntry` | Creates a DNS host entry. |
| `Set-SfosDNSHostEntry` | Updates a DNS host entry. |
| `Remove-SfosDNSHostEntry` | Removes a DNS host entry. |
| `New-SfosDNSHostEntryAddress` | Builds an address entry for DNS host entry cmdlets. |
| `Add-SfosDNSHostEntryMember` | Adds an address to a DNS host entry. |
| `Remove-SfosDNSHostEntryMember` | Removes an address from a DNS host entry. |
| `Get-SfosDNSRequestRoute` | Retrieves DNS request routes. |
| `New-SfosDNSRequestRoute` | Creates a DNS request route. |
| `Set-SfosDNSRequestRoute` | Updates a DNS request route. |
| `Remove-SfosDNSRequestRoute` | Removes a DNS request route. |
| `Add-SfosDNSRequestRouteMember` | Adds a target server to a DNS request route. |
| `Remove-SfosDNSRequestRouteMember` | Removes a target server from a DNS request route. |
| `Get-SfosDynamicDNS` | Retrieves dynamic DNS configurations. |
| `New-SfosDynamicDNS` | Creates a dynamic DNS configuration. |
| `Set-SfosDynamicDNS` | Updates a dynamic DNS configuration. |
| `Remove-SfosDynamicDNS` | Removes a dynamic DNS configuration. |
| `Get-SfosDHCPServer` | Retrieves DHCP server objects. |
| `New-SfosDHCPServer` | Creates a DHCP server. |
| `Set-SfosDHCPServer` | Updates a DHCP server. |
| `Remove-SfosDHCPServer` | Removes a DHCP server. |
| `Set-SfosDHCPServerStatus` | Switches an existing DHCP server on or off. |
| `Get-SfosDHCPServerIpv6` | Retrieves IPv6 DHCP server objects. |
| `New-SfosDHCPServerIpv6` | Creates an IPv6 DHCP server. |
| `Set-SfosDHCPServerIpv6` | Updates an IPv6 DHCP server. |
| `Remove-SfosDHCPServerIpv6` | Removes an IPv6 DHCP server. |
| `Get-SfosDHCPRelay` | Retrieves DHCP relay objects. |
| `New-SfosDHCPRelay` | Creates a DHCP relay. |
| `Set-SfosDHCPRelay` | Updates a DHCP relay. |
| `Remove-SfosDHCPRelay` | Removes a DHCP relay. |

## Limitations

Physical ports cannot be created or removed through this API; only `Get-SfosInterface` and
`Set-SfosInterface` exist.

`Remove-SfosVLAN` by `Name` alone does not remove anything; a VLAN is identified for removal
by the firewall-computed `Hardware` value, so the cmdlet resolves `Interface`/`VLANID` to
`Hardware` first and confirms the object is gone afterwards.

An interface alias has no caller-supplied name - the firewall derives one as
`Interface:Index`. `New-SfosAlias` has no `-Name` parameter; use `Get-SfosAlias` to find the
generated name for a later `Set-`/`Remove-` call.

`DNSRequestRoute` target servers must name an existing IP host object of type `IP`, not a
raw IP address.

`New-SfosTAP` with an unrecognised `-Hardware` value does not create anything and does not
report an error; check with `Get-SfosTAP` afterwards.

`StaticARP` has no in-place update; `Set-SfosStaticARP` removes the existing entry and
recreates it, with a brief gap in which the mapping does not exist.

`New-SfosIPTunnel` requires `-Hardware`. `Remove-SfosIPTunnel` needs both `Name` and
`Hardware`; when `-Hardware` is not supplied, the cmdlet resolves it through
`Get-SfosIPTunnel` first.

`BridgePair`'s MSS override parameter is `-Override`, not `-OverrideMSS` as on `Interface`,
`VLAN` and `LAG`.

`GatewayConfiguration` is a singleton with only `Get-`/`Set-` cmdlets; there is no `New-` or
`Remove-`.

`Get-SfosZone -TypeLike` filters client-side; the firewall's own filter on `Type` returns no
matches at all rather than the full set.

`New-`/`Set-SfosGreRoute` use `-HostAddress` (alias `-Host`) instead of `-Host`, because
`$Host` is an automatic PowerShell variable and a parameter of that name would shadow it.

`GreTunnel` has no delete operation documented for this entity in the vendor API.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [SophosFirewall.HostsAndServices](../SophosFirewall.HostsAndServices/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
