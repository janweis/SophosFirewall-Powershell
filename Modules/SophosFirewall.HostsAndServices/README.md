# SophosFirewall.HostsAndServices

`SophosFirewall.HostsAndServices` manages the reusable network objects a Sophos Firewall
uses in rules and policies: IP hosts, FQDN hosts, MAC hosts, country groups, services and
their groups. It is for administrators who script the setup of these objects instead of
creating them one by one in the web admin.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write these object types

## Installation

```powershell
Install-Module SophosFirewall.HostsAndServices -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

New-SfosIPHost -Name 'WebServer' -HostType IP -IPAddress '192.0.2.50' -Description 'Web server'
Get-SfosIPHost -NameLike 'WebServer'
Set-SfosIPHost -Name 'WebServer' -HostType IP -IPAddress '192.0.2.50' -Description 'Updated web server'
Remove-SfosIPHost -Name 'WebServer'
```

### Groups

```powershell
New-SfosIPHostGroup -Name 'WebServers' -Description 'Production web tier'
Add-SfosIPHostGroupMember -Name 'WebServers' -members 'WebServer'
Remove-SfosIPHostGroupMember -Name 'WebServers' -members 'WebServer'
Remove-SfosIPHostGroup -Name 'WebServers'
```

### Services

```powershell
New-SfosService -Name 'CustomHTTPS' -Protocol TCP -DstPort '8443' -SrcPort '1:65535'
New-SfosServiceGroup -Name 'WebServices' -members 'CustomHTTPS' -Description 'Web-related services'
```

### Bulk export and import

Every object type has matching `Export-Sfos*`/`Import-Sfos*` cmdlets for round-tripping a
whole set of objects through a CSV file:

```powershell
Export-SfosIPHosts -FilePath 'C:\Backup\ip_hosts.csv'
Import-SfosIPHosts -FilePath 'C:\Backup\ip_hosts.csv'
```

## Cmdlets

### IP hosts

| Cmdlet | Purpose |
|---|---|
| `Get-SfosIPHost` | Retrieves IP host objects. |
| `New-SfosIPHost` | Creates an IP host object. |
| `Set-SfosIPHost` | Updates an IP host object. |
| `Remove-SfosIPHost` | Removes an IP host object. |
| `Export-SfosIPHosts` | Exports IP host objects to a file. |
| `Import-SfosIPHosts` | Imports IP host objects from a file. |

### IP host groups

| Cmdlet | Purpose |
|---|---|
| `Get-SfosIPHostGroup` | Retrieves IP host groups and their members. |
| `New-SfosIPHostGroup` | Creates an IP host group. |
| `Set-SfosIPHostGroup` | Updates an IP host group. |
| `Remove-SfosIPHostGroup` | Removes an IP host group. |
| `Add-SfosIPHostGroupMember` | Adds members to an IP host group. |
| `Remove-SfosIPHostGroupMember` | Removes members from an IP host group. |
| `Export-SfosIPHostGroups` | Exports IP host groups to a file. |
| `Import-SfosIPHostGroups` | Imports IP host groups from a file. |

### FQDN hosts

| Cmdlet | Purpose |
|---|---|
| `Get-SfosFQDNHost` | Retrieves FQDN host objects. |
| `New-SfosFQDNHost` | Creates an FQDN host object. |
| `Set-SfosFQDNHost` | Updates an FQDN host object. |
| `Remove-SfosFQDNHost` | Removes an FQDN host object. |
| `Remove-SfosFQDNHostMass` | Removes several FQDN host objects in one request. |
| `Export-SfosFQDNHosts` | Exports FQDN host objects to a file. |
| `Import-SfosFQDNHosts` | Imports FQDN host objects from a file. |

### FQDN host groups

| Cmdlet | Purpose |
|---|---|
| `Get-SfosFQDNHostGroup` | Retrieves FQDN host groups and their members. |
| `New-SfosFQDNHostGroup` | Creates an FQDN host group. |
| `Set-SfosFQDNHostGroup` | Updates an FQDN host group. |
| `Remove-SfosFQDNHostGroup` | Removes an FQDN host group. |
| `Add-SfosFQDNHostGroupMember` | Adds members to an FQDN host group. |
| `Remove-SfosFQDNHostGroupMember` | Removes members from an FQDN host group. |
| `Export-SfosFQDNHostGroups` | Exports FQDN host groups to a file. |
| `Import-SfosFQDNHostGroups` | Imports FQDN host groups from a file. |

### MAC hosts

| Cmdlet | Purpose |
|---|---|
| `Get-SfosMACHost` | Retrieves MAC host objects. |
| `New-SfosMACHost` | Creates a MAC host object. |
| `Set-SfosMACHost` | Updates a MAC host object. |
| `Remove-SfosMACHost` | Removes a MAC host object. |
| `Export-SfosMACHosts` | Exports MAC host objects to a file. |
| `Import-SfosMACHosts` | Imports MAC host objects from a file. |

### Country groups

| Cmdlet | Purpose |
|---|---|
| `Get-SfosCountryGroup` | Retrieves country group objects. |
| `New-SfosCountryGroup` | Creates a country group. |
| `Set-SfosCountryGroup` | Updates a country group. |
| `Remove-SfosCountryGroup` | Removes a country group. |

### Services

| Cmdlet | Purpose |
|---|---|
| `Get-SfosService` | Retrieves service definitions. |
| `New-SfosService` | Creates a service definition. |
| `Set-SfosService` | Updates a service definition. |
| `Remove-SfosService` | Removes a service definition. |
| `Export-SfosServices` | Exports service definitions to a file. |
| `Import-SfosServices` | Imports service definitions from a file. |

### Service groups

| Cmdlet | Purpose |
|---|---|
| `Get-SfosServiceGroup` | Retrieves service groups and their members. |
| `New-SfosServiceGroup` | Creates a service group. |
| `Set-SfosServiceGroup` | Updates a service group. |
| `Remove-SfosServiceGroup` | Removes a service group. |
| `Add-SfosServiceGroupMember` | Adds members to a service group. |
| `Remove-SfosServiceGroupMember` | Removes members from a service group. |
| `Export-SfosServiceGroups` | Exports service groups to a file. |
| `Import-SfosServiceGroups` | Imports service groups from a file. |

## Limitations

A country group is created and filtered with the country's full name, not its ISO code -
`New-SfosCountryGroup -Countries 'China'` is accepted, `'CN'` is rejected. Use
`Get-SfosCountryGroup` on an existing group to see the exact spelling the firewall expects.
Its member list is returned in a property named `Countries`, while host and service groups
use `HostList` and `ServiceList`.

`Get-SfosService` returns an ICMP or ICMPv6 type as text (for example `Echo`), while
`New-SfosService` and `Set-SfosService` expect the matching numeric code (for example `8`)
for the same field. Piping a `Get-SfosService` result for an ICMP service directly into
`New-SfosService` does not work; the numeric code has to be supplied separately.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
