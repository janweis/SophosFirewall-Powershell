# SophosFirewall.SystemServices Module

## Overview

The **SystemServices** module provides PowerShell cmdlets for the **CONFIGURE >
System Services** area of the Sophos XGS / SFOS 22.0 API documentation. With 19
exported functions, it manages QoS (traffic shaping) policies, syslog servers,
the system service daemon manager, High Availability configuration, and RED
(Remote Ethernet Device) broker configuration. Requires `SophosFirewall.Core`
(minimum version 1.3.0).

## Features

- **QoS Policy**: Full CRUD for `QoSPolicy` (traffic shaping) objects, covering
  all four bandwidth field-group combinations and schedule-based override rules
- **Syslog Servers**: Full CRUD for `SyslogServers` objects, including the
  generic per-category `LogSettings` subtree
- **System Services daemon manager**: `Get-SfosSystemServiceStatus` and
  `Set-SfosSystemService` to read and start/stop/restart the ten
  daemon-managed services (AntiSpam, AntiVirus, Authentication, DHCPServer,
  DNSServer, IPS, WebProxy, WAF, DHCPv6Server, RouterAdvertisementService)
- **High Availability**: `Get-`/`Initialize-`/`Reset-`/`Disable-SfosHAConfiguration` for interactive and QuickHA
  setup, disable and reset
- **RED**: `Get-`/`Set-SfosREDConfiguration` for the broker registration, plus
  TLS version settings, automatic device deauthorization settings, and the
  beta firmware toggle
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML
  API

## Installation

```powershell
Install-Module -Name SophosFirewall.SystemServices
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.SystemServices.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module, version 1.3.0 or higher (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### Multi-Session: Recreate a QoS Policy on a Second Firewall

```powershell
Connect-SfosFirewall -Firewall "fw1.example.test" -Credential (Get-Credential) -Name fw1
Connect-SfosFirewall -Firewall "fw2.example.test" -Credential (Get-Credential) -Name fw2 -NoDefault

# Read a policy from fw1 and create the same shape on fw2, without touching the
# ambient default session.
$policy = Get-SfosQoSPolicy -Session fw1 -NameLike "Branch Office Cap"
New-SfosQoSPolicy -Session fw2 -Name $policy.Name -PolicyBasedOn $policy.PolicyBasedOn `
    -ImplementationOn $policy.ImplementationOn -PolicyType $policy.PolicyType `
    -Priority $policy.Priority -TotalBandwidth $policy.TotalBandwidth
```

### QoS Policy

```powershell
# List every QoS policy (43 default policies ship on a fresh appliance)
Get-SfosQoSPolicy

# Find a policy by name (substring match, server-side filter confirmed working)
Get-SfosQoSPolicy -NameLike 'Streaming Video'

# A hard per-user total bandwidth limit
New-SfosQoSPolicy -Name 'Branch Office Cap' -PolicyBasedOn User -ImplementationOn Total `
    -PolicyType Strict -Priority Normal3 -TotalBandwidth 512

# Raise the limit on an existing Total/Strict policy, everything else preserved
Set-SfosQoSPolicy -Name 'Branch Office Cap' -ImplementationOn Total -PolicyType Strict -TotalBandwidth 1024

Remove-SfosQoSPolicy -Name 'Branch Office Cap'
```

### Syslog Servers

```powershell
Get-SfosSyslogServer

# Inspect one server's per-category log settings
(Get-SfosSyslogServer -NameLike 'Central').LogSettings.AntiVirus

# A syslog target with default (all-disabled) log category settings
New-SfosSyslogServer -Name 'Branch Syslog' -ServerAddress 'syslog.example.internal' `
    -SyslogPort 514 -EnableSecureConnection Disable -SeverityLevel Information

# Change only the severity level, LogSettings and everything else unchanged
Set-SfosSyslogServer -Name 'Branch Syslog' -SeverityLevel Debug

# Change one log category leaf and write the whole subtree back
$srv = Get-SfosSyslogServer -NameLike 'Branch Syslog'
$srv.LogSettings.AntiVirus.HTTP = 'Enable'
Set-SfosSyslogServer -Name $srv.Name -LogSettings $srv.LogSettings

Remove-SfosSyslogServer -Name 'Branch Syslog'
```

### System Services daemon manager

```powershell
Get-SfosSystemServiceStatus

Get-SfosSystemServiceStatus -NameLike 'DHCP'

Set-SfosSystemService -Name AntiVirus -Action Restart

Get-SfosSystemServiceStatus -NameLike 'DHCP' | Set-SfosSystemService -Action Restart
```

### High Availability

`Initialize-SfosHAConfiguration` configures **and forms** a cluster (the appliance reboots
and pairs immediately - it is not a passive setting). The dedicated HA link must be an
unbound, DMZ, LAG or VLAN interface - interactive mode accepts DMZ/LAG/VLAN, QuickHA also
accepts an unbound physical port. Both appliances must run identical firmware or the cluster
will not form. **Interactive mode also requires SSH allowed on the dedicated link's zone
(Appliance Access) on both appliances** - without it the primary write answers 556.

```powershell
Get-SfosHAConfiguration

$pw = Read-Host -AsSecureString

# QuickHA (auto HA-link IPs) with an unbound physical port: auxiliary first, then primary.
Initialize-SfosHAConfiguration -Quick -Device Auxilliary -NodeName node2 -DedicatedLink Port4 -Passphrase $pw
Initialize-SfosHAConfiguration -Quick -Device Active_Passive -NodeName node1 -DedicatedLink Port4 -Passphrase $pw

# Interactive mode with monitored ports and a peer administration address (DMZ/LAG/VLAN link).
Initialize-SfosHAConfiguration -Device Active_Passive -NodeName node1 `
    -ClusterID 1 -Passphrase $pw -DedicatedLink PortB.100 -DedicatedLinkIPAddress '169.254.0.2' `
    -MonitorPort Port2,Port3 -PeerAdministrationInterface Port3 -PeerAdministrationIPv4 '10.0.0.60' -WhatIf

Reset-SfosHAConfiguration -WhatIf
Disable-SfosHAConfiguration -WhatIf
```

For a full step-by-step walkthrough of building a cluster (prerequisites, auxiliary-first
ordering, verification and teardown), see **[HA-Setup.md](HA-Setup.md)**.

### RED

```powershell
Get-SfosREDConfiguration

Set-SfosREDConfiguration -Status Disable -WhatIf

Get-SfosREDTLSVersionSettings

Set-SfosREDTLSVersionSettings -TLSVersion 'TLS v1.2 (strict) and later' -WhatIf

Get-SfosREDDeviceDeauthorizationSettings

Set-SfosREDDeviceDeauthorizationSettings -AutoDeauthorization Enable -DeauthorizeAfter 120 -WhatIf

Set-SfosREDBetaFirmware -RunBetaFirmware Disable -WhatIf
```

## Available Cmdlets (19 total)

### QoS Policy (4 functions)
- `Get-SfosQoSPolicy` - Retrieves QoSPolicy (traffic shaping) objects from the Sophos Firewall.
- `New-SfosQoSPolicy` - Creates a new QoSPolicy (traffic shaping policy) on the Sophos Firewall.
- `Set-SfosQoSPolicy` - Updates an existing QoSPolicy (traffic shaping policy) on the Sophos Firewall.
- `Remove-SfosQoSPolicy` - Removes a QoSPolicy object from the Sophos Firewall.

### Syslog Servers (4 functions)
- `Get-SfosSyslogServer` - Retrieves SyslogServers objects from the Sophos Firewall.
- `New-SfosSyslogServer` - Creates a new SyslogServers object on the Sophos Firewall.
- `Set-SfosSyslogServer` - Updates an existing SyslogServers object on the Sophos Firewall.
- `Remove-SfosSyslogServer` - Removes a SyslogServers object from the Sophos Firewall.

### System Services daemon manager (2 functions)
- `Get-SfosSystemServiceStatus` - Retrieves the status of the Sophos Firewall daemon-managed system services.
- `Set-SfosSystemService` - Starts, stops or restarts a Sophos Firewall daemon-managed system service.

### High Availability (2 functions)
- `Get-SfosHAConfiguration` - Retrieves the High Availability (HA) configuration of the Sophos Firewall.
- `Initialize-SfosHAConfiguration` - Configures and forms an HA cluster in interactive or QuickHA mode.
- `Reset-SfosHAConfiguration` - Resets the interactive HA configuration back to unconfigured.
- `Disable-SfosHAConfiguration` - Disables High Availability on the Sophos Firewall.

### RED (7 functions)
- `Get-SfosREDConfiguration` - Retrieves the RED (Remote Ethernet Device) broker configuration of the Sophos Firewall.
- `Set-SfosREDConfiguration` - Configures the RED broker registration of the Sophos Firewall.
- `Get-SfosREDTLSVersionSettings` - Retrieves the TLS version setting used for RED broker connections.
- `Set-SfosREDTLSVersionSettings` - Sets the TLS version setting used for RED broker connections.
- `Get-SfosREDDeviceDeauthorizationSettings` - Retrieves the automatic RED device deauthorization settings of the Sophos Firewall.
- `Set-SfosREDDeviceDeauthorizationSettings` - Sets the automatic RED device deauthorization settings of the Sophos Firewall.
- `Set-SfosREDBetaFirmware` - Enables or disables RED beta firmware on the Sophos Firewall.

## Known behaviour / limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance unless marked otherwise.

- **`QoSPolicy`**: `BandwidthUsageType` takes the plain-text values `Individual` or
  `Shared`. The attribute table's `on`/`off` form is silently accepted with code `200`
  but blanks **both** `BandwidthUsageType` and `PolicyBasedOn` on the stored object -
  the API does not validate the enum and a bad value corrupts unrelated fields rather
  than failing the request, so this module enforces a client-side `ValidateSet` on
  both fields. `PolicyBasedOn 'Firewall'` (the doc table's spelling) is accepted but
  stored as `'FirewallRule'`; this module sends `'FirewallRule'` directly rather than
  relying on that undocumented normalisation. The server-side name filter works for
  this entity.
- **`SyslogServers`**: the server-side filter is broken - any `<Filter>` block,
  regardless of key, criteria or value, makes the appliance return exactly one fixed
  record instead of the matching or full set, so `Get-SfosSyslogServer` never sends a
  `<Filter>`; `-NameLike` is client-side only. `Facility` must be upper-case
  (`LOCAL3`); the sample XML's mixed-case form (`Local3`) is rejected with `501`.
  Creating without `-LogSettings` is accepted and the appliance fills in the full
  category structure itself with every leaf set to `Disable`. The port parameter is
  named `-SyslogPort`, not `-Port`, because `-Port` is reserved for the connection's
  API management port.
- **`SystemServices` (daemon manager)**: only `Start`/`Stop`/`Restart` are
  documented and accepted - there is no `Disable` action. A `Stop` was measured to
  answer the undocumented code `202` ("Unable to get status message"), confirmed by a
  follow-up read that the daemon was actually `STOPPED`. `Set-SfosSystemService`
  therefore treats `202` as a local success-with-warning for this one call, without
  changing Core's shared status-code table. The write response's `<Status>` sits flat
  at `/Response/<Daemon>/Status`, one level shallower than the nested `Get` response.
- **`HAConfigure`**: `[RISK]` - the Set path was verified only structurally (captured
  request XML), never against a live HA pair, since neither lab appliance has an HA
  peer and activating HA is disruptive and not reversible from the API alone.
  `Get-SfosHAConfiguration` on an appliance with no HA peer configured answers a
  code-less `<Status>Transaction fail</Status>` with no other fields present, which
  this module reads as "HA is not configured" and returns nothing for, rather than
  throwing.
- **RED**: `[HW]` - no RED hardware is available in the lab; `Get-SfosREDConfiguration`
  and the other RED `Get-*` cmdlets are live-verified, all RED `Set-*` cmdlets are
  documentation-faithful and verified only structurally. `REDConfiguration`'s own
  `<Status>` field (`Enable`/`Disable`) is plain data, not an API status - it carries
  no `code` attribute and no sibling `<Name>`, which is exactly the shape Core's
  generic status heuristic would otherwise misread as an unrecognised error.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific policy with error handling
    $policy = Get-SfosQoSPolicy -NameLike "Branch Office Cap" -ErrorAction Stop
    Write-Output "Found policy: $($policy.Name) - Priority: $($policy.Priority)"
} catch {
    Write-Error "Failed to retrieve policy: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosQoSPolicy | Select-Object Name` or `Get-SfosSyslogServer | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **`Get-SfosSyslogServer -NameLike` returns one unexpected fixed record when a raw `<Filter>` is sent by hand**: See Known behaviour - the server-side filter is broken for this entity, so the cmdlet never sends one; use the client-side `-NameLike` instead
- **`Set-SfosSystemService -Action Stop` reports a warning instead of an error**: See Known behaviour - code `202` is treated as success-with-warning for this one measured, readback-confirmed case
- **`Get-SfosHAConfiguration` returns nothing on an appliance with no HA peer**: See Known behaviour - this is the entity's own way of saying "not configured", not a failed request

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.SystemServices) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License

MIT License - see [LICENSE.txt](LICENSE.txt) for details.
