# SophosFirewall.SystemServices

`SophosFirewall.SystemServices` manages the System Services area of a Sophos Firewall: QoS
(traffic shaping) policies, syslog servers, the daemon-managed system services, High
Availability configuration, and RED (Remote Ethernet Device) broker configuration. It is
for administrators who script this configuration instead of maintaining it in the web
admin.

`Initialize-SfosHAConfiguration` forms an HA cluster immediately - the appliance reboots and
pairs with its peer as part of the call, it does not just store a setting. Read the
Limitations section and, for a full walkthrough, [HA-Setup.md](HA-Setup.md) before running
it against a production pair.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.SystemServices -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

New-SfosQoSPolicy -Name 'Branch Office Cap' -PolicyBasedOn User -ImplementationOn Total `
    -PolicyType Strict -Priority Normal3 -TotalBandwidth 512

Get-SfosQoSPolicy -NameLike 'Branch Office Cap'
Set-SfosQoSPolicy -Name 'Branch Office Cap' -ImplementationOn Total -PolicyType Strict -TotalBandwidth 1024
Remove-SfosQoSPolicy -Name 'Branch Office Cap'
```

### Syslog servers and the daemon manager

```powershell
New-SfosSyslogServer -Name 'Branch Syslog' -ServerAddress 'syslog.example.com' `
    -SyslogPort 514 -EnableSecureConnection Disable -SeverityLevel Information
Set-SfosSyslogServer -Name 'Branch Syslog' -SeverityLevel Debug
Remove-SfosSyslogServer -Name 'Branch Syslog'

Get-SfosSystemServiceStatus -NameLike 'DHCP'
Set-SfosSystemService -Name AntiVirus -Action Restart
```

### High Availability and RED

```powershell
Get-SfosHAConfiguration

$pw = Read-Host -AsSecureString
Initialize-SfosHAConfiguration -Quick -Device Auxilliary -NodeName node2 -DedicatedLink Port4 -Passphrase $pw -WhatIf

Get-SfosREDConfiguration
Set-SfosREDConfiguration -Status Disable -WhatIf
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosQoSPolicy` | Retrieves QoS (traffic shaping) policies. |
| `New-SfosQoSPolicy` | Creates a QoS policy. |
| `Set-SfosQoSPolicy` | Updates a QoS policy. |
| `Remove-SfosQoSPolicy` | Removes a QoS policy. |
| `Get-SfosSyslogServer` | Retrieves syslog server objects. |
| `New-SfosSyslogServer` | Creates a syslog server object. |
| `Set-SfosSyslogServer` | Updates a syslog server object. |
| `Remove-SfosSyslogServer` | Removes a syslog server object. |
| `Get-SfosSystemServiceStatus` | Reads the status of the daemon-managed system services. |
| `Set-SfosSystemService` | Starts, stops or restarts a daemon-managed system service. |
| `Get-SfosHAConfiguration` | Reads the High Availability configuration. |
| `Initialize-SfosHAConfiguration` | Configures and forms an HA cluster. |
| `Reset-SfosHAConfiguration` | Resets the interactive HA configuration to unconfigured. |
| `Disable-SfosHAConfiguration` | Disables High Availability. |
| `Get-SfosREDConfiguration` | Reads the RED broker configuration. |
| `Set-SfosREDConfiguration` | Updates the RED broker configuration. |
| `Get-SfosREDTLSVersionSettings` | Reads the TLS version used for RED broker connections. |
| `Set-SfosREDTLSVersionSettings` | Sets the TLS version used for RED broker connections. |
| `Get-SfosREDDeviceDeauthorizationSettings` | Reads the automatic RED device deauthorization settings. |
| `Set-SfosREDDeviceDeauthorizationSettings` | Updates the automatic RED device deauthorization settings. |
| `Set-SfosREDBetaFirmware` | Enables or disables RED beta firmware. |

## Limitations

`Set-SfosQoSPolicy` and `New-SfosQoSPolicy` accept only the named `BandwidthUsageType`
values `Individual` or `Shared`; any other value can blank both `BandwidthUsageType` and
`PolicyBasedOn` on the stored object. `PolicyBasedOn Firewall` is stored and read back as
`FirewallRule`.

`Get-SfosSyslogServer`'s `-NameLike` filters client-side; sending a server-side filter to
this entity returns one fixed record instead of the matching set. `Facility` must be
upper-case (for example `LOCAL3`). Creating a syslog server without `-LogSettings` leaves
every log category disabled.

`Set-SfosSystemService` only supports `Start`, `Stop` and `Restart`; there is no `Disable`
action.

`Get-SfosHAConfiguration` returns nothing on an appliance with no HA peer configured; this
is the entity's own way of reporting "not configured", not a failed request.

`Get-SfosREDConfiguration`'s `Status` field describes whether the RED feature itself is
enabled; it is a data field, not an indicator of whether the API call succeeded.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
