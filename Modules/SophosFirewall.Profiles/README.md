# SophosFirewall.Profiles

`SophosFirewall.Profiles` manages the SYSTEM > Profiles area of a Sophos Firewall: schedules,
access time policies, data transfer policies, decryption profiles and administration profiles.
A profile is an object that other rules point at instead of repeating the same settings: a
schedule names the times a rule is active, an access time policy allows or denies internet
access during a schedule, a data transfer policy caps how much a user may transfer, a
decryption profile decides how TLS connections are inspected, and an administration profile is
the role that decides what an administrator may see and change. It is for administrators who
build and maintain firewall rules, web filter policies and admin accounts that reference these
profiles.

An administration profile is a role, not a per-account setting. Changing or removing one
changes the rights of every administrator it is currently assigned to.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.Profiles -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

New-SfosSchedule -Name 'Night shift' -Type Recurring -Days 'Week Days' -StartTime '22:00' -StopTime '06:00'
New-SfosAccessTimePolicy -Name 'Night access' -Strategy Allow -Schedule 'Night shift'

Get-SfosSchedule
Get-SfosAccessTimePolicy -StrategyLike Allow

New-SfosDataTransferPolicy -Name '10 GB Monthly' -RestrictionBasedOn TotalDataTransfer -CycleType Cyclic -CyclePeriod Month -CycleDataTransferInMB 10240

New-SfosDecryptionProfile -Name 'Standard TLS' -MinTLSVersion 'TLS v1.2'

New-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Write
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSchedule` | Reads schedule objects. |
| `New-SfosSchedule` | Creates a schedule object. |
| `Set-SfosSchedule` | Updates a schedule object. |
| `Remove-SfosSchedule` | Removes a schedule object. |
| `Get-SfosAccessTimePolicy` | Reads access time policies. |
| `New-SfosAccessTimePolicy` | Creates an access time policy. |
| `Set-SfosAccessTimePolicy` | Updates an access time policy. |
| `Remove-SfosAccessTimePolicy` | Removes an access time policy. |
| `Get-SfosDataTransferPolicy` | Reads data transfer policies. |
| `New-SfosDataTransferPolicy` | Creates a data transfer policy. |
| `Set-SfosDataTransferPolicy` | Updates a data transfer policy. |
| `Remove-SfosDataTransferPolicy` | Removes a data transfer policy. |
| `Get-SfosDecryptionProfile` | Reads decryption profiles. |
| `New-SfosDecryptionProfile` | Creates a decryption profile. |
| `Set-SfosDecryptionProfile` | Updates a decryption profile. |
| `Remove-SfosDecryptionProfile` | Removes a decryption profile. |
| `Get-SfosAdministrationProfile` | Reads administration profiles (roles). |
| `New-SfosAdministrationProfile` | Creates an administration profile. |
| `Set-SfosAdministrationProfile` | Updates an administration profile. |
| `Remove-SfosAdministrationProfile` | Removes an administration profile. |

## Limitations

A schedule named "All the time" is referenced by the predefined access time policies but does
not appear in `Get-SfosSchedule`. Schedule names are therefore not checked client-side against
the existing schedule objects; a value that only exists as a built-in reference is still
accepted.

`New-SfosDecryptionProfile` does not send `IsDefault`; the firewall sets it to `no` on its own.

The two TLS version bounds, `MinTLSVersion` and `MaxTLSVersion`, are always sent together. If
only one is given, the cmdlet fills in the other before sending the request.

An administration profile is a role. Changing or removing one changes the permissions of every
administrator account it is currently assigned to.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
