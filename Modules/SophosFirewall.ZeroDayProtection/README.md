# SophosFirewall.ZeroDayProtection

`SophosFirewall.ZeroDayProtection` manages the MONITOR & ANALYZE > Zero-day protection area of a
Sophos Firewall: the cloud datacenter used for sandbox analysis of new downloads and email
attachments, and the file types excluded from that analysis. It is for administrators who need
to steer where analysis happens (for example for data-residency reasons) or exempt certain file
types from being sent to the cloud.

There is exactly one instance of this configuration object per firewall.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.ZeroDayProtection -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosZeroDayProtectionSettings

Set-SfosZeroDayProtectionSettings -ExcludeFileTypes 'Audio Files', 'Video Files'
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosZeroDayProtectionSettings` | Reads the zero-day protection settings. |
| `Set-SfosZeroDayProtectionSettings` | Updates the datacenter location and/or the excluded file types. |

## Limitations

**`ExcludeFileTypes` accepts only the names of existing `FileType` objects**, not free text.
`Get-SfosFileType` from `SophosFirewall.Web` lists the valid names. An unknown name is rejected
with status `501`. The vendor sample names `Database File`, which does not exist on the
appliance - the correct name is `Database Files`; do not copy that example unchecked.

**A `Set` replaces the whole object.** A field that is not sent is cleared, not left alone -
`Set-SfosZeroDayProtectionSettings` reads the current settings first and resends every field so
that a call passing only one parameter leaves the other one in place.

**Changing the datacenter may discard analysis in progress**, per the Sophos admin help: files
currently being processed by zero-day protection lose that analysis when the datacenter changes.

**The 50-file-type limit (status `502`) is documented but not enforced by this module** - it is
not exercised by a write, to avoid an unnecessary change to a security setting during testing.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
