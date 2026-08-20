# SophosFirewall.SophosCentral

`SophosFirewall.SophosCentral` manages the SYSTEM > Sophos Central area of a Sophos
Firewall: the cloud central management switches - centralized reporting, management from
Sophos Central, and configuration backup.

## What this module does not do

**It does not register a firewall with Sophos Central, and that is deliberate.** The API
offers exactly one registration operation, and it carries the account name and password of a
Sophos Central administrator in the request body - Sophos requires a super admin account
outside any sub-estate for it. A tenant secured with a passkey or any other passwordless
sign-in cannot supply those credentials at all, and the one-time password the web admin
console offers as the alternative has no API equivalent: it appears in the administrator help
and in no API operation. Register the firewall in the console, then use this module for the
switches.

The same applies to clearing a registration and to the separate disable-management
operation. Both exist in the API, neither can be verified from this side: they have no read
path, so nothing can confirm what they did, and exercising them means acting on a live
registration. Shipping cmdlets whose effect has never been observed would be worse than
leaving them out.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission
- A firewall already registered with Sophos Central, if the switches are to have any effect

## Installation

```powershell
Install-Module SophosFirewall.SophosCentral -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosCentralManagement

Set-SfosCentralManagement -UseCentralReporting Disable -Confirm:$false
Get-SfosCentralManagement
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosCentralManagement` | Reads the four cloud central management switches: configuration backup, join method, centralized reporting, management from Sophos Central. |
| `Set-SfosCentralManagement` | Updates those switches, reading the current object first and resending every field. |

## Behaviour worth knowing

**A service can be switched off through the API but not switched back on.** Turning
`UseCentralReporting` or `CMStatus` off works and is visible immediately. Turning either back
on is accepted, answered `200 Configuration applied successfully.` and not applied, because a
service that is switched on has to be confirmed by a super admin in the Sophos Central
console with *Accept services*. There is no API operation for that confirmation. Treat every
switch here as one-way: what you turn off from PowerShell, you turn back on in the console.

**`Set-SfosCentralManagement` reads the object back and throws when a change did not take
effect.** A write that reports success and changes nothing is the worst outcome available,
so the cmdlet does not rely on the status code alone.

**These switches have a third value that no documentation mentions.** After a service is
switched on in the console, `Get-SfosCentralManagement` reports `WaitingForApproval` for it
until a super admin accepts it in Sophos Central; only then does it read `Enable`. A `Set`
may request `Enable` or `Disable`; a field that comes back as `WaitingForApproval` produces a
warning rather than an error, because the request was accepted and is pending.

**`FWBackup` depends on `CMStatus`.** In the web admin console the configuration backup
checkbox is nested under *Manage from Sophos Central*. `Set-SfosCentralManagement` refuses to
set `FWBackup` to `BackupEnable` while the resolved `CMStatus` is `Disable`, and throws a
message naming both fields rather than sending a combination the console itself cannot
produce.

**Nothing here reports the registration state.** Registration and these switches are
independent according to Sophos: turning a switch off does not end a registration, and a
switch can read `Enable` without a registration ever having been confirmed. No API entity on
the firewall exposes whether it is registered - the web admin console is the only place that
shows it.

**Two of the four fields are undocumented.** `UseCentralReporting` and `CMStatus` appear in
neither the attribute table nor the sample XML of the vendor's API reference; only a live
object shows them. The wire element for the settings object is
`EnableCloudCentralManagement`, which despite its name is a settings object rather than a
command.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
