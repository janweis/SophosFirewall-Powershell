# SophosFirewall.Diagnostics

`SophosFirewall.Diagnostics` manages the MONITOR & ANALYZE > Diagnostics area of a Sophos
Firewall: remote support access. It is for administrators who need to open a temporary
channel for Sophos support to reach the appliance.

## Security note

Switching support access on lets Sophos support connect to the firewall's web admin console
and shell over TCP port 22, **without needing the administrator's own credentials**, for as
long as the chosen duration runs. It stays open until it is switched off again or the
duration expires; inactive sessions are closed after 15 minutes by the firewall itself, but
the channel itself is not. Treat `Set-SfosSupportAccess -ConfigOption Enable` the same way you
would treat handing out a temporary account: open it only for as long as it is actually
needed, and switch it off explicitly afterwards rather than relying on the duration to run
out unattended.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.Diagnostics -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosSupportAccess

Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' -Confirm:$false
Get-SfosSupportAccess

Set-SfosSupportAccess -ConfigOption Disable -Confirm:$false
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSupportAccess` | Reads the current support access state and, while it is on, its remaining duration. |
| `Set-SfosSupportAccess` | Switches support access on or off and sets its duration. |

## Behaviour worth knowing

**`ConfigOption` is always sent by `Set-SfosSupportAccess`, even when you do not pass it.**
The firewall accepts a write that omits it, answers success, and leaves the setting neither
Enable nor Disable. `Set-SfosSupportAccess` reads the current value first and resends it, and
throws instead of writing if that value cannot be resolved to Enable or Disable.

**The wire element is `GrantAccessFor`, one `r`.** The vendor's own attribute table spells it
`GrantAccessForr`, two `r`s; the firewall accepts a request using that spelling, answers `200`,
and silently resets the duration to its own default of one week instead of applying the value
sent. This module always uses the one-`r` spelling.

**The duration is only ever reported while support access is on.** `Get-SfosSupportAccess`
returns an empty string for `GrantAccessFor` while access is off, because the firewall itself
has nothing to report. Switching from off to on without passing `-GrantAccessFor` therefore
does not restore a previous duration - the firewall applies its own default of one week.

**The access ID shown in the web admin console is not available through the API.** Once
support access is switched on, the appliance generates an access ID that Sophos support uses
to connect; neither `Get-SfosSupportAccess` nor any other operation in this area exposes it.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
