# SophosFirewall.WebServer

`SophosFirewall.WebServer` manages the PROTECT > Web server area of a Sophos Firewall - the
reverse proxy (WAF) that publishes an internal web server to the outside and filters the
traffic on its way in. A web server names the internal machine and the port it listens on. A
protection policy decides what happens to a request before it reaches that machine: request
size limits, form and URL hardening, virus scanning and the threat filters. An authentication
policy puts a login in front of the published server and can pass the credentials on to it; an
authentication template supplies the HTML form such a policy shows. Slow HTTP protection guards
against clients that hold connections open by sending their request headers a byte at a time.

It is for administrators who publish internal web applications through the firewall.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.WebServer -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

# The host is an existing host object, not an address
New-SfosIPHost -Name 'IntranetServerHost' -HostType IP -IPAddress '192.0.2.50'
New-SfosWebServer -Name 'IntranetServer' -HostName 'IntranetServerHost' -PortNumber 8080

New-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Mode Reject -RequestSizeLimitMB 10 -AntiVirus Enable -AVMode DualScan

New-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth' -VirtualWebserverMode Basic `
    -FrontendRealm 'intranetrealm' -BasicPrompt 'Please sign in.' -RealWebserverMode Basic -UsernameAffix Basic

Get-SfosWebServer
Get-SfosWebServerProtectionPolicy -NameLike 'Exchange'
Get-SfosWebServerSlowHTTPProtectionSettings
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosWebServer` | Reads published web servers. |
| `New-SfosWebServer` | Publishes a web server. |
| `Set-SfosWebServer` | Updates a published web server. |
| `Remove-SfosWebServer` | Removes a published web server. |
| `Get-SfosWebServerProtectionPolicy` | Reads protection policies. |
| `New-SfosWebServerProtectionPolicy` | Creates a protection policy. |
| `Set-SfosWebServerProtectionPolicy` | Updates a protection policy. |
| `Remove-SfosWebServerProtectionPolicy` | Removes a protection policy. |
| `Get-SfosWebServerAuthenticationPolicy` | Reads authentication policies. |
| `New-SfosWebServerAuthenticationPolicy` | Creates an authentication policy. |
| `Set-SfosWebServerAuthenticationPolicy` | Updates an authentication policy. |
| `Remove-SfosWebServerAuthenticationPolicy` | Removes an authentication policy. |
| `Get-SfosWebServerAuthenticationTemplate` | Downloads an authentication form template. |
| `New-SfosWebServerAuthenticationTemplate` | Uploads a new authentication form template. |
| `Set-SfosWebServerAuthenticationTemplate` | Replaces the template (and assets) of an authentication form template. |
| `Remove-SfosWebServerAuthenticationTemplate` | Removes an authentication form template. |
| `Get-SfosWebServerSlowHTTPProtectionSettings` | Reads the slow HTTP protection settings. |
| `Set-SfosWebServerSlowHTTPProtectionSettings` | Updates the slow HTTP protection settings. |

The cmdlet names carry the area name because the suite already has an `Authentication` module:
a bare `Get-SfosAuthenticationPolicy` would not say which kind of authentication it means.

## Limitations

**Authentication templates can be created and changed, but not removed.** `New-` and
`Set-SfosWebServerAuthenticationTemplate` upload the HTML template file (and, optionally, one
or more asset files such as a stylesheet) through the multipart transport added to
`SophosFirewall.Core` 1.3.5 - the file name given to `-TemplateFile`/`-AssetFile` is what the
firewall stores as the reference, so the file itself and its XML reference always agree.
`Set-*` cannot do the usual read-modify-write: a `Get` on this entity never returns parsed
fields (see below), so there is nothing to merge into. It checks the object exists, then
uploads a full replacement - a `Set-*` call without `-AssetFile` does not know whether assets
existed before and cannot preserve them.

**The firewall corrupts any stored template byte 0x80 or higher on the way back out**, no
matter which transport uploaded it. Plain-ASCII HTML round-trips correctly; content with
accented characters, curly quotes, or other non-ASCII bytes does not - confirmed to be a
defect in the entity's own tar export on the firmware this was measured against, not in the
upload or the module's HTTP handling.

**`-AssetFile` is accepted but does nothing on this firmware.** The request is built exactly as
the API documentation describes it - its own multipart part per asset file, referenced from an
`Assets`/`Asset` list in the request XML - and the firewall answers `200`, but the asset never
appears in a later `Get`: neither in the archive nor in its `Entities.xml`. Measured with
different file extensions and with the multipart parts in both possible orders; none stored the
asset. The parameter stays because it matches the documented contract and costs nothing to keep,
but do not build a workflow around it actually attaching an asset.

**A template that exists is returned as the raw archive the firewall sends**
(`application/octet-stream`), not as parsed fields - the firewall answers this endpoint with a
file, not with XML. Only the empty result is regular XML.

**The firewall answers every template removal with `200`, including the ones it does not
perform.** A template that does not exist is reported as removed, and so is one that does -
which is still there afterwards. `Remove-SfosWebServerAuthenticationTemplate` therefore checks
that the object exists before sending the request and reads it back afterwards, throwing in
both cases rather than passing a success on. On this firmware a template can only be removed
in the web admin console. For the three other entities the firewall answers a removal of a
non-existent object with `504 Deleting entity referred by another entity`, which is misleading
but at least not a success.

**`-HostName` on a web server is the name of an existing `IPHost` of type `IP`**, not an
address. A raw IP address is rejected with `501`, and so are the built-in system hosts; create
the host with `New-SfosIPHost -HostType IP` first.

**`-FrontendRealm` is mandatory on an authentication policy** although neither the attribute
table nor the sample XML of the API documentation mentions it. Without it every create fails
with `501`. The web admin console generates the value; through the API the caller supplies it.

**A protection policy has two size fields with different units.** `-RequestSizeLimitMB` is
given in megabytes and stored by the firewall in bytes, so the cmdlet converts in both
directions and a round trip leaves the value unchanged. `-Megabytes`, the size limit for virus
scanning, is stored as sent and is not converted. They are different settings.

**Server-side filtering is limited to `-NameLike`** (plus `-DescriptionLike` on protection
policies and `-VirtualWebserverMode` on authentication policies). The policy `Mode` cannot be
used as a server-side filter: the firewall answers a filter on it with an empty result even
when a matching object exists. Every other filter is applied client-side.

**The slow HTTP settings are a single configuration object** that is replaced as a whole on
every write. `Set-SfosWebServerSlowHTTPProtectionSettings` reads the current values first and
only overrides what the caller passes. Its `-NetworkExceptionHost` list is replaced, not
appended to: passing an empty array clears the list.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
