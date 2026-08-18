# SophosFirewall.Certificates

`SophosFirewall.Certificates` manages the SYSTEM > Certificates area of a Sophos Firewall: the
certificates the firewall presents or inspects with, the certificate authorities it trusts when
it validates one, and the revocation lists those authorities publish. It is for administrators
who roll out or renew certificate material on a firewall.

Unlike every other area of the API, these endpoints do not answer with XML. A read returns an
archive holding the stored files and a manifest describing them. The `Get-` cmdlets build their
objects from that manifest, and the `Export-` cmdlets write the files themselves to disk.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.Certificates -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

# Upload a PKCS#12 bundle
$pfxPassword = Read-Host -AsSecureString
New-SfosCertificate -Name 'PortalCert' -PfxFilePath 'C:\pki\portal.pfx' -PfxPassword $pfxPassword

# Or upload certificate and key separately
New-SfosCertificate -Name 'PortalCert' -CertificateFilePath 'C:\pki\portal.pem' -PrivateKeyFilePath 'C:\pki\portal.key'

Get-SfosCertificate
Get-SfosCertificateAuthority -NameLike 'GlobalSign'
Get-SfosCRL

Export-SfosCertificate -Name 'PortalCert' -Path 'C:\pki\export'
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosCertificate` | Reads stored certificates. |
| `New-SfosCertificate` | Uploads a certificate, as PKCS#12 or as certificate plus key. |
| `Set-SfosCertificate` | Replaces the material of a stored certificate. |
| `Remove-SfosCertificate` | Removes a certificate. |
| `Export-SfosCertificate` | Writes a stored certificate's files to a local directory. |
| `Get-SfosCertificateAuthority` | Reads certificate authorities. |
| `New-SfosCertificateAuthority` | Uploads a certificate authority. |
| `Set-SfosCertificateAuthority` | Replaces the material of a certificate authority. |
| `Remove-SfosCertificateAuthority` | Removes a certificate authority. |
| `Export-SfosCertificateAuthority` | Writes a certificate authority's files to a local directory. |
| `Get-SfosCRL` | Reads certificate revocation lists. |

`Export-*` is singular here, unlike the CSV bulk exports elsewhere in the suite: it writes the
files of one named object, not a table of many.

## Limitations

**A revocation list can be read, but not uploaded.** Ten request shapes were tried against the
appliance, including the one from the vendor's own sample and with the documented `.crl`
extension: every one is answered with `500`, and so is an empty file. The documented `503` for
an expired list never appears, so the appliance does not reach the point of inspecting the
content. There is deliberately no `New-`, `Set-` or `Remove-SfosCRL`.

**Generating a certificate authority on the appliance is not wrapped.** The operation is
documented and its validation works - an invalid country code is refused with `501` - but a
valid request answers `200` without storing anything. A cmdlet reporting that as success would
be misleading.

**What comes back is equivalent, not identical.** The appliance converts DER input to PEM and
re-encodes a PKCS#8 private key to PKCS#1. An exported file therefore differs byte for byte
from the uploaded one while carrying the same key material.

**Reading every authority at once returns an incomplete set of files.** The appliance ships
authorities whose names contain non-ASCII characters, and it encodes those names twice in the
archive header, which desynchronises the archive at that point. `Get-SfosCertificateAuthority`
reads its objects from the manifest, so the list stays complete; the files after that entry
cannot be extracted, and a warning names where it breaks. Filtering by name avoids it.

**A certificate name may be at most 50 characters.** The vendor documentation says 50 on the
add page and 60 on the delete page for the same field; the module uses the stricter limit.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
