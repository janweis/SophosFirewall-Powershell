# SophosFirewall.VPN

`SophosFirewall.VPN` manages the VPN area of a Sophos Firewall: IPsec connections, VPN
profiles (IKE policies) and failover groups, the Sophos Connect client, SSL VPN tunnel
access settings, policies, bookmarks and bookmark groups, site-to-site SSL VPN connections,
and L2TP/PPTP configuration and connections. It is for administrators who script VPN
maintenance instead of using the web admin.

These cmdlets change who can build tunnels into the network and how that traffic is keyed.
Every write cmdlet supports `-WhatIf`; use it before running an unfamiliar call against a
production firewall. Passing a production user group name to `-Member` on
`New-`/`Set-SfosSSLVPNPolicy` changes that group's own SSL VPN policy assignment as a side
effect - use a dedicated test group while trying out a call.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.VPN -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

New-SfosIPsecConnection -Name 'BranchTunnel' -ConnectionType SiteToSite `
    -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
    -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
    -LocalSubnet 'BranchLocalNet' -AliasLocalWANPort 'Port2'

Get-SfosIPsecConnection -NameLike 'BranchTunnel'
Set-SfosIPsecConnection -Name 'BranchTunnel' -Status Active
Remove-SfosIPsecConnection -Name 'BranchTunnel' -WhatIf
```

### SSL VPN

```powershell
New-SfosSSLVPNPolicy -Name 'BranchTunnelPolicy' -PolicyType Tunnel -Member 'TestGroup' `
    -PermittedNetworkResourcesIPv4 'BranchLocalNet'
Set-SfosSSLVPNPolicy -Name 'BranchTunnelPolicy' -Description 'Updated'
Remove-SfosSSLVPNPolicy -Name 'BranchTunnelPolicy' -WhatIf

$bookmarkPw = ConvertTo-SecureString 'a-strong-password' -AsPlainText -Force
New-SfosSSLBookmark -Name 'IntranetHTTP' -Type HTTP -URL 'intranet.example.com' -BookmarkPort 443 `
    -AutoLogin Enable -LoginUserName 'svc-portal' -SecurePassword $bookmarkPw
```

### L2TP and PPTP

```powershell
Get-SfosL2TPConfiguration
Set-SfosL2TPConfiguration -StartIP '203.0.113.10' -EndIP '203.0.113.20' -PrimaryDNSServer '203.0.113.1'
Add-SfosL2TPConfigurationMember -MemberName 'VPNUser1'
```

## Cmdlets

### IPsec, VPN profiles, failover groups, Sophos Connect client

| Cmdlet | Purpose |
|---|---|
| `Get-SfosIPsecConnection` | Retrieves IPsec connections. |
| `New-SfosIPsecConnection` | Creates an IPsec connection. |
| `Set-SfosIPsecConnection` | Updates an IPsec connection. |
| `Remove-SfosIPsecConnection` | Removes an IPsec connection. |
| `Get-SfosVPNProfile` | Retrieves VPN profiles (IKE policies). |
| `New-SfosVPNProfile` | Creates a VPN profile. |
| `Set-SfosVPNProfile` | Updates a VPN profile. |
| `Remove-SfosVPNProfile` | Removes a VPN profile. |
| `Get-SfosVPNFailoverGroup` | Retrieves VPN failover groups. |
| `New-SfosVPNFailoverGroup` | Creates a VPN failover group. |
| `Set-SfosVPNFailoverGroup` | Updates a VPN failover group. |
| `Remove-SfosVPNFailoverGroup` | Removes a VPN failover group. |
| `Add-SfosVPNFailoverGroupMember` | Adds an IPsec connection to a failover group. |
| `Remove-SfosVPNFailoverGroupMember` | Removes an IPsec connection from a failover group. |
| `Get-SfosSophosConnectClient` | Reads the Sophos Connect client configuration. |

### SSL VPN: tunnel access, policies, bookmarks, site-to-site

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSSLTunnelAccessSettings` | Reads the device-wide SSL VPN tunnel access settings. |
| `Set-SfosSSLTunnelAccessSettings` | Updates the device-wide SSL VPN tunnel access settings. |
| `Get-SfosSSLVPNPolicy` | Retrieves SSL VPN policies. |
| `New-SfosSSLVPNPolicy` | Creates an SSL VPN policy. |
| `Set-SfosSSLVPNPolicy` | Updates an SSL VPN policy. |
| `Remove-SfosSSLVPNPolicy` | Removes an SSL VPN policy. |
| `Get-SfosSSLBookmark` | Retrieves SSL VPN bookmarks. |
| `New-SfosSSLBookmark` | Creates an SSL VPN bookmark. |
| `Set-SfosSSLBookmark` | Updates an SSL VPN bookmark. |
| `Remove-SfosSSLBookmark` | Removes an SSL VPN bookmark. |
| `Get-SfosSSLBookmarkGroup` | Retrieves SSL VPN bookmark groups. |
| `New-SfosSSLBookmarkGroup` | Creates an SSL VPN bookmark group. |
| `Set-SfosSSLBookmarkGroup` | Updates an SSL VPN bookmark group. |
| `Remove-SfosSSLBookmarkGroup` | Removes an SSL VPN bookmark group. |
| `Add-SfosSSLBookmarkGroupMember` | Adds a bookmark to a bookmark group. |
| `Remove-SfosSSLBookmarkGroupMember` | Removes a bookmark from a bookmark group. |
| `Get-SfosSiteToSiteClient` | Retrieves SSL VPN site-to-site client connections. |
| `New-SfosSiteToSiteClient` | Creates an SSL VPN site-to-site client connection. |
| `Set-SfosSiteToSiteClient` | Updates an SSL VPN site-to-site client connection. |
| `Remove-SfosSiteToSiteClient` | Removes an SSL VPN site-to-site client connection. |
| `Get-SfosSiteToSiteServer` | Retrieves SSL VPN site-to-site server connections. |
| `New-SfosSiteToSiteServer` | Creates an SSL VPN site-to-site server connection. |
| `Set-SfosSiteToSiteServer` | Updates an SSL VPN site-to-site server connection. |
| `Remove-SfosSiteToSiteServer` | Removes an SSL VPN site-to-site server connection. |

### L2TP and PPTP

| Cmdlet | Purpose |
|---|---|
| `Get-SfosL2TPConfiguration` | Reads the L2TP configuration. |
| `Set-SfosL2TPConfiguration` | Updates the L2TP configuration. |
| `Add-SfosL2TPConfigurationMember` | Grants a user L2TP access. |
| `Remove-SfosL2TPConfigurationMember` | Revokes a user's L2TP access. |
| `Get-SfosL2TPConnection` | Retrieves L2TP connections. |
| `New-SfosL2TPConnection` | Creates an L2TP connection. |
| `Set-SfosL2TPConnection` | Updates an L2TP connection. |
| `Remove-SfosL2TPConnection` | Removes an L2TP connection. |
| `Get-SfosPPTPConfiguration` | Reads the PPTP configuration. |
| `Set-SfosPPTPConfiguration` | Updates the PPTP configuration. |
| `Add-SfosPPTPConfigurationMember` | Grants a user PPTP access. |
| `Remove-SfosPPTPConfigurationMember` | Revokes a user's PPTP access. |

## Limitations

`New-SfosIPsecConnection` requires a name without a hyphen, `-Status Deactive` at creation,
and both `-LocalWANPort` and `-AliasLocalWANPort` set to the WAN interface; activation is a
separate call, `Set-SfosIPsecConnection -Status Active`.

`New-SfosL2TPConnection` and `New-SfosVPNFailoverGroup` do not succeed against this
firmware; neither cmdlet's create path is confirmed to work. Because no L2TP connection can
be created, `Set-SfosIPsecConnection` and `Set-SfosL2TPConnection` have no `-PresharedKey`
parameter - a field this module cannot read back is not offered for write, so an update can
never silently clear it.

`-ServerConfigurationFile` on `New-`/`Set-SfosSiteToSiteClient` takes a local path to a
`.apc`/`.epc` file and is uploaded as a multipart file; the file must exist locally when the
cmdlet runs. The upload mechanism is confirmed against a live firewall (an invalid probe file
now gets a content-specific `501` from the firewall's own file parser instead of the old
field-less `500`), but the success path with a genuine exported configuration file has not
been verified - no lab appliance exposes a server-side configuration download through the
API. `SiteToSiteServer` and `L2TPConnection` names must not contain a hyphen.

`Set-SfosL2TPConfiguration` and `Set-SfosPPTPConfiguration` require `-StartIP`, `-EndIP` and
`-PrimaryDNSServer` on every update, and once a value has been written to either singleton
it cannot be cleared back to empty through the API.

`Remove-SfosSSLVPNPolicy` fails while a user group still references the policy; remove or
rewire the referencing group first. `-Member` on `New-`/`Set-SfosSSLVPNPolicy` sets the
referenced group's own SSL VPN policy assignment as a side effect.

`Remove-SfosSSLBookmark` does not delete the object on this firmware even though the request
succeeds; the cmdlet reads the bookmark back afterwards and throws rather than reporting a
false success. `Get-SfosSSLBookmark` never returns the stored password in plain text; pass
`-SecurePassword` explicitly on `Set-SfosSSLBookmark` when the password needs to be certain
rather than relying on it being preserved.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
