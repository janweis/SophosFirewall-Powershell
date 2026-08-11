# SophosFirewall.VPN Module

> **Security warning.** These cmdlets change who can build tunnels into a live network and
> how that traffic is keyed - IPsec connections, VPN profiles (IKE policies), failover groups,
> SSL VPN policies, bookmarks and site-to-site connections, and L2TP/PPTP. Every write cmdlet
> in this module supports `-WhatIf`; use it before running an unfamiliar call against a
> production firewall. Pay particular attention to `New-`/`Set-SfosSSLVPNPolicy`: passing a
> production `UserGroup` name to `-Member` writes back onto that group's own SSL VPN policy
> assignment - see Known limitations.

## Overview

The **VPN** module provides PowerShell cmdlets for the **CONFIGURE > VPN** area of the Sophos
XGS / SFOS 22.0 API documentation. The web admin console splits this area into two menus,
"Site-to-site VPN" and "Remote access VPN"; the underlying XML API keeps everything in one
category, and so does this module. With 51 exported functions, it manages IPsec connections,
VPN profiles (IKE policies) and failover groups, the Sophos Connect client, SSL VPN tunnel
access settings, policies, bookmarks and bookmark groups, site-to-site SSL VPN client/server
connections, and L2TP/PPTP configuration, member lists and L2TP connections. Requires
`SophosFirewall.Core` (minimum version 1.1.0).

## Features

- **IPsec**: `VPNIPSecConnection` objects, `VPNProfile` (IKE) profiles, `VPNFailoverGroup`
  objects with member management, and the read-only `SophosConnectClient` entity
- **SSL VPN (Remote Access)**: the device-wide `SSLTunnelAccessSettings` singleton,
  `SSLVPNPolicy` objects (Tunnel and Clientless sub-types), `SSLBookmark` objects and
  `SSLBookmarkGroup` objects with member management
- **SSL VPN (Site-to-site)**: `SiteToSiteClient` and `SiteToSiteServer` connection objects
- **L2TP and PPTP**: the `L2TPConfiguration`/`PPTPConfiguration` settings singletons, their
  member lists, and `L2TPConnection` objects
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Install-Module -Name SophosFirewall.VPN
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.VPN.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module, version 1.1.0 or higher (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "fw.example.invalid" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### IPsec, VPN Profiles, Failover Groups and Sophos Connect Client

```powershell
# List IPsec connections and VPN profiles
Get-SfosIPsecConnection
Get-SfosVPNProfile | Format-Table Name, KeyingMethod

# Documentation-faithful create - UNCONFIRMED on this firmware, see Known limitations
New-SfosIPsecConnection -Name 'BranchTunnel' -ConnectionType SiteToSite `
    -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
    -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
    -LocalSubnet 'BranchLocalNet' -AliasLocalWANPort 'Port2' -WhatIf

# Update the status only; every other field is preserved
Set-SfosIPsecConnection -Name 'BranchTunnel' -Status Active -WhatIf

# Remove a connection
Remove-SfosIPsecConnection -Name 'BranchTunnel' -WhatIf
```

```powershell
# Create a complete IKEv2 profile - every Phase1/Phase2 field below is mandatory on create
New-SfosVPNProfile -Name 'Branch-IKEv2' -AuthenticationMode MainMode `
    -Phase1EncryptionAlgorithm1 AES256 -Phase1AuthenticationAlgorithm1 SHA2_256 `
    -Phase1KeyLife 3600 -Phase1ReKeyMargin 120 -Phase1RandomizeReKeyingMarginBy 0 `
    -Phase2EncryptionAlgorithm1 AES256 -Phase2AuthenticationAlgorithm1 SHA2_256 `
    -Phase2KeyLife 3600 -SupportedDHGroup '14(DH2048)'

# Update the description only; both Phase1 and Phase2 blocks are preserved
Set-SfosVPNProfile -Name 'Branch-IKEv2' -Description 'Updated branch profile'

# Remove it again
Remove-SfosVPNProfile -Name 'Branch-IKEv2'
```

```powershell
# Documentation-faithful create - UNCONFIRMED, see Known limitations
New-SfosVPNFailoverGroup -Name 'BranchFailover' -Connection 'BranchTunnel' -MailNotification Disable -WhatIf

# Add and remove a member connection
Add-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'BranchTunnel2' -WhatIf
Remove-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'BranchTunnel2' -WhatIf

# Read the Sophos Connect client entity - Get only, see Known limitations
Get-SfosSophosConnectClient
```

### SSL VPN (Remote Access): Tunnel Access, Policies, Bookmarks

```powershell
# Read the device-wide tunnel access settings and flip debug mode only
Get-SfosSSLTunnelAccessSettings
Set-SfosSSLTunnelAccessSettings -DebugMode Enable

# Create a Tunnel policy - use a dedicated test group, never a production one, see Known limitations
New-SfosSSLVPNPolicy -Name 'BranchTunnelPolicy' -PolicyType Tunnel -Member 'TestGroup' `
    -PermittedNetworkResourcesIPv4 'BranchLocalNet'

Set-SfosSSLVPNPolicy -Name 'BranchTunnelPolicy' -Description 'Updated'
Remove-SfosSSLVPNPolicy -Name 'BranchTunnelPolicy' -WhatIf
```

```powershell
# Create a bookmark, prefer -SecurePassword over relying on hash preservation, see Known limitations
$bookmarkPw = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
New-SfosSSLBookmark -Name 'IntranetHTTP' -Type HTTP -URL 'intranet.example.invalid' -BookmarkPort 443 `
    -AutoLogin Enable -LoginUserName 'svc-portal' -SecurePassword $bookmarkPw

Set-SfosSSLBookmark -Name 'IntranetHTTP' -Description 'Updated'

# Remove-SfosSSLBookmark throws even though the firewall answers 200 - see Known limitations
Remove-SfosSSLBookmark -Name 'IntranetHTTP' -WhatIf
```

```powershell
# Bookmark group and member management
New-SfosSSLBookmarkGroup -Name 'IntranetBookmarks' -Bookmark 'IntranetHTTP'
Add-SfosSSLBookmarkGroupMember -GroupName 'IntranetBookmarks' -Bookmark 'IntranetHTTP2'
Remove-SfosSSLBookmarkGroupMember -GroupName 'IntranetBookmarks' -Bookmark 'IntranetHTTP2'
Remove-SfosSSLBookmarkGroup -Name 'IntranetBookmarks'
```

### SSL VPN (Site-to-site): Client and Server Connections

```powershell
# Documentation-faithful create - blocked by a file-upload field, see Known limitations
New-SfosSiteToSiteClient -Name 'BranchS2SClient' -ServerConfigurationFile $apcFileContent -WhatIf

# Server connection - names must not contain a hyphen, see Known limitations
New-SfosSiteToSiteServer -Name 'BranchS2SServer' -LocalNetworks 'BranchLocalNet' -RemoteNetworks 'BranchRemoteNet'
Set-SfosSiteToSiteServer -Name 'BranchS2SServer' -Description 'Updated'
Remove-SfosSiteToSiteServer -Name 'BranchS2SServer' -WhatIf
```

### L2TP and PPTP

```powershell
# Read the L2TP singleton; StartIP/EndIP/PrimaryDNSServer are mandatory on every update, see Known limitations
Get-SfosL2TPConfiguration
Set-SfosL2TPConfiguration -StartIP '203.0.113.10' -EndIP '203.0.113.20' -PrimaryDNSServer '203.0.113.1' -WhatIf

# Grant/revoke L2TP access for a local user
Add-SfosL2TPConfigurationMember -MemberName 'VPNUser1' -WhatIf
Remove-SfosL2TPConfigurationMember -MemberName 'VPNUser1' -WhatIf

# Documentation-faithful create - UNCONFIRMED on this firmware, see Known limitations
New-SfosL2TPConnection -Name 'BranchL2TP' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey `
    -PresharedKey 'Secret123' -AliasLocalWANPort 'Port2' -LocalID '203.0.113.1' `
    -RemoteHost '203.0.113.10' -RemoteLANNetwork 'BranchRemoteNet' -RemoteID '203.0.113.10' `
    -LocalPort 1701 -RemotePort '*' -WhatIf
```

```powershell
# PPTP follows the same singleton/member shape as L2TP
Get-SfosPPTPConfiguration
Set-SfosPPTPConfiguration -StartIP '203.0.113.30' -EndIP '203.0.113.40' -PrimaryDNSServer '203.0.113.1' -WhatIf
Add-SfosPPTPConfigurationMember -MemberName 'VPNUser1' -WhatIf
Remove-SfosPPTPConfigurationMember -MemberName 'VPNUser1' -WhatIf
```

## Available Cmdlets (51 total)

### IPsec, VPN Profiles, Failover Groups and Sophos Connect Client (15 functions)
- `Get-SfosIPsecConnection` - Retrieves VPNIPSecConnection objects from the Sophos Firewall.
- `New-SfosIPsecConnection` - Creates a new VPNIPSecConnection object on the Sophos Firewall.
- `Set-SfosIPsecConnection` - Updates an existing VPNIPSecConnection object on the Sophos Firewall.
- `Remove-SfosIPsecConnection` - Removes a VPNIPSecConnection object from the Sophos Firewall.
- `Get-SfosVPNProfile` - Retrieves VPNProfile objects from the Sophos Firewall.
- `New-SfosVPNProfile` - Creates a new VPNProfile object on the Sophos Firewall.
- `Set-SfosVPNProfile` - Updates an existing VPNProfile object on the Sophos Firewall.
- `Remove-SfosVPNProfile` - Removes a VPNProfile object from the Sophos Firewall.
- `Get-SfosVPNFailoverGroup` - Retrieves VPNFailoverGroup objects from the Sophos Firewall.
- `New-SfosVPNFailoverGroup` - Creates a new VPNFailoverGroup object on the Sophos Firewall.
- `Set-SfosVPNFailoverGroup` - Updates an existing VPNFailoverGroup object on the Sophos Firewall.
- `Remove-SfosVPNFailoverGroup` - Removes a VPNFailoverGroup object from the Sophos Firewall.
- `Add-SfosVPNFailoverGroupMember` - Adds a VPNIPSecConnection to a VPNFailoverGroup's member list.
- `Remove-SfosVPNFailoverGroupMember` - Removes a VPNIPSecConnection from a VPNFailoverGroup's member list.
- `Get-SfosSophosConnectClient` - Retrieves the SophosConnectClient configuration from the Sophos Firewall.

### SSL VPN: Tunnel Access, Policies, Bookmarks, Site-to-Site (24 functions)
- `Get-SfosSSLTunnelAccessSettings` - Retrieves the SSLVPN tunnel access settings from the Sophos Firewall.
- `Set-SfosSSLTunnelAccessSettings` - Updates the SSLVPN tunnel access settings on the Sophos Firewall.
- `Get-SfosSSLVPNPolicy` - Retrieves SSLVPNPolicy objects from the Sophos Firewall.
- `New-SfosSSLVPNPolicy` - Creates a new SSLVPNPolicy object on the Sophos Firewall.
- `Set-SfosSSLVPNPolicy` - Updates an existing SSLVPNPolicy object on the Sophos Firewall.
- `Remove-SfosSSLVPNPolicy` - Removes an SSLVPNPolicy object from the Sophos Firewall.
- `Get-SfosSSLBookmark` - Retrieves SSLBookmark objects from the Sophos Firewall.
- `New-SfosSSLBookmark` - Creates a new SSLBookmark object on the Sophos Firewall.
- `Set-SfosSSLBookmark` - Updates an existing SSLBookmark object on the Sophos Firewall.
- `Remove-SfosSSLBookmark` - Removes an SSLBookmark object from the Sophos Firewall.
- `Get-SfosSSLBookmarkGroup` - Retrieves SSLBookmarkGroup objects from the Sophos Firewall.
- `New-SfosSSLBookmarkGroup` - Creates a new SSLBookmarkGroup object on the Sophos Firewall.
- `Set-SfosSSLBookmarkGroup` - Updates an existing SSLBookmarkGroup object on the Sophos Firewall.
- `Remove-SfosSSLBookmarkGroup` - Removes an SSLBookmarkGroup object from the Sophos Firewall.
- `Add-SfosSSLBookmarkGroupMember` - Adds a member bookmark to an SSLBookmarkGroup.
- `Remove-SfosSSLBookmarkGroupMember` - Removes a member bookmark from an SSLBookmarkGroup.
- `Get-SfosSiteToSiteClient` - Retrieves SiteToSiteClient objects from the Sophos Firewall.
- `New-SfosSiteToSiteClient` - Creates a new SiteToSiteClient object on the Sophos Firewall.
- `Set-SfosSiteToSiteClient` - Updates an existing SiteToSiteClient object on the Sophos Firewall.
- `Remove-SfosSiteToSiteClient` - Removes a SiteToSiteClient object from the Sophos Firewall.
- `Get-SfosSiteToSiteServer` - Retrieves SiteToSiteServer objects from the Sophos Firewall.
- `New-SfosSiteToSiteServer` - Creates a new SiteToSiteServer object on the Sophos Firewall.
- `Set-SfosSiteToSiteServer` - Updates an existing SiteToSiteServer object on the Sophos Firewall.
- `Remove-SfosSiteToSiteServer` - Removes a SiteToSiteServer object from the Sophos Firewall.

### L2TP and PPTP (12 functions)
- `Get-SfosL2TPConfiguration` - Retrieves the L2TP configuration singleton from the Sophos Firewall.
- `Set-SfosL2TPConfiguration` - Updates the L2TP configuration singleton on the Sophos Firewall.
- `Add-SfosL2TPConfigurationMember` - Adds a user to the L2TP configuration's member list.
- `Remove-SfosL2TPConfigurationMember` - Removes a user from the L2TP configuration's member list.
- `Get-SfosL2TPConnection` - Retrieves L2TPConnection objects from the Sophos Firewall.
- `New-SfosL2TPConnection` - Creates a new L2TPConnection object on the Sophos Firewall.
- `Set-SfosL2TPConnection` - Updates an existing L2TPConnection object on the Sophos Firewall.
- `Remove-SfosL2TPConnection` - Removes an L2TPConnection object from the Sophos Firewall.
- `Get-SfosPPTPConfiguration` - Retrieves the PPTP configuration singleton from the Sophos Firewall.
- `Set-SfosPPTPConfiguration` - Updates the PPTP configuration singleton on the Sophos Firewall.
- `Add-SfosPPTPConfigurationMember` - Adds a user to the PPTP configuration's member list.
- `Remove-SfosPPTPConfigurationMember` - Removes a user from the PPTP configuration's member list.

## Known limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance. Every read-modify-write `Set-*` in this module
exists because of the general finding that an update replaces the whole entity - see the
points below for the exceptions and additional defects found on top of that.

- **`New-SfosIPsecConnection` and `New-SfosL2TPConnection` are not satisfiable on this
  firmware.** Both need `-AliasLocalWANPort` to reference a real, already-configured
  interface Alias object; the lab's only WAN-zone interface passes that field's own
  validation but every request then fails with an opaque, field-less code `545`. This holds
  for every combination of the remaining fields tried, including distinct network objects for
  local/remote and both ID fields supplied. Because no object of either type could ever be
  created, whether `Get-SfosIPsecConnection`/`Get-SfosL2TPConnection` return the pre-shared
  key on read is unknown; `Set-SfosIPsecConnection` and `Set-SfosL2TPConnection` accordingly
  do not offer `-PresharedKey` for preservation - a field this module cannot read back is not
  offered for write, so a read-modify-write update can never silently clear it.
- **`New-SfosSiteToSiteClient` cannot succeed through this transport.**
  `-ServerConfigurationFile` is a genuine file upload (`.apc`/`.epc`) per the vendor's own
  sample, not a text field; `Core` has no multipart transport, only the urlencoded `reqxml`
  POST body. Every attempt - omitted element, empty element, base64 placeholder - answered a
  field-less `500`. Because Add never succeeds, whether `-FilePassword` or the proxy password
  survive a read-modify-write could not be measured either; `Set-SfosSiteToSiteClient` does
  not attempt to preserve them.
- **`SSLVPNPolicy.PolicyMembers` writes back onto the referenced `UserGroup`.** Adding a
  group name to `-Member` on `New-`/`Set-SfosSSLVPNPolicy` sets that group's own
  `SSLVPNPolicy`/`ClientlessPolicy` assignment field as a side effect - confirmed live.
  Never pass a production group name for testing; use a dedicated test group.
- **`Remove-SfosSSLBookmark` is a confirmed firmware no-op.** The firewall answers `200`
  "Configuration applied successfully" and the object is never deleted, reproduced in every
  shape tried (bare `Name`, `Name` plus `Type`, the full object, the undocumented
  `Set operation="remove"`). The cmdlet reads the object back afterwards and throws rather
  than reporting the firewall's false success - the object still has to be removed through
  the web admin console.
- **`SSLBookmark.Password` comes back hashed and re-salts on every write.** `Get-*` returns
  `<Password hashform="mode1">$sfos$7$0$...</Password>`, never plaintext.
  `Set-SfosSSLBookmark` resends that hash with its `hashform` attribute when `-SecurePassword`
  is omitted (the vendor's own mechanism for pre-hashed secrets), but the stored hash text
  changes on every single update regardless, so whether the firewall treats the resent hash as
  the same password or as new plaintext cannot be measured without a real portal login. Where
  it matters, pass `-SecurePassword` explicitly rather than relying on preservation.
- **`SiteToSiteServer` and `L2TPConnection` names reject a hyphen.** `<Set operation="add">`
  with a hyphenated `Name` answers `501` naming the `Name` field; the identical request
  without the hyphen succeeds. Both `New-*` cmdlets validate this client-side.
- **Several fields the documentation marks optional are mandatory in practice.** On
  `New-SfosVPNProfile`, the entire dead-peer-detection block
  (`-DeadPeerDetection`/`-CheckPeerAfterEvery`/`-WaitForResponseUpto`/
  `-ActionWhenPeerUnreachable`) and `-PFSGroup` are always sent, backed by parameter defaults
  rather than a conditional check, because the firewall rejected requests that omitted them.
  On `New-SfosVPNFailoverGroup`, `-MailNotification` is required even though the
  documentation marks it optional. On `Set-SfosL2TPConfiguration`/`Set-SfosPPTPConfiguration`,
  `-StartIP`, `-EndIP` and `-PrimaryDNSServer` are required on every update, including one
  that changes nothing else - the firewall names all three in `<InvalidParams>` when any is
  missing, even resending the object's own current (empty) values.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "fw.example.invalid" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific VPN profile with error handling
    $profile = Get-SfosVPNProfile -NameLike "Branch-IKEv2" -ErrorAction Stop
    Write-Output "Found profile: $($profile.Name) - KeyingMethod: $($profile.KeyingMethod)"
} catch {
    Write-Error "Failed to retrieve VPN profile: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosVPNProfile | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are entity-specific (VPNIPSecConnection, VPNProfile, VPNFailoverGroup, SSLVPNPolicy, SSLBookmark, SiteToSiteClient, SiteToSiteServer, L2TPConnection, ...)
- **`New-SfosIPsecConnection`/`New-SfosL2TPConnection` fail with code 545**: See Known limitations - this is an unresolved environmental/firmware blocker on `-AliasLocalWANPort`, not a module defect
- **`New-SfosSiteToSiteClient` fails with an empty 500**: See Known limitations - `-ServerConfigurationFile` needs a multipart upload this module's transport cannot send
- **`Remove-SfosSSLBookmark` throws even though the firewall answered success**: See Known limitations - the delete operation is a confirmed firmware no-op
- **A UserGroup's SSL VPN policy assignment changed unexpectedly**: See Known limitations - `-Member` on `New-`/`Set-SfosSSLVPNPolicy` writes back onto that group

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.VPN) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License
