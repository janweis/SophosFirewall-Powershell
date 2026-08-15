# SophosFirewall.Authentication

`SophosFirewall.Authentication` manages the Authentication area of a Sophos Firewall:
authentication servers (Active Directory, LDAP, RADIUS, TACACS+, eDirectory), users and user
groups, guest and clientless users, SMS gateways, one-time passwords, firewall/admin/VPN/SSL
VPN authentication, web authentication and captive portal, Microsoft Entra ID (Azure AD)
SSO, STAS and live user sessions. It is for administrators who script who may log in and how
instead of configuring it in the web admin.

These cmdlets change who can authenticate against the firewall. An update that drops an
authentication server, or a group membership written to the wrong object, decides whether
people can log in at all. Every write cmdlet supports `-WhatIf`; use it before running an
unfamiliar call against a production firewall, especially anything under admin, VPN or SSL
VPN authentication.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.Authentication -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

$securePw = ConvertTo-SecureString 'a-strong-password' -AsPlainText -Force
New-SfosUser -AccountName 'jdoe' -Name 'Jane Doe' -UserType User -AccountPassword $securePw -LoginRestriction UserGroupNode -Group 'Open Group'

New-SfosUserGroup -Name 'Sales' -GroupType Normal -QoSPolicy 'None' -SurfingQuotaPolicy 'Unlimited Internet Access' -AccessTimePolicy 'Allowed all the time' -LoginRestriction AnyNode

Get-SfosUser -UsernameLike 'jdoe' | Set-SfosUser -SurfingQuotaPolicy 'Unlimited Internet Access'
Remove-SfosUser -AccountName 'jdoe' -WhatIf
```

### Authentication servers

```powershell
$bindPw = ConvertTo-SecureString 'a-strong-password' -AsPlainText -Force
New-SfosActiveDirectoryServer -ServerName 'CorpAD' -ServerAddress 'ad.example.com' -ServerPort 389 `
    -NetBIOSDomain 'CORP' -ADSUsername 'svc-sfos' -BindPassword $bindPw -ConnectionSecurity Simple -DomainName 'example.com'

Get-SfosLDAPServer | Format-Table ServerName, ServerAddress, Port, BaseDN
Remove-SfosActiveDirectoryServer -ServerName 'CorpAD' -WhatIf
```

### One-time passwords and guest users

```powershell
Add-SfosOTPSettingsMember -Members 'jdoe'
$secret = ConvertTo-SecureString '0123456789abcdef0123456789abcdef' -AsPlainText -Force
New-SfosOTPTokens -User 'jdoe' -Secret $secret -Algorithm SHA1

New-SfosGuestUser -Name 'visitor1' -UserValidity '1' -Email 'visitor1@example.com'
Get-SfosGuestUser -NameLike 'visitor1' | Remove-SfosGuestUser
```

## Cmdlets

### Authentication servers

| Cmdlet | Purpose |
|---|---|
| `Get-SfosActiveDirectoryServer` | Retrieves Active Directory server objects. |
| `New-SfosActiveDirectoryServer` | Creates an Active Directory server. |
| `Set-SfosActiveDirectoryServer` | Updates an Active Directory server. |
| `Remove-SfosActiveDirectoryServer` | Removes an Active Directory server. |
| `Get-SfosLDAPServer` | Retrieves LDAP server objects. |
| `New-SfosLDAPServer` | Creates an LDAP server. |
| `Set-SfosLDAPServer` | Updates an LDAP server. |
| `Remove-SfosLDAPServer` | Removes an LDAP server. |
| `Get-SfosRADIUSServer` | Retrieves RADIUS server objects. |
| `New-SfosRADIUSServer` | Creates a RADIUS server. |
| `Set-SfosRADIUSServer` | Updates a RADIUS server. |
| `Remove-SfosRADIUSServer` | Removes a RADIUS server. |
| `Get-SfosTACACSServer` | Retrieves TACACS+ server objects. |
| `New-SfosTACACSServer` | Creates a TACACS+ server. |
| `Set-SfosTACACSServer` | Updates a TACACS+ server. |
| `Remove-SfosTACACSServer` | Removes a TACACS+ server. |
| `Get-SfosEDirectoryServer` | Retrieves eDirectory server objects. |
| `New-SfosEDirectoryServer` | Creates an eDirectory server. |
| `Set-SfosEDirectoryServer` | Updates an eDirectory server. |
| `Remove-SfosEDirectoryServer` | Removes an eDirectory server. |

### Users and groups

| Cmdlet | Purpose |
|---|---|
| `Get-SfosUser` | Retrieves user accounts. |
| `New-SfosUser` | Creates a user account. |
| `Set-SfosUser` | Updates a user account. |
| `Remove-SfosUser` | Removes a user account. |
| `Get-SfosUserGroup` | Retrieves user group objects. |
| `New-SfosUserGroup` | Creates a user group. |
| `Set-SfosUserGroup` | Updates a user group. |
| `Remove-SfosUserGroup` | Removes a user group. |
| `Add-SfosUserGroupMember` | Places users into a user group. |
| `Remove-SfosUserGroupMember` | Removes users from a user group. |

### Guest users, clientless users, SMS gateways

| Cmdlet | Purpose |
|---|---|
| `Get-SfosGuestUser` | Retrieves guest user objects. |
| `New-SfosGuestUser` | Creates a guest user. |
| `Remove-SfosGuestUser` | Removes a guest user. |
| `Get-SfosGuestUserSettings` | Reads the guest user settings. |
| `Set-SfosGuestUserSettings` | Updates the guest user settings. |
| `Get-SfosClientlessUser` | Retrieves clientless user objects. |
| `New-SfosClientlessUser` | Creates a clientless user. |
| `Set-SfosClientlessUser` | Updates a clientless user. |
| `Remove-SfosClientlessUser` | Removes a clientless user. |
| `New-SfosClientlessUserRange` | Creates a range of clientless users. |
| `Get-SfosSMSGateway` | Retrieves SMS gateway profiles. |
| `New-SfosSMSGateway` | Creates an SMS gateway profile. |
| `Set-SfosSMSGateway` | Updates an SMS gateway profile. |
| `Remove-SfosSMSGateway` | Removes an SMS gateway profile. |

### One-time passwords

| Cmdlet | Purpose |
|---|---|
| `Get-SfosOTPSettings` | Reads the one-time password settings. |
| `Set-SfosOTPSettings` | Updates the one-time password settings. |
| `Add-SfosOTPSettingsMember` | Adds users to the explicit OTP user list. |
| `Remove-SfosOTPSettingsMember` | Removes users from the explicit OTP user list. |
| `Get-SfosOTPTokens` | Retrieves one-time password tokens. |
| `New-SfosOTPTokens` | Creates a one-time password token. |
| `Set-SfosOTPTokens` | Updates a one-time password token. |
| `Remove-SfosOTPTokens` | Removes a one-time password token. |

### Firewall authentication

| Cmdlet | Purpose |
|---|---|
| `Get-SfosFirewallAuthenticationGlobalSettings` | Reads the firewall authentication global settings. |
| `Set-SfosFirewallAuthenticationGlobalSettings` | Updates the firewall authentication global settings. |
| `Get-SfosFirewallAuthenticationMethods` | Reads the firewall authentication method configuration. |
| `Set-SfosFirewallAuthenticationMethods` | Updates the firewall authentication method configuration. |
| `Add-SfosFirewallAuthenticationMethodsMember` | Adds servers to the firewall authentication server list. |
| `Remove-SfosFirewallAuthenticationMethodsMember` | Removes servers from the firewall authentication server list. |
| `Get-SfosFirewallAuthenticationNTLMSettings` | Reads the NTLM authentication settings. |
| `Set-SfosFirewallAuthenticationNTLMSettings` | Updates the NTLM authentication settings. |
| `Get-SfosFirewallAuthenticationCTASSettings` | Reads the CTAS authentication settings. |
| `Set-SfosFirewallAuthenticationCTASSettings` | Updates the CTAS authentication settings. |
| `Get-SfosFirewallAuthenticationiOSWebClientSettings` | Reads the iOS web client authentication settings. |
| `Set-SfosFirewallAuthenticationiOSWebClientSettings` | Updates the iOS web client authentication settings. |
| `Get-SfosSSORadiusAccount` | Reads the RADIUS accounting single sign-on configuration. |
| `Set-SfosSSORadiusAccount` | Updates the RADIUS accounting single sign-on configuration. |

### Admin, VPN and SSL VPN authentication

| Cmdlet | Purpose |
|---|---|
| `Get-SfosAdminAuthentication` | Reads the administrator authentication configuration. |
| `Set-SfosAdminAuthentication` | Updates the administrator authentication configuration. |
| `Add-SfosAdminAuthenticationMember` | Adds servers to the administrator authentication server list. |
| `Remove-SfosAdminAuthenticationMember` | Removes servers from the administrator authentication server list. |
| `Get-SfosVPNAuthentication` | Reads the VPN authentication configuration. |
| `Set-SfosVPNAuthentication` | Updates the VPN authentication configuration. |
| `Add-SfosVPNAuthenticationMember` | Adds servers to the VPN authentication server list. |
| `Remove-SfosVPNAuthenticationMember` | Removes servers from the VPN authentication server list. |
| `Get-SfosSSLVPNAuthentication` | Reads the SSL VPN authentication configuration. |
| `Set-SfosSSLVPNAuthentication` | Updates the SSL VPN authentication configuration. |
| `Add-SfosSSLVPNAuthenticationMember` | Adds servers to the SSL VPN authentication server list. |
| `Remove-SfosSSLVPNAuthenticationMember` | Removes servers from the SSL VPN authentication server list. |

### Web authentication and captive portal

| Cmdlet | Purpose |
|---|---|
| `Get-SfosWebAuthenticationSettings` | Reads the web authentication settings. |
| `Set-SfosWebAuthenticationSettings` | Updates the web authentication settings. |
| `Get-SfosCaptivePortalAppearance` | Reads the captive portal appearance settings. |
| `Set-SfosCaptivePortalAppearance` | Updates the captive portal appearance settings. |
| `Get-SfosDefaultCaptivePortal` | Reads the default captive portal wording. |
| `Set-SfosDefaultCaptivePortal` | Updates the default captive portal wording. |
| `Get-SfosDirectWebProxyAuthentication` | Reads the direct web proxy authentication configuration. |
| `Set-SfosDirectWebProxyAuthentication` | Updates the direct web proxy authentication configuration. |
| `Add-SfosDirectWebProxyAuthenticationMember` | Adds hosts to the direct web proxy multi-user host list. |
| `Remove-SfosDirectWebProxyAuthenticationMember` | Removes hosts from the direct web proxy multi-user host list. |

### SSO, STAS and live user sessions

| Cmdlet | Purpose |
|---|---|
| `Get-SfosAzureADSSO` | Retrieves Microsoft Entra ID (Azure AD) SSO server objects. |
| `New-SfosAzureADSSO` | Creates a Microsoft Entra ID (Azure AD) SSO server. |
| `Set-SfosAzureADSSO` | Updates a Microsoft Entra ID (Azure AD) SSO server. |
| `Remove-SfosAzureADSSO` | Removes a Microsoft Entra ID (Azure AD) SSO server. |
| `Get-SfosSTAS` | Reads the STAS configuration. |
| `Set-SfosSTAS` | Enables or disables STAS. |
| `Get-SfosLiveUser` | Retrieves currently logged-in live users. |
| `Connect-SfosLiveUser` | Logs an end user in at the firewall's live user tracking. |
| `Disconnect-SfosLiveUser` | Logs an end user out of the firewall's live user tracking. |

## Limitations

There is no `Set-SfosGuestUser`: an in-place update of a guest user is refused by this
firmware. To change a guest user's fields, remove and recreate it with
`Remove-SfosGuestUser` and `New-SfosGuestUser`.

`Get-SfosGuestUserSettings` can stop returning the settings after a write to
`Set-SfosGuestUserSettings` on this firmware, even though the write itself succeeds and the
stored values are correct. When this happens, verify or change the settings through the web
admin console instead.

A user belongs to exactly one group at a time; the group membership is a field on the user,
not a list on the group. `Add-SfosUserGroupMember` on a user who is already in another group
moves that user into the new group rather than adding a second membership.

`Set-`/`Add-`/`Remove-SfosAdminAuthentication` change the firewall's own administrator login
path; a wrong value can lock out the account used to fix it. Confirm the current
configuration with `Get-SfosAdminAuthentication` and use `-WhatIf` before writing.

`Connect-SfosLiveUser` creates a permanent user account as a side effect of the login; the
matching `Disconnect-SfosLiveUser` ends only the live session and does not remove that
account. Remove it with `Remove-SfosUser` if it is not wanted.

`Set-SfosDirectWebProxyAuthentication -PerConnectionAuth Enable` and
`Set-SfosWebAuthenticationSettings -OpenWebpageInNewWindow Disable` are both rejected by this
firmware.

The authentication server list of firewall, VPN and SSL VPN authentication cannot be made
empty; removing the last entry is rejected.

`Set-SfosSTAS` only switches STAS on or off. The `Collector`, `Settings` and `VpnZone`
sub-blocks that `Get-SfosSTAS` returns once STAS is enabled have no matching write cmdlet in
this module.

A `Remove-*` call against an object that does not exist can answer success on some entities
in this module and a not-found-style error on others; none of the `Remove-*` cmdlets here
check existence first.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
