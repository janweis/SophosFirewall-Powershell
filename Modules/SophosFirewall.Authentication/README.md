# SophosFirewall.Authentication Module

> **Security warning.** These cmdlets change who may log in to a live firewall and how -
> authentication servers, users, group membership, admin/VPN/SSL VPN authentication and SSO.
> An update that drops an authentication server, or a group membership written to the wrong
> object, decides whether people can authenticate at all. Every write cmdlet in this module
> supports `-WhatIf`; use it before running an unfamiliar call against a production firewall,
> especially anything under Admin/VPN/SSLVPN authentication.

## Overview

The **Authentication** module provides PowerShell cmdlets for the **CONFIGURE > Authentication**
area of the Sophos XGS / SFOS 22.0 API documentation. With 97 exported functions, it manages
authentication servers (Active Directory, LDAP, RADIUS, TACACS+, eDirectory), users and user
groups, guest users, clientless users, SMS gateways, one-time passwords, firewall/admin/VPN/SSL
VPN authentication, web authentication and captive portal, Microsoft Entra ID (Azure AD) SSO,
STAS and live user sessions. Requires `SophosFirewall.Core`.

## Features

- **Authentication Servers**: Active Directory, LDAP, RADIUS, TACACS+ and eDirectory server objects
- **Users and User Groups**: User accounts and groups, with membership management
- **Guest Users, Clientless Users and SMS Gateways**: Temporary/portal-based access and SMS delivery for OTPs
- **One-Time Passwords**: OTP settings, explicit OTP user list and OTP tokens
- **Firewall Authentication**: Global settings, authentication methods, NTLM, CTAS, iOS web client and SSO-via-RADIUS-accounting
- **Admin, VPN and SSL VPN Authentication**: Which server(s) the firewall consults for each login surface
- **Web Authentication and Captive Portal**: Login flow settings, portal branding and direct web proxy authentication
- **SSO, STAS and Live User Sessions**: Azure AD SSO servers, STAS enable/disable, live user login/logout
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Import-Module -Name SophosFirewall.Authentication
```

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.Authentication.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### Authentication Server Management

```powershell
# List the configured LDAP servers
Get-SfosLDAPServer | Format-Table ServerName, ServerAddress, Port, BaseDN

# Create an Active Directory server with simple bind
$bindPw = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
New-SfosActiveDirectoryServer -ServerName "CorpAD" -ServerAddress "ad.example.invalid" -ServerPort 389 -NetBIOSDomain "CORP" -ADSUsername "svc-sfos" -BindPassword $bindPw -ConnectionSecurity Simple -DomainName "example.invalid"

# Update the domain name only, everything else preserved except the bind password
Set-SfosActiveDirectoryServer -ServerName "CorpAD" -DomainName "corp.example.invalid" -BindPassword $bindPw

# Preview removal
Remove-SfosActiveDirectoryServer -ServerName "CorpAD" -WhatIf
```

### User and Group Management

```powershell
# Create a user and place it in a group
$securePw = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
New-SfosUser -AccountName "jdoe" -Name "Jane Doe" -UserType User -AccountPassword $securePw -LoginRestriction UserGroupNode -Group "Open Group"

# Create a normal group
New-SfosUserGroup -Name "Sales" -GroupType Normal -QoSPolicy "None" -SurfingQuotaPolicy "Unlimited Internet Access" -AccessTimePolicy "Allowed all the time" -LoginRestriction AnyNode

# Add users to an existing group - see Known limitations, this moves the user out of any other group
Add-SfosUserGroupMember -Name "Sales" -Members "jdoe","asmith"

# Update using pipeline input
Get-SfosUser -UsernameLike "jdoe" | Set-SfosUser -SurfingQuotaPolicy "Unlimited Internet Access"

# Remove a user
Remove-SfosUser -AccountName "jdoe" -WhatIf
```

### Guest User, Clientless User and SMS Gateway Management

```powershell
# Create a single guest user - see Known limitations, there is no Set-SfosGuestUser
New-SfosGuestUser -Name "visitor1" -UserValidity "1" -Email "visitor1@example.test"

# List and remove via the pipeline
Get-SfosGuestUser -NameLike "visitor1" | Remove-SfosGuestUser

# Create a clientless user
New-SfosClientlessUser -AccountName "jdoe" -Name "John Doe" -ClientLessGroup "Clientless Group" -Email "jdoe@example.test" -IPAddress "203.0.113.10"

# Add a whole range of clientless users at once
New-SfosClientlessUserRange -FromIPAddress "203.0.113.10" -ToIPAddress "203.0.113.20" -ClientLessGroup "Clientless Group"

# Create an SMS gateway used for OTP delivery
New-SfosSMSGateway -Name "ExampleGateway" -URL "https://sms.example.test/send" -HTTPMethod Post -RequestParameterName @('to','msg') -RequestParameterValue @('{mobileno}','{msg}')
```

### One-Time Password Management

```powershell
# Read the one-time password settings and enrol a user
Get-SfosOTPSettings
Add-SfosOTPSettingsMember -Members "jdoe"

# Create a token for a user with a hexadecimal secret
$secret = ConvertTo-SecureString "0123456789abcdef0123456789abcdef" -AsPlainText -Force
New-SfosOTPTokens -User "jdoe" -Secret $secret -Algorithm SHA1

# Disable a token, every other field is preserved
Set-SfosOTPTokens -TokenId "ABC123" -Active 0
```

### Firewall, Admin, VPN and SSL VPN Authentication

```powershell
# Inspect which authentication servers the firewall consults for VPN logins
(Get-SfosVPNAuthentication).AuthenticationServerList

# Add a RADIUS server alongside the existing firewall authentication servers
Add-SfosFirewallAuthenticationMethodsMember -Members "RADIUS-Server1"

# Add a RADIUS server alongside the existing VPN authentication servers
Add-SfosVPNAuthenticationMember -Members "RADIUS-Server1"

# See Known limitations - the list must never become empty
Remove-SfosSSLVPNAuthenticationMember -Members "RADIUS-Server1"
```

### Web Authentication and Captive Portal

```powershell
# Retrieve the current captive portal branding
Get-SfosCaptivePortalAppearance

# Change only the sign-in prompt text, every other field is preserved
Set-SfosCaptivePortalAppearance -UserPrompt "Please sign in"

# Retrieve the current direct web proxy authentication configuration
Get-SfosDirectWebProxyAuthentication

# Add a terminal server to the multi-user hosts list
Add-SfosDirectWebProxyAuthenticationMember -Members "TS-Server1"
```

### SSO, STAS and Live User Sessions

```powershell
# Create a user-facing Azure AD SSO server (no role mapping)
$secret = ConvertTo-SecureString "MySecret" -AsPlainText -Force
New-SfosAzureADSSO -ServerName "CorpEntra" -ApplicationID "fa7fc787-011e-4398-812f-3152d8843320" -TenantID "10657f8b-d541-41a5-8e25-a8d7cbb9d4dd" -ClientSecret $secret -RedirectURI "fw.example.invalid" -DisplayName upn -EmailAddress email -FallbackUserGroup "Open Group" -UserType User

# Enable STAS (Single Agent Transparent Authentication Suite)
Set-SfosSTAS -ACTION Enable

# Preview a live user login/logout - see Known limitations, these throw on this firmware
Connect-SfosLiveUser -LiveUserName "jdoe" -IPAddress "10.0.0.55" -WhatIf
Disconnect-SfosLiveUser -LiveUserName "jdoe" -IPAddress "10.0.0.55" -WhatIf
```

## Available Cmdlets (97 total)

### Authentifizierungsserver (20 functions)
- `Get-SfosActiveDirectoryServer` - Retrieves ActiveDirectory authentication server objects from the Sophos Firewall.
- `New-SfosActiveDirectoryServer` - Creates a new ActiveDirectory authentication server on the Sophos Firewall.
- `Set-SfosActiveDirectoryServer` - Updates an existing ActiveDirectory authentication server on the Sophos Firewall.
- `Remove-SfosActiveDirectoryServer` - Removes an ActiveDirectory authentication server from the Sophos Firewall.
- `Get-SfosLDAPServer` - Retrieves LDAPServer authentication server objects from the Sophos Firewall.
- `New-SfosLDAPServer` - Creates a new LDAPServer authentication server on the Sophos Firewall.
- `Set-SfosLDAPServer` - Updates an existing LDAPServer authentication server on the Sophos Firewall.
- `Remove-SfosLDAPServer` - Removes an LDAPServer authentication server from the Sophos Firewall.
- `Get-SfosRADIUSServer` - Retrieves RADIUSServer authentication server objects from the Sophos Firewall.
- `New-SfosRADIUSServer` - Creates a new RADIUSServer authentication server on the Sophos Firewall.
- `Set-SfosRADIUSServer` - Updates an existing RADIUSServer authentication server on the Sophos Firewall.
- `Remove-SfosRADIUSServer` - Removes a RADIUSServer authentication server from the Sophos Firewall.
- `Get-SfosTACACSServer` - Retrieves TACACSServer authentication server objects from the Sophos Firewall.
- `New-SfosTACACSServer` - Creates a new TACACSServer authentication server on the Sophos Firewall.
- `Set-SfosTACACSServer` - Updates an existing TACACSServer authentication server on the Sophos Firewall.
- `Remove-SfosTACACSServer` - Removes a TACACSServer authentication server from the Sophos Firewall.
- `Get-SfosEDirectoryServer` - Retrieves EDirectory authentication server objects from the Sophos Firewall.
- `New-SfosEDirectoryServer` - Creates a new EDirectory authentication server on the Sophos Firewall.
- `Set-SfosEDirectoryServer` - Updates an existing EDirectory authentication server on the Sophos Firewall.
- `Remove-SfosEDirectoryServer` - Removes an EDirectory authentication server from the Sophos Firewall.

### Benutzer und Gruppen (10 functions)
- `Get-SfosUser` - Retrieves User objects from the Sophos Firewall.
- `New-SfosUser` - Creates a new User on the Sophos Firewall.
- `Set-SfosUser` - Updates an existing User object on the Sophos Firewall.
- `Remove-SfosUser` - Removes a User object from the Sophos Firewall.
- `Get-SfosUserGroup` - Retrieves UserGroup objects from the Sophos Firewall.
- `New-SfosUserGroup` - Creates a new UserGroup on the Sophos Firewall.
- `Set-SfosUserGroup` - Updates an existing UserGroup object on the Sophos Firewall.
- `Remove-SfosUserGroup` - Removes a UserGroup object from the Sophos Firewall.
- `Add-SfosUserGroupMember` - Adds members to an existing UserGroup object on the Sophos Firewall.
- `Remove-SfosUserGroupMember` - Removes members from an existing UserGroup object on the Sophos Firewall.

### Gast- und Clientless-Benutzer (14 functions)
- `Get-SfosGuestUser` - Retrieves GuestUser objects from the Sophos Firewall.
- `New-SfosGuestUser` - Creates a new GuestUser on the Sophos Firewall.
- `Remove-SfosGuestUser` - Removes a GuestUser object from the Sophos Firewall.
- `Get-SfosGuestUserSettings` - Retrieves the GuestUserSettings from the Sophos Firewall.
- `Set-SfosGuestUserSettings` - Updates the GuestUserSettings on the Sophos Firewall.
- `Get-SfosClientlessUser` - Retrieves ClientlessUser objects from the Sophos Firewall.
- `New-SfosClientlessUser` - Creates a new ClientlessUser on the Sophos Firewall.
- `Set-SfosClientlessUser` - Updates an existing ClientlessUser object on the Sophos Firewall.
- `Remove-SfosClientlessUser` - Removes a ClientlessUser object from the Sophos Firewall.
- `New-SfosClientlessUserRange` - Adds a range of ClientlessUser objects on the Sophos Firewall.
- `Get-SfosSMSGateway` - Retrieves SMSGateway objects from the Sophos Firewall.
- `New-SfosSMSGateway` - Creates a new SMSGateway on the Sophos Firewall.
- `Set-SfosSMSGateway` - Updates an existing SMSGateway object on the Sophos Firewall.
- `Remove-SfosSMSGateway` - Removes an SMSGateway object from the Sophos Firewall.

### Einmalpasswörter (8 functions)
- `Get-SfosOTPSettings` - Retrieves the OTPSettings singleton from the Sophos Firewall.
- `Set-SfosOTPSettings` - Updates the OTPSettings singleton on the Sophos Firewall.
- `Add-SfosOTPSettingsMember` - Adds usernames to the OTPSettings explicit OTP user list.
- `Remove-SfosOTPSettingsMember` - Removes usernames from the OTPSettings explicit OTP user list.
- `Get-SfosOTPTokens` - Retrieves OTPTokens objects from the Sophos Firewall.
- `New-SfosOTPTokens` - Creates a new OTPTokens object on the Sophos Firewall.
- `Set-SfosOTPTokens` - Updates an existing OTPTokens object on the Sophos Firewall.
- `Remove-SfosOTPTokens` - Removes an OTPTokens object from the Sophos Firewall.

### Firewall-Authentifizierung (14 functions)
- `Get-SfosFirewallAuthenticationGlobalSettings` - Retrieves the FirewallAuthentication GlobalSettings from the Sophos Firewall.
- `Set-SfosFirewallAuthenticationGlobalSettings` - Updates the FirewallAuthentication GlobalSettings on the Sophos Firewall.
- `Get-SfosFirewallAuthenticationMethods` - Retrieves the FirewallAuthentication AuthenticationMethods from the Sophos Firewall.
- `Set-SfosFirewallAuthenticationMethods` - Updates the FirewallAuthentication AuthenticationMethods on the Sophos Firewall.
- `Add-SfosFirewallAuthenticationMethodsMember` - Adds authentication servers to the FirewallAuthentication AuthenticationMethods server list.
- `Remove-SfosFirewallAuthenticationMethodsMember` - Removes authentication servers from the FirewallAuthentication AuthenticationMethods server list.
- `Get-SfosFirewallAuthenticationNTLMSettings` - Retrieves the FirewallAuthentication NTLMSettings from the Sophos Firewall.
- `Set-SfosFirewallAuthenticationNTLMSettings` - Updates the FirewallAuthentication NTLMSettings on the Sophos Firewall.
- `Get-SfosFirewallAuthenticationCTASSettings` - Retrieves the FirewallAuthentication CTASSettings from the Sophos Firewall.
- `Set-SfosFirewallAuthenticationCTASSettings` - Updates the FirewallAuthentication CTASSettings on the Sophos Firewall.
- `Get-SfosFirewallAuthenticationiOSWebClientSettings` - Retrieves the FirewallAuthentication iOSWebClientSettings from the Sophos Firewall.
- `Set-SfosFirewallAuthenticationiOSWebClientSettings` - Updates the FirewallAuthentication iOSWebClientSettings on the Sophos Firewall.
- `Get-SfosSSORadiusAccount` - Retrieves the FirewallAuthentication SSORadiusAccount configuration from the Sophos Firewall.
- `Set-SfosSSORadiusAccount` - Creates or replaces the FirewallAuthentication SSORadiusAccount configuration on the Sophos Firewall.

### Admin/VPN/SSLVPN (12 functions)
- `Get-SfosAdminAuthentication` - Retrieves the AdminAuthentication configuration from the Sophos Firewall.
- `Set-SfosAdminAuthentication` - Updates the AdminAuthentication configuration on the Sophos Firewall.
- `Add-SfosAdminAuthenticationMember` - Adds authentication servers to the AdminAuthentication server list.
- `Remove-SfosAdminAuthenticationMember` - Removes authentication servers from the AdminAuthentication server list.
- `Get-SfosVPNAuthentication` - Retrieves the VPNAuthentication configuration from the Sophos Firewall.
- `Set-SfosVPNAuthentication` - Updates the VPNAuthentication configuration on the Sophos Firewall.
- `Add-SfosVPNAuthenticationMember` - Adds authentication servers to the VPNAuthentication server list.
- `Remove-SfosVPNAuthenticationMember` - Removes authentication servers from the VPNAuthentication server list.
- `Get-SfosSSLVPNAuthentication` - Retrieves the SSLVPNAuthentication configuration from the Sophos Firewall.
- `Set-SfosSSLVPNAuthentication` - Updates the SSLVPNAuthentication configuration on the Sophos Firewall.
- `Add-SfosSSLVPNAuthenticationMember` - Adds authentication servers to the SSLVPNAuthentication server list.
- `Remove-SfosSSLVPNAuthenticationMember` - Removes authentication servers from the SSLVPNAuthentication server list.

### Web-Authentifizierung und Captive Portal (10 functions)
- `Get-SfosWebAuthenticationSettings` - Retrieves the WebAuthentication WebAuthenticationSettings from the Sophos Firewall.
- `Set-SfosWebAuthenticationSettings` - Updates the WebAuthentication WebAuthenticationSettings on the Sophos Firewall.
- `Get-SfosCaptivePortalAppearance` - Retrieves the WebAuthentication CaptivePortalAppearance from the Sophos Firewall.
- `Set-SfosCaptivePortalAppearance` - Updates the WebAuthentication CaptivePortalAppearance on the Sophos Firewall.
- `Get-SfosDefaultCaptivePortal` - Retrieves the DefaultCaptivePortal configuration from the Sophos Firewall.
- `Set-SfosDefaultCaptivePortal` - Updates the DefaultCaptivePortal configuration on the Sophos Firewall.
- `Get-SfosDirectWebProxyAuthentication` - Retrieves the DirectWebProxyAuthentication configuration from the Sophos Firewall.
- `Set-SfosDirectWebProxyAuthentication` - Updates the DirectWebProxyAuthentication configuration on the Sophos Firewall.
- `Add-SfosDirectWebProxyAuthenticationMember` - Adds hosts to the DirectWebProxyAuthentication MultiUserHosts list.
- `Remove-SfosDirectWebProxyAuthenticationMember` - Removes hosts from the DirectWebProxyAuthentication MultiUserHosts list.

### SSO/STAS/Live-User (9 functions)
- `Get-SfosAzureADSSO` - Retrieves Microsoft Entra ID (Azure AD) SSO server objects from the Sophos Firewall.
- `New-SfosAzureADSSO` - Creates a new Microsoft Entra ID (Azure AD) SSO server on the Sophos Firewall.
- `Set-SfosAzureADSSO` - Updates an existing Microsoft Entra ID (Azure AD) SSO server on the Sophos Firewall.
- `Remove-SfosAzureADSSO` - Removes a Microsoft Entra ID (Azure AD) SSO server from the Sophos Firewall.
- `Get-SfosSTAS` - Retrieves the STAS (Single Agent Transparent Authentication Suite) configuration from the Sophos Firewall.
- `Set-SfosSTAS` - Enables or disables STAS (Single Agent Transparent Authentication Suite) on the Sophos Firewall.
- `Get-SfosLiveUser` - Retrieves LiveUser objects (currently logged-in end users) from the Sophos Firewall.
- `Connect-SfosLiveUser` - Logs an end user in at the Sophos Firewall's live/transparent-authentication user tracking.
- `Disconnect-SfosLiveUser` - Logs an end user out of the Sophos Firewall's live/transparent-authentication user tracking.

## Known limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance. Every read-modify-write `Set-*` in this module
exists because of the general finding that an update replaces the whole entity - see the
points below for the exceptions and additional defects found on top of that.

- **`GuestUser` has no working update.** `operation="update"` is refused with `500`/`501`
  depending on the identifying field tried, and `operation="edit"` (undocumented but accepted
  by other entities in this API) answers `200` but silently creates a duplicate object instead
  of changing the one named - the original guest user is left untouched. No `Set-SfosGuestUser`
  cmdlet exists; to change a guest user's fields, remove and recreate it with
  `Remove-SfosGuestUser` and `New-SfosGuestUser`.
- **`Get-`/`Set-SfosGuestUserSettings` break the read path on this firmware.** Every call that
  reached the lab appliance - including a pure no-op update resending the values just read
  back - made every subsequent `Get-SfosGuestUserSettings` answer `<Status>Transaction fail</Status>`
  (no code attribute) instead of the settings, with no self-healing observed after 30+ seconds.
  The write itself still answers `200`. This looks like a firmware-side bug in the settings
  singleton's own transaction handling; both cmdlets are implemented documentation-faithful but
  are not usable on this firmware without the ability to verify the result through the web
  admin console immediately afterward.
- **Group membership lives on the user, not on the group, and is a single value.** Writing
  `GroupMembers` under `UserGroup` answers `200` and does nothing. The `Group` field of a
  `User` holds exactly one group name, so a user belongs to exactly one group at a time -
  `Add-SfosUserGroupMember`/`Add-SfosUserGroupMember` on a user already in another group moves
  it rather than adding a second membership.
- **`Set-`/`Add-`/`Remove-SfosAdminAuthentication` were deliberately not verified against the
  appliance.** These fields carry the firewall's own management/administrator login path;
  a wrong write could lock out the API user needed to fix it. The cmdlets are implemented
  strictly to the documented request shape and to the pattern confirmed for
  `FirewallAuthentication`, but the write itself is unconfirmed - see the cmdlet `.NOTES`.
- **`Connect-`/`Disconnect-SfosLiveUser` throw on this firmware.** The firewall accepts the
  request (`HTTP 200`, a well-formed `<Response>`) but returns no `<Status>` element at all for
  the `LiveUser` object, so neither cmdlet can confirm the login/logout took effect; both throw
  rather than report success they cannot verify. Not usable on this firmware.
- **Two specific fields are rejected outright.** `Set-SfosDirectWebProxyAuthentication
  -PerConnectionAuth Enable` and `Set-SfosWebAuthenticationSettings -OpenWebpageInNewWindow
  Disable` are both answered with `501` and an empty `<InvalidParams/>` - no field is named as
  invalid, so nothing can be narrowed down further client-side.
- **The authentication server lists of firewall, VPN and SSL VPN authentication must never
  become empty.** Removing the last entry answers `500` and changes nothing; there is no
  client-side guard against attempting it.
- **`Set-SfosSTAS` covers only enable/disable.** The `Collector`, `Settings` and `VpnZone`
  sub-blocks that `Get-SfosSTAS` exposes once STAS is enabled are read-only in this module;
  writing them would need per-sub-block status verification that was never measured live.
- **`Remove-Sfos*` reports a non-existent object inconsistently.** Depending on the entity, an
  attempt to remove an object that is not there answers `200` "Configuration applied
  successfully" (e.g. `Remove-SfosAzureADSSO`), `526` "no record" or `528` "Trying to update
  default entities which are not editable" - never a message that actually says "not found".
  None of the `Remove-*` cmdlets in this module pre-check existence, so the caller cannot
  distinguish "removed" from "never existed" from the response alone.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific user with error handling
    $user = Get-SfosUser -UsernameLike "jdoe" -ErrorAction Stop
    Write-Output "Found user: $($user.AccountName) - Group: $($user.Group)"
} catch {
    Write-Error "Failed to retrieve user: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosUser | Select-Object AccountName` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are entity-specific (User, UserGroup, GuestUser, ClientlessUser, ...)
- **A user unexpectedly moved between groups**: See Known limitations - group membership is a single value on the user, not a list on the group
- **`Set-SfosGuestUserSettings` breaks `Get-SfosGuestUserSettings`**: See Known limitations - this is a known, unresolved firmware limitation, not a module defect
- **`Connect-`/`Disconnect-SfosLiveUser` always throw**: See Known limitations - the firewall returns no status for this operation on this firmware

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.Authentication) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License
