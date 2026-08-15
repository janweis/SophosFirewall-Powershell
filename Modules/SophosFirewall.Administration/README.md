# SophosFirewall.Administration Module

## Overview

The **Administration** module provides PowerShell cmdlets for the **SYSTEM >
Administration** area of the Sophos XGS / SFOS 22.0 API documentation. With 29
exported functions, it manages mail server notification settings, SNMP agent
configuration, system date/time, SNMP communities, SNMPv3 users,
customizable end-user messages, the appliance service access matrix (which
zones may reach which management service), the admin settings singleton
(hostname, web admin/portal HTTPS ports, login security, password
complexity, login disclaimer, default language), and Local Service ACL
rules (management access by zone/source host/service). Requires
`SophosFirewall.Core` (minimum version 1.3.0).

**Several cmdlets in this module are access-critical**: a wrong value can
make the appliance unreachable with no way to revert the change remotely.
Read the Known Limitations section below before using
`Set-SfosApplianceAccess`, `Set-SfosWebAdminSettings` or
`Set-SfosLoginSecurity`.

## Features

- **Notification**: `Get-`/`Set-SfosNotification` for the device-wide mail
  server used for system notification emails
- **SNMP Agent Configuration**: `Get-`/`Set-SfosSNMPAgentConfiguration` for
  the SNMP agent toggle, location and contact details
- **SNMP Community**: `Get-`/`New-`/`Set-`/`Remove-SfosSNMPCommunity` for
  SNMP v1/v2c communities and their authorized manager hosts
- **SNMPv3 User**: `Get-`/`New-`/`Set-`/`Remove-SfosSNMPv3User` for SNMPv3
  USM users with authentication/privacy credentials
- **Time**: `Get-`/`Set-SfosTime` for the appliance time zone and clock
- **Messages**: `Get-`/`Set-SfosMessages` for SMTP rejection texts, the admin
  login disclaimer, the default guest-user SMS text, and
  authentication/session messages
- **Appliance Access**: `Get-`/`Set-SfosApplianceAccess` for the zone-per-service
  matrix that controls which zones may reach HTTPS, SSH, the captive portal
  and 11 other management services
- **Admin Settings**: `Get-SfosAdminSettings` plus five focused single-block `Set-*`
  cmdlets - `Set-SfosWebAdminSettings`, `Set-SfosLoginSecurity`,
  `Set-SfosAdminPasswordComplexity`, `Set-SfosLoginDisclaimer`, `Set-SfosHostname` -
  each writing only its own block of the AdminSettings singleton (HTTPSport and the
  other blocks are never resent)
- **Factory reset**: `Reset-SfosToFactoryDefaults` - the AdminSettings singleton also
  carries a misleadingly-named `DefaultConfigurationLanguage` field that is in fact a
  **factory reset** (web admin: Backup & firmware > Firmware); the cmdlet is named for
  what it does, carries `ConfirmImpact = High`, and is documented in Known Limitations
- **Local Service ACL**: `Get-`/`New-`/`Set-`/`Remove-SfosLocalServiceACL`
  for rules controlling which zones/source hosts may reach which management
  services (`New`/`Set`/`Remove` are UNCONFIRMED - never executed live, see
  Known Limitations)
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML
  API

## Installation

```powershell
Install-Module -Name SophosFirewall.Administration
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.Administration.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module, version 1.3.0 or higher (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### Read and Update Settings

```powershell
Get-SfosNotification
Set-SfosNotification -SenderAddress 'firewall-alerts@example.test'

Get-SfosSNMPAgentConfiguration
Set-SfosSNMPAgentConfiguration -ContactPerson 'ops@example.test'

Get-SfosTime
Set-SfosTime -TimeZone 'Europe/Berlin'

$secret = ConvertTo-SecureString 'public-secret' -AsPlainText -Force
New-SfosSNMPCommunity -Name 'Monitoring' -CommunityString $secret -AuthorizedHostIpv4 '10.0.0.50' -AcceptQueries 'True'
Get-SfosSNMPCommunity
Remove-SfosSNMPCommunity -Name 'Monitoring'

$authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
$privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
New-SfosSNMPv3User -Name 'MonitoringUser' -SNMPUsername 'monitor' -AuthenticationAlgorithm 'MD5' -AuthenticationPassword $authPw -EncryptionAlgorithm 'DES' -EncryptionPassword $privPw -AcceptQueries 'True'
Get-SfosSNMPv3User
Remove-SfosSNMPv3User -Name 'MonitoringUser'

(Get-SfosMessages).Administration.DisclaimerMessage
Set-SfosMessages -DefaultSMS 'Your Sophos guest account is ready.'

Get-SfosApplianceAccess
# Add DMZ to the zones allowed to ping the appliance, every other service is preserved.
# UNCONFIRMED - never executed live, see Known Limitations before using this cmdlet.
Set-SfosApplianceAccess -Ping 'LAN', 'WiFi', 'DMZ'

Get-SfosAdminSettings
Set-SfosLoginDisclaimer -LoginDisclaimer 'Enable'
Set-SfosAdminPasswordComplexity -MinimumPasswordLengthValue 12
Set-SfosHostname -HostNameDesc 'Lab firewall'
# DANGER: Reset-SfosToFactoryDefaults WIPES the appliance to factory defaults - it is NOT a
# language setting despite the API field name. Prompts unless -Confirm:$false. Left commented out.
# Reset-SfosToFactoryDefaults -DefaultLanguage German

Get-SfosLocalServiceACL
# UNCONFIRMED - never executed live, see Known Limitations before using these cmdlets.
# New-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Service HTTPS -SourceZone 'LAN' -Action accept
```

## Cmdlet Reference

| Cmdlet | Description |
|---|---|
| `Get-SfosNotification` | Reads the mail server notification settings |
| `Set-SfosNotification` | Updates the mail server notification settings |
| `Get-SfosSNMPAgentConfiguration` | Reads the SNMP agent configuration |
| `Set-SfosSNMPAgentConfiguration` | Updates the SNMP agent configuration |
| `Get-SfosSNMPCommunity` | Reads SNMP communities |
| `New-SfosSNMPCommunity` | Creates an SNMP community |
| `Set-SfosSNMPCommunity` | Updates an SNMP community |
| `Remove-SfosSNMPCommunity` | Removes an SNMP community |
| `Get-SfosSNMPv3User` | Reads SNMPv3 users |
| `New-SfosSNMPv3User` | Creates an SNMPv3 user |
| `Set-SfosSNMPv3User` | Updates an SNMPv3 user |
| `Remove-SfosSNMPv3User` | Removes an SNMPv3 user |
| `Get-SfosTime` | Reads the appliance time zone and clock |
| `Set-SfosTime` | Updates the appliance time zone and clock |
| `Get-SfosMessages` | Reads the customizable end-user messages |
| `Set-SfosMessages` | Updates the customizable end-user messages |
| `Get-SfosApplianceAccess` | Reads the zone-per-service access matrix |
| `Set-SfosApplianceAccess` | Updates the zone-per-service access matrix (UNCONFIRMED) |
| `Get-SfosAdminSettings` | Reads the six-block admin settings singleton |
| `Set-SfosWebAdminSettings` | Updates web admin/portal HTTPS ports, certificate, redirect mode (UNCONFIRMED) |
| `Set-SfosLoginSecurity` | Updates admin session timeout and failed-login blocking (UNCONFIRMED) |
| `Set-SfosAdminPasswordComplexity` | Updates the admin password complexity policy |
| `Set-SfosLoginDisclaimer` | Updates the admin login disclaimer toggle |
| `Set-SfosHostname` | Updates the appliance hostname/description |
| `Reset-SfosToFactoryDefaults` | **FACTORY-RESETS the appliance** (the API's `DefaultConfigurationLanguage` field is a factory reset, not a language setting); ConfirmImpact High |
| `Get-SfosLocalServiceACL` | Reads Local Service ACL rules |
| `New-SfosLocalServiceACL` | Creates a Local Service ACL rule (UNCONFIRMED) |
| `Set-SfosLocalServiceACL` | Updates a Local Service ACL rule (UNCONFIRMED) |
| `Remove-SfosLocalServiceACL` | Removes a Local Service ACL rule (UNCONFIRMED) |

## Known Limitations

- `Set-SfosNotification`'s `-SmtpPassword` is sent only when explicitly
  supplied; `Get-SfosNotification` always reads `Password` back empty on this
  firmware (no hash, unlike `ThirdPartyFeed`), so whether omitting it
  preserves or clears the stored mail server password could not be confirmed
  without a live SMTP server. See the cmdlet's `.NOTES`.
- `Set-SfosNotification -SmtpPort` is a silent no-op on this firmware: the
  request answers 200 and the port is unchanged. `-NotificationServer` and
  `-ManagementInterface` answer 501 against the lab's loopback `MailServer`
  placeholder (misleadingly naming `MailServer` in the error). `Get-`/
  `Set-SfosNotification -AuthenticationRequired 'Enable'` likewise does not
  persist - it reads back as `'Disable'` regardless. See the region header in
  the `.psm1` for details.
- `Set-SfosSNMPAgentConfiguration` does not expose `-AgentPort`/`-ManagerPort`:
  the API documents both as read-only.
- `Set-SfosSNMPAgentConfiguration` could not be verified live: on the lab
  appliance `Location` and `Name` are stored empty but are enforced as
  mandatory on every update (measured, `400` naming each in turn), so *any*
  update - even a single-field change of `ContactPerson` - requires supplying
  non-empty values for both, and there is no evidence a firewall value can be
  set back to empty afterward. Writing to this entity risks permanently
  losing the appliance's blank baseline, so no write was attempted; the read
  path is verified live, the write path is documentation-faithful and
  unconfirmed, matching the class of entity already flagged this way
  elsewhere (e.g. `GuestUserSettings`, `SiteToSiteClient`).
- `Set-SfosTime -TimeZone` causes a 30-90 second management-interface outage
  while the appliance restarts the affected service - the call itself times
  out client-side and the change lands after the fact. See the cmdlet's
  `.NOTES`.
- `Set-SfosTime` only merges `TimeZone` and the clock fields from the current
  object. `PredefinedNTPServer`, `NTPServer` and `SyncNow` are absent from
  `Get-SfosTime` on the lab appliance (NTP not configured) and are sent only
  when the caller binds them explicitly.
- `SNMPv3User`'s `-AuthenticationAlgorithm`/`-EncryptionAlgorithm` are an
  undocumented, only partially mapped enum - no page exists for this entity
  on this API version. `'MD5'`/`'DES'`/`'AES'` are confirmed text values;
  other algorithms only accept numeric codes with no known text form. No
  `ValidateSet` is applied. See the `.psm1` region header for the full
  measurement.
- `Set-SfosSNMPv3User` requires `-AuthenticationPassword`/`-EncryptionPassword`
  on every call; there is no working way to preserve the stored secret.
  Resending the read-back hash with its `hashform` attribute (the mechanism
  that works for `Set-SfosSNMPCommunity`/`Set-SfosSSLBookmark`) makes the
  firewall answer with no `SNMPv3User` element and no status at all - not
  even a code-less one. See the `.psm1` region header for the full
  measurement.
- `Get-SfosMessages` returns only the SMTP fields the lab appliance actually
  has; the doc sample lists three more (`DataControlListRejection`,
  `SourceIPAddressRejection`, `DestinationIPAddressRejection`) that never
  appeared on a live `Get` and are not implemented.
- No `Reset-SfosMessages` cmdlet is provided. The documented "Reset Admin
  Messages" operation was probed with every plausible XML shape and each one
  answered `200` while changing nothing - a silent no-op. Use
  `Set-SfosMessages` with the original text to revert a field.
- `Set-SfosMessages` text fields are trimmed of trailing whitespace by the
  firewall on write - resending a value with trailing spaces intact loses
  them, confirmed on the lab's pre-existing `NotAuthenticate` baseline text.
- **`Set-SfosApplianceAccess` was never executed against a live firewall.**
  This entity has no documentation page anywhere in the SFOS 22.0 API menu.
  `Https`/`SSH` carry the appliance's own management access; removing the
  zone that hosts the current session (typically `LAN`) can make the
  appliance permanently unreachable with no out-of-band recovery path on
  this lab. The generated request XML was verified structurally only, by
  shadowing `Invoke-SfosApi` in the calling session (no network call).
- **`Set-SfosWebAdminSettings` and `Set-SfosLoginSecurity` were never
  executed against a live firewall**, for the same reason: `-HTTPSport` and
  the failed-login block settings both gate the current admin session's own
  reachability. Both were verified structurally only, the same way as
  `Set-SfosApplianceAccess`.
- **`AdminSettings` write status lands FLAT and per-block**, not nested
  under `AdminSettings` - `/Response/HostnameSettings/Status`,
  `/Response/WebAdminSettings/Status`, `/Response/LoginSecurity/Status`,
  `/Response/PasswordComplexitySettings/Status`,
  `/Response/LoginDisclaimer/Status`,
  `/Response/DefaultConfigurationLanguage/Status` - one independent status
  per block, even though a single request only ever changes one block. Every
  `Set-*` in this region asserts against its own block's path.
- **Root cause of the AdminSettings outages (RESOLVED)**: the early
  full-object AdminSettings writes resent the whole singleton, including its
  `<DefaultConfigurationLanguage>` element. That element is not a language
  setting - despite the API field name it is a **factory reset** (web admin:
  Backup & firmware > Firmware, "reset to factory settings with the default
  language"). Every such write therefore factory-reset the lab appliance,
  which is why it went unreachable and needed a snapshot each time. Two fixes
  followed: (1) every `Set-*` in this region is now a single-block write that
  sends only its own block, so it never resends the factory-reset field -
  `Set-SfosLoginDisclaimer` and `Set-SfosHostname` are since live-confirmed to
  change only their block and leave HTTPSport untouched; (2) the factory-reset
  field is exposed only as `Reset-SfosToFactoryDefaults` (ConfirmImpact High),
  named for what it does. `Set-SfosAdminPasswordComplexity` is now a safe
  single-block write.
- **`New-`/`Set-`/`Remove-SfosLocalServiceACL` were never executed against a
  live firewall.** This entity has no documentation page anywhere in the
  SFOS 22.0 API menu, though a field shape for it (`RuleName`, `Services`
  mandatory; `Description`, `IPFamily`, `SourceZone`, `Hosts`, `Action`
  optional) is documented. The lab appliance has zero rules configured, so
  none of this is corroborated against a live sample. This entity controls
  admin/API/SSH/SNMP reachability by zone and source host - a wrong write
  (especially `Action drop`, or a rule excluding the management source) can
  cut off the same access path the API itself uses, with no out-of-band
  recovery on this lab, the same class of risk as `Set-SfosSpoofPrevention`'s
  measured lock-out elsewhere in this project. All three cmdlets are shipped
  documentation-faithful and UNCONFIRMED; only the generated request XML was
  verified, by shadowing `Invoke-SfosApi` (no network call).

## License

MIT License - see [LICENSE.txt](LICENSE.txt)

## API Reference

https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/
