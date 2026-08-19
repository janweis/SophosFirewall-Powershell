# SophosFirewall.Email

`SophosFirewall.Email` manages the PROTECT > Email area of a Sophos Firewall: the policies that
decide what happens to mail passing the firewall, the address groups and exceptions they refer
to, data control lists, SPX encryption, and the mail configuration itself.

The area exists in two shapes, and an appliance runs in one of them at a time. In **MTA mode**
the firewall accepts and delivers mail itself: SMTP policies, exception policies, MTA address
groups and MTA data control lists are the objects that matter. In **legacy mode** the firewall
scans mail in passing, and anti-spam rules and SMTP malware scanning policies take that role.
Some objects are shared and behave the same in both shapes: the mail configuration, malware
protection, POP/IMAP scanning policies and trusted domains.

## Requirements

- `SophosFirewall.Core` 1.3.5 or later (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.Email -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosEmailConfiguration
Get-SfosSMTPPolicy
Get-SfosMailRelaySettings

# A domain is referenced through an address group, not typed into the policy
New-SfosMTAAddressGroup -Name 'Partner domains' -GroupType EmailAddressOrDomain -Member 'partner.example.com'
New-SfosSMTPPolicy -Name 'Partner mail' -DomainName 'Partner domains' -MalwareScanning Enable -DropMessageGreaterThan 51200

# An exception policy matches on host objects that already exist
New-SfosIPHost -Name 'MailRelay' -HostType IP -IPAddress '192.0.2.50'
New-SfosMailExceptionPolicy -Name 'Relay bypass' -ForTheseSourceHost Enable -SourceHost 'MailRelay' -Antispam Enable
```

## Which mode is the appliance in, and how to change it

The mode lives in its own API object, `SMTPDeploymentMode`, with a single field: `MTAMode` is
`ON` for MTA mode and `OFF` for legacy mode. Reading it is the only reliable way to tell the two
apart - objects of the inactive shape stay readable, so finding populated anti-spam rules or
SMTP policies proves nothing about which mode is running.

```powershell
Get-SfosSMTPDeploymentMode                                  # MTAMode: ON = MTA, OFF = legacy

Set-SfosSMTPDeploymentMode -MTAMode OFF                     # switch to legacy mail scanning
Set-SfosSMTPDeploymentMode -MTAMode ON                      # switch back to MTA mode
```

The change takes effect immediately, with no reboot: an operation that was refused with `545`
before the switch goes through afterwards. `Set-SfosSMTPDeploymentMode` is marked high impact,
so it asks before writing and automation has to pass `-Confirm:$false`.

This changes how the appliance handles mail for everyone behind it. Read both shapes before
flipping it and compare afterwards, so a value lost in the transition does not go unnoticed.

## Cmdlets

### MTA mode

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSMTPPolicy` | Reads SMTP policies - the largest object of the area. |
| `New-SfosSMTPPolicy` | Creates an SMTP policy. |
| `Set-SfosSMTPPolicy` | Updates an SMTP policy. |
| `Remove-SfosSMTPPolicy` | Removes an SMTP policy. |
| `Get-SfosMailExceptionPolicy` | Reads exceptions from scanning and protection checks. |
| `New-SfosMailExceptionPolicy` | Creates an exception policy. |
| `Set-SfosMailExceptionPolicy` | Updates an exception policy. |
| `Remove-SfosMailExceptionPolicy` | Removes an exception policy. |
| `Get-SfosMTAAddressGroup` | Reads address groups: RBL lists, IP addresses, email addresses and domains. |
| `New-SfosMTAAddressGroup` | Creates an address group. |
| `Set-SfosMTAAddressGroup` | Updates an address group. |
| `Remove-SfosMTAAddressGroup` | Removes an address group. |
| `Get-SfosMTADataControlList` | Reads data control lists built from the signature catalogue. |
| `New-SfosMTADataControlList` | Creates a data control list. |
| `Set-SfosMTADataControlList` | Updates a data control list. |
| `Remove-SfosMTADataControlList` | Removes a data control list. |
| `Get-SfosMTASPXConfiguration` | Reads the SPX encryption settings. |
| `Set-SfosMTASPXConfiguration` | Updates the SPX encryption settings. |
| `Get-SfosMTASPXTemplate` | Reads SPX templates. |
| `New-SfosMTASPXTemplate` | Creates an SPX template. |
| `Set-SfosMTASPXTemplate` | Updates an SPX template. |
| `Remove-SfosMTASPXTemplate` | Removes an SPX template. |
| `Get-SfosAdvancedSMTPSetting` | Reads the advanced SMTP settings, including the BATV secret. |
| `Set-SfosAdvancedSMTPSetting` | Updates the advanced SMTP settings. |

### Legacy mode

| Cmdlet | Purpose |
|---|---|
| `Get-SfosAntiSpamRule` | Reads anti-spam rules. |
| `New-SfosAntiSpamRule` | Creates an anti-spam rule. |
| `Set-SfosAntiSpamRule` | Updates an anti-spam rule. |
| `Remove-SfosAntiSpamRule` | Removes an anti-spam rule. |
| `Get-SfosSMTPMalwareScanningPolicy` | Reads SMTP malware scanning policies. |
| `New-SfosSMTPMalwareScanningPolicy` | Creates an SMTP malware scanning policy. |
| `Set-SfosSMTPMalwareScanningPolicy` | Updates an SMTP malware scanning policy. |
| `Remove-SfosSMTPMalwareScanningPolicy` | Removes an SMTP malware scanning policy. |
| `Get-SfosAntiSpamEmailArchiver` | Reads email archivers. |
| `New-SfosAntiSpamEmailArchiver` | Creates an email archiver. |
| `Set-SfosAntiSpamEmailArchiver` | Updates an email archiver. |
| `Remove-SfosAntiSpamEmailArchiver` | Removes an email archiver. |
| `Get-SfosAntiSpamQuarantineDigestSettings` | Reads the quarantine digest settings. |
| `Set-SfosAntiSpamQuarantineDigestSettings` | Updates the quarantine digest settings. |
| `Get-SfosAVASAddressGroup` | Reads the legacy address groups. |
| `New-SfosAVASAddressGroup` | Creates a legacy address group. |
| `Set-SfosAVASAddressGroup` | Updates a legacy address group. |
| `Remove-SfosAVASAddressGroup` | Removes a legacy address group. |
| `Get-SfosDataControlList` | Reads the legacy data control lists. |
| `New-SfosDataControlList` | Creates a legacy data control list. |
| `Set-SfosDataControlList` | Updates a legacy data control list. |
| `Remove-SfosDataControlList` | Removes a legacy data control list. |
| `Get-SfosSPXConfiguration` | Reads the legacy SPX configuration. |
| `Set-SfosSPXConfiguration` | Updates the legacy SPX configuration. |
| `Get-SfosSPXTemplate` | Reads the legacy SPX templates. |
| `New-SfosSPXTemplate` | Creates a legacy SPX template. |
| `Set-SfosSPXTemplate` | Updates a legacy SPX template. |
| `Remove-SfosSPXTemplate` | Removes a legacy SPX template. |

### Shared by both shapes

| Cmdlet | Purpose |
|---|---|
| `Get-SfosEmailConfiguration` | Reads the mail configuration: general settings, SMTP/S and POP/IMAP, TLS. |
| `Set-SfosEmailConfiguration` | Updates the mail configuration. |
| `Get-SfosMailMalwareProtection` | Reads the malware protection settings for mail. |
| `Set-SfosMailMalwareProtection` | Updates the malware protection settings for mail. |
| `Get-SfosPOPIMAPScanningPolicy` | Reads POP/IMAP scanning policies. |
| `New-SfosPOPIMAPScanningPolicy` | Creates a POP/IMAP scanning policy. |
| `Set-SfosPOPIMAPScanningPolicy` | Updates a POP/IMAP scanning policy. |
| `Remove-SfosPOPIMAPScanningPolicy` | Removes a POP/IMAP scanning policy. |
| `Get-SfosAntiSpamTrustedDomain` | Reads trusted domains. |
| `New-SfosAntiSpamTrustedDomain` | Adds a trusted domain. |
| `Remove-SfosAntiSpamTrustedDomain` | Removes a trusted domain. |

A trusted domain carries nothing but its name, so there is no `Set-` cmdlet for it.

### Deployment mode

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSMTPDeploymentMode` | Reads whether the appliance runs MTA mode or legacy mail scanning. |
| `Set-SfosSMTPDeploymentMode` | Switches between the two. Marked high impact - automation needs -Confirm:$false. |

### Read-only

These control how the appliance accepts and forwards mail; write paths are deliberately not
implemented.

| Cmdlet | Purpose |
|---|---|
| `Get-SfosMailRelaySettings` | Reads the relay settings. |
| `Get-SfosSmarthostSettings` | Reads the smarthost settings. |
| `Get-SfosMTABlockedSender` | Reads the blocked sender list. |
| `Get-SfosDKIMSigning` | Reads the DKIM signing entries. |
| `Get-SfosDKIMVerification` | Reads the DKIM verification settings. |

## Limitations

**Some objects only accept writes in one of the two modes, and it is decided per object.** A
refusal comes back as status `545`, which the vendor documents as `MTAModeDisableCheck`. Reading
always works, in either mode.

Measured with the appliance in MTA mode: anti-spam rules, SMTP malware scanning policies, the
legacy data control lists and the legacy SPX templates are refused, while the legacy address
groups and the email archiver are accepted. In legacy mode the MTA address groups are refused in
turn. The obvious rule - "the shape you are not in is read-only" - does not hold, so treat a
`545` as a statement about that one operation, not about everything around it.

**Some fields take the name of an existing object, not a literal.** An SMTP policy references
its domains through an `MTAAddressGroup` of type `EmailAddressOrDomain`; an exception policy
references its source hosts through host objects. A literal value is refused with `501`. Both
cmdlets say so in their error message.

**`Set-SfosSMTPPolicy` requires `-MalwareScanning` and `-DropMessageGreaterThan`.** The firewall
accepts both when creating a policy but never returns them when reading one back, so they
cannot be preserved across an update. Making them mandatory is the honest alternative to
silently sending an empty value on every change.

**An email archiver only really accepts the recipient value `Any`.** Another address on its own
is refused; the same address alongside `Any` is accepted with `200` and then silently dropped.

**The quarantine digest settings can be read but barely written.** The write path reports its
status at two separate roots, and the settings sub-block refuses even an unchanged round trip
with `501`. The cause is unresolved and was not probed further: the object carries live
recipient lists.

**`Set-SfosMTASPXConfiguration` has one field without a working write shape.** Five variants of
`-AllowedNetwork` were refused with `501`; clearing it or leaving it out works.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
