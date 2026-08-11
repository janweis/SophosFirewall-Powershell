# SophosFirewall.Firewall Module

> **Security warning.** These cmdlets change the rule base of a live firewall: firewall
> rules, rule groups, NAT rules and SSL/TLS inspection rules. A rule inserted at the wrong
> position, or an update that drops a rule's position, changes which traffic the appliance
> permits - immediately, with no confirmation beyond `ShouldProcess`. Every write cmdlet in
> this module supports `-WhatIf`; use it before running an unfamiliar call against a
> production firewall, especially anything that touches `-Position`, `-After` or `-Before`.

## Overview

The **Firewall** module provides PowerShell cmdlets for the **PROTECT > Firewall** area of
the Sophos XGS / SFOS 22.0 API documentation; the SFOS web admin presents the same area as
**Rules and policies**. With 21 functions, it manages firewall rules (network policies),
firewall rule groups, NAT rules, SSL/TLS inspection rules and the device-wide SSL/TLS
inspection settings. Requires `SophosFirewall.Core`.

## Features

- **Firewall Rules**: Network-policy security rules, with a builder for the policy subtree
- **Firewall Rule Groups**: Named groupings of firewall rules, with member management
- **NAT Rules**: Source and destination NAT policies
- **SSL/TLS Inspection Rules**: Per-traffic decrypt/exempt/deny rules
- **SSL/TLS Inspection Settings**: Device-wide TLS engine configuration (singleton)
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Import-Module -Name SophosFirewall.Firewall
```

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.Firewall.psd1"
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

### Firewall Rule Management

```powershell
# List rules in evaluation order
Get-SfosFirewallRule | Format-Table Name, Status, Position, PolicyType

# Build the NetworkPolicy subtree, then preview a new disabled rule at the bottom
$policy = New-SfosFirewallRuleNetworkPolicy -Action Accept -SourceZone "LAN" -DestinationZone "WAN"
New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $policy -WhatIf

# Create it for real
New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $policy

# Enable it - Position, After/Before and NetworkPolicy are preserved
Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN" | Set-SfosFirewallRule -Status Enable

# Preview removal
Remove-SfosFirewallRule -Name "Allow-LAN-to-WAN" -WhatIf
```

### Changing a single NetworkPolicy field

A rule carries what it actually does in its `NetworkPolicy` subtree - roughly 30 fields such
as `Action`, the zone and service lists, `ScanVirus`, `IntrusionPrevention` and
`ApplicationControl`. `Get-SfosFirewallRule` returns it as a nested object, and
`Set-SfosFirewallRule` accepts each of those fields as its own parameter. Only the fields you
pass are changed; everything else is read from the rule and written back unchanged.

```powershell
# Turn on virus scanning. Nothing else about the rule changes.
Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -ScanVirus Enable

# Several fields at once
Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -LogTraffic Enable -IntrusionPrevention "lantowan_general"

# Inspect the current policy
(Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN").NetworkPolicy
```

Do **not** build a fresh policy with `New-SfosFirewallRuleNetworkPolicy` just to change one
field. That cmdlet applies its own defaults to everything you leave out, so a policy built to
switch on virus scanning would also reset intrusion prevention, application control and the
schedule. To start from an existing policy instead, pipe it in - then only the parameters you
supply override it:

```powershell
$policy = (Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN").NetworkPolicy |
    New-SfosFirewallRuleNetworkPolicy -ScanVirus Enable

# -NetworkPolicy replaces the whole subtree, so pass a complete policy
Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -NetworkPolicy $policy
```

### Firewall Rule Group Management

```powershell
# Get all rule groups
Get-SfosFirewallRuleGroup -NameLike "Outbound"

# Create an empty group
New-SfosFirewallRuleGroup -Name "Outbound" -Description "Outbound rules"

# Add a member
Add-SfosFirewallRuleGroupMember -Name "Outbound" -Members "Allow-LAN-to-WAN"

# Inspect membership
(Get-SfosFirewallRuleGroup -NameLike "Outbound").SecurityPolicyList

# Update the description, membership is preserved
Set-SfosFirewallRuleGroup -Name "Outbound" -Description "Updated description"

# Remove a member - see Known Firmware Limitations, this can fail even though the firewall answers 200
Remove-SfosFirewallRuleGroupMember -Name "Outbound" -Members "Allow-LAN-to-WAN"

# Delete the (now empty) group
Remove-SfosFirewallRuleGroup -Name "Outbound"
```

### NAT Rule Management

```powershell
# Get all NAT rules
Get-SfosNATRule -NameLike "SNAT"

# Create a disabled masquerade rule at the bottom of the rule list
New-SfosNATRule -Name "SNAT-LAN-to-WAN" -TranslatedSource "MASQ" -Status Disable -Position Bottom

# Update only the description; Position and every translation field are preserved
Set-SfosNATRule -Name "SNAT-LAN-to-WAN" -Description "Masquerade LAN to WAN"

# Enable it via the pipeline
Get-SfosNATRule -NameLike "SNAT-LAN-to-WAN" | Set-SfosNATRule -Status Enable

# Preview removal
Remove-SfosNATRule -Name "SNAT-LAN-to-WAN" -WhatIf
```

### SSL/TLS Inspection Rule Management

```powershell
# Read existing rules - the built-in default rule is flagged IsDefault=Yes
Get-SfosSSLTLSInspectionRule | Format-Table Name, IsDefault, Enable, DecryptAction

# Build a website reference and preview a new exemption rule.
# See Known Firmware Limitations: New-SfosSSLTLSInspectionRule is documentation-faithful
# but every tested call was rejected with 501 on the lab firewall.
$website = [PSCustomObject]@{ Name = "Banking"; Type = "Web Category" }
New-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -Enable No -DecryptAction "Do not decrypt" -Website $website -WhatIf

# Update a non-default rule - Set-/Remove- refuse rules with IsDefault=Yes
Set-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -Enable No -WhatIf

# Preview removal of a non-default rule
Remove-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -WhatIf
```

### SSL/TLS Inspection Settings

The settings functions manage a device-wide singleton: no `-Name`, no `New-`/`Remove-`,
only `Get-` and `Set-`. Every field acts firewall-wide - see Known Firmware Limitations
before running the `Set-` example without `-WhatIf`.

```powershell
Get-SfosSSLTLSInspectionSettings

# Preview a change to the RSA re-signing CA only; every other field is preserved
Set-SfosSSLTLSInspectionSettings -RSACA "MyIssuingCA" -WhatIf
```

## Available Cmdlets (21 total)

### Firewall Rule Management (5 functions)
- `Get-SfosFirewallRule` - Retrieve FirewallRule objects
- `New-SfosFirewallRule` - Create a new firewall rule (PolicyType=Network only)
- `Set-SfosFirewallRule` - Update an existing firewall rule
- `Remove-SfosFirewallRule` - Delete a firewall rule
- `New-SfosFirewallRuleNetworkPolicy` - Build a NetworkPolicy subtree for New-/Set-SfosFirewallRule (no API call)

### Firewall Rule Group Management (6 functions)
- `Get-SfosFirewallRuleGroup` - Retrieve FirewallRuleGroup objects
- `New-SfosFirewallRuleGroup` - Create a new rule group
- `Set-SfosFirewallRuleGroup` - Update an existing rule group
- `Remove-SfosFirewallRuleGroup` - Delete a rule group
- `Add-SfosFirewallRuleGroupMember` - Add firewall rules to a group
- `Remove-SfosFirewallRuleGroupMember` - Remove firewall rules from a group (append-only on this firmware, see below)

### NAT Rule Management (4 functions)
- `Get-SfosNATRule` - Retrieve NATRule objects
- `New-SfosNATRule` - Create a new NAT rule
- `Set-SfosNATRule` - Update an existing NAT rule
- `Remove-SfosNATRule` - Delete a NAT rule

### SSL/TLS Inspection Rule Management (4 functions)
- `Get-SfosSSLTLSInspectionRule` - Retrieve SSLTLSInspectionRule objects
- `New-SfosSSLTLSInspectionRule` - Create a new SSL/TLS inspection rule (unverified, see below)
- `Set-SfosSSLTLSInspectionRule` - Update an existing rule (refuses IsDefault=Yes)
- `Remove-SfosSSLTLSInspectionRule` - Delete a rule (refuses IsDefault=Yes)

### SSL/TLS Inspection Settings (2 functions, 1 Get/Set pair)
- `Get-SfosSSLTLSInspectionSettings` / `Set-SfosSSLTLSInspectionSettings` - Device-wide TLS engine configuration

## Known Firmware Limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance. Every read-modify-write `Set-*` in this module
exists because of the general finding that an update replaces the whole entity - see the
points below for the exceptions and additional defects found on top of that.

- **Documentation folder names differ from the wire element names.** The doc folder is
  called `SecurityPolicy`, but the XML element is `FirewallRule`; a `<SecurityPolicy>` root
  answers `529 Input request module is Invalid`. The same applies to `FirewallGroup` (folder)
  vs. `FirewallRuleGroup` (element), `TLSRule` vs. `SSLTLSInspectionRule`, and `TLSSettings`
  vs. `SSLTLSInspectionSettings`.
- **Only `PolicyType Network` is supported.** `User` and `HTTPBased` are documented with
  their own subtrees (`UserPolicy`, `HTTPBasedPolicy`), but neither was observed on the lab
  firewall and could not be verified. `New-`/`Set-SfosFirewallRule` refuse both rather than
  guessing at fields nobody has confirmed.
- **`Position Bottom` is normalised by the firewall to `After` anchored on the last existing
  rule.** A `Get` immediately following a `New-SfosFirewallRule -Position Bottom` therefore
  does not return `Position=Bottom` - it returns `After` with a `Name`.
- **The wire element for traffic shaping is misspelled.** `TrafficShappingPolicy`, with a
  doubled p, is what the live `NetworkPolicy` subtree actually uses; the documentation spells
  it correctly (`TrafficShapingPolicy`). Sending the correct spelling would land on an unknown
  element and silently fail to set the field.
- **A firewall rule group's member list is append-only on update.** A shorter list, an empty
  `<SecurityPolicyList/>` and an omitted wrapper are all answered with status 200, and no
  member disappears - only the order changes. `Remove-SfosFirewallRuleGroupMember` therefore
  reads the group back after the update and throws if the members it was asked to remove are
  still present, instead of reporting a success the firewall did not perform. A rule leaves
  its group when the rule itself is deleted; a group with members cannot be deleted.
- **`New-SfosSSLTLSInspectionRule` does not work on this firmware.** Every attempt - more than
  20 variants, including a byte-for-byte copy of a rule the appliance itself returned, and
  both documented field orderings - ended in `501`, most often with an empty
  `<InvalidParams/>`. The minimal case names `IsDefault` as the invalid field, even though the
  documentation marks it read-only. The cmdlet is implemented strictly to the documented
  request shape but is unverified as working.
- **`Set-`/`Remove-SfosSSLTLSInspectionRule` refuse to touch rules with `IsDefault=Yes`.** The
  firewall's built-in exemption rule ('Exclusions by website or category') has no undo if
  altered or removed, so both cmdlets read the object first and stop with a named error rather
  than risk it.
- **`Set-SfosSSLTLSInspectionSettings` was verified structurally only, not against a live
  write.** Every field of this entity is device-wide and applies immediately to every HTTPS
  connection through the firewall; a wrong value can drop or reject traffic that was
  previously allowed, or turn TLS inspection off firewall-wide. The generated XML was
  inspected (e.g. via `-WhatIf`), but the write path itself was never executed.
- **`New-`/`Set-SfosNATRule` do not implement every documented field.**
  `OriginalSourceNetworks`, `OriginalDestinationNetworks`, `OriginalServices`, `NATMethod`,
  `HealthCheck`, `LoadBalance` and `InterfaceNATPolicyList` are not sent by this module.
  Because an update replaces the whole entity, running `Set-SfosNATRule` against a rule that
  uses any of these fields would clear them.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific firewall rule with error handling
    $rule = Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN" -ErrorAction Stop
    Write-Output "Found rule: $($rule.Name) - Status: $($rule.Status), Position: $($rule.Position)"
} catch {
    Write-Error "Failed to retrieve firewall rule: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosFirewallRule | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are entity-specific (FirewallRule, FirewallRuleGroup, NATRule, SSLTLSInspectionRule, ...)
- **A Set that appears to move a rule unexpectedly**: Check whether `-Position` was passed; if omitted, the existing Position/After/Before is always preserved - see Known Firmware Limitations for the `Bottom` -> `After` normalisation
- **Members not removed from a rule group**: See Known Firmware Limitations - the member list is append-only on this firmware; `Remove-SfosFirewallRuleGroupMember` reports this as an error rather than a silent no-op
- **`New-SfosSSLTLSInspectionRule` fails with 501**: See Known Firmware Limitations - this is a known, unresolved firmware limitation, not a module defect

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.Firewall) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License
