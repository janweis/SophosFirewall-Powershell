# SophosFirewall.Firewall

`SophosFirewall.Firewall` manages the rule base of a Sophos Firewall: firewall rules
(network policies), firewall rule groups, NAT rules, SSL/TLS inspection rules and the
device-wide SSL/TLS inspection settings. It is for administrators who script rule
maintenance instead of editing the rule base in the web admin.

These cmdlets change what traffic the appliance permits, immediately and with no
confirmation beyond `ShouldProcess`. A rule inserted at the wrong position, or an update
that drops a rule's position, changes traffic handling as soon as it runs. Every write
cmdlet supports `-WhatIf`; use it before running an unfamiliar call against a production
firewall, especially one that touches `-Position`, `-After` or `-Before`.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write the rule base

## Installation

```powershell
Install-Module SophosFirewall.Firewall -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosFirewallRule | Format-Table Name, Status, Position, PolicyType

$policy = New-SfosFirewallRuleNetworkPolicy -Action Accept -SourceZone 'LAN' -DestinationZone 'WAN'
New-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $policy -WhatIf
New-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $policy

Get-SfosFirewallRule -NameLike 'Allow-LAN-to-WAN' | Set-SfosFirewallRule -Status Enable
Remove-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -WhatIf
```

### Changing a single field on an existing rule

A rule keeps what it actually does in its `NetworkPolicy` subtree - around 30 fields such as
`Action`, the zone and service lists, `ScanVirus`, `IntrusionPrevention` and
`ApplicationControl`. `Set-SfosFirewallRule` accepts each of these as its own parameter; only
the fields you pass change, everything else is read from the rule and kept.

```powershell
Set-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -ScanVirus Enable
Set-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -LogTraffic Enable -IntrusionPrevention 'lantowan_general'
```

Do not build a fresh policy with `New-SfosFirewallRuleNetworkPolicy` to change a single
field on an existing rule - it applies its own defaults to every field you leave out. To
start from the current policy instead, pipe it in first:

```powershell
$policy = (Get-SfosFirewallRule -NameLike 'Allow-LAN-to-WAN').NetworkPolicy |
    New-SfosFirewallRuleNetworkPolicy -ScanVirus Enable
Set-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -NetworkPolicy $policy
```

### Rule groups, NAT rules, SSL/TLS inspection

```powershell
New-SfosFirewallRuleGroup -Name 'Outbound' -Description 'Outbound rules'
Add-SfosFirewallRuleGroupMember -Name 'Outbound' -Members 'Allow-LAN-to-WAN'
Remove-SfosFirewallRuleGroup -Name 'Outbound' -WhatIf

New-SfosNATRule -Name 'SNAT-LAN-to-WAN' -TranslatedSource 'MASQ' -Status Disable -Position Bottom
Get-SfosNATRule -NameLike 'SNAT-LAN-to-WAN' | Set-SfosNATRule -Status Enable

Get-SfosSSLTLSInspectionRule | Format-Table Name, IsDefault, Enable, DecryptAction
Get-SfosSSLTLSInspectionSettings
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosFirewallRule` | Retrieves firewall rules. |
| `New-SfosFirewallRule` | Creates a firewall rule. |
| `Set-SfosFirewallRule` | Updates a firewall rule. |
| `Remove-SfosFirewallRule` | Removes a firewall rule. |
| `New-SfosFirewallRuleNetworkPolicy` | Builds a NetworkPolicy object for `New-`/`Set-SfosFirewallRule`. |
| `Get-SfosFirewallRuleGroup` | Retrieves firewall rule groups. |
| `New-SfosFirewallRuleGroup` | Creates a firewall rule group. |
| `Set-SfosFirewallRuleGroup` | Updates a firewall rule group. |
| `Remove-SfosFirewallRuleGroup` | Removes a firewall rule group. |
| `Add-SfosFirewallRuleGroupMember` | Adds rules to a firewall rule group. |
| `Remove-SfosFirewallRuleGroupMember` | Removes rules from a firewall rule group. |
| `Get-SfosNATRule` | Retrieves NAT rules. |
| `New-SfosNATRule` | Creates a NAT rule. |
| `Set-SfosNATRule` | Updates a NAT rule. |
| `Remove-SfosNATRule` | Removes a NAT rule. |
| `Get-SfosSSLTLSInspectionRule` | Retrieves SSL/TLS inspection rules. |
| `New-SfosSSLTLSInspectionRule` | Creates an SSL/TLS inspection rule. |
| `Set-SfosSSLTLSInspectionRule` | Updates an SSL/TLS inspection rule. |
| `Remove-SfosSSLTLSInspectionRule` | Removes an SSL/TLS inspection rule. |
| `Get-SfosSSLTLSInspectionSettings` | Reads the device-wide SSL/TLS inspection settings. |
| `Set-SfosSSLTLSInspectionSettings` | Updates the device-wide SSL/TLS inspection settings. |

## Limitations

`New-`/`Set-SfosFirewallRule` support `PolicyType Network` only; `User` and `HTTPBased`
rules are not built by this module. Creating a rule with `-Position Bottom` does not read
back as `Bottom` afterwards - the firewall reports it as `After` the rule that was last in
the list at creation time.

A firewall rule group's member list only grows on update: removing a name from the list you
send does not remove it from the group. `Remove-SfosFirewallRuleGroupMember` reads the group
back after the update and throws if the members it was asked to remove are still present. A
rule leaves its group automatically when the rule itself is deleted, and a group that still
has members cannot be deleted.

`Set-/Remove-SfosSSLTLSInspectionRule` refuse to touch a rule with `IsDefault=Yes` - the
built-in exemption rule has no undo if altered or removed.

`New-`/`Set-SfosNATRule` do not implement `OriginalSourceNetworks`,
`OriginalDestinationNetworks`, `OriginalServices`, `NATMethod`, `HealthCheck`, `LoadBalance`
or `InterfaceNATPolicyList`. Running `Set-SfosNATRule` against a rule that uses any of these
fields removes them, because an update replaces the whole rule.

`Set-SfosSSLTLSInspectionSettings` applies device-wide, to every HTTPS connection through
the firewall; a wrong value can drop previously allowed traffic or turn off TLS inspection
entirely. Preview the call with `-WhatIf` first.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
