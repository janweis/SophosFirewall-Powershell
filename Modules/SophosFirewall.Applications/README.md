# SophosFirewall.Applications

`SophosFirewall.Applications` manages the Application Control area of a Sophos Firewall:
application filter policies and their rules, application objects, the 26 application filter
categories with their QoS assignment, application classification assignments, and the
device-wide application classification switch. It is for administrators who script
application control policy instead of building it rule by rule in the web admin.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.Applications -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

$rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'Lantern' -Action Deny -Schedule 'All The Time'
New-SfosApplicationFilterPolicy -Name 'BranchOfficeBlockLantern' -DefaultAction Allow -Rule $rule

Get-SfosApplicationFilterPolicy -NameLike 'BranchOffice'
Set-SfosApplicationFilterPolicy -Name 'BranchOfficeBlockLantern' -Description 'Blocks a single application'
Remove-SfosApplicationFilterPolicy -Name 'BranchOfficeBlockLantern'
```

### Application objects and categories

```powershell
New-SfosApplicationObject -Name 'KnownProxyApp' -SelectAllRule Disable -Application 'Lantern'
Set-SfosApplicationObject -Name 'KnownProxyApp' -Application 'Lantern', 'TurboVPN'
Remove-SfosApplicationObject -Name 'KnownProxyApp'

Get-SfosApplicationFilterCategory -NameLike 'Mobile'
Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -QoSPolicy 'Streaming Video - Limit to SD Quality'
Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram'
```

### Classification assignments

```powershell
Get-SfosApplicationClassificationAssignment -ApplicationLike '1Password'
Set-SfosApplicationClassificationAssignment -Application '1Password' -Classification 'New'

@(
    [PSCustomObject]@{ Application = '10Web'; Classification = 'New' }
    [PSCustomObject]@{ Application = '1Password'; Classification = 'New' }
) | Set-SfosApplicationClassificationAssignmentBatch
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosApplicationFilterPolicy` | Retrieves application filter policies. |
| `New-SfosApplicationFilterPolicy` | Creates an application filter policy. |
| `Set-SfosApplicationFilterPolicy` | Updates an application filter policy. |
| `Remove-SfosApplicationFilterPolicy` | Removes an application filter policy. |
| `New-SfosApplicationFilterPolicyRule` | Builds a rule for a policy's rule list. |
| `Add-SfosApplicationFilterPolicyRule` | Appends a rule to an existing policy's rule list. |
| `Remove-SfosApplicationFilterPolicyRule` | Removes a rule from a policy's rule list by index. |
| `Get-SfosApplicationObject` | Retrieves application objects. |
| `New-SfosApplicationObject` | Creates an application object. |
| `Set-SfosApplicationObject` | Updates an application object. |
| `Remove-SfosApplicationObject` | Removes an application object. |
| `Get-SfosApplicationFilterCategory` | Retrieves application filter categories. |
| `Set-SfosApplicationFilterCategory` | Updates an application filter category. |
| `Add-SfosApplicationFilterCategoryMember` | Adds or updates a per-application QoS override in a category. |
| `Remove-SfosApplicationFilterCategoryMember` | Removes a per-application QoS override from a category. |
| `Get-SfosApplicationClassificationAssignment` | Retrieves application classification assignments. |
| `Set-SfosApplicationClassificationAssignment` | Updates one application's classification. |
| `Set-SfosApplicationClassificationAssignmentBatch` | Updates several applications' classifications in one request. |
| `Get-SfosApplicationClassification` | Reads the device-wide application classification switch. |
| `Set-SfosApplicationClassification` | Switches device-wide application classification on or off. |

## Limitations

`CategoryList`, `RiskList`, `CharacteristicsList` and `TechnologyList` are not settable on a
policy rule or application object. With `-SelectAllRule Disable` they are computed from the
applications you name in `-Application`; with `-SelectAllRule Enable` the reverse happens
and `-Application` itself is computed from those lists, so whichever side you did not choose
is discarded. `-SelectAllRule Disable` without `-Application` would delete the rule or
object instead of creating it, so the cmdlets refuse that combination before sending it.
`-SmartFilter` is a third selection mode; using it always reports back as `Enable`.

`DefaultAction` on an application filter policy cannot be changed after creation. An
unrecognised `-Schedule` name is silently replaced with `All The Time` rather than rejected.

The 26 application filter categories are fixed by the firmware; there is no `New-` or
`Remove-` cmdlet for them, only `Get-`/`Set-SfosApplicationFilterCategory` and the member
cmdlets. `-Description` cannot be changed on this firmware; `Set-SfosApplicationFilterCategory`
reads the category back afterwards and throws if the change was not applied. `-QoSPolicy`
only accepts a QoS policy that is itself scoped to applications, and `-BandwidthUsageType`
only takes effect together with a real (non-`None`) `-QoSPolicy` in the same request.
`Add-SfosApplicationFilterCategoryMember` refuses `-QoSPolicy None`; use
`Remove-SfosApplicationFilterCategoryMember` to drop an override instead.

`Get-SfosApplicationClassificationAssignment`'s `-ApplicationLike` and `-ClassificationLike`
filter client-side; the firewall does not narrow the result set itself. Only the
classification value `New` is confirmed to be accepted for `-Classification`.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
