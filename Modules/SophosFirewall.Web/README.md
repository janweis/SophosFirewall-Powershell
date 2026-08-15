# SophosFirewall.Web

`SophosFirewall.Web` manages the Web Protection area of a Sophos Firewall: URL groups, file
types, web categories, user activities, web filter policies and exceptions, surfing quota
policies, content condition lists, and the web protection settings singletons. It is for
administrators who script web filtering configuration instead of maintaining it in the web
admin.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.Web -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

New-SfosWebFilterURLGroup -Name 'Blocked-Sites' -Members 'blocked.example.com' -Description 'Manually blocked'
Get-SfosWebFilterURLGroup -NameLike 'Blocked-Sites'
Add-SfosWebFilterURLGroupMember -Name 'Blocked-Sites' -Members 'blocked2.example.com'
Remove-SfosWebFilterURLGroup -Name 'Blocked-Sites'
```

### Web filter policy

```powershell
$category = New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory
$rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
New-SfosWebFilterPolicy -Name 'Restrict-Extreme' -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

Add-SfosWebFilterPolicyRule -Name 'Restrict-Extreme' -Rule $rule
Set-SfosWebFilterPolicy -Name 'Restrict-Extreme' -Description 'Updated'
Remove-SfosWebFilterPolicy -Name 'Restrict-Extreme'
```

### Content condition lists (addressed by Key, not Name)

```powershell
New-SfosContentConditionList -Name 'Sensitive-Terms' -ContentStrings 'foo', 'bar' -Description 'Test list'
$key = (Get-SfosContentConditionList -NameLike 'Sensitive-Terms').Key
Add-SfosContentConditionListMember -Key $key -ContentStrings 'baz'
Remove-SfosContentConditionList -Key $key
```

### Web protection settings

The settings cmdlets manage singletons: no `-Name`, no `New-`/`Remove-`, only `Get-` and
`Set-`.

```powershell
Get-SfosWebFilterSettings
Set-SfosWebFilterSettings -WebCaching 'Enable'
```

## Cmdlets

### URL groups

| Cmdlet | Purpose |
|---|---|
| `Get-SfosWebFilterURLGroup` | Retrieves URL groups. |
| `New-SfosWebFilterURLGroup` | Creates a URL group. |
| `Set-SfosWebFilterURLGroup` | Updates a URL group. |
| `Remove-SfosWebFilterURLGroup` | Removes a URL group. |
| `Add-SfosWebFilterURLGroupMember` | Adds URLs to a URL group. |
| `Remove-SfosWebFilterURLGroupMember` | Removes URLs from a URL group. |

### File types

| Cmdlet | Purpose |
|---|---|
| `Get-SfosFileType` | Retrieves file type objects. |
| `New-SfosFileType` | Creates a file type object. |
| `Set-SfosFileType` | Updates a file type object. |
| `Remove-SfosFileType` | Removes a file type object. |

### Web categories

| Cmdlet | Purpose |
|---|---|
| `Get-SfosWebFilterCategory` | Retrieves web categories. |
| `New-SfosWebFilterCategory` | Creates a local or external web category. |
| `Set-SfosWebFilterCategory` | Updates a web category. |
| `Remove-SfosWebFilterCategory` | Removes a web category. |

### User activities

| Cmdlet | Purpose |
|---|---|
| `Get-SfosUserActivity` | Retrieves user activity objects. |
| `New-SfosUserActivity` | Creates a user activity object. |
| `Set-SfosUserActivity` | Updates a user activity object. |
| `Remove-SfosUserActivity` | Removes a user activity object. |
| `Add-SfosUserActivityMember` | Adds category references to a user activity. |
| `Remove-SfosUserActivityMember` | Removes category references from a user activity. |

### Web filter exceptions

| Cmdlet | Purpose |
|---|---|
| `Get-SfosWebFilterException` | Retrieves web filter exceptions. |
| `New-SfosWebFilterException` | Creates a web filter exception. |
| `Set-SfosWebFilterException` | Updates a web filter exception. |
| `Remove-SfosWebFilterException` | Removes a web filter exception. |

### Web filter policies

| Cmdlet | Purpose |
|---|---|
| `Get-SfosWebFilterPolicy` | Retrieves web filter policies. |
| `New-SfosWebFilterPolicy` | Creates a web filter policy. |
| `Set-SfosWebFilterPolicy` | Updates a web filter policy. |
| `Remove-SfosWebFilterPolicy` | Removes a web filter policy. |
| `New-SfosWebFilterPolicyCategory` | Builds a category reference for a policy rule. |
| `New-SfosWebFilterPolicyRule` | Builds a rule for a policy's rule list. |
| `Add-SfosWebFilterPolicyRule` | Appends a rule to an existing policy's rule list. |
| `Remove-SfosWebFilterPolicyRule` | Removes a rule from a policy's rule list by index. |

### Surfing quota policies

| Cmdlet | Purpose |
|---|---|
| `Get-SfosSurfingQuotaPolicy` | Retrieves surfing quota policies. |
| `New-SfosSurfingQuotaPolicy` | Creates a cyclic or non-cyclic quota policy. |
| `Set-SfosSurfingQuotaPolicy` | Updates a surfing quota policy. |
| `Remove-SfosSurfingQuotaPolicy` | Removes a surfing quota policy. |

### Content condition lists

| Cmdlet | Purpose |
|---|---|
| `Get-SfosContentConditionList` | Retrieves content condition lists. |
| `New-SfosContentConditionList` | Creates a content condition list. |
| `Set-SfosContentConditionList` | Updates a content condition list, addressed by Key. |
| `Remove-SfosContentConditionList` | Removes a content condition list, addressed by Key. |
| `Add-SfosContentConditionListMember` | Adds content strings to a list. |
| `Remove-SfosContentConditionListMember` | Removes content strings from a list. |

### Web protection settings

| Cmdlet | Purpose |
|---|---|
| `Get-SfosMalwareProtection` | Reads the malware protection settings. |
| `Set-SfosMalwareProtection` | Updates the malware protection settings. |
| `Get-SfosWebFilterSettings` | Reads the web filter settings. |
| `Set-SfosWebFilterSettings` | Updates the web filter settings. |
| `Get-SfosWebFilterProtectionSettings` | Reads the web filter protection settings. |
| `Set-SfosWebFilterProtectionSettings` | Updates the web filter protection settings. |
| `Get-SfosWebFilterAdvancedSettings` | Reads the web filter advanced settings. |
| `Set-SfosWebFilterAdvancedSettings` | Updates the web filter advanced settings. |
| `Get-SfosWebFilterNotificationSettings` | Reads the web filter notification settings (override flags, denied message image). |
| `Set-SfosWebFilterNotificationSettings` | Updates the web filter notification settings. |
| `Get-SfosDefaultWebFilterNotificationSettings` | Reads the default web filter notification message text. |
| `Set-SfosDefaultWebFilterNotificationSettings` | Updates the default web filter notification message text. |

## Limitations

`Remove-SfosFileType` does not delete the object on this firmware, for any file type,
including one that is not referenced anywhere.

`Set-SfosUserActivity` always sends a new name, defaulting to the object's current name when
`-NewName` is not supplied; the field cannot be omitted.

`Set-SfosWebFilterCategory -Url` only grows the external URL list; sending fewer URLs, or an
empty list, does not remove any of the previously stored ones.

`New-SfosWebFilterPolicyRule`'s `-HTTPAction` and `-HTTPSAction` do not accept `Log`; every
value tried was rejected.

Predefined web filter policies carry no protection flag. `Set-SfosWebFilterPolicy` or the
rule cmdlets against `Default Policy` overwrite its live rule list with no warning from the
firewall; verify `-Name` before scripting bulk changes.

`Get-SfosContentConditionList`'s `-NameLike` and `-DescriptionLike` filter client-side. Its
objects are addressed by `Key`, not `Name` - `Set-SfosContentConditionList`,
`Remove-SfosContentConditionList` and the member cmdlets all take `-Key`.

`Set-SfosFileType` has no `-Template` parameter; `Get-SfosFileType` never returns the field,
so it can only be set once, at creation with `New-SfosFileType`.

`AntiVirusFTP`, `HTTPSConfiguration`, `WebProxyConfiguration` and
`WebFilterUserNotificationSettings` from the API documentation have no cmdlet of their own;
their fields are reached through `WebFilterProtectionSettings`, `WebFilterAdvancedSettings`
and `WebFilterSettings` instead.

`WebFilterNotificationSettings` (override flags and the denied message image) is a separate
entity from `DefaultWebFilterNotificationSettings` (around 70 notification message texts) -
do not confuse the two cmdlet pairs.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
