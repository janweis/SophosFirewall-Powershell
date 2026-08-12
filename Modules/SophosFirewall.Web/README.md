# SophosFirewall.Web Module

## Overview

The **Web** module provides PowerShell cmdlets for the **Protect > Web** area of the
Sophos XGS / SFOS 22.0 web admin. With 52 functions, it manages URL groups, web
categories, file types, user activities, web filter policies and exceptions, surfing
quota policies, content condition lists, and the web protection settings singletons
used throughout web filtering policies.

## Features

- **URL Groups**: Named lists of URLs for use in web categories and exceptions
- **File Types**: File extension and MIME header groupings for download control
- **Web Categories**: Local (domain/keyword) and external (URL list) categories
- **User Activities**: Named groupings of web categories, URL groups and file types
- **Web Filter Policies**: Rule-based policies with category/action builders
- **Web Filter Exceptions**: Bypass rules matched by IP, URL regex or web category
- **Surfing Quota Policies**: Cyclic and non-cyclic time budgets for web access
- **Content Condition Lists**: Regex-based content match lists with member management
- **Web Protection Settings**: Malware protection, filter, advanced and notification settings
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Import-Module -Name SophosFirewall.Web
```

Or with explicit path:

```powershell
Import-Module -Path "C:\Path\To\SophosFirewall.Web.psd1"
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

### Multiple Firewalls at Once

Register named sessions to work with more than one firewall in the same script,
and pipe an object read from one straight into a write against the other:

```powershell
Connect-SfosFirewall -Firewall "fw1.example.test" -Credential (Get-Credential) -Name fw1
Connect-SfosFirewall -Firewall "fw2.example.test" -Credential (Get-Credential) -Name fw2 -NoDefault

Get-SfosWebFilterURLGroup -Session fw1 -NameLike "Blocked-Sites" |
    ForEach-Object { New-SfosWebFilterURLGroup -Name $_.Name -Members $_.URLlist -Session fw2 }
```

### URL Group Management

```powershell
# Get all URL groups
Get-SfosWebFilterURLGroup

# Get a specific URL group
Get-SfosWebFilterURLGroup -NameLike "Blocked-Sites"

# Create a URL group
New-SfosWebFilterURLGroup -Name "Blocked-Sites" -Members "example.invalid" -Description "Manually blocked"

# Add a member
Add-SfosWebFilterURLGroupMember -Name "Blocked-Sites" -Members "another.invalid"

# Update the description, the URL list is preserved
Set-SfosWebFilterURLGroup -Name "Blocked-Sites" -Description "Updated description"

# Remove a member
Remove-SfosWebFilterURLGroupMember -Name "Blocked-Sites" -Members "another.invalid"

# Delete the group
Remove-SfosWebFilterURLGroup -Name "Blocked-Sites"
```

### File Type Management

```powershell
# Get all file types
Get-SfosFileType

# Create a file type
New-SfosFileType -Name "ArchiveFiles" -FileExtension "zip", "rar", "7z" -Description "Common archive formats"

# Update the description, extensions and MIME headers are preserved
Set-SfosFileType -Name "ArchiveFiles" -Description "Common archive and compressed formats"

# Delete a file type (see Known Firmware Limitations - this always fails on SFOS 22.0)
Remove-SfosFileType -Name "ArchiveFiles"
```

### Web Category Management

```powershell
# Get all web categories
Get-SfosWebFilterCategory -NameLike "Social"

# Create a local category matched by domain
New-SfosWebFilterCategory -Name "Internal-Sites" -Classification Productive -QoSPolicy None -Domain "example.com"

# Create an external category matched by URL (no scheme - see Known Firmware Limitations)
New-SfosWebFilterCategory -Name "External-List" -Classification Acceptable -QoSPolicy None -Url "www.example.com/list.txt"

# Update just the description, keeping everything else
Set-SfosWebFilterCategory -Name "Internal-Sites" -ConfigureCategory Local -Description "Updated"

# Delete a category
Remove-SfosWebFilterCategory -Name "Internal-Sites"
```

### User Activity Management

```powershell
# Get all user activities
Get-SfosUserActivity -NameLike "Search"

# Create a user activity from web category references
New-SfosUserActivity -Name "Allowed-Search" -CategoryList @([PSCustomObject]@{ ID = 'Search Engines'; Type = 'web category' })

# Add another category reference
Add-SfosUserActivityMember -Name "Allowed-Search" -Members @([PSCustomObject]@{ ID = 'Streaming Media'; Type = 'web category' })

# Rename the object - Set-SfosUserActivity always sends <NewName> internally, see Known Firmware Limitations
Set-SfosUserActivity -Name "Allowed-Search" -NewName "Allowed-Search-Renamed"

# Delete a user activity
Remove-SfosUserActivity -Name "Allowed-Search-Renamed"
```

### Web Filter Exception Management

```powershell
# Get all exceptions
Get-SfosWebFilterException -NameLike "Sophos"

# Create an exception matched by web category
New-SfosWebFilterException -Name "Allow-SearchEngines" -WebCategory "Search Engines"

# Update the description without touching anything else
Set-SfosWebFilterException -Name "Allow-SearchEngines" -Desc "Updated description"

# Delete an exception
Remove-SfosWebFilterException -Name "Allow-SearchEngines"
```

### Web Filter Policy Management

```powershell
# Get all policies
Get-SfosWebFilterPolicy -NameLike "Default"

# Build a rule from a category and create a policy with it
$category = New-SfosWebFilterPolicyCategory -ID "Extreme" -Type WebCategory
$rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
New-SfosWebFilterPolicy -Name "Restrict-Extreme" -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

# Append another rule without losing the existing ones
$weaponsRule = New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -ID "Weapons" -Type WebCategory) -HTTPAction Warn
Add-SfosWebFilterPolicyRule -Name "Restrict-Extreme" -Rule $weaponsRule

# Remove the first rule by index
Remove-SfosWebFilterPolicyRule -Name "Restrict-Extreme" -Index 0

# Update top-level fields
Set-SfosWebFilterPolicy -Name "Restrict-Extreme" -Description "Updated"

# Delete a policy
Remove-SfosWebFilterPolicy -Name "Restrict-Extreme"
```

### Surfing Quota Policy Management

```powershell
# Get all surfing quota policies
Get-SfosSurfingQuotaPolicy

# Create a Cyclic policy: 2 hours 30 minutes per day
New-SfosSurfingQuotaPolicy -Name "DailyQuota" -CycleType Cyclic -CycleHours 2 -CycleMinutes 30 -PerDay Days

# Create a NonCyclic policy: 100 hours over 30 days
New-SfosSurfingQuotaPolicy -Name "MonthQuota" -CycleType NonCyclic -Validity 30 -MaximumHours 100 -Description "One-off quota"

# Update the description, the Cyclic fields are preserved
Set-SfosSurfingQuotaPolicy -Name "DailyQuota" -CycleType Cyclic -Description "Updated"

# Delete a policy
Remove-SfosSurfingQuotaPolicy -Name "MonthQuota"
```

### Content Condition List Management

```powershell
# Get all content condition lists
Get-SfosContentConditionList -NameLike "CCL"

# Create a list with two regexes
New-SfosContentConditionList -Name "Sensitive-Terms" -ContentStrings "foo", "bar" -Description "Test list"

# Content Condition List objects are addressed by Key, not Name, for Set/Remove/member cmdlets
$key = (Get-SfosContentConditionList -NameLike "Sensitive-Terms").Key

# Add a content string
Add-SfosContentConditionListMember -Key $key -ContentStrings "baz"

# Update the description by key
Set-SfosContentConditionList -Key $key -Description "Updated list"

# Remove a content string
Remove-SfosContentConditionListMember -Key $key -ContentStrings "baz"

# Delete a list
Remove-SfosContentConditionList -Key $key
```

### Web Protection Settings

The settings functions manage singletons: no `-Name`, no `New-`/`Remove-`, only `Get-`
and `Set-`.

```powershell
# Malware protection
Get-SfosMalwareProtection
Set-SfosMalwareProtection -PrimaryAntiVirusEngine 'Sophos'

# Web filter settings
Get-SfosWebFilterSettings
Set-SfosWebFilterSettings -WebCaching 'Enable'

# Web filter protection settings
Get-SfosWebFilterProtectionSettings
Set-SfosWebFilterProtectionSettings -FileSizeThreshold 50

# Web filter advanced settings
Get-SfosWebFilterAdvancedSettings
Set-SfosWebFilterAdvancedSettings -WebProxyPort 3128

# Default web filter notification settings (message field hashtable)
Get-SfosDefaultWebFilterNotificationSettings
Set-SfosDefaultWebFilterNotificationSettings -Message @{ Warning = 'Warning!' }
```

## Available Cmdlets (52 total)

### URL Group Management (6 functions)
- `Get-SfosWebFilterURLGroup` - Retrieve WebFilterURLGroup objects
- `New-SfosWebFilterURLGroup` - Create a new URL group
- `Set-SfosWebFilterURLGroup` - Update an existing URL group
- `Remove-SfosWebFilterURLGroup` - Delete a URL group
- `Add-SfosWebFilterURLGroupMember` - Add a URL to a group
- `Remove-SfosWebFilterURLGroupMember` - Remove a URL from a group

### File Type Management (4 functions)
- `Get-SfosFileType` - Retrieve FileType objects
- `New-SfosFileType` - Create a new file type
- `Set-SfosFileType` - Update an existing file type
- `Remove-SfosFileType` - Delete a file type (always fails on SFOS 22.0, see below)

### Web Category Management (4 functions)
- `Get-SfosWebFilterCategory` - Retrieve WebFilterCategory objects
- `New-SfosWebFilterCategory` - Create a new local or external web category
- `Set-SfosWebFilterCategory` - Update an existing web category
- `Remove-SfosWebFilterCategory` - Delete a web category

### User Activity Management (6 functions)
- `Get-SfosUserActivity` - Retrieve UserActivity objects
- `New-SfosUserActivity` - Create a new user activity
- `Set-SfosUserActivity` - Update an existing user activity (always renames, see below)
- `Remove-SfosUserActivity` - Delete a user activity
- `Add-SfosUserActivityMember` - Add a category reference to a user activity
- `Remove-SfosUserActivityMember` - Remove a category reference from a user activity

### Web Filter Exception Management (4 functions)
- `Get-SfosWebFilterException` - Retrieve WebFilterException objects
- `New-SfosWebFilterException` - Create a new exception
- `Set-SfosWebFilterException` - Update an existing exception
- `Remove-SfosWebFilterException` - Delete an exception

### Web Filter Policy Management (8 functions)
- `Get-SfosWebFilterPolicy` - Retrieve WebFilterPolicy objects
- `New-SfosWebFilterPolicy` - Create a new policy
- `Set-SfosWebFilterPolicy` - Update an existing policy (no write protection, see below)
- `Remove-SfosWebFilterPolicy` - Delete a policy
- `New-SfosWebFilterPolicyCategory` - Build a category reference for a rule (no API call)
- `New-SfosWebFilterPolicyRule` - Build a rule for a policy's RuleList (no API call)
- `Add-SfosWebFilterPolicyRule` - Append a rule to an existing policy
- `Remove-SfosWebFilterPolicyRule` - Remove a rule from an existing policy by index

### Surfing Quota Policy Management (4 functions)
- `Get-SfosSurfingQuotaPolicy` - Retrieve SurfingQuotaPolicy objects
- `New-SfosSurfingQuotaPolicy` - Create a new Cyclic or NonCyclic quota policy
- `Set-SfosSurfingQuotaPolicy` - Update an existing quota policy
- `Remove-SfosSurfingQuotaPolicy` - Delete a quota policy

### Content Condition List Management (6 functions)
- `Get-SfosContentConditionList` - Retrieve ContentConditionList objects
- `New-SfosContentConditionList` - Create a new content condition list
- `Set-SfosContentConditionList` - Update an existing list, addressed by Key
- `Remove-SfosContentConditionList` - Delete a list, addressed by Key
- `Add-SfosContentConditionListMember` - Add a content string to a list
- `Remove-SfosContentConditionListMember` - Remove a content string from a list

### Web Protection Settings (10 functions, 5 Get/Set pairs)
- `Get-SfosMalwareProtection` / `Set-SfosMalwareProtection` - Primary anti-virus engine
- `Get-SfosWebFilterSettings` / `Set-SfosWebFilterSettings` - Caching, messages, PUA whitelist
- `Get-SfosWebFilterProtectionSettings` / `Set-SfosWebFilterProtectionSettings` - Scanning, thresholds, pharming protection
- `Get-SfosWebFilterAdvancedSettings` / `Set-SfosWebFilterAdvancedSettings` - Proxy port, TLS minimum, trusted ports
- `Get-SfosDefaultWebFilterNotificationSettings` / `Set-SfosDefaultWebFilterNotificationSettings` - Notification message text fields

## Known Firmware Limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance (`APIVersion="2200.1"`). Every read-modify-write
`Set-*` in this module exists because of the general finding that an update replaces the
whole entity - see the points below for the exceptions and additional defects found on top
of that.

- **`Remove-SfosFileType` always fails.** `<Remove><FileType>...` answers
  `Status code="500" Operation could not be performed on Entity.` on every attempt, including
  for a freshly created, nowhere-referenced object. A `Remove` on `WebFilterURLGroup` in the
  same run returns 200, so this is specific to `FileType`. FileType objects cannot be deleted
  through this API on this firmware.
- **`Set-SfosUserActivity` always sends `<NewName>`.** Sending an update without it answers
  HTTP 200 / status code 200, but renames the object to an empty name - it becomes unreachable
  under its old name and stays behind as an invisible orphan. The cmdlet always includes
  `<NewName>`, set to `-NewName` when supplied or to the object's current name otherwise; this
  cannot be turned off.
- **`Set-SfosWebFilterCategory -Url` can only grow the external URL list, never shrink or
  clear it.** Unlike every other list in this module, `URLList` on an update is append-only -
  sending fewer URLs, or an empty list, still leaves every previously stored URL in place
  (observed status code 201 "Operation partially successful"). There is no client-side
  workaround short of removing and recreating the object.
- **`New-SfosWebFilterPolicyRule -HTTPAction`/`-HTTPSAction` do not offer `Log`.** The vendor
  documentation lists it as a valid value, but every combination tried against the lab
  firewall was rejected with a content-free 501 ("Configuration parameters validation
  failed." / empty `<InvalidParams/>`). `Log` is therefore not in the `ValidateSet`.
- **Predefined web filter policies carry no protection flag.** Unlike `WebFilterException`,
  which exposes `IsDefault`, `WebFilterPolicy` has none. A `Set-SfosWebFilterPolicy` (or
  `Add-`/`Remove-SfosWebFilterPolicyRule`) against `Default Policy` overwrites the live rule
  list without any warning from the API. Verify `-Name` before scripting bulk changes.
- **A partial update of a settings singleton can silently reset a field that was never
  sent.** Observed on `WebFilterProtectionSettings`: sending only `FileSizeThreshold`,
  `FTPFileSizeThreshold` and `AudioVideoFileScanning` reset `PharmingProtection` from
  `Enable` to `Disable`, reported as `code=200`. Every `Set-*` in this module therefore reads
  the current state first and resends the full entity, changing only what the caller
  explicitly passed.
- **`Get-SfosContentConditionList -NameLike` is applied client-side only.** The server-side
  name filter for this entity answers with `Transaction fail`; only `-KeyLike` is sent to the
  firewall, and `-NameLike`/`-DescriptionLike` are always applied locally.
- **`ContentConditionList` objects are addressed by `Key`, not `Name`.** The firewall assigns
  the `Key` itself, derived from the name at creation time. `Set-SfosContentConditionList`,
  `Remove-SfosContentConditionList` and the member cmdlets all take `-Key`, not `-Name`.
- **`Set-SfosFileType` has no `-Template` parameter.** `Get-SfosFileType` never returns a
  `<Template>` element, whether or not one was sent at creation - so a read-modify-write
  cannot preserve it. `Template` is create-time only, on `New-SfosFileType`.
- **Four documentation folders are aliases for fields exposed elsewhere in this module** and
  intentionally have no cmdlet pair of their own, confirmed by write tests: `AntiVirusFTP`
  and `HTTPSConfiguration` map into `WebFilterProtectionSettings`, `WebProxyConfiguration`
  maps into `WebFilterAdvancedSettings`, and `WebFilterUserNotificationSettings` maps into
  `WebFilterSettings`. Giving each folder its own cmdlet would let two cmdlets write the same
  field against each other.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific web category with error handling
    $category = Get-SfosWebFilterCategory -NameLike "Social" -ErrorAction Stop
    Write-Output "Found category: $($category.Name) - Classification: $($category.Classification)"
} catch {
    Write-Error "Failed to retrieve web category: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosWebFilterCategory | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are entity-specific (WebFilterCategory, UserActivity, WebFilterPolicy, ...)
- **ContentConditionList operations failing on Name**: Use `-Key`, not `-Name` - see Known Firmware Limitations

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.Web) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License
