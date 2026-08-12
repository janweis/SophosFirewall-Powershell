# SophosFirewall.Applications Module

## Overview

The **Applications** module provides PowerShell cmdlets for the **PROTECT >
Applications** area of the Sophos XGS / SFOS 22.0 API documentation. With 20
exported functions, it manages application filter policies and their rules,
application objects, application filter categories with QoS assignment,
application classification assignments (single and batch) and the device-wide
application classification switch. Requires `SophosFirewall.Core` (minimum
version 1.0.0).

## Features

- **Application Filter Policy**: Full CRUD for `ApplicationFilterPolicy`
  objects, plus `New-SfosApplicationFilterPolicyRule` to build rule objects
  and `Add-`/`Remove-SfosApplicationFilterPolicyRule` to manage a policy's
  `RuleList` one rule at a time
- **Application Object**: Full CRUD for `ApplicationObject` objects, a
  reusable named grouping of applications
- **Application Filter Category**: `Get-`/`Set-SfosApplicationFilterCategory`
  for the 26 firmware-fixed categories, plus
  `Add-`/`Remove-SfosApplicationFilterCategoryMember` for per-application QoS
  overrides
- **Application Classification Assignment**: `Get-SfosApplicationClassificationAssignment`,
  `Set-SfosApplicationClassificationAssignment` (one API call per object) and
  `Set-SfosApplicationClassificationAssignmentBatch` (one API call for many
  objects)
- **Application Classification switch**: `Get-`/`Set-SfosApplicationClassification`,
  the device-wide on/off switch for classifying newly discovered applications
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML
  API

## Installation

```powershell
Install-Module -Name SophosFirewall.Applications
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.Applications.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module, version 1.0.0 or higher (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (version 22.0)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### Multi-Session: Recreate a Policy Name/Action on a Second Firewall

```powershell
Connect-SfosFirewall -Firewall "fw1.example.test" -Credential (Get-Credential) -Name fw1
Connect-SfosFirewall -Firewall "fw2.example.test" -Credential (Get-Credential) -Name fw2 -NoDefault

# Read a policy from fw1 and create it on fw2, without touching the ambient default session.
# Name and DefaultAction bind by pipeline property name; add -Rule explicitly to also carry rules.
Get-SfosApplicationFilterPolicy -Session fw1 -NameLike "BranchOfficeApps" |
    New-SfosApplicationFilterPolicy -Session fw2
```

### Application Filter Policy and Rules

```powershell
# Retrieve all application filter policies
Get-SfosApplicationFilterPolicy

# Filter by name (substring match)
Get-SfosApplicationFilterPolicy -NameLike "Block"

# Return raw XML for troubleshooting
Get-SfosApplicationFilterPolicy -NameLike "Allow All" -AsXml

# Create a policy with no rules yet
New-SfosApplicationFilterPolicy -Name "BranchOfficeApps" -Description "Empty test policy" -DefaultAction Allow

# Create a policy with one rule that blocks a specific named application
$rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application "Lantern" -Action Deny -Schedule "All The Time"
New-SfosApplicationFilterPolicy -Name "BranchOfficeBlockLantern" -DefaultAction Allow -Rule $rule

# Change only the description, RuleList and DefaultAction are preserved
Set-SfosApplicationFilterPolicy -Name "BranchOfficeApps" -Description "Updated description" -DefaultAction Allow

# Update using pipeline input
Get-SfosApplicationFilterPolicy -NameLike "BranchOfficeApps" | Set-SfosApplicationFilterPolicy -Description "Updated"

# Block a single named application
New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application "Lantern" -Action Deny -Schedule "All The Time"

# Block every application in a whole category
New-SfosApplicationFilterPolicyRule -SelectAllRule Enable -Category "Gaming" -Action Deny

# Change one field of an existing rule read back from the firewall
$policy = Get-SfosApplicationFilterPolicy -NameLike "BranchOfficeApps"
$edited = $policy.RuleList[0] | New-SfosApplicationFilterPolicyRule -Action "Allow"
Set-SfosApplicationFilterPolicy -Name "BranchOfficeApps" -Rule $edited

# Append a rule to an existing policy
$rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application "TurboVPN" -Action Deny
Add-SfosApplicationFilterPolicyRule -Name "BranchOfficeApps" -Rule $rule

# Remove the first rule of the policy
Remove-SfosApplicationFilterPolicyRule -Name "BranchOfficeApps" -Index 0

# Remove the policy itself
Remove-SfosApplicationFilterPolicy -Name "BranchOfficeApps"
```

### Application Object

```powershell
Get-SfosApplicationObject

Get-SfosApplicationObject -NameLike "VPN"

# Group a single named application
New-SfosApplicationObject -Name "KnownProxyApp" -SelectAllRule Disable -Application "Lantern"

# Group every application in a category
New-SfosApplicationObject -Name "AllGamingApps" -SelectAllRule Enable -Category "Gaming"

# Add a second application to an existing 'Disable'-mode object
Set-SfosApplicationObject -Name "KnownProxyApp" -Application "Lantern", "TurboVPN"

# Update using pipeline input
Get-SfosApplicationObject -NameLike "KnownProxyApp" | Set-SfosApplicationObject -SmartFilter "proxy"

Remove-SfosApplicationObject -Name "KnownProxyApp"
```

### Application Filter Category

```powershell
# List all 26 application filter categories
Get-SfosApplicationFilterCategory

# Find a category by name (client-side substring match)
Get-SfosApplicationFilterCategory -NameLike 'Mobile'

# Clear any QoS assignment from a category (round-trips as a no-op if already None)
Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -QoSPolicy 'None'

# Assign an Application-scoped QoS policy with a bandwidth usage type
Set-SfosApplicationFilterCategory -Name 'Mobile Applications' `
    -QoSPolicy 'Streaming Video - Limit to SD Quality' -BandwidthUsageType Individual

Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' `
    -QoSPolicy 'Streaming Video - Limit to SD Quality'

Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram'
```

### Application Classification Assignment

```powershell
# All assignments (520 rows on the lab firewall)
Get-SfosApplicationClassificationAssignment

# One application by exact substring
Get-SfosApplicationClassificationAssignment -ApplicationLike '1Password'

# No-op resend of the current (only confirmed-valid) classification value
Set-SfosApplicationClassificationAssignment -Application '10000ft Plans' -Classification 'New'

# Reclassify every matching application from the pipeline
Get-SfosApplicationClassificationAssignment -ApplicationLike '10000ft' |
    Set-SfosApplicationClassificationAssignment -Classification 'New'

# No-op resend of two applications' current classification in one request
Get-SfosApplicationClassificationAssignment -ApplicationLike '10Web' |
    Set-SfosApplicationClassificationAssignmentBatch

# Explicit pairs
@(
    [PSCustomObject]@{ Application = '10Web'; Classification = 'New' }
    [PSCustomObject]@{ Application = '1Password'; Classification = 'New' }
) | Set-SfosApplicationClassificationAssignmentBatch
```

### Application Classification switch

```powershell
Get-SfosApplicationClassification

# No-op resend of the current value - safe, does not change device behaviour
Set-SfosApplicationClassification -ACTION On
```

## Available Cmdlets (20 total)

### Application Filter Policy and Rules (7 functions)
- `Get-SfosApplicationFilterPolicy` - Retrieves ApplicationFilterPolicy objects from the Sophos Firewall.
- `New-SfosApplicationFilterPolicy` - Creates a new ApplicationFilterPolicy on the Sophos Firewall.
- `Set-SfosApplicationFilterPolicy` - Updates an existing ApplicationFilterPolicy object on the Sophos Firewall.
- `Remove-SfosApplicationFilterPolicy` - Removes an ApplicationFilterPolicy object from the Sophos Firewall.
- `New-SfosApplicationFilterPolicyRule` - Builds a rule for use inside an ApplicationFilterPolicy's RuleList.
- `Add-SfosApplicationFilterPolicyRule` - Appends a rule to the end of an existing ApplicationFilterPolicy's RuleList.
- `Remove-SfosApplicationFilterPolicyRule` - Removes a single rule from an existing ApplicationFilterPolicy's RuleList by index.

### Application Object (4 functions)
- `Get-SfosApplicationObject` - Retrieves ApplicationObject objects from the Sophos Firewall.
- `New-SfosApplicationObject` - Creates a new ApplicationObject on the Sophos Firewall.
- `Set-SfosApplicationObject` - Updates an existing ApplicationObject on the Sophos Firewall.
- `Remove-SfosApplicationObject` - Removes an ApplicationObject from the Sophos Firewall.

### Application Filter Category (4 functions)
- `Get-SfosApplicationFilterCategory` - Retrieves ApplicationFilterCategory objects from the Sophos Firewall.
- `Set-SfosApplicationFilterCategory` - Updates an ApplicationFilterCategory on the Sophos Firewall.
- `Add-SfosApplicationFilterCategoryMember` - Adds or updates a per-application QoS override inside an ApplicationFilterCategory.
- `Remove-SfosApplicationFilterCategoryMember` - Removes a per-application QoS override from an ApplicationFilterCategory.

### Application Classification Assignment (3 functions)
- `Get-SfosApplicationClassificationAssignment` - Retrieves ApplicationClassificationAssignment objects from the Sophos Firewall.
- `Set-SfosApplicationClassificationAssignment` - Updates a single application's classification on the Sophos Firewall.
- `Set-SfosApplicationClassificationAssignmentBatch` - Updates multiple applications' classifications in a single API request.

### Application Classification switch (2 functions)
- `Get-SfosApplicationClassification` - Retrieves the device-wide application classification switch state.
- `Set-SfosApplicationClassification` - Switches device-wide application classification on or off.

## Known behaviour / limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance.

- **`<Template>` is rejected outright.** It appears only in the vendor sample XML for
  `ApplicationFilterPolicy` (with the comment "if set, ignores DefaultAction/RuleList"),
  has no row in the attribute table, and sending it with the documented value `AllowAll`
  is rejected with a `501` naming `/ApplicationFilterPolicy/Template` - so this module has
  no `-Template` parameter.
- **`CategoryList`/`RiskList`/`CharacteristicsList`/`TechnologyList` are server-computed,
  not settable data**, on both `ApplicationFilterPolicy` Rules and `ApplicationObject`. With
  `-SelectAllRule Disable`, these four lists are recomputed by the firewall from the real
  signature metadata of the applications actually in `-Application` - whatever is sent for
  them is silently replaced (`200`, no error). With `-SelectAllRule Enable`, the reverse
  happens: `-ApplicationList` itself is recomputed from whichever of those four lists the
  firewall recognizes, discarding what was sent in `-Application`. An invalid/unrecognized
  category (or risk/characteristics/technology) name in `Enable` mode is not rejected - it
  is silently dropped (`200`, no error), and `-Application` is kept as sent.
- **`-SelectAllRule Disable` without `-Application` silently deletes the rule/object.** The
  firewall answers `200` but drops the Rule from `RuleList` (or the `ApplicationObject`
  entirely) rather than creating it. `New-SfosApplicationFilterPolicyRule`,
  `New-SfosApplicationObject` and `Set-SfosApplicationObject` all throw client-side instead
  of building/sending a request that would silently vanish.
- **`-SmartFilter` is a third selection mode.** A non-empty `SmartFilter` value causes the
  firewall to report `SelectAllRule` back as `Enable` regardless of what was actually sent,
  and drops the computed `CategoryList`/`RiskList`/`CharacteristicsList`/`TechnologyList` -
  measured on both `ApplicationFilterPolicy` Rules and `ApplicationObject`.
- **`DefaultAction` on `ApplicationFilterPolicy` is unchangeable after creation**, and
  `MicroAppSupport` is always reported back as `True` regardless of what is sent on either
  create or update.
- **An unrecognized `Schedule` name is silently replaced with `'All The Time'`** (`200`, no
  error) rather than rejected - no client-side `ValidateSet` is offered, since the schedule
  catalog is a separate, dynamic entity outside the scope of this module.
- **Removing a nonexistent `ApplicationFilterPolicy` or `ApplicationObject` answers a
  misleading `503` "Operation failed. Entity having same parameter details already
  exists."** - not a "not found"-shaped message at all. Both `Remove-*` cmdlets read the
  object first and throw "was not found" for a name that is not present, rather than
  surfacing that response.
- **`ApplicationFilterCategory` has no add or delete operation - only `edit`.** The 26
  categories are firmware-fixed, so this module ships `Get`/`Set` plus
  `Add-`/`Remove-SfosApplicationFilterCategoryMember` and no
  `New-`/`Remove-SfosApplicationFilterCategory`. `operation="update"` is used exclusively
  (measured to behave identically to `edit` for this entity - `200`, no duplicate created).
  `-Description` is a genuine silent no-op on this firmware: an update that changes only
  `Description` answers `200`, but a following `Get` shows the original text unchanged -
  reproduced even bundled with a `QoSPolicy` change that DID persist in the same request.
  `Set-SfosApplicationFilterCategory` reads the object back afterwards and throws when a
  requested `Description` change was not confirmed. `-QoSPolicy` only accepts a QoS policy
  object whose own `PolicyBasedOn` is `Application` - one based on `FirewallRule` or `User`
  is rejected with `501` and no field-level detail. `-BandwidthUsageType` only takes effect
  together with a real (non-`None`) `-QoSPolicy` in the same request - sent alongside
  `QoSPolicy 'None'` it is silently ignored. A **per-application** override of `'None'` is
  equally a silent no-op (`200`, nothing stored - measured), so
  `Add-SfosApplicationFilterCategoryMember` refuses `-QoSPolicy 'None'` client-side; use
  `Remove-SfosApplicationFilterCategoryMember` to drop an override. Server-side filtering
  is a no-op for both the `Name` and `Description` keys -
  `Get-SfosApplicationFilterCategory`'s `-NameLike` is client-side only.
- **`ApplicationClassificationAssignment`: server-side filtering is a no-op for both the
  `Application` and `Classification` keys**, exact and substring match alike - a filtered
  `Get` still returns all 520 rows. `-ApplicationLike` and `-ClassificationLike` on
  `Get-SfosApplicationClassificationAssignment` are therefore client-side only. Only the
  value `'New'` (exact case) is confirmed accepted for `-Classification` on this firmware -
  every other candidate tried was rejected with `501`; no vendor enum is documented, so the
  parameter is left unrestricted rather than guessing a `ValidateSet`.
  `Set-SfosApplicationClassificationAssignmentBatch` sends the wire element names
  lower-case (`<app>`/`<class>`), unlike the single-assignment operation's
  `<Application>`/`<Classification>` - sending the upper-case names inside the batch
  wrapper is rejected with `501` and an **empty** `<InvalidParams/>`. A batch call with an
  unresolvable application name fails the same way, so an unresolvable entry in a batch
  cannot be diagnosed per-item from the response - the whole batch fails as one error,
  unlike the single-assignment cmdlet, which names the specific field.
- **`ApplicationClassification` (the device-wide `ACTION On`/`Off` switch) is an
  undocumented entity.** No operation page exists for it anywhere in the Applications
  documentation tree; `Get-`/`Set-SfosApplicationClassification` were built and verified
  entirely from live probing.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific policy with error handling
    $policy = Get-SfosApplicationFilterPolicy -NameLike "BranchOfficeApps" -ErrorAction Stop
    Write-Output "Found policy: $($policy.Name) - Rules: $($policy.RuleList.Count)"
} catch {
    Write-Error "Failed to retrieve policy: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosApplicationFilterPolicy | Select-Object Name` to list all available policies
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **A rule/object built with `-SelectAllRule Disable` and no `-Application` throws client-side**: See Known behaviour - the firewall would silently drop it rather than reject it, so the cmdlets refuse to send that request at all
- **`Set-SfosApplicationFilterCategory -Description` throws "was not confirmed"**: See Known behaviour - this field is a measured silent no-op on this firmware; the cmdlet detects it rather than reporting a false success
- **`Set-SfosApplicationClassificationAssignmentBatch` fails with an empty `<InvalidParams/>`**: See Known behaviour - a batch failure names no specific entry; use `Set-SfosApplicationClassificationAssignment` per object for precise error attribution
- **`Remove-SfosApplicationFilterPolicy`/`Remove-SfosApplicationObject` report "was not found" instead of a raw `503`**: See Known behaviour - the raw firewall response for a nonexistent object is actively misleading, so both cmdlets check first

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.Applications) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License

MIT License - see [LICENSE.txt](LICENSE.txt) for details.
