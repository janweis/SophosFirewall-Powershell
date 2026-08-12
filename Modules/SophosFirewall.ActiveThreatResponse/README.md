# SophosFirewall.ActiveThreatResponse Module

## Overview

The **ActiveThreatResponse** module provides PowerShell cmdlets for the **PROTECT > Active
threat response** area of the Sophos XGS / SFOS 22.0 API documentation. With 10 exported
functions, it manages the device-wide ATP (Sophos X-Ops threat feeds - the wire element and
doc folder are still named ATP, a rebranding leftover from "Advanced Threat Protection")
singleton, including its HostException and ThreatException lists, and ThirdPartyFeed objects
(Third party threat feed). Requires `SophosFirewall.Core` (minimum version 1.0.0).

## Features

- **ATP (Sophos X-Ops threat feeds)**: `Get-`/`Set-SfosATPSettings` for the device-wide
  singleton, plus `Add-`/`Remove-SfosATPHostException` and `Add-`/`Remove-SfosATPThreatException`
  for its two exception lists
- **Third Party Threat Feeds**: Full CRUD for `ThirdPartyFeed` objects, including
  no-authentication, basic-authentication and API-key feed configurations
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Install-Module -Name SophosFirewall.ActiveThreatResponse
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.ActiveThreatResponse.psd1"
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

### ATP (Sophos X-Ops threat feeds)

```powershell
# Read the device-wide ATP configuration
Get-SfosATPSettings

# Switch content inspection from untrusted-only to all traffic, leaving everything else unchanged
Set-SfosATPSettings -InspectContent all

# Except an existing IPHost object from ATP inspection
Add-SfosATPHostException -HostName 'WebServer01'

# Remove that exception again
Remove-SfosATPHostException -HostName 'WebServer01'

# Except a threat identifier from ATP enforcement
Add-SfosATPThreatException -Threat 'C2/Generic-A'

# Remove that exception again
Remove-SfosATPThreatException -Threat 'C2/Generic-A'
```

### Third Party Threat Feeds

```powershell
# List every configured third-party threat feed
Get-SfosThirdPartyFeed

# Find a feed by name
Get-SfosThirdPartyFeed -NameLike 'Feed'

# Feed with no authentication
New-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Action monitor -IndicatorType ip `
    -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization noAuthentication `
    -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

# Feed with basic authentication
$pw = ConvertTo-SecureString 'FeedSecret1!' -AsPlainText -Force
New-SfosThirdPartyFeed -Name 'VendorIPFeed' -Action monitor -IndicatorType ip `
    -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization basicAuthentication `
    -FeedUsername 'feedreader' -FeedPassword $pw `
    -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

# Feed with API key authentication
$key = ConvertTo-SecureString 'MyApiKeyValue123' -AsPlainText -Force
New-SfosThirdPartyFeed -Name 'PartnerIPFeed' -Action monitor -IndicatorType ip `
    -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization apiKey `
    -ApiKeyName 'X-Api-Key' -ApiKeyValue $key -AddTo header `
    -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

# Disable a feed, leaving every other field untouched (including any stored secret)
Set-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Enabled 0

# Remove a feed
Remove-SfosThirdPartyFeed -Name 'AbuseChIPFeed'
```

## Available Cmdlets (10 total)

### ATP (Sophos X-Ops threat feeds) (6 functions)
- `Get-SfosATPSettings` - Retrieves the ATP (Sophos X-Ops threat feeds) settings from the Sophos Firewall.
- `Set-SfosATPSettings` - Updates the ATP (Sophos X-Ops threat feeds) settings on the Sophos Firewall.
- `Add-SfosATPHostException` - Adds an IPHost exception to the ATP settings on the Sophos Firewall.
- `Remove-SfosATPHostException` - Removes an IPHost exception from the ATP settings on the Sophos Firewall.
- `Add-SfosATPThreatException` - Adds a threat exception to the ATP settings on the Sophos Firewall.
- `Remove-SfosATPThreatException` - Removes a threat exception from the ATP settings on the Sophos Firewall.

### Third Party Threat Feeds (4 functions)
- `Get-SfosThirdPartyFeed` - Retrieves ThirdPartyFeed objects from the Sophos Firewall.
- `New-SfosThirdPartyFeed` - Creates a new ThirdPartyFeed object on the Sophos Firewall.
- `Set-SfosThirdPartyFeed` - Updates an existing ThirdPartyFeed object on the Sophos Firewall.
- `Remove-SfosThirdPartyFeed` - Removes a ThirdPartyFeed object from the Sophos Firewall.

## Known behaviour/limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance.

- **`Remove-SfosThirdPartyFeed` always answers code `500` "Deleted some configurations.
  Couldn't delete all."** - for a genuinely nonexistent object AND for a real object that the
  same call actually deletes cleanly. The message text is identical in both cases, so the
  status code and message cannot distinguish success from failure here at all. This cmdlet
  therefore ignores that status entirely (beyond checking the login itself did not fail) and
  determines the real outcome from a follow-up `Get`.
- **`Position` on `ThirdPartyFeed` is write-only.** `New-SfosThirdPartyFeed -Position` is
  accepted at creation time but the field is never returned by `Get-SfosThirdPartyFeed`. Per
  the project's read-modify-write rule, a field a `Get-*` cannot read back is impossible to
  preserve on update, so `Set-SfosThirdPartyFeed` has no `-Position` parameter at all - only
  `New-*` can set it, and only once, at creation.
- **Resending the hashed secret breaks the update silently.** Resending `ThirdPartyFeed`'s
  `Password`/`Value` element exactly as `Get-SfosThirdPartyFeed` returns it (hashed text plus
  its `hashform` attribute) makes SFOS answer HTTP 200 with a response that contains no
  `<ThirdPartyFeed>` element and no `<Status>` at all - the update is silently dropped,
  including any other field changed in the same request. `Set-SfosThirdPartyFeed` therefore
  never resends `PasswordHash`/`ValueHash`; omitting the secret element entirely (while the
  authorization type stays the same) is what preserves the stored value on this firmware.
  Never return a previously read hash as `-FeedPassword`/`-ApiKeyValue`.
- **ATP `HostException` requires existing `IPHost` object names.** An arbitrary string passed
  to `Add-SfosATPHostException`/`Set-SfosATPSettings -HostException` that is not the name of
  an existing `IPHost` object is rejected with a field-precise `501` naming
  `/ATP/HostException/Host`. `ThreatException` has no such requirement - an arbitrary string
  is accepted there.
- **`Enabled` and `ValidateServerCertificate` on `ThirdPartyFeed` are returned as `1`/`0`.**
  The documentation's sample XML shows `true`/`false` placeholders, but the firewall always
  echoes the value back as `1`/`0` regardless of which form was sent on input, so this module's
  `Get-*`/`New-*`/`Set-*` all use the `'1'`/`'0'` `ValidateSet`, per the project rule that the
  attribute table wins over the sample XML where the two disagree.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific feed with error handling
    $feed = Get-SfosThirdPartyFeed -NameLike "AbuseChIPFeed" -ErrorAction Stop
    Write-Output "Found feed: $($feed.Name) - ExternalURL: $($feed.ExternalURL)"
} catch {
    Write-Error "Failed to retrieve feed: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosThirdPartyFeed | Select-Object Name` to list all available feeds
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **`New-SfosThirdPartyFeed` fails with a field-precise 501 on `/ATP/HostException/Host`**: See Known behaviour - `Add-SfosATPHostException` requires the name of an existing `IPHost` object, not an arbitrary string
- **`Remove-SfosThirdPartyFeed` reports code 500 even though the feed is gone**: See Known behaviour - this entity's delete response cannot distinguish success from failure; the cmdlet confirms the real outcome with a follow-up `Get` and throws only if the object is still present
- **A `Set-SfosThirdPartyFeed` update is silently dropped**: See Known behaviour - never pass a value read back from `Get-SfosThirdPartyFeed` (`PasswordHash`/`ValueHash`) as `-FeedPassword`/`-ApiKeyValue`; omit the secret parameter instead to keep the stored value

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.ActiveThreatResponse) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License

MIT License - see [LICENSE.txt](LICENSE.txt) for details.
