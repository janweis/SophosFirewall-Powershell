# SophosFirewall.ActiveThreatResponse

`SophosFirewall.ActiveThreatResponse` manages the Active Threat Response area of a Sophos
Firewall: the device-wide ATP (Sophos X-Ops threat feeds) configuration with its host and
threat exception lists, and third-party threat feed objects. It is for administrators who
maintain threat feed exceptions and external feed integrations by script.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.ActiveThreatResponse -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosATPSettings
Set-SfosATPSettings -InspectContent all

Add-SfosATPHostException -HostName 'WebServer01'
Remove-SfosATPHostException -HostName 'WebServer01'

Add-SfosATPThreatException -Threat 'C2/Generic-A'
Remove-SfosATPThreatException -Threat 'C2/Generic-A'
```

### Third-party threat feeds

```powershell
New-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Action monitor -IndicatorType ip `
    -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization noAuthentication `
    -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

Get-SfosThirdPartyFeed -NameLike 'Feed'
Set-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Enabled 0
Remove-SfosThirdPartyFeed -Name 'AbuseChIPFeed'
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosATPSettings` | Reads the device-wide ATP configuration. |
| `Set-SfosATPSettings` | Updates the device-wide ATP configuration. |
| `Add-SfosATPHostException` | Adds an IP host exception to ATP inspection. |
| `Remove-SfosATPHostException` | Removes an IP host exception from ATP inspection. |
| `Add-SfosATPThreatException` | Adds a threat identifier exception to ATP enforcement. |
| `Remove-SfosATPThreatException` | Removes a threat identifier exception from ATP enforcement. |
| `Get-SfosThirdPartyFeed` | Retrieves third-party threat feed objects. |
| `New-SfosThirdPartyFeed` | Creates a third-party threat feed object. |
| `Set-SfosThirdPartyFeed` | Updates a third-party threat feed object. |
| `Remove-SfosThirdPartyFeed` | Removes a third-party threat feed object. |

## Limitations

An ATP host exception has to name an existing IP host object; an arbitrary string is
rejected. A threat exception accepts any text.

`Set-SfosThirdPartyFeed` does not accept a value read back from `Get-SfosThirdPartyFeed`
as `-FeedPassword` or `-ApiKeyValue` - resending the stored hash clears the whole update
instead of keeping it. Omit the parameter to leave the stored secret unchanged.

`-Position` on `New-SfosThirdPartyFeed` can only be set at creation. `Get-SfosThirdPartyFeed`
does not return it, so `Set-SfosThirdPartyFeed` has no matching parameter.

`Remove-SfosThirdPartyFeed` reports the same status text for a successful delete and for a
name that does not exist. The cmdlet reads the feed list back afterwards and throws only if
the object is still present.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
