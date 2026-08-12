# SophosFirewall.IntrusionPrevention Module

## Overview

The **IntrusionPrevention** module provides PowerShell cmdlets for the **PROTECT >
Intrusion Prevention** area of the Sophos XGS / SFOS 22.0 API documentation. With 29
exported functions, it manages IPS policies and their rules, custom IPS signatures, the
device-wide IPS switch, the IPS full signature pack, DoS settings, DoS bypass rules,
spoof prevention and trusted MAC addresses. Requires `SophosFirewall.Core` (minimum
version 1.0.0).

## Features

- **IPS Policy**: Full CRUD for `IPSPolicy` objects, plus `New-SfosIPSPolicyRule` to
  build rule objects and `Add-`/`Remove-SfosIPSPolicyRule` to manage a policy's
  `RuleList` one rule at a time
- **IPS Custom Signature**: Full CRUD for `IPSCustomSignature` objects (unconfirmed to
  succeed on write against this firmware - see Known behaviour)
- **IPS Switch**: `Get-`/`Set-SfosIPSSwitch`, the master on/off switch for the whole
  intrusion prevention engine
- **IPS Full Signature Pack**: `Get-`/`Set-SfosIPSFullSignaturePack`
- **DoS Settings**: `Get-`/`Set-SfosDoSSettings` for the device-wide flood-protection
  singleton (SYN/UDP/TCP/ICMP flood, source-routed packets, ICMP redirects, ARP
  flooding)
- **DoS Bypass Rules**: Full CRUD for `DoSBypassRules` objects
- **Spoof Prevention**: `Get-`/`Set-SfosSpoofPrevention` for the device-wide
  IP/MAC spoofing filter
- **Trusted MAC**: Full CRUD plus `Export-`/`Import-SfosTrustedMACs` for `TrustedMAC`
  objects
- **API Integration**: Full integration with the Sophos XGS/SFOS firewall XML API

## Installation

```powershell
Install-Module -Name SophosFirewall.IntrusionPrevention
```

This pulls in `SophosFirewall.Core` automatically as a required module.

Or with explicit path:

```powershell
Import-Module -Name "C:\Path\To\SophosFirewall.IntrusionPrevention.psd1"
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

### IPS Policy and Rules

```powershell
# Retrieve all IPS policies
Get-SfosIPSPolicy

# Filter by name (substring match)
Get-SfosIPSPolicy -NameLike "dmz"

# Return raw XML for troubleshooting
Get-SfosIPSPolicy -NameLike "dmz" -AsXml

# Create a policy with no rules yet
New-SfosIPSPolicy -Name "BranchOffice" -Description "Empty test policy"

# Create a policy with one rule
$rule = New-SfosIPSPolicyRule -RuleName "AllTraffic" -Category "All Categories" -Severity "All Severity" -Target "All Target" -Platform "All Platform"
New-SfosIPSPolicy -Name "BranchOfficeIPS" -Description "One-rule test policy" -Rule $rule

# Change only the description, RuleList is preserved
Set-SfosIPSPolicy -Name "BranchOfficeIPS" -Description "Updated description"

# Update using pipeline input
Get-SfosIPSPolicy -NameLike "BranchOfficeIPS" | Set-SfosIPSPolicy -Description "Updated"

# A simple all-traffic rule using the recommended action
New-SfosIPSPolicyRule -RuleName "AllTraffic" -Category "All Categories" -Severity "All Severity" -Target "All Target" -Platform "All Platform"

# Change one field of an existing rule read back from the firewall
$policy = Get-SfosIPSPolicy -NameLike "BranchOfficeIPS"
$edited = $policy.RuleList[0] | New-SfosIPSPolicyRule -Action "Drop Session"
Set-SfosIPSPolicy -Name "BranchOfficeIPS" -Rule $edited

# Append a rule to an existing policy
$rule = New-SfosIPSPolicyRule -RuleName "ExtraRule" -Category "All Categories" -Severity "All Severity" -Target "All Target" -Platform "All Platform"
Add-SfosIPSPolicyRule -Name "BranchOfficeIPS" -Rule $rule

# Remove the first rule of the policy
Remove-SfosIPSPolicyRule -Name "BranchOfficeIPS" -Index 0

# Remove the policy itself
Remove-SfosIPSPolicy -Name "BranchOffice"
```

### Multi-Session

Hold connections to more than one firewall at once with `Connect-SfosFirewall -Name`,
and move an object from one to the other by piping across sessions:

```powershell
Connect-SfosFirewall -Firewall "fw1.example.test" -Credential (Get-Credential) -Name "fw1"
Connect-SfosFirewall -Firewall "fw2.example.test" -Credential (Get-Credential) -Name "fw2" -NoDefault

Get-SfosIPSPolicy -Session "fw1" -NameLike "BranchOfficeIPS" |
    New-SfosIPSPolicy -Session "fw2"
```

### IPS Custom Signature

```powershell
Get-SfosIPSCustomSignature

Get-SfosIPSCustomSignature -NameLike "Block"

# Documentation-faithful call; unconfirmed to succeed on this firmware - see Known behaviour
New-SfosIPSCustomSignature -Name "BlockTelnet" -Protocol TCP -CustomRule 'alert tcp any any -> any any (msg:"probe"; sid:1000001; rev:1;)' -Severity Minor -RecommendedAction "Allow Packet"

# Documentation-faithful call; unconfirmed to succeed on this firmware - see Known behaviour
Set-SfosIPSCustomSignature -Name "BlockTelnet" -Severity Major

Remove-SfosIPSCustomSignature -Name "BlockTelnet"
```

### IPS Switch and Full Signature Pack

```powershell
# Check whether intrusion prevention is currently switched on
Get-SfosIPSSwitch

Set-SfosIPSSwitch -Status Disable

# Check whether the full (as opposed to base) IPS signature pack is active
Get-SfosIPSFullSignaturePack

Set-SfosIPSFullSignaturePack -Status enable
```

### DoS Settings

```powershell
# Check the current SYN flood packet-rate limits
Get-SfosDoSSettings | Select-Object SYNFloodSourcePacketRate, SYNFloodDestinationPacketRate

# Change only the ICMP flood source packet rate, every other field is preserved
Set-SfosDoSSettings -ICMPFloodSourcePacketRate 121
```

### Spoof Prevention

```powershell
# Check whether spoof prevention is on, and if so, for which zones
Get-SfosSpoofPrevention

# Enable IP spoofing prevention for the DMZ zone only - never a zone carrying your own
# admin/API session, see the WARNING in Known behaviour
Set-SfosSpoofPrevention -Status Enable -IPSpoofingZoneList 'DMZ'

# Turn Spoof Prevention back off entirely
Set-SfosSpoofPrevention -Status Disable
```

### DoS Bypass Rules

```powershell
# List every DoS bypass rule
Get-SfosDoSBypassRule

# Find every TCP bypass rule
Get-SfosDoSBypassRule -ProtocolLike 'TCP'

# Bypass DoS protection for TCP traffic between two private test subnets on ports 2201/2202
New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202

# Bypass DoS protection for all ICMP traffic from a private test subnet
New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -Protocol ICMP

# Widen the destination netmask of an existing ICMP bypass rule
Set-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -DestinationIPNetmask '10.99.94.0/24' -Protocol ICMP -NewSourceIPNetmask '10.99.85.0/24'

Remove-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202
```

### Trusted MAC

```powershell
# List every trusted MAC entry
Get-SfosTrustedMAC

# Find entries in the documented vendor test range
Get-SfosTrustedMAC -MACAddressLike '00:16:76'

New-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Association Static -IPV4Address '10.99.60.10'

# Change only the bound IPv4 address, everything else is preserved
Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Address '10.99.60.20'

# Rename the MAC address itself
Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:02' -NewMACAddress '00:16:76:00:00:99'

Remove-SfosTrustedMAC -MACAddress '00:16:76:00:00:01'

Export-SfosTrustedMACs -FilePath 'C:\Exports\SophosTrustedMACs.csv'

Import-SfosTrustedMACs -FilePath 'C:\Imports\SophosTrustedMACs.csv'
```

## Available Cmdlets (29 total)

### IPS Policy and Rules (7 functions)
- `Get-SfosIPSPolicy` - Retrieves IPSPolicy objects from the Sophos Firewall.
- `New-SfosIPSPolicy` - Creates a new IPSPolicy on the Sophos Firewall.
- `Set-SfosIPSPolicy` - Updates an existing IPSPolicy object on the Sophos Firewall.
- `Remove-SfosIPSPolicy` - Removes an IPSPolicy object from the Sophos Firewall.
- `New-SfosIPSPolicyRule` - Builds a rule for use inside an IPSPolicy's RuleList.
- `Add-SfosIPSPolicyRule` - Appends a rule to the end of an existing IPSPolicy's RuleList.
- `Remove-SfosIPSPolicyRule` - Removes a single rule from an existing IPSPolicy's RuleList by index.

### IPS Custom Signature (4 functions)
- `Get-SfosIPSCustomSignature` - Retrieves IPSCustomSignature objects from the Sophos Firewall.
- `New-SfosIPSCustomSignature` - Creates a new IPSCustomSignature on the Sophos Firewall.
- `Set-SfosIPSCustomSignature` - Updates an existing IPSCustomSignature object on the Sophos Firewall.
- `Remove-SfosIPSCustomSignature` - Removes an IPSCustomSignature object from the Sophos Firewall.

### IPS Switch (2 functions)
- `Get-SfosIPSSwitch` - Retrieves the device-wide IPSSwitch status from the Sophos Firewall.
- `Set-SfosIPSSwitch` - Switches the device-wide intrusion prevention engine on or off.

### IPS Full Signature Pack (2 functions)
- `Get-SfosIPSFullSignaturePack` - Retrieves the device-wide IPSFullSignaturePack status from the Sophos Firewall.
- `Set-SfosIPSFullSignaturePack` - Sets the device-wide IPSFullSignaturePack status on the Sophos Firewall.

### DoS Settings (2 functions)
- `Get-SfosDoSSettings` - Retrieves the device-wide DoSSettings from the Sophos Firewall.
- `Set-SfosDoSSettings` - Updates the device-wide DoSSettings on the Sophos Firewall.

### DoS Bypass Rules (4 functions)
- `Get-SfosDoSBypassRule` - Retrieves DoSBypassRules objects from the Sophos Firewall.
- `New-SfosDoSBypassRule` - Creates a new DoSBypassRules object on the Sophos Firewall.
- `Set-SfosDoSBypassRule` - Updates an existing DoSBypassRules object on the Sophos Firewall.
- `Remove-SfosDoSBypassRule` - Removes a DoSBypassRules object from the Sophos Firewall.

### Spoof Prevention (2 functions)
- `Get-SfosSpoofPrevention` - Retrieves the device-wide SpoofPrevention settings from the Sophos Firewall.
- `Set-SfosSpoofPrevention` - Updates the device-wide SpoofPrevention settings on the Sophos Firewall.

### Trusted MAC (6 functions)
- `Get-SfosTrustedMAC` - Retrieves TrustedMAC objects from the Sophos Firewall.
- `New-SfosTrustedMAC` - Creates a new TrustedMAC object on the Sophos Firewall.
- `Set-SfosTrustedMAC` - Updates an existing TrustedMAC object on the Sophos Firewall, optionally renaming its MAC address.
- `Remove-SfosTrustedMAC` - Removes a TrustedMAC object from the Sophos Firewall.
- `Export-SfosTrustedMACs` - Exports all TrustedMAC objects to a CSV or JSON file.
- `Import-SfosTrustedMACs` - Imports TrustedMAC objects from a CSV or JSON file.

## Known behaviour / limitations (SFOS 22.0)

Measured against a live SFOS 22.0 appliance.

- **`Set-SfosIPSPolicy` does not validate nested enum values on update.** An unrecognized
  value inside a Rule's nested lists (for example an invalid `Severity`) is not rejected
  by the firewall - it is silently dropped from the Rule while the request still answers
  `200 Configuration applied successfully`. `New-SfosIPSPolicyRule` validates
  `Severity`/`Target` client-side to guard against this.
- **`<Template>` is rejected outright.** It appears only in the vendor sample XML for
  `IPSPolicy`, has no row in the attribute table, and sending it with any value is
  rejected with a `501` naming `/IPSPolicy/Template` - so this module has no `-Template`
  parameter.
- **`New-`/`Set-SfosIPSCustomSignature` are unconfirmed on SFOS 22.0.** Every one of ten
  `-CustomRule` syntax variants tried against the live firewall was rejected with a bare
  `501` naming only `/IPSCustomSignature/CustomRule`; `-Protocol`, `-Severity` and
  `-RecommendedAction` were independently confirmed valid. No working `-CustomRule` syntax
  was found, so these cmdlets are implemented documentation-faithful and not confirmed to
  succeed on this firmware.
- **`IPSCustomSignature` writes `<RecommendedAction>`, not the vendor table's "Action".**
  The attribute table calls the field "Action" and marks it mandatory, but the actual wire
  element - confirmed via `InvalidParams` - is `<RecommendedAction>`, matching the vendor's
  own XML sample.
- **Removing a nonexistent `IPSPolicy` or `IPSCustomSignature` answers `200`.** Both
  `Remove-*` cmdlets read the object first and throw "was not found" rather than trusting
  that response.
- **`IPSPolicy`'s `RuleList` is NOT append-only.** Shrinking a policy from two rules to one,
  or sending an empty `RuleList`, both take effect correctly - unlike some other list
  fields in this project family.
- **`Set-SfosIPSFullSignaturePack` is firmware-broken on SFOS 22.0.** `operation="update"`
  answers `500` for every value tried, including a same-value re-send; `operation="add"` is
  a silent no-op with no `<IPSFullSignaturePack>` element and no `<Status>` in the response
  at all. This cmdlet uses `operation="update"` (the only verb this project trusts) and
  reliably throws via the coded `500` rather than silently doing nothing.
- **`DoSSettings.ApplyFlag` is not validated server-side.** Sending an invalid value
  together with an otherwise complete body answers `200` and a follow-up `Get` shows the
  field unchanged - the invalid value is silently discarded, not applied or rejected.
  `Set-SfosDoSSettings` enforces `ValidateSet('Enable','Disable')` client-side on every
  `*ApplyFlag` parameter for this reason.
- **Spoof Prevention's main switch is a full-replace, not a partial update.** Setting the
  main switch to `Disable` clears/ignores every other field (`RestrictUnknownIPOnTrustedMAC`
  and all three zone lists) regardless of what is sent alongside it.
  **WARNING (measured):** enabling `IPSpoofing` for the zone that carries the firewall's own
  admin/API interface, on a topology where that interface shares a subnet with another
  interface of a different zone, made the firewall treat its own management traffic as
  spoofed and drop it - the appliance became unreachable over the network and had to be
  recovered through an out-of-band path. Never enable spoof prevention for a zone that
  carries your own management session without first confirming that zone's interface does
  not share a subnet with another zone's interface.
- **`DoSBypassRules` has no working server-side filter.** Sending any `<Filter>` at all
  answers `404`, even one that matches an existing record, so `Get-SfosDoSBypassRule`
  never sends one - every `-*Like` parameter is client-side only. Identification requires
  all six fields: the three fields the documentation marks mandatory for Delete
  (`IPFamily`/`SourcePort`/`DestinationPort`) are not sufficient to disambiguate two
  records that share those three values but differ elsewhere, and a Delete sent with only
  those three answers `200` while deleting nothing. `Get-SfosDoSBypassRule` reports a
  wildcard netmask back as the literal string `any`; the wire only accepts the literal
  `*` for identification on write, and this module's cmdlets translate between the two
  automatically so piping `Get-*` into `Set-*`/`Remove-*` works.
- **`SourcePort`/`DestinationPort` on `DoSBypassRules` are only needed for TCP/UDP.**
  Omitting them for `Protocol TCP`/`UDP` answers `400`. For `ICMP`/`AllProtocol` they are
  accepted if sent but never actually stored - a follow-up `Get` shows no
  `SourcePort`/`DestinationPort` element for those records.
- **`TrustedMAC`'s server-side filter on `MACAddress` returns every record regardless of
  match.** `Get-SfosTrustedMAC`'s `-MACAddressLike` is therefore client-side only.
  `AssociateIP` is write-only - it accepts any value unvalidated and is never returned by a
  subsequent `Get`, so there is no way to observe its effect; per this project's
  write-only-field rule, it is not exposed by `New-`/`Set-SfosTrustedMAC` at all.
  `Set-SfosTrustedMAC` can rename the `MACAddress` itself via `-NewMACAddress` and the
  documented `<OldConfiguration>` wrapper.
  `Upload_TrustedMAC` (the bulk file-upload operation) is not implemented - it is a genuine
  multipart file upload, and `Invoke-SfosApi` in `SophosFirewall.Core` only builds the
  single urlencoded `reqxml=` POST body this project uses everywhere else.

## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

    # Retrieve a specific policy with error handling
    $policy = Get-SfosIPSPolicy -NameLike "BranchOfficeIPS" -ErrorAction Stop
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
- **Object Not Found**: Use `Get-SfosIPSPolicy | Select-Object Name` to list all available policies
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **`New-SfosIPSCustomSignature` fails with a `501` on `/IPSCustomSignature/CustomRule`**: See Known behaviour - no working rule syntax was found for this field on SFOS 22.0
- **`Set-SfosIPSFullSignaturePack` throws with code `500`**: See Known behaviour - this entity's update is firmware-broken for every value on SFOS 22.0; the cmdlet throws rather than silently doing nothing
- **Lost connectivity after `Set-SfosSpoofPrevention -Status Enable`**: See the WARNING in Known behaviour - never enable spoof prevention for a zone carrying your own admin/API session on a shared-subnet topology
- **`Set-`/`Remove-SfosDoSBypassRule` reports "not found" for a record you can see with `Get-*`**: See Known behaviour - pipe `Get-SfosDoSBypassRule` output directly into `Set-*`/`Remove-*` rather than retyping netmask/port values, so the `any`/`*` translation happens automatically

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.IntrusionPrevention) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License

MIT License - see [LICENSE.txt](LICENSE.txt) for details.
