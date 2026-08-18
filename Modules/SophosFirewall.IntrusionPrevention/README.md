# SophosFirewall.IntrusionPrevention

`SophosFirewall.IntrusionPrevention` manages the Intrusion Prevention area of a Sophos
Firewall: IPS policies and their rules, custom IPS signatures, the device-wide IPS switch
and signature pack, DoS settings and bypass rules, spoof prevention, and trusted MAC
addresses. It is for administrators who script this configuration instead of maintaining it
in the web admin.

Enabling IP spoof prevention for a zone that carries the firewall's own management
interface can make the appliance treat its own admin or API traffic as spoofed and drop it,
leaving it unreachable over the network with no way to revert the change remotely. Never
enable spoof prevention for a zone whose interface shares a subnet with the zone you manage
the firewall from, and confirm the topology with `Get-SfosSpoofPrevention` first.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with permission to read and write this area

## Installation

```powershell
Install-Module SophosFirewall.IntrusionPrevention -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

$rule = New-SfosIPSPolicyRule -RuleName 'AllTraffic' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
New-SfosIPSPolicy -Name 'BranchOfficeIPS' -Description 'One-rule test policy' -Rule $rule

Get-SfosIPSPolicy -NameLike 'BranchOfficeIPS'
Set-SfosIPSPolicy -Name 'BranchOfficeIPS' -Description 'Updated description'
Remove-SfosIPSPolicy -Name 'BranchOfficeIPS'
```

### IPS switch, DoS settings, spoof prevention

```powershell
Get-SfosIPSSwitch
Set-SfosIPSSwitch -Status Disable

Get-SfosDoSSettings | Select-Object SYNFloodSourcePacketRate, SYNFloodDestinationPacketRate
Set-SfosDoSSettings -ICMPFloodSourcePacketRate 121

Get-SfosSpoofPrevention
```

### DoS bypass rules and trusted MAC addresses

```powershell
New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '198.51.100.0/24' -DestinationIPNetmask '203.0.113.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202
Get-SfosDoSBypassRule -ProtocolLike 'TCP'

New-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Association Static -IPV4Address '198.51.100.10'
Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Address '198.51.100.20'
Remove-SfosTrustedMAC -MACAddress '00:16:76:00:00:01'

Import-SfosTrustedMACList -FilePath 'C:\Lists\TrustedMAC.csv'
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosIPSPolicy` | Retrieves IPS policies. |
| `New-SfosIPSPolicy` | Creates an IPS policy. |
| `Set-SfosIPSPolicy` | Updates an IPS policy. |
| `Remove-SfosIPSPolicy` | Removes an IPS policy. |
| `New-SfosIPSPolicyRule` | Builds a rule for a policy's rule list. |
| `Add-SfosIPSPolicyRule` | Appends a rule to an existing policy's rule list. |
| `Remove-SfosIPSPolicyRule` | Removes a rule from a policy's rule list by index. |
| `Get-SfosIPSCustomSignature` | Retrieves custom IPS signatures. |
| `New-SfosIPSCustomSignature` | Creates a custom IPS signature. |
| `Set-SfosIPSCustomSignature` | Updates a custom IPS signature. |
| `Remove-SfosIPSCustomSignature` | Removes a custom IPS signature. |
| `Get-SfosIPSSwitch` | Reads the device-wide intrusion prevention switch. |
| `Set-SfosIPSSwitch` | Switches the intrusion prevention engine on or off. |
| `Get-SfosIPSFullSignaturePack` | Reads whether the full IPS signature pack is active. |
| `Set-SfosIPSFullSignaturePack` | Switches between the base and full IPS signature pack. |
| `Get-SfosDoSSettings` | Reads the device-wide DoS flood-protection settings. |
| `Set-SfosDoSSettings` | Updates the device-wide DoS flood-protection settings. |
| `Get-SfosDoSBypassRule` | Retrieves DoS bypass rules. |
| `New-SfosDoSBypassRule` | Creates a DoS bypass rule. |
| `Set-SfosDoSBypassRule` | Updates a DoS bypass rule. |
| `Remove-SfosDoSBypassRule` | Removes a DoS bypass rule. |
| `Get-SfosSpoofPrevention` | Reads the device-wide spoof prevention settings. |
| `Set-SfosSpoofPrevention` | Updates the device-wide spoof prevention settings. |
| `Get-SfosTrustedMAC` | Retrieves trusted MAC address entries. |
| `New-SfosTrustedMAC` | Creates a trusted MAC address entry. |
| `Set-SfosTrustedMAC` | Updates a trusted MAC address entry, optionally renaming the MAC address. |
| `Remove-SfosTrustedMAC` | Removes a trusted MAC address entry. |
| `Export-SfosTrustedMACs` | Exports trusted MAC address entries to a file. |
| `Import-SfosTrustedMACs` | Reads a local CSV/JSON file and creates one trusted MAC entry per row. |
| `Import-SfosTrustedMACList` | Uploads a trusted MAC list file to the firewall for it to import. |

## Limitations

An IPS policy accepts a `RuleList` with fewer entries than before, including an empty one -
sending it removes rules, unlike some other list fields in this suite. An invalid value
inside a rule's nested fields (for example `Severity`) is dropped from the rule rather than
rejected, so `New-SfosIPSPolicyRule` validates those fields before the request is sent.

`New-`/`Set-SfosIPSCustomSignature` did not find a `-CustomRule` value the firewall accepts;
these two cmdlets are implemented to the documented request shape but are not confirmed to
create or update a signature on this firmware.

`Set-SfosIPSFullSignaturePack` fails on every attempted value on this firmware; the cmdlet
throws rather than reporting a silent no-op.

Setting the spoof prevention main switch to `Disable` clears every other field of the
entity, including the zone lists and `RestrictUnknownIPOnTrustedMAC`.

`Get-SfosDoSBypassRule`'s filters run client-side; the firewall does not narrow the result
itself. A DoS bypass rule is identified by all six of its fields together, not by the three
the documentation marks mandatory for delete - piping a `Get-SfosDoSBypassRule` result
directly into `Set-SfosDoSBypassRule` or `Remove-SfosDoSBypassRule` carries the values
through correctly; retyping them, in particular a wildcard netmask, does not.

`SourcePort` and `DestinationPort` on a DoS bypass rule are required for `TCP`/`UDP` and
have no effect for `ICMP`/`AllProtocol`.

`Get-SfosTrustedMAC`'s `-MACAddressLike` filters client-side. `New-`/`Set-SfosTrustedMAC`
have no `-AssociateIP` parameter, because `Get-SfosTrustedMAC` never returns the field back
for verification.

`Import-SfosTrustedMACList` uploads a file; the firewall requires it to be a CSV with the
exact header `MAC Address, IP Association, IP Address`, and rejects anything else with a
400 error. Re-uploading the same file is a no-op, not a conflict, and does not duplicate
entries.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
