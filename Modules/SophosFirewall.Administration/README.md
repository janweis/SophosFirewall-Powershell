# SophosFirewall.Administration

`SophosFirewall.Administration` manages the SYSTEM > Administration area of a Sophos
Firewall: mail server notification, SNMP agent and communities, SNMPv3 users, system time,
end-user messages, the appliance access matrix, the admin settings singleton (hostname, web
admin ports, login security, password complexity, login disclaimer), the Local Service ACL,
a factory reset, and restart/shutdown of the appliance. It is for administrators who script
the device-level configuration that sits outside network, routing and policy objects.

Several cmdlets in this module change the settings that the current management session
itself depends on. A wrong value on `Set-SfosApplianceAccess`, `Set-SfosWebAdminSettings`,
`Set-SfosLoginSecurity` or `New-`/`Set-`/`Remove-SfosLocalServiceACL` can make the appliance
unreachable over the network, with no way to undo the change through the same API session.
Read the Limitations section before using them, and check the current configuration with
the matching `Get-*` cmdlet first.

## Requirements

- `SophosFirewall.Core` (installed automatically as a dependency)
- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API
- A firewall account with administrative permission

## Installation

```powershell
Install-Module SophosFirewall.Administration -Repository PSGallery -Scope CurrentUser
```

## Quick Start

```powershell
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck

Get-SfosNotification
Set-SfosNotification -SenderAddress 'firewall-alerts@example.com'

Get-SfosTime
Set-SfosTime -TimeZone 'Europe/Berlin'

$secret = ConvertTo-SecureString 'public-secret' -AsPlainText -Force
New-SfosSNMPCommunity -Name 'Monitoring' -CommunityString $secret -AuthorizedHostIpv4 '198.51.100.50' -AcceptQueries 'True'
Get-SfosSNMPCommunity
Remove-SfosSNMPCommunity -Name 'Monitoring'
```

### Appliance access (read before writing)

```powershell
Get-SfosApplianceAccess | Format-List

# Preview the change before sending it
Set-SfosApplianceAccess -Ping 'LAN', 'WiFi', 'DMZ' -WhatIf
```

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Get-SfosNotification` | Reads the mail server notification settings. |
| `Set-SfosNotification` | Updates the mail server notification settings. |
| `Get-SfosSNMPAgentConfiguration` | Reads the SNMP agent configuration. |
| `Set-SfosSNMPAgentConfiguration` | Updates the SNMP agent configuration. |
| `Get-SfosSNMPCommunity` | Reads SNMP communities. |
| `New-SfosSNMPCommunity` | Creates an SNMP community. |
| `Set-SfosSNMPCommunity` | Updates an SNMP community. |
| `Remove-SfosSNMPCommunity` | Removes an SNMP community. |
| `Get-SfosSNMPv3User` | Reads SNMPv3 users. |
| `New-SfosSNMPv3User` | Creates an SNMPv3 user. |
| `Set-SfosSNMPv3User` | Updates an SNMPv3 user. |
| `Remove-SfosSNMPv3User` | Removes an SNMPv3 user. |
| `Get-SfosTime` | Reads the appliance time zone and clock. |
| `Set-SfosTime` | Updates the appliance time zone and clock. |
| `Get-SfosMessages` | Reads the customizable end-user messages. |
| `Set-SfosMessages` | Updates the customizable end-user messages. |
| `Get-SfosNetFlowConfiguration` | Reads the Netflow collector server list. |
| `Set-SfosNetFlowConfiguration` | Updates the Netflow collector server list. |
| `Get-SfosApplianceAccess` | Reads the zone-per-service access matrix. |
| `Set-SfosApplianceAccess` | Updates the zone-per-service access matrix. |
| `Get-SfosAdminSettings` | Reads the admin settings singleton. |
| `Set-SfosWebAdminSettings` | Updates the web admin and portal HTTPS settings. |
| `Set-SfosLoginSecurity` | Updates the admin login security policy. |
| `Set-SfosAdminPasswordComplexity` | Updates the admin password complexity policy. |
| `Set-SfosLoginDisclaimer` | Updates the admin login disclaimer toggle. |
| `Set-SfosHostname` | Updates the appliance host name and description. |
| `Reset-SfosToFactoryDefaults` | Resets the appliance to its factory default configuration. |
| `Set-SfosAdminPassword` | Changes the password of the built-in administrator account. |
| `Get-SfosLocalServiceACL` | Reads Local Service ACL rules. |
| `New-SfosLocalServiceACL` | Creates a Local Service ACL rule. |
| `Set-SfosLocalServiceACL` | Updates a Local Service ACL rule. |
| `Remove-SfosLocalServiceACL` | Removes a Local Service ACL rule. |
| `Restart-SfosFirewall` | Restarts the appliance (web admin console, not the XML API). |
| `Stop-SfosFirewall` | Shuts the appliance down (web admin console, not the XML API). |

## Limitations

`Set-SfosApplianceAccess` replaces the zone list of every service you pass and keeps the
current list for services you omit. Its `Https` and `SSH` lists carry the management
session's own access; removing the zone your web admin or API session comes from makes the
appliance unreachable over the network. Check `Get-SfosApplianceAccess` first and use
`-WhatIf` to preview the call.

`Set-SfosWebAdminSettings` and `Set-SfosLoginSecurity` change the HTTPS port and the login
policy that the current admin session depends on. A wrong value can end that session with
no way to sign back in remotely.

`New-SfosLocalServiceACL`, `Set-SfosLocalServiceACL` and `Remove-SfosLocalServiceACL`
control which zones and source hosts may reach the appliance's management services. A rule
that excludes the zone or host you manage from, or a rule with `Action drop` placed ahead of
your own access, can cut off the same path used to fix it.

`Reset-SfosToFactoryDefaults` wipes the appliance configuration back to factory defaults.
This is the API's `DefaultConfigurationLanguage` field; the name suggests a language
setting, but the effect is a full reset. The cmdlet prompts for confirmation unless
`-Confirm:$false` is passed.

`Set-SfosAdminPassword` changes the password of the appliance's built-in `admin` account,
not the account the module uses to sign in to the API - those are normally two different
accounts. Supplying the wrong current password is rejected, but the appliance answers with
an error about a deleted object that is unrelated to the actual problem; read it as "current
password incorrect" and try again with the correct value.

`Set-SfosNotification` cannot change `SmtpPort`, `NotificationServer` or
`ManagementInterface` on this firmware: the request succeeds but the values stay unchanged.

`Set-SfosSNMPAgentConfiguration` requires both `Location` and `Name` on every update, even
when only one field is being changed; both keep their previous value unless you supply
non-empty replacements for both.

`Set-SfosSNMPv3User` requires `-AuthenticationPassword` and `-EncryptionPassword` on every
update. There is no way to keep the stored secrets while changing another field.

`Set-SfosNetFlowConfiguration` takes `-ServerName`, `-NetflowServer` and `-NetflowServerPort`
as parallel arrays; entries at the same index describe one server, and any array left out is
filled from the current configuration. There is no cmdlet to remove a single server. To clear
the whole list, pass all three arrays empty:
`Set-SfosNetFlowConfiguration -ServerName @() -NetflowServer @() -NetflowServerPort @()`.

`Restart-SfosFirewall` and `Stop-SfosFirewall` are not part of the documented XML API - the
vendor's operation index has no restart or shutdown operation at all. Both go through the
same undocumented web admin console access used by the log viewer in
`SophosFirewall.Diagnostics`, so they can change or break on a firmware update without
notice. `Stop-SfosFirewall` has no counterpart to switch the appliance back on; that has to
happen physically or through the hypervisor/virtualization console. Measured downtime for a
restart on the lab appliance used to verify these cmdlets was about 3 minutes from request to
the management port answering again - one data point, not a guarantee across hardware and
configurations.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [SophosFirewall.Core](../SophosFirewall.Core/README.md)
- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
