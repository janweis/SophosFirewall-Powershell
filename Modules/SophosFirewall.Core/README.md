# SophosFirewall.Core

`SophosFirewall.Core` is the transport layer for the Sophos Firewall PowerShell module
suite. It manages the connection to the firewall, sends the XML API requests, and checks
whether the firewall reports success or failure. Every other `SophosFirewall.*` module
depends on it and calls it instead of talking to the firewall directly.

Most users only need `Connect-SfosFirewall` and `Disconnect-SfosFirewall` from this
module. The remaining functions are the building blocks the domain modules use
internally; they are documented here because they are exported and can be called
directly, for example to send a request that no domain cmdlet covers yet.

## Requirements

- PowerShell 5.1 or 7.x
- HTTPS access to the firewall's management API (default port 4444)
- A firewall account with API access

## Installation

```powershell
Install-Module SophosFirewall.Core -Repository PSGallery -Scope CurrentUser
```

Installing any domain module (for example `SophosFirewall.HostsAndServices`) pulls in
`SophosFirewall.Core` automatically, since it is listed as a required module.

## Quick Start

```powershell
$cred = Get-Credential
Connect-SfosFirewall -Firewall '192.0.2.10' -Port 4444 -Credential $cred -SkipCertificateCheck

# Any other Sophos Firewall module now reuses this connection
Get-SfosIPHost

Disconnect-SfosFirewall
```

### Working with more than one firewall

`Connect-SfosFirewall -Name` registers a connection under a name without making it the
default session. Pass `-Session` to any cmdlet in any module to address that connection
directly.

```powershell
$fw1 = Connect-SfosFirewall -Firewall '192.0.2.10' -Credential $cred1 -Name fw1
$fw2 = Connect-SfosFirewall -Firewall '192.0.2.20' -Credential $cred2 -Name fw2 -NoDefault

Get-SfosIPHost -Session $fw1
Get-SfosSession
Disconnect-SfosFirewall -All
```

### Sending a request the domain modules do not cover

```powershell
[SecureString]$securePw = $cred.Password
$response = Invoke-SfosApi -Firewall '192.0.2.10' -Port 4444 -Username $cred.UserName -Password $securePw -InnerXml '<Get><Zone/></Get>' -SkipCertificateCheck
[xml]$xml = $response.Content
Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'Zone' -Action 'read' -Target 'Zone'
```

### Uploading a file alongside the request

A handful of operations (FormTemplate, Certificate, CertificateAuthority, CRL, and
similar) take a file upload together with the request XML. Pass it as `-MultipartFile`, a
hashtable of multipart field name to one file path or an array of paths:

```powershell
$inner = '<Set operation="add"><FormTemplate><Name>Portal1</Name><Template>portal.html</Template></FormTemplate></Set>'
$response = Invoke-SfosApi -Firewall '192.0.2.10' -Username $cred.UserName -Password $securePw -InnerXml $inner -MultipartFile @{ Template = 'C:\templates\portal.html' } -SkipCertificateCheck
[xml]$xml = $response.Content
Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'FormTemplate' -Action 'create' -Target 'Portal1'
```

The field name must match the XML element that references the upload (`Template` above),
and that element's text must be the file's base name, matching the uploaded file. Calls
that do not pass `-MultipartFile` are unaffected - the request is sent exactly as before
this parameter existed.

### Reaching the appliance's CLI console

`Connect-SfosCliConsole`, `Send-SfosCliInput`, `Receive-SfosCliOutput` and
`Disconnect-SfosCliConsole` reach the appliance's own text console - the same screen an
administrator opens from the "Console" entry of the web admin interface - rather than the
XML API or the web admin screens `Connect-SfosWebAdmin` reaches. Use it only for actions
that have no equivalent anywhere else in this module suite.

A few things to know before using it:

- Only the `admin` and `support` accounts can open the console; every other account is
  turned away.
- The console asks for the account's password a second time once the session opens, even
  though the caller already authenticated to reach it. `Connect-SfosCliConsole` answers
  that prompt automatically.
- Always close a session you opened with `Disconnect-SfosCliConsole`, including on an
  error path. A session that is not closed stays open on the appliance.
- The console's main menu includes an entry that reboots or shuts down the appliance, and
  every key reaches it exactly as if typed at a physical terminal, with no confirmation
  prompt of its own. Never send an entry you have not verified yourself.
- Like the web admin interface, this path is undocumented and specific to the current
  firmware; it can change or stop working on a future update without notice.

```powershell
$cli = Connect-SfosCliConsole -Session 'fw1'
$cli.Banner
Send-SfosCliInput -CliSession $cli -Text '4'
Send-SfosCliInput -CliSession $cli -Key 'Enter'
Receive-SfosCliOutput -CliSession $cli -Until 'console>'
Disconnect-SfosCliConsole -CliSession $cli
```

### Reading a file response

Certificate, CertificateAuthority, CRL and FormTemplate answer a Get with a tar archive
instead of XML - one embedded file per matching object, plus an Entities.xml holding the
same metadata a normal Get response would carry:

```powershell
$response = Invoke-SfosApi -Session 'fw1' -InnerXml '<Get><CertificateAuthority></CertificateAuthority></Get>'
$archive = ConvertFrom-SfosArchive -Bytes $response.Content
$archive.Entities.Response.CertificateAuthority | Select-Object Name, Type
$archive.Files | Select-Object Name
```

The firewall can produce a malformed tar header for an object whose stored name contains
non-ASCII characters, which breaks the archive's internal structure from that point on.
`ConvertFrom-SfosArchive` does not throw for that: it returns every file it read
successfully, sets `.Truncated`, and names the last entry that read cleanly in
`.TruncatedAfter`. `.Entities` is unaffected either way, because it is recovered
independently of the tar structure.

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Connect-SfosFirewall` | Opens a connection and stores it for reuse by every module. |
| `Disconnect-SfosFirewall` | Closes one, several, or all stored connections. |
| `Get-SfosSession` | Lists the registered connections. |
| `Invoke-SfosApi` | Sends a raw XML request to the firewall's management API. |
| `Get-SfosApiStatus` | Reads the status code and message out of an API response. |
| `Assert-SfosApiReturnSuccess` | Checks an API response and throws if the request failed. |
| `Resolve-SfosParameters` | Merges explicit connection parameters with the active session; used internally by the domain modules. |
| `ConvertTo-SfosXmlEscaped` | Escapes text for safe use inside the request XML. |
| `ConvertFrom-SfosArchive` | Reads the tar archive returned by Certificate, CertificateAuthority, CRL and FormTemplate instead of XML. |
| `Connect-SfosWebAdmin` | Logs into the web admin interface (Web Admin Console - not the XML API, not the appliance's CLI console) and returns a session context. Undocumented and firmware-bound - see its own help before using it. |
| `Invoke-SfosWebAdminRequest` | Sends one request to the web admin interface's controller. Undocumented and firmware-bound - see its own help before using it. |
| `Connect-SfosCliConsole` | Opens a session on the appliance's own CLI console (reached through the web admin interface's "Console" entry) and returns its context. Undocumented and firmware-bound - see its own help before using it. |
| `Send-SfosCliInput` | Sends one piece of input - text or a named key - to an open CLI console session. |
| `Receive-SfosCliOutput` | Collects pending output from an open CLI console session. |
| `Disconnect-SfosCliConsole` | Closes a CLI console session. |

## Status codes

`Assert-SfosApiReturnSuccess` follows the status table published by Sophos: codes 200 and
216 are success, codes 201, 203 and 211-215 succeed with a warning, and codes 500-599 are
failures. Codes 217 and 222, which the table does not define, are treated as a warning
rather than a failure because writes that return them do apply. Every other undefined code
is treated as a failure, so an unrecognised response is never read as a success.

## License

MIT License - Copyright (c) 2025 Jan Weis

## Links

- [Sophos Firewall API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/)
