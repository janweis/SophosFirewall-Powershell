# SophosFirewall.Core Module

Foundation module providing connection management, API communication, and security functions for all Sophos Firewall PowerShell modules.

## Quick Start

```powershell
# Connect to firewall (stores credentials for all modules to use)
$cred = Get-Credential
Connect-SfosFirewall -Firewall "192.168.1.1" -Credential $cred -SkipCertificateCheck

# Use any other Sophos Firewall module - connection is automatically available
Get-SfosIPHostGroup    # From SophosFirewall.HostsAndServices
Get-SfosIPHost        # From SophosFirewall.HostsAndServices

# Disconnect when done
Disconnect-SfosFirewall
```

## Installation

SophosFirewall.Core is automatically loaded as a dependency when you import any other Sophos Firewall module:

```powershell
Import-Module SophosFirewall.HostsAndServices   # Core loads automatically
```

Or import directly:

```powershell
Import-Module SophosFirewall.Core
```

## Requirements

- PowerShell 5.1 or higher
- HTTPS connectivity to Sophos XGS/SFOS firewall (port 4444)
- Valid firewall administrator account

## Core Functions

### Connect-SfosFirewall / Disconnect-SfosFirewall

Manage firewall connection and credential storage:

```powershell
# Connect (credentials stored in module scope)
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential $cred [-SkipCertificateCheck]

# Disconnect (securely clears credentials)
Disconnect-SfosFirewall
```

**Parameters:**
- `-Firewall`: IP address or hostname (required)
- `-Port`: API port (default: 4444)
- `-Credential`: PSCredential with admin account (required)
- `-SkipCertificateCheck`: Skip SSL validation for self-signed certificates

### Invoke-SfosApi

Low-level HTTP POST wrapper to firewall XML API (used by all modules):

```powershell
$response = Invoke-SfosApi -Firewall "192.168.1.1" -Port 4444 `
    -Username "admin" -Password "password" `
    -InnerXml "<Get><Zone/></Get>" -SkipCertificateCheck

[xml]$xml = $response.Content
```

**API Endpoint:** `https://{firewall}:4444/webconsole/APIController`

### Get-SfosApiStatus / Assert-SfosApiReturnSuccess

Parse and validate API responses:

```powershell
[xml]$xml = $response.Content

# Check status
$status = Get-SfosApiStatus -Xml $xml
Write-Host "Status: $($status.Code)"

# Throw error on failure
Assert-SfosApiReturnSuccess -Xml $xml -ObjectName 'Zone'
```

**Success Codes:** 200 (OK), 202 (Accepted)

### Resolve-SfosParameters

Merge explicit parameters with stored connection context:

```powershell
$resolved = Resolve-SfosParameters -BoundParameters $PSBoundParameters
# Returns hashtable with Firewall, Port, Username, Password, SkipCertificateCheck
```

Allows functions to work with either stored connection OR explicit parameters.

### ConvertTo-SfosXmlEscaped

Prevent XML injection by escaping special characters:

```powershell
$description = "Company & Co"
$safe = ConvertTo-SfosXmlEscaped -Text $description
# Result: "Company &amp; Co"

# Always escape user input before embedding in XML
$xml = "<Set><Zone><Description>$safe</Description></Zone></Set>"
```

Escape mappings:

| Input | Output |
|-------|--------|
| `&` | `&amp;` |
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&apos;` |


## Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection fails | Check firewall IP/port, verify network connectivity with `Test-NetConnection -ComputerName "192.168.1.1" -Port 4444` |
| SSL certificate error | Add `-SkipCertificateCheck` parameter (use valid certs in production) |
| Authentication fails (502) | Verify username/password, ensure account is admin, check API is enabled on firewall |
| "No active connection found..." | Run `Connect-SfosFirewall` first OR provide explicit `-Firewall` and `-Credential` parameters |

**Status Codes:**
| Code | Meaning |
|------|---------|
| 200 | Success |
| 202 | Request accepted (async) |
| 502 | Authentication failed |


## License

MIT License - Copyright (c) 2025 Jan Weis (www.it-explorations.de)
