# SophosFirewall.HostsAndServices Module

## Overview

The **HostsAndServices** module provides comprehensive PowerShell cmdlets for managing network objects on Sophos XGS / SFOS 21.5, 22.0+ firewalls. With 53 functions, it enables definition and management of IP hosts, FQDN hosts, MAC hosts, services, service groups, and country groups used throughout firewall policies and rules.

## Features

- **IP Host Objects**: Create, update, and manage IP-based host definitions
- **IP Host Groups**: Organize IP hosts into logical groups for policy management
- **FQDN Host Objects**: Manage hostname/DNS-based host definitions
- **FQDN Host Groups**: Organize FQDN hosts with bulk deletion support
- **MAC Host Objects**: MAC address-based host definitions
- **Country Groups**: Geographic-based access control groups
- **Service Objects**: Define custom TCP/UDP services with single ports or port ranges
- **Service Groups**: Group related services for simplified policy assignment
- **Import/Export**: Bulk import and export for all object types
- **Bulk Operations**: Mass delete operations for FQDN hosts
- **Comments**: Add descriptive metadata to all objects
- **API Integration**: Full integration with Sophos XGS/SFOS firewall REST API

## Installation

```powershell
Import-Module -Name SophosFirewall.HostsAndServices
```

Or with explicit path:

```powershell
Import-Module -Path "C:\Path\To\SophosFirewall.HostsAndServices.psd1"
```

## Requirements

- PowerShell 5.1 or higher (Windows PowerShell)
- PowerShell 7.0+ (PowerShell Core) recommended
- SophosFirewall.Core module (automatically loaded as dependency)
- Network access to Sophos XGS / SFOS firewall (versions 21.5, 22.0+)
- API credentials with appropriate permissions

## Quick Start

### Establish Connection

```powershell
Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
```

### IP Host Management

```powershell
# Get all IP hosts
Get-SfosIPHost

# Get specific IP host
Get-SfosIPHost -NameLike "CORP-WEB-01"

# Create IP host
New-SfosIPHost -Name "CORP-WEB-01" -HostType IP -IPAddress "192.168.1.10" -Description "Production Web Server"

# Create IP network/subnet
New-SfosIPHost -Name "InternalNetwork" -HostType Network -IPAddress "192.168.0.0" -Subnet "255.255.255.0" -Description "Internal subnet"

# Update IP host
Set-SfosIPHost -Name "CORP-WEB-01" -HostType IP -IPAddress "192.168.1.10" -Description "Updated: Primary web server"

# Delete IP host
Remove-SfosIPHost -Name "CORP-WEB-01"

# Export all IP hosts
Export-SfosIPHosts -FilePath "c:\backups\ip_hosts.csv"

# Import IP hosts
Import-SfosIPHosts -FilePath "c:\backups\ip_hosts.csv"
```

### IP Host Group Management

```powershell
# Get all IP host groups
Get-SfosIPHostGroup

# Create IP host group
New-SfosIPHostGroup -Name "WebServers" -Description "Production web tier"

# Add member to group
Add-SfosIPHostGroupMember -Name "WebServers" -members "CORP-WEB-01", "CORP-WEB-02"

# Update group
Set-SfosIPHostGroup -Name "WebServers" -Description "Updated: All production web servers"

# Remove member from group
Remove-SfosIPHostGroupMember -Name "WebServers" -members "CORP-WEB-03"

# Delete group
Remove-SfosIPHostGroup -Name "WebServers"

# Export/Import groups
Export-SfosIPHostGroups -FilePath "c:\backups\ip_host_groups.csv"
Import-SfosIPHostGroups -FilePath "c:\backups\ip_host_groups.csv"
```

### FQDN Host Management

```powershell
# Get all FQDN hosts
Get-SfosFQDNHost

# Create FQDN host
New-SfosFQDNHost -Name "MailServer" -FQDN "mail.company.com" -Description "Corporate Mail"

# Update FQDN host
Set-SfosFQDNHost -Name "MailServer" -FQDN "mail.company.com" -Description "Updated mail server"

# Delete FQDN host
Remove-SfosFQDNHost -Name "MailServer"

# Delete multiple FQDN hosts in bulk
Remove-SfosFQDNHostMass -Names "OldHost1", "OldHost2", "OldHost3"

# Export/Import FQDN hosts
Export-SfosFQDNHosts -FilePath "c:\backups\fqdn_hosts.csv"
Import-SfosFQDNHosts -FilePath "c:\backups\fqdn_hosts.csv"
```

### FQDN Host Group Management

```powershell
# Get all FQDN host groups
Get-SfosFQDNHostGroup

# Create FQDN host group
New-SfosFQDNHostGroup -Name "MailServers" -Description "Mail infrastructure"

# Add member to group
Add-SfosFQDNHostGroupMember -Name "MailServers" -members "MailServer"

# Update group
Set-SfosFQDNHostGroup -Name "MailServers" -Description "Updated: Corporate mail systems"

# Remove member from group
Remove-SfosFQDNHostGroupMember -Name "MailServers" -members "OldMailServer"

# Delete group
Remove-SfosFQDNHostGroup -Name "MailServers"

# Export/Import FQDN groups
Export-SfosFQDNHostGroups -FilePath "c:\backups\fqdn_host_groups.csv"
Import-SfosFQDNHostGroups -FilePath "c:\backups\fqdn_host_groups.csv"
```

### MAC Host Management

```powershell
# Get all MAC hosts
Get-SfosMACHost

# Create MAC host
New-SfosMACHost -Name "PrinterDevice" -MacAddress "00:1A:2B:3C:4D:5E" -Description "Network Printer"

# Update MAC host
Set-SfosMACHost -Name "PrinterDevice" -MACAddress "00:1A:2B:3C:4D:5E" -Description "Updated: Main floor printer"

# Delete MAC host
Remove-SfosMACHost -Name "PrinterDevice"

# Export/Import MAC hosts
Export-SfosMACHosts -FilePath "c:\backups\mac_hosts.csv"
Import-SfosMACHosts -FilePath "c:\backups\mac_hosts.csv"
```

### Country Group Management

```powershell
# Get all Country Groups
Get-SfosCountryGroup

# Create country group for geo-blocking.
# Countries are the full names the firewall itself returns, not ISO alpha-2 codes -
# "CN" is rejected with code 501, "China" is accepted. Use Get-SfosCountryGroup on an
# existing group to see the exact spelling the firewall expects.
New-SfosCountryGroup -Name "HighRiskCountries" -Countries "China", "North Korea" -Description "Restricted countries"

# Update country group
Set-SfosCountryGroup -Name "HighRiskCountries" -countries "China", "North Korea" -Description "Updated: Countries for blocking"

# Delete country group
Remove-SfosCountryGroup -Name "HighRiskCountries"
```

### Service Management

```powershell
# Get all services
Get-SfosService

# Create TCP service
New-SfosService -Name "HTTPS" -Protocol TCP -DstPort "443" -SrcPort "1:65535" -Description "HTTPS traffic"

# Create service with port range
New-SfosService -Name "AppServer-Ports" -Protocol TCP -DstPort "8000:9000" -SrcPort "1:65535" -Description "Custom app ports"

# Create UDP service
New-SfosService -Name "DNS" -Protocol UDP -DstPort "53" -SrcPort "1:65535" -Description "DNS service"

# Update service
Set-SfosService -Name "HTTPS" -Description "Updated: HTTPS service definition"

# Delete service
Remove-SfosService -Name "OldService"

# Export/Import services
Export-SfosServices -FilePath "c:\backups\services.csv"
Import-SfosServices -FilePath "c:\backups\services.csv"
```

### Service Group Management

```powershell
# Get all service groups
Get-SfosServiceGroup

# Create service group
New-SfosServiceGroup -Name "WebServices" -members "HTTPS" -Description "HTTP/HTTPS services"

# Add service to group
Add-SfosServiceGroupMember -Name "WebServices" -members "HTTPS", "HTTP"

# Update group
Set-SfosServiceGroup -Name "WebServices" -members "HTTPS", "HTTP" -Description "Updated: All web-related services"

# Remove service from group
Remove-SfosServiceGroupMember -Name "WebServices" -members "OldService"

# Delete group
Remove-SfosServiceGroup -Name "WebServices"

# Export/Import service groups
Export-SfosServiceGroups -FilePath "c:\backups\service_groups.csv"
Import-SfosServiceGroups -FilePath "c:\backups\service_groups.csv"
```

## Available Cmdlets (53 total)

### IP Host Management (6 functions)
- `Get-SfosIPHost` - Retrieve all IP hosts
- `New-SfosIPHost` - Create new IP host with IP address/network
- `Set-SfosIPHost` - Update existing IP host properties
- `Remove-SfosIPHost` - Delete IP host from firewall
- `Export-SfosIPHosts` - Export IP hosts to file
- `Import-SfosIPHosts` - Import IP hosts from file

### IP Host Group Management (8 functions)
- `Get-SfosIPHostGroup` - Retrieve all IP host groups and members
- `New-SfosIPHostGroup` - Create new IP host group
- `Set-SfosIPHostGroup` - Update existing IP host group properties
- `Remove-SfosIPHostGroup` - Delete IP host group from firewall
- `Add-SfosIPHostGroupMember` - Add host to IP host group
- `Remove-SfosIPHostGroupMember` - Remove host from IP host group
- `Export-SfosIPHostGroups` - Export IP host groups to file
- `Import-SfosIPHostGroups` - Import IP host groups from file

### FQDN Host Management (7 functions)
- `Get-SfosFQDNHost` - Retrieve all FQDN hosts
- `New-SfosFQDNHost` - Create new FQDN host with hostname
- `Set-SfosFQDNHost` - Update existing FQDN host properties
- `Remove-SfosFQDNHost` - Delete FQDN host from firewall
- `Remove-SfosFQDNHostMass` - Delete multiple FQDN hosts in bulk
- `Export-SfosFQDNHosts` - Export FQDN hosts to file
- `Import-SfosFQDNHosts` - Import FQDN hosts from file

### FQDN Host Group Management (8 functions)
- `Get-SfosFQDNHostGroup` - Retrieve all FQDN host groups and members
- `New-SfosFQDNHostGroup` - Create new FQDN host group
- `Set-SfosFQDNHostGroup` - Update existing FQDN host group properties
- `Remove-SfosFQDNHostGroup` - Delete FQDN host group from firewall
- `Add-SfosFQDNHostGroupMember` - Add host to FQDN host group
- `Remove-SfosFQDNHostGroupMember` - Remove host from FQDN host group
- `Export-SfosFQDNHostGroups` - Export FQDN host groups to file
- `Import-SfosFQDNHostGroups` - Import FQDN host groups from file

### MAC Host Management (6 functions)
- `Get-SfosMACHost` - Retrieve all MAC-based hosts
- `New-SfosMACHost` - Create new MAC host with MAC address
- `Set-SfosMACHost` - Update existing MAC host properties
- `Remove-SfosMACHost` - Delete MAC host from firewall
- `Export-SfosMACHosts` - Export MAC hosts to file
- `Import-SfosMACHosts` - Import MAC hosts from file

### Country Group Management (4 functions)
- `Get-SfosCountryGroup` - Retrieve all Country Groups
- `New-SfosCountryGroup` - Create new Country Group with countries
- `Set-SfosCountryGroup` - Update existing Country Group properties
- `Remove-SfosCountryGroup` - Delete Country Group from firewall

### Service Management (6 functions)
- `Get-SfosService` - Retrieve all service definitions
- `New-SfosService` - Create new service (TCP/UDP with port or port range)
- `Set-SfosService` - Update existing service properties
- `Remove-SfosService` - Delete service from firewall
- `Export-SfosServices` - Export services to file
- `Import-SfosServices` - Import services from file

### Service Group Management (8 functions)
- `Get-SfosServiceGroup` - Retrieve all service groups and members
- `New-SfosServiceGroup` - Create new service group
- `Set-SfosServiceGroup` - Update existing service group properties
- `Remove-SfosServiceGroup` - Delete service group from firewall
- `Add-SfosServiceGroupMember` - Add service to service group
- `Remove-SfosServiceGroupMember` - Remove service from service group
- `Export-SfosServiceGroups` - Export service groups to file
- `Import-SfosServiceGroups` - Import service groups from file


## Error Handling

```powershell
try {
    # Connect with proper error handling
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential (Get-Credential) -SkipCertificateCheck
    
    # Retrieve specific IP host with error handling
    $host = Get-SfosIPHost -NameLike "CORP-WEB-01" -ErrorAction Stop
    Write-Output "Found host: $($host.Name) - IP: $($host.IpAddress)"
} catch {
    Write-Error "Failed to retrieve IP host: $_"
    $_.Exception
} finally {
    Disconnect-SfosFirewall
}
```

## Troubleshooting

- **Connection Issues**: Ensure firewall IP, port (4444 default), and credentials are correct
- **Object Not Found**: Use `Get-SfosIPHost | Select-Object Name` to list all available objects
- **Permission Denied**: Verify API user has proper role assignments on the firewall
- **Invalid Parameters**: Check exact parameter names - functions are type-specific (IPHost, FQDNHost, MACHost)

## See Also

- [SophosFirewall.Core](../SophosFirewall.Core/README.md) - Core connectivity functions (Connect-SfosFirewall, Disconnect-SfosFirewall, Invoke-SfosApi)
- [Sophos API Documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/) - Official Sophos firewall REST API reference
- [PowerShell Gallery](https://www.powershellgallery.com/packages/SophosFirewall.HostsAndServices) - Download module from PSGallery

## Author

Jan Weis - www.it-explorations.de

## License

