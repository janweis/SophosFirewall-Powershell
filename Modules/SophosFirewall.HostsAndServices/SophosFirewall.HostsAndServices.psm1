#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }
<#
        .SYNOPSIS
        Manages IP hosts, FQDN hosts, MAC hosts, host groups, services, and service groups on Sophos Firewall.

        .DESCRIPTION
        PowerShell module for comprehensive management of Sophos XGS / SFOS 21.5+ firewall 
        hosts and services via XML REST API.
    
        This module provides functions to create, read, update, and delete:
        - IP Hosts (single IPs, networks, ranges, lists)
        - IP Host Groups (with member management)
        - FQDN Hosts and FQDN Host Groups (with member management)
        - MAC Hosts
        - Country Groups
        - Services (TCP/UDP, IP protocols, ICMP/ICMPv6)
        - Service Groups (with member management)
    
        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect to firewall and retrieve all IP hosts
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosIPHost

        .EXAMPLE
        # Create a new IP host and add it to a host group
        New-SfosIPHost -Name "WebServer01" -IPAddress "10.0.1.100" -HostType IP -Description "Production Web Server"
        Add-SfosIPHostGroupMember -Name "WebServers" -Members "WebServer01"

        .EXAMPLE
        # Find all hosts matching a pattern. All -*Like filters are substring
        # matches, following the SFOS meaning of 'like' - not wildcard patterns.
        Get-SfosIPHost -NameLike "Web" -IPAddressLike "10.0."
        Get-SfosFQDNHost -FqdnLike ".example.com"

        .EXAMPLE
        # Create a TCP service and add to service group
        New-SfosService -Name "CustomHTTPS" -Protocol TCP -DstPort 8443 -SrcPort "1:65535" -Description "Custom HTTPS Port"
        Add-SfosServiceGroupMember -Name "WebServices" -Members "CustomHTTPS"

        .EXAMPLE
        # Create IP network and range hosts
        New-SfosIPHost -Name "Office-Network" -HostType Network -IPAddress "192.168.10.0" -Subnet "255.255.255.0"
        New-SfosIPHost -Name "DHCP-Range" -HostType IPRange -StartIPAddress "192.168.10.100" -EndIPAddress "192.168.10.200"

        .EXAMPLE
        # Pipeline operations for bulk removal (with WhatIf safety)
        Get-SfosIPHost -NameLike "OldServer" | Remove-SfosIPHost -WhatIf
        Get-SfosService -NameLike "Deprecated" | Remove-SfosService -WhatIf

        .EXAMPLE
        # Work with service groups
        $webServices = Get-SfosServiceGroup -NameLike "Web"
        $webServices | ForEach-Object { $_.ServiceList }

        .NOTES
        Module Name: SophosFirewall.HostsAndServices
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+
    
        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)
    
        API Compatibility:
        - Sophos SFOS 21.5+
        - Sophos XGS Firewall Series
    
        Total Functions: 53
        - 6 IP Host functions (Get, New, Set, Remove, Export, Import)
        - 8 IP Host Group functions (including Add/Remove members)
        - 7 FQDN Host functions (including mass removal)
        - 8 FQDN Host Group functions (including Add/Remove members)
        - 6 MAC Host functions
        - 4 Country Group functions
        - 6 Service functions (supports TCP/UDP, IP protocols, ICMP/ICMPv6)
        - 8 Service Group functions (including Add/Remove members)
    
        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
    
        .LINK
        Connect-SfosFirewall
    
        .LINK
        Get-SfosIPHost
    
        .LINK
        Get-SfosService
#>

# Helper functions are provided by SophosFirewall.Core module
# Module dependency is handled via RequiredModules in .psd1

#region IPHost

<#
        .SYNOPSIS
        Retrieves IPHost objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for IPHost objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER IPAddressLike
        Optional IP address filter, matched as a substring anywhere in the value. Sent to the firewall as the server-side filter only when -NameLike is not specified (SFOS evaluates only one filter key per request); always re-applied client-side as well.

        .PARAMETER HostTypeLike
        Optional host type filter. Unlike the other '*Like' parameters, this is an exact match against one of the ValidateSet values, not a substring match. Applied client-side only.

        .PARAMETER SubnetLike
        Optional subnet filter, matched as a substring anywhere in the value. Applied client-side only.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosIPHost

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosIPHost -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosIPHost -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosIPHost {
    [CmdletBinding()]
    param(
        # Functional parameters
        [ValidateLength(1, 60)]
        [string]$NameLike,

        [ValidateLength(1, 255)]
        [string]$DescriptionLike,
        
        [ValidateLength(1, 15)]
        [string]$IPAddressLike,

        [ValidateSet('IP', 'Network', 'IPRange', 'IPList', 'System Host')]
        [string]$HostTypeLike,
        
        [ValidateLength(1, 15)]
        [string]$SubnetLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter. SFOS evaluates only the first <key> of the first <Filter>
    # and silently ignores keys it does not support - <key name="Description"> for
    # instance returns every object instead of none. So exactly one supported key goes
    # to the firewall; every requested filter is applied again client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<key name="Name" criteria="like">{0}</key>' -f $nameLikeEsc)
    }
    elseif ($IPAddressLike) {
        $ipLikeEsc = ConvertTo-SfosXmlEscaped -Text $IPAddressLike
        $filterXml = ('<key name="IPAddress" criteria="like">{0}</key>' -f $ipLikeEsc)
    }

    $xmlFilterAdvanced = ''
    if ($filterXml) {
        $xmlFilterAdvanced = @"
<Filter>
    $filterXml
</Filter>
"@
    }

    # Build XML body for the API call
    $inner = @"
<Get>
  <IPHost>
    $xmlFilterAdvanced
  </IPHost>
</Get>
"@
    # Execute API call
    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve IPHost objects: $($_.Exception.Message)"
    }
    $XmlResponse = [xml]($response.Content)

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'get'

    # Extract IPHost nodes
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPHost[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. 'Like' keeps the SFOS meaning of the
    # word: a substring match, not a wildcard pattern.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }
    if ($IPAddressLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.IPAddress -like "*$IPAddressLike*" })
    }
    if ($SubnetLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Subnet -like "*$SubnetLike*" })
    }
    if ($HostTypeLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.HostType -eq $HostTypeLike })
    }

    # Return raw nodes when -AsXml is used
    if ($AsXml) {
        return @($nodes)
    }

    # Build PSObjects
    $ipHostObjects = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $ipHostObjects += [PSCustomObject]@{
            Name           = $node.Name
            IPFamily       = $node.IPFamily
            HostType       = $node.HostType
            IPAddress      = $node.IPAddress
            Subnet         = $node.Subnet
            Description    = $node.Description
            StartIPAddress = $node.StartIPAddress
            EndIPAddress   = $node.EndIPAddress
            ListOfIPAddresses = $node.ListOfIPAddresses
            HostGroupList  = if ($node.HostGroupList -and $node.HostGroupList.HostGroup) {
                @($node.HostGroupList.HostGroup)
            }
            else {
                @()
            }
        }
    }

    return $ipHostObjects
}

<#
        .SYNOPSIS
        Creates a new IP host object on the Sophos Firewall.

        .DESCRIPTION
        Creates an IP host object using the Sophos Firewall XML API. Supports four host types:
        - IP: Single IP address
        - Network: Network address with subnet mask
        - IPRange: IP address range (start to end)
        - IPList: Comma-separated list of IP addresses
        
        The cmdlet validates input and escapes XML special characters automatically.

        .PARAMETER Name
        Name of the IP host object (1-50 characters, no commas).

        .PARAMETER HostType
        Type of IP host: 'IP', 'Network', 'IPRange', or 'IPList'.

        .PARAMETER IPAddress
        IP address (required for HostType 'IP' and 'Network').

        .PARAMETER Subnet
        Subnet mask (required for HostType 'Network'). Example: 255.255.255.0

        .PARAMETER StartIPAddress
        Starting IP address (required for HostType 'IPRange').

        .PARAMETER EndIPAddress
        Ending IP address (required for HostType 'IPRange').

        .PARAMETER ListOfIPAddresses
        Array of IP addresses (required for HostType 'IPList').

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. Default: 'IPv4'.

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER HostGroupList
        Optional array of host group names to add this host to.

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a single IP host
        New-SfosIPHost -Name "WebServer01" -HostType IP -IPAddress "10.0.1.100" -Description "Production Web Server"

        .EXAMPLE
        # Create a network host
        New-SfosIPHost -Name "Office-LAN" -HostType Network -IPAddress "192.168.10.0" -Subnet "255.255.255.0"

        .EXAMPLE
        # Create an IP range for DHCP pool
        New-SfosIPHost -Name "DHCP-Pool" -HostType IPRange -StartIPAddress "192.168.10.100" -EndIPAddress "192.168.10.200"

        .EXAMPLE
        # Create an IP list with multiple addresses
        New-SfosIPHost -Name "DMZ-Servers" -HostType IPList -ListOfIPAddresses @("10.1.1.10", "10.1.1.20", "10.1.1.30")

        .EXAMPLE
        # Create host and add to group
        New-SfosIPHost -Name "DB-Server" -HostType IP -IPAddress "10.0.2.50" -HostGroupList @("DatabaseServers", "Production")

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function uses parameter sets to enforce correct parameter combinations.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosIPHost
        
        .LINK
        Set-SfosIPHost
        
        .LINK
        Remove-SfosIPHost
#>
function New-SfosIPHost {
    [CmdletBinding(DefaultParameterSetName = 'IP', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',
        
        [ValidateLength(0, 255)]
        [string]$Description,
        
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [Parameter(Mandatory, ParameterSetName = 'IPList')]
        [Parameter(Mandatory)]
        [ValidateSet('IP', 'Network', 'IPRange', 'IPList')]
        [string]$HostType,

        # --- IP ---
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [IPAddress]$IPAddress,
        
        # --- NETWORK ---
        [Parameter(Mandatory, ParameterSetName = 'Network')]
        [string]$Subnet,

        # --- IPRange ---
        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [IPAddress]$StartIPAddress,

        [Parameter(Mandatory, ParameterSetName = 'IPRange')]
        [IPAddress]$EndIPAddress,

        # --- IPList ---
        [Parameter(Mandatory, ParameterSetName = 'IPList')]
        [IPAddress[]]$ListOfIPAddresses,
        
        [string[]]$HostGroupList,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Preparations
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }
    
    # Setup HostGroup XML
    $xmlHostGroupList = ''
    if ($HostGroupList) {
        $hostGroupXml = ''
        foreach ($hostGroupItem in $HostGroupList) {
            if (-not $hostGroupItem) {
                continue
            }
            if ($hostGroupItem.Length -gt 50) {
                throw "HostGroup entry '$hostGroupItem' must be at most 50 characters."
            }
            if ($hostGroupItem -match '^[#,]') {
                throw "HostGroup entry '$hostGroupItem' must not start with '#' or ','."
            }
            if ($hostGroupItem -match ',') {
                throw "HostGroup entry '$hostGroupItem' must not contain a comma."
            }
            $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
            $hostGroupXml += "<HostGroup>$hgEsc</HostGroup>"
        }
        
        $xmlHostGroupList = @"
<HostGroupList>
    $hostGroupXml
</HostGroupList>
"@
    }


    # PowerShell resolves the parameter set from the supplied fields, and -HostType is a
    # separate parameter - so -HostType Network without -Subnet lands in the IP set and
    # would send <HostType>Network</HostType> with no subnet. Catch the contradiction here
    # instead of letting the firewall answer with an opaque 501.
    if ($HostType -ne $PSCmdlet.ParameterSetName) {
        throw ("HostType '{0}' does not match the supplied parameters, which describe a '{1}' host. " -f $HostType, $PSCmdlet.ParameterSetName +
            "Supply the fields that belong to '{0}': Network needs -IPAddress and -Subnet, IPRange needs -StartIPAddress and -EndIPAddress, IPList needs -ListOfIPAddresses." -f $HostType)
    }

    # Build Data IP/Network/IPRange/IPList Data XML
    $xmlIPHost = @()
    switch ($PSCmdlet.ParameterSetName) {
        'IP' {
            $xmlIPHost += "<IPAddress>$($IPAddress.IPAddressToString)</IPAddress>"
        }
        'Network' {
            $xmlIPHost += "<IPAddress>$($IPAddress.IPAddressToString)</IPAddress>"
            $xmlIPHost += "<Subnet>$(ConvertTo-SfosXmlEscaped -Text $Subnet)</Subnet>"
        }
        'IPRange' {
            $xmlIPHost += "<StartIPAddress>$($StartIPAddress.IPAddressToString)</StartIPAddress>"
            $xmlIPHost += "<EndIPAddress>$($EndIPAddress.IPAddressToString)</EndIPAddress>"
        }
        'IPList' {
            $joinedIPs = ($ListOfIPAddresses | ForEach-Object -Process {
                    $_.IPAddressToString
                }) -join ','
            $xmlIPHost = "<ListOfIPAddresses>$joinedIPs</ListOfIPAddresses>"
        }
    }

    # Build final XML
    $inner = @"
<Set operation="add">
    <IPHost>
        <Name>$nameEsc</Name>
        <IPFamily>$IPFamily</IPFamily>
        $xmlDescription
        <HostType>$HostType</HostType>
        $xmlIPHost
        $xmlHostGroupList
    </IPHost>
</Set>
"@

    # Send API command
    if (-not $PSCmdlet.ShouldProcess("IPHost '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create IPHost object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Validate responses
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing IPHost object on the Sophos Firewall.

        .DESCRIPTION
        Updates a IPHost object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current host first and keeps whatever
        the caller does not explicitly pass (Description, IPFamily, HostGroupList). To clear
        a field, pass it explicitly with an empty value.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. If omitted, the existing value on the firewall is kept.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER HostType
        Type of the IP host: 'IP', 'Network', 'IPRange', or 'IPList'. Determines which of the
        address parameters below is required.

        .PARAMETER IPAddress
        IP address (required for HostType 'IP' and 'Network').

        .PARAMETER Subnet
        Subnet mask (required for HostType 'Network'). Example: 255.255.255.0

        .PARAMETER StartIPAddress
        Starting IP address (required for HostType 'IPRange').

        .PARAMETER EndIPAddress
        Ending IP address (required for HostType 'IPRange').

        .PARAMETER ListOfIPAddresses
        Array of IP addresses (required for HostType 'IPList').

        .PARAMETER HostGroupList
        Optional array of host group names. If omitted, the existing group membership is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name (HostType and the matching address parameter are mandatory)
        Set-SfosIPHost -Name "Example" -HostType IP -IPAddress "10.0.1.100" -Description "Updated web server"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosIPHost -NameLike "Example" | Set-SfosIPHost -HostType IP -IPAddress "10.0.1.101"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosIPHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,
        
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('IP', 'Network', 'IPRange', 'IPList')]
        [string]$HostType,

        # --- IP ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [IPAddress]$IPAddress,
        
        # --- NETWORK ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Subnet,

        # --- IPRange ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [IPAddress]$StartIPAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [IPAddress]$EndIPAddress,

        # --- IPList ---
        # [string[]], not [IPAddress[]]: Get-SfosIPHost returns the addresses the way the
        # firewall does, as one comma-separated string. An [IPAddress[]] parameter cannot
        # convert that, so Get-SfosIPHost | Set-SfosIPHost failed for IPList hosts. The
        # values are split and validated in the body instead.
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$ListOfIPAddresses,
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$HostGroupList,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared. Read the
        # current host and keep whatever the caller did not pass. Without this, a Set that
        # only changes the address wiped the description, dropped the host out of every
        # group, and reset an IPv6 host to IPv4 through the parameter default.
        $existing = @(Get-SfosIPHost -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPHost object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetHostGroupList = if ($PSBoundParameters.ContainsKey('HostGroupList')) {
            @($HostGroupList)
        }
        else {
            @($existing[0].HostGroupList)
        }

        $targetIPFamily = if ($PSBoundParameters.ContainsKey('IPFamily')) {
            $IPFamily
        }
        elseif ($existing[0].IPFamily) {
            [string]$existing[0].IPFamily
        }
        else {
            $IPFamily
        }

        # Setup Description XML
        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup HostGroup XML
        $xmlHostGroupList = ''
        if ($targetHostGroupList.Count) {
            $hostGroupXml = ''
            foreach ($hostGroupItem in $targetHostGroupList) {
                if (-not $hostGroupItem) {
                    continue
                }
                if ($hostGroupItem.Length -gt 50) {
                    throw "HostGroup entry '$hostGroupItem' must be at most 50 characters."
                }
                if ($hostGroupItem -match '^[#,]') {
                    throw "HostGroup entry '$hostGroupItem' must not start with '#' or ','."
                }
                if ($hostGroupItem -match ',') {
                    throw "HostGroup entry '$hostGroupItem' must not contain a comma."
                }
                $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
                $hostGroupXml += "<HostGroup>$hgEsc</HostGroup>"
            }
        
            $xmlHostGroupList = @"
<HostGroupList>
    $hostGroupXml
</HostGroupList>
"@
        }


        # Build Data IP/Network/IPRange/IPList Data XML
        $xmlIPHost = ''
        # Parameter sets cannot carry this: with pipeline input PowerShell fixes the set before
        # it binds properties, so a set-specific parameter such as -Subnet never binds and
        # Get-SfosIPHost | Set-SfosIPHost silently sent <HostType>Network</HostType> without a
        # subnet, which the firewall rejects with 501. The type is validated here instead.
        switch ($HostType) {
            'IP' {
                $addr = if ($PSBoundParameters.ContainsKey('IPAddress')) { [string]$IPAddress } else { [string]$existing[0].IPAddress }
                if (-not $addr) { throw "HostType 'IP' needs -IPAddress for IPHost '$Name'." }
                $xmlIPHost = "<IPAddress>$(ConvertTo-SfosXmlEscaped -Text $addr)</IPAddress>"
            }
            'Network' {
                $addr = if ($PSBoundParameters.ContainsKey('IPAddress')) { [string]$IPAddress } else { [string]$existing[0].IPAddress }
                $mask = if ($PSBoundParameters.ContainsKey('Subnet')) { [string]$Subnet } else { [string]$existing[0].Subnet }
                if (-not $addr -or -not $mask) { throw "HostType 'Network' needs -IPAddress and -Subnet for IPHost '$Name'." }
                $xmlIPHost = "<IPAddress>$(ConvertTo-SfosXmlEscaped -Text $addr)</IPAddress>"
                $xmlIPHost += "<Subnet>$(ConvertTo-SfosXmlEscaped -Text $mask)</Subnet>"
            }
            'IPRange' {
                $from = if ($PSBoundParameters.ContainsKey('StartIPAddress')) { [string]$StartIPAddress } else { [string]$existing[0].StartIPAddress }
                $to = if ($PSBoundParameters.ContainsKey('EndIPAddress')) { [string]$EndIPAddress } else { [string]$existing[0].EndIPAddress }
                if (-not $from -or -not $to) { throw "HostType 'IPRange' needs -StartIPAddress and -EndIPAddress for IPHost '$Name'." }
                $xmlIPHost = "<StartIPAddress>$(ConvertTo-SfosXmlEscaped -Text $from)</StartIPAddress>"
                $xmlIPHost += "<EndIPAddress>$(ConvertTo-SfosXmlEscaped -Text $to)</EndIPAddress>"
            }
            'IPList' {
                # Accept both shapes: an array of addresses from a caller, and the single
                # comma-separated string Get-SfosIPHost hands over through the pipeline.
                $list = if ($PSBoundParameters.ContainsKey('ListOfIPAddresses')) {
                    (@($ListOfIPAddresses) -split ',' | Where-Object -FilterScript { $_ }) -join ','
                }
                else {
                    [string]$existing[0].ListOfIPAddresses
                }
                if (-not $list) { throw "HostType 'IPList' needs -ListOfIPAddresses for IPHost '$Name'." }

                foreach ($oneAddress in ($list -split ',')) {
                    $parsedAddress = $null
                    if (-not [IPAddress]::TryParse($oneAddress.Trim(), [ref]$parsedAddress)) {
                        throw "'$oneAddress' is not a valid IP address for IPHost '$Name'."
                    }
                }
                $xmlIPHost = "<ListOfIPAddresses>$(ConvertTo-SfosXmlEscaped -Text $list)</ListOfIPAddresses>"
            }
        }

        # Build final XML
        $inner = @"
<Set operation="update">
    <IPHost>
        <Name>$nameEsc</Name>
        <IPFamily>$targetIPFamily</IPFamily>
        $xmlDescription
        <HostType>$HostType</HostType>
        $xmlIPHost
        $xmlHostGroupList
    </IPHost>
</Set>
"@

        # Send API command
        if (-not $PSCmdlet.ShouldProcess("IPHost '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update IPHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Validate responses
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a IPHost object from the Sophos Firewall.

        .DESCRIPTION
        Removes a IPHost object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosIPHost -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosIPHost -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosIPHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("IPHost '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <IPHost>
    <Name>$nameEsc</Name>
  </IPHost>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing IPHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHost' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Exports all IPHost objects to a CSV file.

        .DESCRIPTION
        Retrieves all IPHost objects from the Sophos Firewall and exports them to a CSV file at the specified path. If the file already exists, an error is thrown unless the -Overwrite switch is used.

        .PARAMETER FilePath
        Full path to the output CSV file.

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'.

        .PARAMETER Overwrite
        Optional switch to overwrite the file if it already exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        None. The function writes the output to a CSV file.

        .EXAMPLE
        # Export IP hosts to a CSV file
        Export-SfosIPHosts -FilePath "C:\Exports\SophosIPHosts.csv"

        .EXAMPLE
        # Export and overwrite existing file
        Export-SfosIPHosts -FilePath "C:\Exports\SophosIPHosts.csv" -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosIPHost to retrieve the data.

        .LINK
        Get-SfosIPHost
#>
function Export-SfosIPHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Optional overwrite switch
        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "The file '$FilePath' already exists. Please specify a different file name."
        }
    }
    
    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve IP hosts
    $ipHosts = Get-SfosIPHost -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            # HostGroupList is an array; Export-Csv would otherwise stringify it as
            # "System.Object[]". Flatten it to a comma-separated string so Import-SfosIPHosts
            # can split it back into an array.
            $csvRows = foreach ($ipHostItem in $ipHosts) {
                $row = $ipHostItem | Select-Object *
                $row.HostGroupList = ($ipHostItem.HostGroupList -join ',')
                $row
            }
            $csvRows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $ipHosts | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Exported IP hosts to '$FilePath' successfully." -InformationAction Continue
    }
    catch {
        throw "Failed to export IP hosts to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports IPHost objects from a CSV file.

        .DESCRIPTION
        Reads IPHost objects from a specified CSV file and creates them on the Sophos Firewall using the New-SfosIPHost cmdlet. The CSV file must have the appropriate headers matching the IPHost properties.

        .PARAMETER FilePath
        Full path to the input CSV file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        None. The function creates IPHost objects on the Sophos Firewall.

        .EXAMPLE
        # Import IP hosts from a CSV file
        Import-SfosIPHosts -FilePath "C:\Imports\SophosIPHosts.csv"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosIPHost to create the objects.

        .LINK
        New-SfosIPHost
#>
function Import-SfosIPHosts {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    
    if (-not (Test-Path -Path $FilePath)) {
        throw "The file '$FilePath' was not found."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    
    try {
        $ipHosts = Import-Csv -Path $FilePath -Encoding UTF8
    }
    catch {
        throw "Failed to import IP hosts from '$FilePath': $($_.Exception.Message)"
    }

    foreach ($ipHost in $ipHosts) {

        if (-not $ipHost.Name) {
            Write-Information "Skipping entry without Name." -InformationAction Continue
            continue
        }

        if ($ipHost.Name.StartsWith('#')) {
            Write-Information "Skipping commented entry: $($ipHost.Name)" -InformationAction Continue
            continue
        }

        if ($ipHost.HostType -notin @('IP', 'Network', 'IPRange', 'IPList')) {
            Write-Information "Skipping entry with invalid HostType '$($ipHost.HostType)': $($ipHost.Name)" -InformationAction Continue
            continue
        }

        switch ($ipHost.HostType) {
            'IP' {
                if (-not $ipHost.IPAddress) {
                    Write-Information "Skipping IP host without IPAddress: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            'Network' {
                if (-not $ipHost.IPAddress -or -not $ipHost.Subnet) {
                    Write-Information "Skipping Network host without IPAddress or Subnet: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            'IPRange' {
                if (-not $ipHost.StartIPAddress -or -not $ipHost.EndIPAddress) {
                    Write-Information "Skipping IPRange host without StartIPAddress or EndIPAddress: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            'IPList' {
                if (-not $ipHost.ListOfIPAddresses) {
                    Write-Information "Skipping IPList host without ListOfIPAddresses: $($ipHost.Name)" -InformationAction Continue
                    continue
                }
            }
            default {
                Write-Information "Skipping entry with invalid HostType '$($ipHost.HostType)': $($ipHost.Name)" -InformationAction Continue
                continue
            }
        }

        try {

            # HostGroupList/ListOfIPAddresses come back from the CSV as a comma-separated
            # string (see Export-SfosIPHosts). Split them into arrays and drop empty
            # entries so an object without groups does not get assigned a bogus group.
            $hostGroupArr = @($ipHost.HostGroupList -split ',' | Where-Object -FilterScript { $_ })

            if ($ipHost.HostType -eq 'IP') {
                New-SfosIPHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -IPAddress $ipHost.IPAddress `
                    -HostGroupList $hostGroupArr -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            elseif ($ipHost.HostType -eq 'Network') {
                New-SfosIPHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -IPAddress $ipHost.IPAddress `
                    -Subnet $ipHost.Subnet -HostGroupList $hostGroupArr -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
                    -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            elseif ($ipHost.HostType -eq 'IPRange') {
                New-SfosIPHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -StartIPAddress $ipHost.StartIPAddress `
                    -EndIPAddress $ipHost.EndIPAddress -HostGroupList $hostGroupArr -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
                    -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            elseif ($ipHost.HostType -eq 'IPList') {
                $ipListArr = @($ipHost.ListOfIPAddresses -split ',' | Where-Object -FilterScript { $_ })
                New-SfosIPHost -Name $ipHost.Name -IPFamily $ipHost.IPFamily -Description $ipHost.Description -HostType $ipHost.HostType -ListOfIPAddresses $ipListArr `
                    -HostGroupList $hostGroupArr -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck
            }
            else {
                throw "Invalid HostType '$($ipHost.HostType)' for IP host: $($ipHost.Name)"
            }

            Write-Information "Imported: $($ipHost.Name)" -InformationAction Continue
        }
        catch {
            Write-Information "Failed to import '$($ipHost.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }
}


#endregion IPHost

#region IPHostGroup

<#
        .SYNOPSIS
        Retrieves IPHostGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for IPHostGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosIPHostGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosIPHostGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosIPHostGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosIPHostGroup {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <IPHostGroup>
    $filterXml
  </IPHostGroup>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving IPHostGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'get'

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPHostGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $ipHostGroupObjects = @()
    foreach ($node in $nodes) {
        $ipHostGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            IPFamily    = $node.IPFamily
            Description = $node.Description
            HostList    = [string[]]($node.HostList | Select-Object -ExpandProperty Host)
        }
    }

    return $ipHostGroupObjects
}

<#
        .SYNOPSIS
        Creates a new IP host group on the Sophos Firewall.

        .DESCRIPTION
        Creates an IP host group that can contain multiple IP host objects.
        Use this to logically group related hosts for easier firewall rule management.
        After creation, use Add-SfosIPHostGroupMember to add additional members.

        .PARAMETER Name
        Name of the IP host group (1-50 characters, no commas).

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. Default: 'IPv4'.

        .PARAMETER Members
        Array of IP host names to include in the group.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create an empty host group
        New-SfosIPHostGroup -Name "WebServers" -Description "Production web server farm"

        .EXAMPLE
        # Create group with initial members
        New-SfosIPHostGroup -Name "DatabaseServers" -Members @("DB-Primary", "DB-Secondary") -Description "Database cluster"

        .EXAMPLE
        # Create group and add members separately
        New-SfosIPHostGroup -Name "OfficeHosts" -Description "Office network devices"
        Add-SfosIPHostGroupMember -Name "OfficeHosts" -Members @("Printer01", "Scanner01")

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosIPHostGroup
        
        .LINK
        Add-SfosIPHostGroupMember
#>
function New-SfosIPHostGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [string[]]$members,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    }

    $xmlMember = ''
    foreach ($member in $members) {
        if (-not $member) {
            continue
        }
        if ($member.Length -gt 50) {
            throw "Member '$member' must be 50 characters or fewer."
        }
        if ($member -match ',') {
            throw "Member '$member' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<Host>$mEsc</Host>"
    }

    $inner = @"
<Set operation="add">
  <IPHostGroup>
    <Name>$nameEsc</Name>
    <IPFamily>$IPFamily</IPFamily>
    <Description>$descEsc</Description>
    <HostList>
        $xmlMember
    </HostList> 
  </IPHostGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("IPHostGroup '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error creating IPHostGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing IPHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a IPHostGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current group first and keeps whatever
        the caller does not explicitly pass (Description, IPFamily, Members). To clear a
        field, pass it explicitly with an empty value.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. If omitted, the existing value on the firewall is kept.

        .PARAMETER Members
        One or more member object names to include. If omitted, the existing members are kept.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosIPHostGroup -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosIPHostGroup -NameLike "Example" | Set-SfosIPHostGroup

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosIPHostGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,
        
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',
        
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('HostList')]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall. So read the current group first and override only what the caller
        # actually passed. Without this, changing just the description deleted every
        # member, and the IPFamily default silently downgraded an IPv6 group to IPv4.
        $existing = @(Get-SfosIPHostGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPHostGroup object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetMembers = if ($PSBoundParameters.ContainsKey('members')) {
            @($members)
        }
        else {
            @($existing[0].HostList)
        }

        $targetIPFamily = if ($PSBoundParameters.ContainsKey('IPFamily')) {
            $IPFamily
        }
        elseif ($existing[0].IPFamily) {
            [string]$existing[0].IPFamily
        }
        else {
            $IPFamily
        }

        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Host>$mEsc</Host>"
        }

        $inner = @"
<Set operation="update">
  <IPHostGroup>
    <Name>$nameEsc</Name>
    <IPFamily>$targetIPFamily</IPFamily>
    <Description>$descEsc</Description>
    <HostList>
        $xmlMember
    </HostList>
  </IPHostGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("IPHostGroup '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating IPHostGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a IPHostGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a IPHostGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosIPHostGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosIPHostGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosIPHostGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("IPHostGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <IPHostGroup>
    <Name>$nameEsc</Name>
  </IPHostGroup>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing IPHostGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds members to an existing IPHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Adds members to a IPHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Add members to an existing object
        Add-SfosIPHostGroupMember -Name "Example" -Members "Host1","Host2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Add-SfosIPHostGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        
        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $ipHostGroup = Get-SfosIPHostGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact group
        $ipHostGroup = @($ipHostGroup | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($ipHostGroup.Count -eq 0) {
            throw "The IPHostGroup object '$Name' was not found."
        }

        $ipHostGroup = $ipHostGroup[0]
        
        # Prefill existing members. SFOS applies the member list as a whole - a
        # <Set operation="update"> replaces it instead of appending - so the current
        # members must be written back together with the new ones.
        $ipHostGroupMembers = @()
        $ipHostGroupMembers += $ipHostGroup.HostList
        $ipHostGroupMembers += $members
        $ipHostGroupMembers = $ipHostGroupMembers | Where-Object -FilterScript { $_ } | Select-Object -Unique

        # Build XML member list
        $xmlMember = ''
        foreach ($member in $ipHostGroupMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Host>$memberEsc</Host>"
        }

        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        # IPFamily gehoert ebenfalls zum vollstaendigen Datensatz - fehlt sie im Update,
        # faellt eine IPv6-Gruppe auf den Firewall-Default zurueck.
        $ipFamilyXml = ''
        
if ($ipHostGroup.IPFamily) {
            $ipFamilyXml = "<IPFamily>$($ipHostGroup.IPFamily)</IPFamily>"
        }

        $descriptionXml = ''
        if ($ipHostGroup.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $ipHostGroup.Description)</Description>"
        }

        $inner = @"
<Set operation="update">
    <IPHostGroup>
        <Name>$nameEsc</Name>
        $descriptionXml
        $ipFamilyXml
        <HostList>
            $xmlMember
        </HostList> 
    </IPHostGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("IPHostGroup '$($Name)' on $($params.Firewall)", 'Add members')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error adding members to IPHostGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'add members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes members from an existing IPHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Removes members from a IPHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Remove members from an existing object
        Remove-SfosIPHostGroupMember -Name "Example" -Members "Host1","Host2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosIPHostGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }
    process {

        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $ipHostGroup = Get-SfosIPHostGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact group
        $ipHostGroup = @($ipHostGroup | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($ipHostGroup.Count -eq 0) {
            throw "The IPHostGroup object '$Name' was not found."
        }

        $ipHostGroup = $ipHostGroup[0]
        
        if (@($ipHostGroup.HostList).Count -eq 0) {
            # Nothing to remove
            return
        }


        # Prefill existing members
        $ipHostGroupMembers = [Collections.ArrayList]@()
        $ipHostGroupMembers.AddRange([string[]]@($ipHostGroup.HostList))
        
        foreach ($member in $members) {
            [int]$indexMember = $ipHostGroupMembers.IndexOf($member)
            
            if ($indexMember -ne -1) {
                $ipHostGroupMembers.RemoveAt($indexMember)
            }
        }

        $xmlMember = ''
        foreach ($member in $ipHostGroupMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Host>$memberEsc</Host>"
        }

        # 'update' with the complete remaining list, not 'remove': SFOS replaces the
        # member list with whatever is sent, so a <Set operation="remove"> carrying the
        # members to drop would keep exactly those and discard the rest.
        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        # IPFamily gehoert ebenfalls zum vollstaendigen Datensatz - fehlt sie im Update,
        # faellt eine IPv6-Gruppe auf den Firewall-Default zurueck.
        $ipFamilyXml = ''
        
if ($ipHostGroup.IPFamily) {
            $ipFamilyXml = "<IPFamily>$($ipHostGroup.IPFamily)</IPFamily>"
        }

        $descriptionXml = ''
        if ($ipHostGroup.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $ipHostGroup.Description)</Description>"
        }

        $inner = @"
<Set operation="update">
    <IPHostGroup>
        <Name>$nameEsc</Name>
        $descriptionXml
        $ipFamilyXml
        <HostList>
            $xmlMember
        </HostList>
    </IPHostGroup>
</Set>
"@
        # Send Request to the API
        if (-not $PSCmdlet.ShouldProcess("IPHostGroup '$($Name)' on $($params.Firewall)", 'Remove members')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing members from IPHostGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPHostGroup' -Action 'remove members' -Target $Name
    }   
}

<#
        .SYNOPSIS
        Exports IPHostGroup objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all IPHostGroup objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Group members are stored as JSON arrays within the file for proper handling of multiple members.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format stores member arrays as JSON strings. JSON format preserves nested structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'IPHostGroup'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported IPHostGroup names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all IP host groups to CSV
        Export-SfosIPHostGroups -FilePath "C:\Exports\IPHostGroups.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosIPHostGroups -FilePath "C:\Exports\IPHostGroups.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosIPHostGroup to retrieve the objects.
        Group members are stored as JSON arrays within CSV fields for proper serialization.

        .LINK
        Import-SfosIPHostGroups

        .LINK
        Get-SfosIPHostGroup
#>
function Export-SfosIPHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '$FilePath' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve IP host groups
    try {
        $ipHostGroups = Get-SfosIPHostGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving IP host groups: $($_.Exception.Message)"
    }

    # Flatten HostList (an array) to a comma-separated string for CSV export.
    try {
        $groupsToExport = @()
        foreach ($group in $ipHostGroups) {
            $groupObj = $group | Select-Object * -ExcludeProperty HostList
            $groupObj | Add-Member -NotePropertyName HostList -NotePropertyValue ($group.HostList -join ',')
            $groupsToExport += $groupObj
        }

        if ($Format -eq 'AsCSV') {
            $groupsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $ipHostGroups | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of IP host groups to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation    = 'Export'
            ObjectType   = 'IPHostGroup'
            Total        = $ipHostGroups.Count
            Success      = $ipHostGroups.Count
            Failed       = 0
            SuccessItems = @($ipHostGroups.Name)
            FailedItems  = @()
        }
    }
    catch {
        throw "Error exporting IP host groups to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports IPHostGroup objects from a CSV or JSON file.

        .DESCRIPTION
        Reads IPHostGroup objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosIPHostGroup cmdlet.
        The file must have the appropriate headers/structure. In CSV files, the HostList member list is a single comma-separated string.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'IPHostGroup'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported IPHostGroup names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import IP host groups from CSV
        Import-SfosIPHostGroups -FilePath "C:\Imports\IPHostGroups.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosIPHostGroups -FilePath "C:\Imports\IPHostGroups.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosIPHostGroup to create the objects.
        Members in CSV files are a single comma-separated string, e.g. "Host1,Host2"

        .LINK
        Export-SfosIPHostGroups

        .LINK
        New-SfosIPHostGroup
#>
function Import-SfosIPHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '$FilePath' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $ipHostGroups = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $ipHostGroups = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing IP host groups from '$FilePath': $($_.Exception.Message)"
    }

    # Ensure ipHostGroups is an array
    if ($ipHostGroups -isnot [array]) {
        $ipHostGroups = @($ipHostGroups)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create IP host groups on the Sophos Firewall
    foreach ($group in $ipHostGroups) {
        try {
            # HostList comes back as a comma-separated string (see Export-SfosIPHostGroups).
            # Split it into an array and drop empty entries.
            $members = @($group.HostList -split ',' | Where-Object -FilterScript { $_ })

            New-SfosIPHostGroup -Name $group.Name `
                -Description $group.Description `
                -Members $members `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $group.Name
            Write-Information "Imported: $($group.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $group.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($group.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation    = 'Import'
        ObjectType   = 'IPHostGroup'
        Total        = $ipHostGroups.Count
        Success      = $successItems.Count
        Failed       = $failedItems.Count
        SuccessItems = $successItems
        FailedItems  = $failedItems
    }
}

#endregion IPHostGroup

#region FQDNHost

<#
        .SYNOPSIS
        Retrieves FQDNHost objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for FQDNHost objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER FqdnLike
        Optional FQDN filter, matched as a substring anywhere in the value. The firewall does not support filtering on FQDN, so this filter is always applied client-side.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosFQDNHost

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosFQDNHost -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosFQDNHost -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosFQDNHost {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$FqdnLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter: SFOS evaluates only the first <key> of the first <Filter>,
    # so only the name is sent. Everything else is filtered client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <FQDNHost>
    $filterXml
  </FQDNHost>
</Get>
"@

    try {
        $response = Invoke-SfosApi `
            -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving FQDN host objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'get'
    # Important: Only return actual objects, not containers with status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FQDNHost[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($FqdnLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.FQDN -like "*$FqdnLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $fqdnHostObjects = @()
    foreach ($node in $nodes) {
        $fqdnHostObjects += [PSCustomObject]@{
            Name              = $node.Name
            Description       = $node.Description
            FQDN              = $node.FQDN
            FQDNHostGroupList = [string[]]@($node.FQDNHostGroupList | Select-Object -ExpandProperty FQDNHostGroup)
        }
    }

    return $fqdnHostObjects
}

<#
        .SYNOPSIS
        Creates a new FQDN (Fully Qualified Domain Name) host on the Sophos Firewall.

        .DESCRIPTION
        Creates an FQDN host object for DNS-based host definitions. Useful for cloud services,
        dynamic IPs, or SaaS applications where IP addresses change frequently.
        The firewall resolves the FQDN to current IP addresses automatically.

        .PARAMETER Name
        Name of the FQDN host object (1-50 characters, no commas).

        .PARAMETER FQDN
        Fully qualified domain name (max 255 characters).
        Examples: 'mail.example.com', '*.cloudapp.azure.com', 'api.service.com'

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER HostGroup
        Optional array of FQDN host group names to add this host to.

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create FQDN host for Office 365
        New-SfosFQDNHost -Name "Office365-Outlook" -FQDN "outlook.office365.com" -Description "Microsoft Office 365 Outlook"

        .EXAMPLE
        # Create FQDN host with wildcard for Azure services
        New-SfosFQDNHost -Name "Azure-WestEU" -FQDN "*.westeurope.cloudapp.azure.com"

        .EXAMPLE
        # Create FQDN and add to group
        New-SfosFQDNHost -Name "SalesforceAPI" -FQDN "api.salesforce.com" -HostGroup @("SaaSServices", "CriticalServices")

        .EXAMPLE
        # Create FQDN for internal service
        New-SfosFQDNHost -Name "InternalDB" -FQDN "db.internal.corp" -Description "Internal database cluster"

        .NOTES
        Minimum supported PowerShell version: 5.1
        FQDN resolution happens on the firewall, not at definition time.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosFQDNHost
        
        .LINK
        Set-SfosFQDNHost
        
        .LINK
        Remove-SfosFQDNHost
#>
function New-SfosFQDNHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateLength(1, 255)]
        [string]$FQDN,

        [ValidateLength(0, 255)]
        [string]$Description,

        [string[]]$HostGroup,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $fqdnEsc = ConvertTo-SfosXmlEscaped -Text $FQDN

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $xmlHostGroupList = ''
    if ($HostGroup) {
        $hostGroupXml = ''
        foreach ($hostGroupItem in $HostGroup) {
            if (-not $hostGroupItem) {
                continue
            }
            if ($hostGroupItem.Length -gt 50) {
                throw "HostGroup '$hostGroupItem' darf max. 50 Zeichen lang sein."
            }
            if ($hostGroupItem -match ',') {
                throw "HostGroup '$hostGroupItem' darf kein Komma enthalten."
            }
            $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
            $hostGroupXml += "<FQDNHostGroup>$hgEsc</FQDNHostGroup>"
        }
        
        $xmlHostGroupList = @"
<FQDNHostGroupList>
    $hostGroupXml
</FQDNHostGroupList>
"@    
    }

    $inner = @"
<Set operation="add">
  <FQDNHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    <FQDN>$fqdnEsc</FQDN>
    $xmlHostGroupList
  </FQDNHost>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("FQDNHost '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error creating FQDNHost object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing FQDNHost object on the Sophos Firewall.

        .DESCRIPTION
        Updates a FQDNHost object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER FQDN
        Parameter used by this cmdlet.

        .PARAMETER Description
        Optional description text.

        .PARAMETER HostGroup
        Parameter used by this cmdlet.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosFQDNHost -Name "Example" -FQDN "www.example.com"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosFQDNHost -NameLike "Example" | Set-SfosFQDNHost

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosFQDNHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$FQDN,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$HostGroup,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $fqdnEsc = ConvertTo-SfosXmlEscaped -Text $FQDN

        # Setup Description XML
        # SFOS replaces the whole entity on update, so a description that is not sent
        # gets cleared. Read the current object and keep it unless the caller passes one.
        $existing = @(Get-SfosFQDNHost -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        
if ($existing.Count -eq 0) {
            throw "The FQDNHost object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup HostGroup XML
        $xmlHostGroupList = ''
        # HostGroup ebenfalls per ContainsKey: sonst entfernt jedes Set ohne -HostGroup den
        # Host aus allen Gruppen, weil das Element im Request fehlt.
        $targetHostGroup = if ($PSBoundParameters.ContainsKey('HostGroup')) {
            @($HostGroup)
        }
        else {
            @($existing[0].FQDNHostGroupList)
        }

        if ($targetHostGroup.Count) {
            $hostGroupXml = ''
            foreach ($hostGroupItem in $targetHostGroup) {
                if (-not $hostGroupItem) {
                    continue
                }
                if ($hostGroupItem.Length -gt 50) {
                    throw "HostGroup '$hostGroupItem' darf max. 50 Zeichen lang sein."
                }
                if ($hostGroupItem -match ',') {
                    throw "HostGroup '$hostGroupItem' darf kein Komma enthalten."
                }
                $hgEsc = ConvertTo-SfosXmlEscaped -Text $hostGroupItem
                $hostGroupXml += "<FQDNHostGroup>$hgEsc</FQDNHostGroup>"
            }
            
            $xmlHostGroupList = @"
<FQDNHostGroupList>
    $hostGroupXml
</FQDNHostGroupList>
"@
        }

        # Build final XML
        $inner = @"
<Set operation="update">
  <FQDNHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    <FQDN>$fqdnEsc</FQDN>
    $xmlHostGroupList
  </FQDNHost>
</Set>
"@
        
        # Send API Request
        if (-not $PSCmdlet.ShouldProcess("FQDNHost '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating FQDNHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a FQDNHost object from the Sophos Firewall.

        .DESCRIPTION
        Removes a FQDNHost object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosFQDNHost -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosFQDNHost -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosFQDNHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("FQDNHost '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FQDNHost>
    <Name>$nameEsc</Name>
  </FQDNHost>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing FQDNHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes multiple FQDNHost objects from the Sophos Firewall in a single request.

        .DESCRIPTION
        Removes one or more FQDNHost objects using the Sophos Firewall XML API. All names are
        sent in a single <Remove> request instead of one request per object; because of that,
        the response can carry a status per removed object rather than a single overall status.
        This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Names
        One or more FQDNHost object names to remove.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the request fails.

        .EXAMPLE
        # Preview removal of several objects in one request
        Remove-SfosFQDNHostMass -Names "Host1", "Host2", "Host3" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        (Get-SfosFQDNHost -NameLike "Old").Name | Remove-SfosFQDNHostMass -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        -- BETA -- Works but needs further testing

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosFQDNHostMass {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$Names,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        # Respect -WhatIf / -Confirm
        if (-not $PSCmdlet.ShouldProcess(("FQDNHost(s) '{0}' auf {1}" -f ($Names -join ', '), $params.Firewall), 'Remove')) {
            return
        }

        # Build Name XML
        $xmlNames = foreach ($nameItem in $Names) {
            $nameEsc = ConvertTo-SfosXmlEscaped -Text $nameItem
            "<Name>$nameEsc</Name>"
        }

        # Build XML
        $inner = @"
<Remove>
  <FQDNHost>
    $xmlNames
  </FQDNHost>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing multiple FQDNHost objects: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHost' -Action 'remove' -Target ($Names -join ', ')
    }
    end {
    }
}

<#
        .SYNOPSIS
        Exports FQDNHost objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all FQDNHost objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format is human-readable and Excel-compatible. JSON format preserves data structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'FQDNHost'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported FQDNHost names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all FQDN hosts to CSV
        Export-SfosFQDNHosts -FilePath "C:\Exports\FQDNHosts.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosFQDNHosts -FilePath "C:\Exports\FQDNHosts.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosFQDNHost to retrieve the objects.

        .LINK
        Import-SfosFQDNHosts

        .LINK
        Get-SfosFQDNHost
#>
function Export-SfosFQDNHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '$FilePath' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve FQDN hosts
    try {
        $fqdnHosts = Get-SfosFQDNHost -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving FQDN hosts: $($_.Exception.Message)"
    }

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            # FQDNHostGroupList is an array; Export-Csv would otherwise stringify it as
            # "System.Object[]". Flatten it to a comma-separated string so Import-SfosFQDNHosts
            # can split it back into an array.
            $csvRows = foreach ($fqdnHostItem in $fqdnHosts) {
                $row = $fqdnHostItem | Select-Object *
                $row.FQDNHostGroupList = ($fqdnHostItem.FQDNHostGroupList -join ',')
                $row
            }
            $csvRows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $fqdnHosts | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of FQDN hosts to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation    = 'Export'
            ObjectType   = 'FQDNHost'
            Total        = $fqdnHosts.Count
            Success      = $fqdnHosts.Count
            Failed       = 0
            SuccessItems = @($fqdnHosts.Name)
            FailedItems  = @()
        }
    }
    catch {
        throw "Error exporting FQDN hosts to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports FQDNHost objects from a CSV or JSON file.

        .DESCRIPTION
        Reads FQDNHost objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosFQDNHost cmdlet.
        The file must have the appropriate headers/structure matching the FQDNHost properties (Name, FQDN, Description, FQDNHostGroupList).
        FQDNHostGroupList is a single comma-separated string, e.g. "Group1,Group2".

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'FQDNHost'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported FQDNHost names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import FQDN hosts from CSV
        Import-SfosFQDNHosts -FilePath "C:\Imports\FQDNHosts.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosFQDNHosts -FilePath "C:\Imports\FQDNHosts.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosFQDNHost to create the objects.

        .LINK
        Export-SfosFQDNHosts

        .LINK
        New-SfosFQDNHost
#>
function Import-SfosFQDNHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '$FilePath' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $fqdnHosts = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $fqdnHosts = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing FQDN hosts from '$FilePath': $($_.Exception.Message)"
    }

    # Ensure fqdnHosts is an array
    if ($fqdnHosts -isnot [array]) {
        $fqdnHosts = @($fqdnHosts)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create FQDN hosts on the Sophos Firewall
    foreach ($fqdnHost in $fqdnHosts) {
        try {
            # FQDNHostGroupList comes back as a comma-separated string (see
            # Export-SfosFQDNHosts). Split it into an array and drop empty entries.
            $hostGroupArr = @($fqdnHost.FQDNHostGroupList -split ',' | Where-Object -FilterScript { $_ })

            New-SfosFQDNHost -Name $fqdnHost.Name `
                -FQDN $fqdnHost.FQDN `
                -Description $fqdnHost.Description `
                -HostGroup $hostGroupArr `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $fqdnHost.Name
            Write-Information "Imported: $($fqdnHost.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $fqdnHost.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($fqdnHost.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation    = 'Import'
        ObjectType   = 'FQDNHost'
        Total        = $fqdnHosts.Count
        Success      = $successItems.Count
        Failed       = $failedItems.Count
        SuccessItems = $successItems
        FailedItems  = $failedItems
    }
}

#endregion FQDNHost

#region FQDNHostGroup

# --- FQDNHostGroup ---

<#
        .SYNOPSIS
        Retrieves FQDNHostGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for FQDNHostGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosFQDNHostGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosFQDNHostGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosFQDNHostGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosFQDNHostGroup {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <FQDNHostGroup>
    $filterXml
  </FQDNHostGroup>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving FQDNHostGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'get'

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FQDNHostGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $fqdnHostGroupObjects = @()
    foreach ($node in $nodes) {
        $fqdnHostGroupObjects += [PSCustomObject]@{
            Name         = $node.Name
            Description  = $node.Description
            FQDNHostList = [string[]]@($node.FQDNHostList | Select-Object -ExpandProperty FQDNHost)
        }
    }

    return $fqdnHostGroupObjects
}

<#
        .SYNOPSIS
        Creates a new FQDNHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Creates a FQDNHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Create a new object
        New-SfosFQDNHostGroup -Name "Example"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function New-SfosFQDNHostGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$members = @(),

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    }

    $xmlMember = ''
    foreach ($member in $members) {
        if (-not $member) {
            continue
        }
        if ($member.Length -gt 50) {
            throw "Member '$member' must be 50 characters or fewer."
        }
        if ($member -match ',') {
            throw "Member '$member' cannot contain a comma."
        }
        $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<FQDNHost>$memberEsc</FQDNHost>"
    }

    $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

    $inner = @"
<Set operation="add">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("FQDNHostGroup '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error creating FQDNHostGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing FQDNHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a FQDNHostGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosFQDNHostGroup -Name "Example"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosFQDNHostGroup -NameLike "Example" | Set-SfosFQDNHostGroup

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosFQDNHostGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FQDNHostList')]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared. Read the
        # current group and override only what the caller passed, otherwise changing just
        # the description would delete every member.
        $existing = @(Get-SfosFQDNHostGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The FQDNHostGroup object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetMembers = if ($PSBoundParameters.ContainsKey('members')) {
            @($members)
        }
        else {
            @($existing[0].FQDNHostList)
        }

        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<FQDNHost>$mEsc</FQDNHost>"
        }

        $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

        $inner = @"
<Set operation="update">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FQDNHostGroup '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating FQDNHostGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a FQDNHostGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a FQDNHostGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosFQDNHostGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosFQDNHostGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosFQDNHostGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("FQDNHostGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
  </FQDNHostGroup>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing FQDNHostGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds members to an existing FQDNHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Adds members to a FQDNHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Add members to an existing object
        Add-SfosFQDNHostGroupMember -Name "Example" -Members "Host1","Host2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Add-SfosFQDNHostGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS applies the member list as a whole - a <Set> replaces it instead of
        # appending - so the current members are read first and written back together
        # with the new ones. -NameLike is a substring match, hence the exact-name filter.
        $fqdnHostGroup = @(Get-SfosFQDNHostGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($fqdnHostGroup.Count -eq 0) {
            throw "The FQDNHostGroup object '$Name' was not found."
        }

        $targetMembers = @(@($fqdnHostGroup[0].FQDNHostList) + @($members) |
                Where-Object -FilterScript { $_ } |
                Select-Object -Unique)

        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<FQDNHost>$memberEsc</FQDNHost>"
        }

        $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        $descriptionXml = ''
        if ($fqdnHostGroup[0].Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $fqdnHostGroup[0].Description)</Description>"
        }

        $inner = @"
<Set operation="update">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    $descriptionXml
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FQDNHostGroup '$($Name)' on $($params.Firewall)", 'Add members')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error adding members to FQDNHostGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'add members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes members from an existing FQDNHostGroup object on the Sophos Firewall.

        .DESCRIPTION
        Removes members from a FQDNHostGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Remove members from an existing object
        Remove-SfosFQDNHostGroupMember -Name "Example" -Members "Host1","Host2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosFQDNHostGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the member list with whatever is sent, so removal means writing
        # back the remaining members - a <Set operation="remove"> carrying the members to
        # drop would keep exactly those and discard the rest.
        $fqdnHostGroup = @(Get-SfosFQDNHostGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($fqdnHostGroup.Count -eq 0) {
            throw "The FQDNHostGroup object '$Name' was not found."
        }

        $currentMembers = @($fqdnHostGroup[0].FQDNHostList)
        if ($currentMembers.Count -eq 0) {
            # Nothing to remove
            return
        }

        $targetMembers = @($currentMembers | Where-Object -FilterScript { $members -notcontains $_ })

        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<FQDNHost>$memberEsc</FQDNHost>"
        }

        $xmlMemberList = @"
<FQDNHostList>
    $xmlMember
</FQDNHostList>
"@

        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        $descriptionXml = ''
        if ($fqdnHostGroup[0].Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $fqdnHostGroup[0].Description)</Description>"
        }

        $inner = @"
<Set operation="update">
  <FQDNHostGroup>
    <Name>$nameEsc</Name>
    $descriptionXml
    $xmlMemberList
  </FQDNHostGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FQDNHostGroup '$($Name)' on $($params.Firewall)", 'Remove members')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing members from FQDNHostGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FQDNHostGroup' -Action 'remove members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Exports FQDNHostGroup objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all FQDNHostGroup objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Group members are stored as JSON arrays within the file for proper handling of multiple members.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format stores member arrays as JSON strings. JSON format preserves nested structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'FQDNHostGroup'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported FQDNHostGroup names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all FQDN host groups to CSV
        Export-SfosFQDNHostGroups -FilePath "C:\Exports\FQDNHostGroups.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosFQDNHostGroups -FilePath "C:\Exports\FQDNHostGroups.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosFQDNHostGroup to retrieve the objects.
        Group members are stored as JSON arrays within CSV fields for proper serialization.

        .LINK
        Import-SfosFQDNHostGroups

        .LINK
        Get-SfosFQDNHostGroup
#>
function Export-SfosFQDNHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '$FilePath' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve FQDN host groups
    try {
        $fqdnHostGroups = Get-SfosFQDNHostGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving FQDN host groups: $($_.Exception.Message)"
    }

    # Convert member arrays to JSON strings for proper serialization
    try {
        $groupsToExport = @()
        foreach ($group in $fqdnHostGroups) {
            $groupObj = $group | Select-Object * -ExcludeProperty FQDNHostList
            if ($group.FQDNHostList) {
                $groupObj | Add-Member -NotePropertyName FQDNHostList -NotePropertyValue ($group.FQDNHostList | ConvertTo-Json -Compress)
            }
            else {
                $groupObj | Add-Member -NotePropertyName FQDNHostList -NotePropertyValue ''
            }
            $groupsToExport += $groupObj
        }

        if ($Format -eq 'AsCSV') {
            $groupsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $fqdnHostGroups | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of FQDN host groups to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation    = 'Export'
            ObjectType   = 'FQDNHostGroup'
            Total        = $fqdnHostGroups.Count
            Success      = $fqdnHostGroups.Count
            Failed       = 0
            SuccessItems = @($fqdnHostGroups.Name)
            FailedItems  = @()
        }
    }
    catch {
        throw "Error exporting FQDN host groups to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports FQDNHostGroup objects from a CSV or JSON file.

        .DESCRIPTION
        Reads FQDNHostGroup objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosFQDNHostGroup cmdlet.
        The file must have the appropriate headers/structure. Members are expected as JSON arrays in CSV fields.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'FQDNHostGroup'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported FQDNHostGroup names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import FQDN host groups from CSV
        Import-SfosFQDNHostGroups -FilePath "C:\Imports\FQDNHostGroups.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosFQDNHostGroups -FilePath "C:\Imports\FQDNHostGroups.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosFQDNHostGroup to create the objects.
        Members in CSV files should be JSON arrays: ["Host1","Host2"]

        .LINK
        Export-SfosFQDNHostGroups

        .LINK
        New-SfosFQDNHostGroup
#>
function Import-SfosFQDNHostGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '$FilePath' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $fqdnHostGroups = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $fqdnHostGroups = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing FQDN host groups from '$FilePath': $($_.Exception.Message)"
    }

    # Ensure fqdnHostGroups is an array
    if ($fqdnHostGroups -isnot [array]) {
        $fqdnHostGroups = @($fqdnHostGroups)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create FQDN host groups on the Sophos Firewall
    foreach ($group in $fqdnHostGroups) {
        try {
            # Parse member list from JSON string if present
            $members = @()
            if ($group.FQDNHostList) {
                try {
                    $members = $group.FQDNHostList | ConvertFrom-Json
                }
                catch {
                    # If JSON parsing fails, treat as empty
                    $members = @()
                }
            }

            New-SfosFQDNHostGroup -Name $group.Name `
                -Description $group.Description `
                -Members $members `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $group.Name
            Write-Information "Imported: $($group.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $group.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($group.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation    = 'Import'
        ObjectType   = 'FQDNHostGroup'
        Total        = $fqdnHostGroups.Count
        Success      = $successItems.Count
        Failed       = $failedItems.Count
        SuccessItems = $successItems
        FailedItems  = $failedItems
    }
}

#endregion FQDNHostGroup

#region MACHost

<#
        .SYNOPSIS
        Retrieves MACHost objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for MACHost objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER MACAddressLike
        Optional MAC address filter, matched as a substring anywhere in the value. The firewall does not support filtering on MACAddress, so this filter is always applied client-side.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosMACHost

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosMACHost -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosMACHost -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosMACHost {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$MACAddressLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <MACHost>
    $filterXml
  </MACHost>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MAC host objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'get'

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/MACHost[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($MACAddressLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.MACAddress -like "*$MACAddressLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $macHostObjects = @()
    foreach ($node in $nodes) {
        $macHostObjects += [PSCustomObject]@{
            Name        = $node.Name
            Type        = $node.Type
            MACAddress  = $node.MACAddress
            MACList     = @($node.MACList.MACAddress)
            Description = $node.Description
        }
    }

    return $macHostObjects
}

<#
        .SYNOPSIS
        Creates a new MAC address host on the Sophos Firewall.

        .DESCRIPTION
        Creates a MAC host object for Layer 2 device identification. Useful for:
        - Device-based firewall rules (regardless of IP)
        - Guest network management
        - IoT device control
        - BYOD policies
        
        Supports single MAC addresses or comma-separated lists for multiple MACs.

        .PARAMETER Name
        Name of the MAC host object (1-60 characters, no commas).

        .PARAMETER MACAddress
        MAC address in standard format. Examples:
        - Single: '00:11:22:33:44:55'
        - Multiple: '00:11:22:33:44:55,AA:BB:CC:DD:EE:FF'
        Formats supported: colon-separated, hyphen-separated, or no separators.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create MAC host for a specific device
        New-SfosMACHost -Name "CEO-Laptop" -MACAddress "00:11:22:33:44:55" -Description "Executive laptop"

        .EXAMPLE
        # Create MAC host for IoT device
        New-SfosMACHost -Name "SecurityCamera-01" -MACAddress "AA:BB:CC:DD:EE:FF"

        .EXAMPLE
        # Create MAC host with multiple addresses (device with multiple NICs)
        New-SfosMACHost -Name "Server-Dual-NIC" -MACAddress "00:11:22:33:44:55,00:11:22:33:44:66" -Description "Server with 2 network cards"

        .EXAMPLE
        # Create MAC host for guest device
        New-SfosMACHost -Name "Guest-iPhone" -MACAddress "12:34:56:78:9A:BC" -Description "Visitor device"

        .NOTES
        Minimum supported PowerShell version: 5.1
        MAC addresses are case-insensitive.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosMACHost
        
        .LINK
        Set-SfosMACHost
        
        .LINK
        Remove-SfosMACHost
#>
function New-SfosMACHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$MACAddress,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # Setup MACAddress or MACList XML
    $xmlMAC = ''
    $xmlMACType = ''
    $MACList = $MACAddress.Split(',')

    if ($MACList.Count -gt 1) {
        $xmlMACType = '<Type>MACList</Type>'
        $xmlMAC = '<MACList>'
        foreach ($mac in $MACList) {
            $macEsc = ConvertTo-SfosXmlEscaped -Text $mac
            $xmlMAC += "<MACAddress>$macEsc</MACAddress>"
        }
        $xmlMAC += '</MACList>'
    }
    else {
        $xmlMACType = '<Type>MACAddress</Type>'
        $xmlMAC = "<MACAddress>$macEsc</MACAddress>"
    }

    # Build Inner XML
    $inner = @"
<Set operation="add">
  <MACHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlMACType
    $xmlMAC
  </MACHost>
</Set>
"@

    # Send API Request
    if (-not $PSCmdlet.ShouldProcess("MACHost '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error creating MACHost object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing MACHost object on the Sophos Firewall.

        .DESCRIPTION
        Updates a MACHost object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current object first and keeps the
        existing description unless the caller explicitly passes one. To clear the
        description, pass it explicitly with an empty value.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER MACAddress
        MAC address in standard format, or a comma-separated list of MAC addresses. Examples:
        - Single: '00:11:22:33:44:55'
        - Multiple: '00:11:22:33:44:55,AA:BB:CC:DD:EE:FF'

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosMACHost -Name "Example" -MACAddress "00:11:22:33:44:55"

        .EXAMPLE
        # Update using pipeline input (Get-SfosMACHost returns a MACAddress property)
        Get-SfosMACHost -NameLike "Example" | Set-SfosMACHost

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosMACHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$MACAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress

        # SFOS replaces the whole entity on update, so a description that is not sent
        # gets cleared. Read the current object and keep it unless the caller passes one.
        $existing = @(Get-SfosMACHost -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        
if ($existing.Count -eq 0) {
            throw "The MACHost object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup MACAddress or MACList XML
        $xmlMAC = ''
        # Ohne <Type> weist die Firewall jeden Set-Aufruf mit Code 501 zurueck.
        $xmlMACType = ''
        $MACList = $MACAddress.Split(',')

        if ($MACList.Count -gt 1) {
            $xmlMACType = '<Type>MACList</Type>'
            $xmlMAC = '<MACList>'
            foreach ($mac in $MACList) {
                $macEsc = ConvertTo-SfosXmlEscaped -Text $mac
                $xmlMAC += "<MACAddress>$macEsc</MACAddress>"
            }
            $xmlMAC += '</MACList>'
        }
        else {
            $xmlMACType = '<Type>MACAddress</Type>'
            $xmlMAC = "<MACAddress>$macEsc</MACAddress>"
        }

        # Build Inner XML
        $inner = @"
<Set operation="update">
  <MACHost>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlMACType
    $xmlMAC
  </MACHost>
</Set>
"@

        # Send API Request
        if (-not $PSCmdlet.ShouldProcess("MACHost '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating MACHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a MACHost object from the Sophos Firewall.

        .DESCRIPTION
        Removes a MACHost object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosMACHost -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosMACHost -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosMACHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("MACHost '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <MACHost>
    <Name>$nameEsc</Name>
  </MACHost>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing MACHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MACHost' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Exports MACHost objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all MACHost objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format is human-readable and Excel-compatible. JSON format preserves data structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'MACHost'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported MACHost names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all MAC hosts to CSV
        Export-SfosMACHosts -FilePath "C:\Exports\MACHosts.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosMACHosts -FilePath "C:\Exports\MACHosts.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosMACHost to retrieve the objects.

        .LINK
        Import-SfosMACHosts

        .LINK
        Get-SfosMACHost
#>
function Export-SfosMACHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '$FilePath' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve MAC hosts
    try {
        $macHosts = Get-SfosMACHost -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving MAC hosts: $($_.Exception.Message)"
    }

    # A MAC host has either a single MACAddress or a MACList array, depending on Type.
    # Flatten both cases into the single MACAddress column New-SfosMACHost expects
    # (comma-separated for multiple addresses), for both CSV and JSON output.
    $hostsToExport = foreach ($macHostItem in $macHosts) {
        $row = $macHostItem | Select-Object * -ExcludeProperty MACList
        if (-not $row.MACAddress -and $macHostItem.MACList) {
            $row.MACAddress = ($macHostItem.MACList -join ',')
        }
        $row
    }

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $hostsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $hostsToExport | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of MAC hosts to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation    = 'Export'
            ObjectType   = 'MACHost'
            Total        = $macHosts.Count
            Success      = $macHosts.Count
            Failed       = 0
            SuccessItems = @($macHosts.Name)
            FailedItems  = @()
        }
    }
    catch {
        throw "Error exporting MAC hosts to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports MACHost objects from a CSV or JSON file.

        .DESCRIPTION
        Reads MACHost objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosMACHost cmdlet.
        The file must have the appropriate headers/structure matching the MACHost properties (Name, MACAddress, Description).
        MACAddress holds a single address or a comma-separated list, matching the New-SfosMACHost parameter of the same name.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'MACHost'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported MACHost names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import MAC hosts from CSV
        Import-SfosMACHosts -FilePath "C:\Imports\MACHosts.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosMACHosts -FilePath "C:\Imports\MACHosts.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosMACHost to create the objects.

        .LINK
        Export-SfosMACHosts

        .LINK
        New-SfosMACHost
#>
function Import-SfosMACHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '$FilePath' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $macHosts = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $macHosts = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing MAC hosts from '$FilePath': $($_.Exception.Message)"
    }

    # Ensure macHosts is an array
    if ($macHosts -isnot [array]) {
        $macHosts = @($macHosts)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create MAC hosts on the Sophos Firewall
    foreach ($macHost in $macHosts) {
        try {
            New-SfosMACHost -Name $macHost.Name `
                -MACAddress $macHost.MACAddress `
                -Description $macHost.Description `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $macHost.Name
            Write-Information "Imported: $($macHost.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $macHost.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($macHost.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation    = 'Import'
        ObjectType   = 'MACHost'
        Total        = $macHosts.Count
        Success      = $successItems.Count
        Failed       = $failedItems.Count
        SuccessItems = $successItems
        FailedItems  = $failedItems
    }
}

#endregion MACHost

#region CountryGroup 

# --- CountryGroup ---

<#
        .SYNOPSIS
        Retrieves CountryGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for CountryGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosCountryGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosCountryGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosCountryGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosCountryGroup {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <CountryGroup>
    $filterXml
  </CountryGroup>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving CountryGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryGroup' -Action 'get'

    # Check login status
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/CountryGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $countryHostGroupObjects = @()
    foreach ($node in $nodes) {
        $countryHostGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            Countries   = [string[]]($node.CountryList | Select-Object -ExpandProperty Country)
        }
    }

    return $countryHostGroupObjects
}

<#
        .SYNOPSIS
        Creates a new country-based host group on the Sophos Firewall.

        .DESCRIPTION
        Creates a country group using Geo-IP databases. Useful for:
        - Geographic access restrictions (block/allow by country)
        - Compliance requirements (GDPR, data sovereignty)
        - Threat mitigation (block high-risk regions)
        - License enforcement (region-specific services)
        
        The firewall uses its Geo-IP database to match IP addresses to countries.

        .PARAMETER Name
        Name of the country group (1-50 characters, no commas).

        .PARAMETER Countries
        Array of country names as the firewall spells them, for example 'China' or
        'North Korea'. ISO 3166-1 alpha-2 codes such as 'CN' are rejected with
        code 501. Use Get-SfosCountryGroup on an existing group to see the exact
        spelling. The API documentation does not specify the format.
        Examples: 'United States', 'Germany', 'United Kingdom', 'China'
        Use Get-SfosCountryGroup to see available country codes.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create group for European countries
        New-SfosCountryGroup -Name "EU-Countries" -Countries @('DE', 'FR', 'IT', 'ES', 'NL') -Description "European Union member states"

        .EXAMPLE
        # Create group to block high-risk countries
        New-SfosCountryGroup -Name "BlockList-Countries" -Countries @('CN', 'RU', 'KP') -Description "Countries to block for security"

        .EXAMPLE
        # Create group for US regions
        New-SfosCountryGroup -Name "North-America" -Countries @('US', 'CA', 'MX') -Description "North American countries"

        .EXAMPLE
        # Create single-country group
        New-SfosCountryGroup -Name "Germany-Only" -Countries @('DE') -Description "German IP addresses only"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Requires up-to-date Geo-IP database on firewall.
        Country codes are case-sensitive (use uppercase).

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosCountryGroup
        
        .LINK
        Set-SfosCountryGroup
        
        .LINK
        Remove-SfosCountryGroup
#>
function New-SfosCountryGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$countries,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # Setup Countries XML
    $countriesXml = ''
    foreach ($country in $countries) {
        if (-not $country) {
            continue
        }
        $cEsc = ConvertTo-SfosXmlEscaped -Text $country
        $countriesXml += "<Country>$cEsc</Country>"
    }

    # Build Countries List XML
    $xmlCountriesList = ''
    if ( $countriesXml ) {
        $xmlCountriesList = @"
<CountryList>
    $countriesXml
</CountryList>
"@
    }

    # Build API Inner XML
    $inner = @"
<Set operation="add">
  <CountryGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlCountriesList
  </CountryGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("CountryGroup '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error creating CountryGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing CountryGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a CountryGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Countries
        Country names as the firewall spells them, for example 'China' or 'Germany'.
        ISO 3166-1 alpha-2 codes such as 'CN' are rejected with code 501.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosCountryGroup -Name "Example" -countries @('China', 'North Korea')

        .EXAMPLE
        # Update using pipeline input
        Get-SfosCountryGroup -NameLike "Example" | Set-SfosCountryGroup

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosCountryGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string[]]$countries,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Setup Description XML
        # SFOS replaces the whole entity on update, so a description that is not sent
        # gets cleared. Read the current object and keep it unless the caller passes one.
        $existing = @(Get-SfosCountryGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        
if ($existing.Count -eq 0) {
            throw "The CountryGroup object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup Countries XML
        $countriesXml = ''
        foreach ($country in $countries) {
            if (-not $country) {
                continue
            }
            $cEsc = ConvertTo-SfosXmlEscaped -Text $country
            $countriesXml += "<Country>$cEsc</Country>"
        }

        # Build Countries List XML
        $xmlCountriesList = ''
        if ( $countriesXml ) {
            $xmlCountriesList = @"
<CountryList>
    $countriesXml
</CountryList>
"@
        }

        # Build API Inner XML
        $inner = @"
<Set operation="update">
  <CountryGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlCountriesList
  </CountryGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("CountryGroup '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating CountryGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a CountryGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a CountryGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosCountryGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosCountryGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosCountryGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("CountryGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <CountryGroup>
    <Name>$nameEsc</Name>
  </CountryGroup>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing CountryGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CountryGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion CountryGroup

#region Service

# --- Service ---

<#
        .SYNOPSIS
        Retrieves service definitions from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for service objects. Returns PowerShell-friendly 
        objects by default, or raw XML nodes with -AsXml.
        
        Supports multiple filter parameters:
        - Server-side filters: NameLike, DescriptionLike, TypeLike (faster)
        - Client-side filters: ProtocolLike, SourcePortLike, DestinationPortLike (more flexible)
        
        Returns empty result when no services match the criteria.

        .PARAMETER NameLike
        Filter by service name (substring match). Server-side filter.

        .PARAMETER DescriptionLike
        Filter by description (substring match). Server-side filter.

        .PARAMETER TypeLike
        Filter by service type. Valid values: 'TCPorUDP', 'IP', 'ICMP', 'ICMPv6'. Server-side filter.

        .PARAMETER ProtocolLike
        Filter by protocol (e.g., 'TCP', 'UDP'). Client-side filter using wildcards.

        .PARAMETER SourcePortLike
        Filter by source port or range. Client-side filter using wildcards.

        .PARAMETER DestinationPortLike
        Filter by destination port or range. Client-side filter using wildcards.

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        # Output parameters
        
        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell objects.

        .OUTPUTS
        PSCustomObject with properties: Name, Description, Type, ServiceDetails
        System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all services
        Get-SfosService

        .EXAMPLE
        # Find services by name pattern
        Get-SfosService -NameLike "HTTP"

        .EXAMPLE
        # Find all TCP services
        Get-SfosService -TypeLike "TCPorUDP" -ProtocolLike "TCP"

        .EXAMPLE
        # Find services using specific port
        Get-SfosService -DestinationPortLike "443"

        .EXAMPLE
        # Find services in port range
        Get-SfosService -DestinationPortLike "8"

        .EXAMPLE
        # Get service details as XML
        Get-SfosService -NameLike "HTTPS" -AsXml

        .EXAMPLE
        # Find all ICMP services
        Get-SfosService -TypeLike "ICMP"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Client-side filters retrieve all services first, then filter locally.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        New-SfosService
        
        .LINK
        Set-SfosService
        
        .LINK
        Remove-SfosService

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosService {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        [ValidateSet('TCPorUDP', 'IP', 'ICMP', 'ICMPv6')]
        [string]$TypeLike,
        [string]$ProtocolLike,
        [string]$SourcePortLike,
        [string]$DestinationPortLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter. SFOS evaluates only the first <key> of the first <Filter>;
    # additional <Filter> blocks are silently dropped. So one supported key goes to the
    # firewall and every requested filter is applied again client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    # Build API Inner XML
    $inner = @"
<Get>
  <Services>
    $filterXml
  </Services>
</Get>
"@

    # Invoke API
    $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner `
        -SkipCertificateCheck:$params.SkipCertificateCheck
    
    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Services' -Action 'get'

    $nodeList = Select-Xml -Xml $XmlResponse -XPath '/Response/Services[Name]' -ErrorAction SilentlyContinue | `
        ForEach-Object -Process {
        $_.Node
    }

    # Create PSCustomObjectss
    try {
        $result = foreach ($nodeItem in @($nodeList)) {
            $serviceNodes = @()
            $serviceNodes += $nodeItem.ServiceDetails | Select-Object -ExpandProperty ServiceDetail
        
            $serviceObjects = foreach ($serviceItem in $serviceNodes) {
                if ($nodeItem.Type -like 'TCPorUDP') {
                    [pscustomobject]@{
                        SourcePort      = [string]$serviceItem.SourcePort
                        DestinationPort = [string]$serviceItem.DestinationPort
                        Protocol        = [string]$serviceItem.Protocol
                    }
                }
                elseif ($nodeItem.Type -like 'IP') {
                    [pscustomobject]@{
                        ProtocolName = [string]$serviceItem.ProtocolName
                    }
                }
                elseif ($nodeItem.Type -like 'ICMP') {
                    [pscustomobject]@{
                        ICMPType = [string]$serviceItem.ICMPType
                        ICMPCode = [string]$serviceItem.ICMPCode
                    }
                }
                elseif ($nodeItem.Type -like 'ICMPv6') {
                    [pscustomobject]@{
                        ICMPv6Type = [string]$serviceItem.ICMPv6Type
                        ICMPv6Code = [string]$serviceItem.ICMPv6Code
                    }
                }
                else {
                    Write-Warning -Message ('[W] Could not detect ServiceType:{0}' -f $nodeItem.Type)
                }
            }

            # Build Custom Object
            [pscustomobject]@{
                Name           = [string]$nodeItem.Name
                Description    = [string]$nodeItem.Description
                Type           = [string]$nodeItem.Type
                ServiceDetails = $serviceObjects
            }
        }
    }
    catch [Management.Automation.RuntimeException] {
        # get error record
        [Management.Automation.ErrorRecord]$e = $_

        # retrieve information about runtime error
        $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
        }
        
        # output information. Post-process collected info, and log info (optional)
        $info
    }

    # Client-side filtering, combined with AND. 'Like' keeps the SFOS meaning of the
    # word: a substring match, not a wildcard pattern.
    $result = @($result)
    if ($NameLike) {
        $result = @($result | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $result = @($result | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }
    if ($TypeLike) {
        $result = @($result | Where-Object -FilterScript { $_.Type -eq $TypeLike })
    }
    if ($ProtocolLike) {
        $result = @($result | Where-Object -FilterScript { $_.ServiceDetails.Protocol -like "*$ProtocolLike*" })
    }
    if ($SourcePortLike) {
        $result = @($result | Where-Object -FilterScript { $_.ServiceDetails.SourcePort -like "*$SourcePortLike*" })
    }
    if ($DestinationPortLike) {
        $result = @($result | Where-Object -FilterScript { $_.ServiceDetails.DestinationPort -like "*$DestinationPortLike*" })
    }

    # Return raw XML if requested - limited to the objects that survived filtering
    if ($AsXml) {
        $keptNames = @($result | ForEach-Object -Process { $_.Name })
        return @($nodeList | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $result
}

<#
        .SYNOPSIS
        Creates a new service definition on the Sophos Firewall.

        .DESCRIPTION
        Creates a service object for TCP/UDP ports, IP protocols, ICMP, or ICMPv6.
        Services are used in firewall rules to define allowed/blocked traffic.
        
        Supports four parameter sets:
        - TCPUDP: TCP or UDP services with port numbers/ranges
        - IP: IP protocol numbers (e.g., GRE, ESP, OSPF)
        - ICMP: ICMP types and codes for IPv4
        - ICMPv6: ICMPv6 types and codes for IPv6

        .PARAMETER Name
        Name of the service (1-50 characters, no commas).

        .PARAMETER Type
        Service type: 'TCPorUDP', 'IP', 'ICMP', or 'ICMPv6'. Default: 'TCPorUDP'.

        .PARAMETER Protocol
        Protocol for TCP/UDP services: 'TCP' or 'UDP'. Required for TCPUDP parameter set.

        .PARAMETER DstPort
        Destination port or port range. Examples: '443', '8080-8090', '1024:65535'.
        Required for TCPUDP parameter set.

        .PARAMETER SrcPort
        Source port or port range. Default: '1:65535' (all ports).

        .PARAMETER ProtocolName
        IP protocol name (e.g., 'GRE', 'ESP', 'OSPFIGP'). Required for IP parameter set.

        .PARAMETER ICMPType
        ICMP type(s) for IPv4. Valid values: -1, 0, 3, 4, 5, 8, 11-18, 30-40.
        Use -1 for 'any'. Required for ICMP parameter set.

        .PARAMETER ICMPCode
        ICMP code(s). Valid values: -1 (any), 0-15. Optional for ICMP parameter set.

        .PARAMETER ICMPv6Type
        ICMPv6 type(s) for IPv6. Valid values: -1, 0-4, 100-101, 128-158, 200-201.
        Required for ICMPv6 parameter set.

        .PARAMETER ICMPv6Code
        ICMPv6 code(s). Valid values: -1 (any), 0-15. Optional for ICMPv6 parameter set.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a TCP service for custom HTTPS port
        New-SfosService -Name "HTTPS-Custom" -Protocol TCP -DstPort 8443 -Description "Custom HTTPS port"

        .EXAMPLE
        # Create a UDP service for DNS
        New-SfosService -Name "DNS-Custom" -Protocol UDP -DstPort 53 -SrcPort "1024:65535"

        .EXAMPLE
        # Create a service with port range
        New-SfosService -Name "WebPorts" -Protocol TCP -DstPort "8080-8090" -Description "Web application ports"

        .EXAMPLE
        # Create an IP protocol service (GRE for VPN)
        New-SfosService -Name "GRE-Protocol" -ProtocolName "GRE" -Description "Generic Routing Encapsulation"

        .EXAMPLE
        # Create ICMP echo service (ping). -Type belongs to the TCPUDP parameter set only;
        # ICMPType/-ICMPCode select the ICMP parameter set on their own.
        New-SfosService -Name "ICMP-Echo" -ICMPType "8" -ICMPCode "0" -Description "Ping requests"

        .EXAMPLE
        # Create ICMPv6 service. -Type belongs to the TCPUDP parameter set only;
        # -ICMPv6Type selects the ICMPv6 parameter set on its own.
        New-SfosService -Name "ICMPv6-EchoRequest" -ICMPv6Type "128" -Description "IPv6 ping"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Uses parameter sets to enforce correct parameter combinations.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosService
        
        .LINK
        Set-SfosService
        
        .LINK
        Remove-SfosService
        
        .LINK
        New-SfosServiceGroup
#>
function New-SfosService {
    [CmdletBinding(DefaultParameterSetName = 'TCPUDP', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,
        
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ParameterSetName = 'TCPUDP')]
        [ValidateSet('TCPorUDP', 'IP', 'ICMP', 'ICMPv6')]
        [string]$Type = 'TCPorUDP',
        
        # --- Parameter-Set fr TCP/UDP ---
        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        [Parameter(Mandatory, ParameterSetName = 'TCPUDP')]
        [string]$DstPort,

        [Parameter(ParameterSetName = 'TCPUDP')]
        [string]$SrcPort = '1:65535',

        # --- Parameter-Set fr IP-Protokolle ---
        [Parameter(Mandatory, ParameterSetName = 'IP')]
        [string]$ProtocolName, # z.B. GRE, ESP, OSPFIGP

        # --- Parameter-Set fr ICMP ---
        [Parameter(Mandatory, ParameterSetName = 'ICMP')]
        [ValidateSet('-1', '0', '3', '4', '5', '6', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40')]
        [string[]]$ICMPType,

        [Parameter(ParameterSetName = 'ICMP')]
        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPCode,
        
        # --- Parameter-Set fr ICMPv6 ---
        [Parameter(Mandatory, ParameterSetName = 'ICMPv6')]
        [ValidateSet('0', '-1', '1', '2', '3', '4', '100', '101', '128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138', '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '149', '150', '151', '152', '153', '154', '155', '156', '157', '158', '200', '201')]
        [string[]]$ICMPv6Type,

        [Parameter(ParameterSetName = 'ICMPv6')]
        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPv6Code,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Initialisierung des Service-Details basierend auf dem Parameter-Set
    $detailXml = ''
    switch ($PSCmdlet.ParameterSetName) {
        'TCPUDP' {
            $detailXml = "<Protocol>$Protocol</Protocol><SourcePort>$(ConvertTo-SfosXmlEscaped -Text $SrcPort)</SourcePort><DestinationPort>$(ConvertTo-SfosXmlEscaped -Text $DstPort)</DestinationPort>" 
        }
        'IP' {
            $Type = 'IP'
            $detailXml = "<ProtocolName>$(ConvertTo-SfosXmlEscaped -Text $ProtocolName)</ProtocolName>"
        }
        'ICMP' {
            $Type = 'ICMP'
            # An omitted code must go on the wire as -1 ("Any Code"): an empty <ICMPCode/>
            # is rejected with 501 by the firewall (measured 2026-08-12).
            $codeWire = if ($PSBoundParameters.ContainsKey('ICMPCode')) { $ICMPCode -join ',' } else { '-1' }
            $detailXml = "<ICMPType>$($ICMPType -join ',')</ICMPType><ICMPCode>$codeWire</ICMPCode>"
        }
        'ICMPv6' {
            $Type = 'ICMPv6'
            # Same rule as ICMP: omitted code -> -1 ("Any Code"), empty element -> 501.
            $codeWire6 = if ($PSBoundParameters.ContainsKey('ICMPv6Code')) { $ICMPv6Code -join ',' } else { '-1' }
            $detailXml = "<ICMPv6Type>$($ICMPv6Type -join ',')</ICMPv6Type><ICMPv6Code>$codeWire6</ICMPv6Code>"
        }
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $xmlDescription = if ($Description) {
        "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>" 
    }
    else {
        '' 
    }
    $inner = "<Set operation='add'><Services><Name>$nameEsc</Name>$xmlDescription<Type>$Type</Type><ServiceDetails><ServiceDetail>$detailXml</ServiceDetail></ServiceDetails></Services></Set>"

    if (-not $PSCmdlet.ShouldProcess("Service '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Services' -Action 'create' -Target $Name
    }
    catch {
        throw "Failed to create Service '$Name': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Updates an existing service definition on the Sophos Firewall.

        .DESCRIPTION
        Updates a service object for TCP/UDP ports, IP protocols, ICMP, or ICMPv6.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current service first and keeps
        whatever the caller does not explicitly pass (Description, and for the TCPUDP
        parameter set also SrcPort and, for ICMP/ICMPv6, the Code value). To clear a field,
        pass it explicitly with an empty value.

        Supports four parameter sets:
        - TCPUDP: TCP or UDP services with port numbers/ranges
        - IP: IP protocol numbers (e.g., GRE, ESP, OSPF)
        - ICMP: ICMP types and codes for IPv4
        - ICMPv6: ICMPv6 types and codes for IPv6

        .PARAMETER Name
        Name of the service to update (1-50 characters, no commas).

        .PARAMETER Type
        Service type: 'TCPorUDP', 'IP', 'ICMP', or 'ICMPv6'. Default: 'TCPorUDP'.

        .PARAMETER Protocol
        Protocol for TCP/UDP services: 'TCP' or 'UDP'. Required for TCPUDP parameter set.

        .PARAMETER DstPort
        Destination port or port range. Examples: '443', '8080-8090', '1024:65535'.
        Required for TCPUDP parameter set.

        .PARAMETER SrcPort
        Source port or port range. If omitted, the existing source port on the firewall is
        kept; the parameter default is only used when no matching value is found.

        .PARAMETER ProtocolName
        IP protocol name (e.g., 'GRE', 'ESP', 'OSPFIGP'). Required for IP parameter set.

        .PARAMETER ICMPType
        ICMP type(s) for IPv4. Valid values: -1, 0, 3, 4, 5, 8, 11-18, 30-40.
        Use -1 for 'any'. Required for ICMP parameter set.

        .PARAMETER ICMPCode
        ICMP code(s). Valid values: -1 (any), 0-15. If omitted, the existing ICMP code on the
        firewall is kept.

        .PARAMETER ICMPv6Type
        ICMPv6 type(s) for IPv6. Valid values: -1, 0-4, 100-101, 128-158, 200-201.
        Required for ICMPv6 parameter set.

        .PARAMETER ICMPv6Code
        ICMPv6 code(s). Valid values: -1 (any), 0-15. If omitted, the existing ICMPv6 code on
        the firewall is kept.

        .PARAMETER Description
        Optional description (max 255 characters). If omitted, the existing description is kept.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Change the destination port of an existing TCP service, keeping its source port
        Set-SfosService -Name "HTTPS-Custom" -Protocol TCP -DstPort 8444

        .EXAMPLE
        # Update description of an ICMP service, keeping its existing type/code
        Set-SfosService -Name "ICMP-Echo" -ICMPType "8" -Description "Ping requests (updated)"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Uses parameter sets to enforce correct parameter combinations.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosService

        .LINK
        New-SfosService

        .LINK
        Remove-SfosService
#>
function Set-SfosService {
    # One parameter set only: with pipeline input PowerShell fixes the set before binding
    # properties, so set-specific parameters would never bind and Get-SfosService |
    # Set-SfosService failed outright. The type is validated in the body instead.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('TCPorUDP', 'IP', 'ICMP', 'ICMPv6')]
        [string]$Type,

        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        [string]$DstPort,

        [string]$SrcPort,

        [string]$ProtocolName,

        [ValidateSet('-1', '0', '3', '4', '5', '6', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40')]
        [string[]]$ICMPType,

        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPCode,

        [ValidateSet('0', '-1', '1', '2', '3', '4', '100', '101', '128', '129', '130', '131', '132', '133', '134', '135', '136', '137', '138', '139', '140', '141', '142', '143', '144', '145', '146', '147', '148', '149', '150', '151', '152', '153', '154', '155', '156', '157', '158', '200', '201')]
        [string[]]$ICMPv6Type,

        [ValidateSet('-1', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15')]
        [string[]]$ICMPv6Code,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update, so every element the request leaves out
        # is cleared. Read the current service first and keep what the caller did not pass.
        $existing = @(Get-SfosService -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The Service object '$Name' was not found."
        }

        $currentDetail = @($existing[0].ServiceDetails)[0]

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetType = if ($PSBoundParameters.ContainsKey('Type')) {
            $Type
        }
        else {
            [string]$existing[0].Type
        }

        $detailXml = ''
        switch ($targetType) {
            'TCPorUDP' {
                $targetProtocol = if ($PSBoundParameters.ContainsKey('Protocol')) { $Protocol } else { [string]$currentDetail.Protocol }
                $targetSrcPort = if ($PSBoundParameters.ContainsKey('SrcPort')) { $SrcPort } else { [string]$currentDetail.SourcePort }
                $targetDstPort = if ($PSBoundParameters.ContainsKey('DstPort')) { $DstPort } else { [string]$currentDetail.DestinationPort }
                if (-not $targetProtocol -or -not $targetDstPort) {
                    throw "Type 'TCPorUDP' needs -Protocol and -DstPort for Service '$Name'."
                }
                if (-not $targetSrcPort) { $targetSrcPort = '1:65535' }
                $detailXml = "<Protocol>$targetProtocol</Protocol><SourcePort>$(ConvertTo-SfosXmlEscaped -Text $targetSrcPort)</SourcePort><DestinationPort>$(ConvertTo-SfosXmlEscaped -Text $targetDstPort)</DestinationPort>"
            }
            'IP' {
                $targetProtocolName = if ($PSBoundParameters.ContainsKey('ProtocolName')) { $ProtocolName } else { [string]$currentDetail.ProtocolName }
                if (-not $targetProtocolName) { throw "Type 'IP' needs -ProtocolName for Service '$Name'." }
                $detailXml = "<ProtocolName>$(ConvertTo-SfosXmlEscaped -Text $targetProtocolName)</ProtocolName>"
            }
            'ICMP' {
                $targetICMPType = if ($PSBoundParameters.ContainsKey('ICMPType')) { $ICMPType -join ',' } else { [string]$currentDetail.ICMPType }
                $targetICMPCode = if ($PSBoundParameters.ContainsKey('ICMPCode')) { $ICMPCode -join ',' } else { [string]$currentDetail.ICMPCode }
                if (-not $targetICMPType) { throw "Type 'ICMP' needs -ICMPType for Service '$Name'." }
                $detailXml = "<ICMPType>$(ConvertTo-SfosXmlEscaped -Text $targetICMPType)</ICMPType><ICMPCode>$(ConvertTo-SfosXmlEscaped -Text $targetICMPCode)</ICMPCode>"
            }
            'ICMPv6' {
                $targetICMPv6Type = if ($PSBoundParameters.ContainsKey('ICMPv6Type')) { $ICMPv6Type -join ',' } else { [string]$currentDetail.ICMPv6Type }
                $targetICMPv6Code = if ($PSBoundParameters.ContainsKey('ICMPv6Code')) { $ICMPv6Code -join ',' } else { [string]$currentDetail.ICMPv6Code }
                if (-not $targetICMPv6Type) { throw "Type 'ICMPv6' needs -ICMPv6Type for Service '$Name'." }
                $detailXml = "<ICMPv6Type>$(ConvertTo-SfosXmlEscaped -Text $targetICMPv6Type)</ICMPv6Type><ICMPv6Code>$(ConvertTo-SfosXmlEscaped -Text $targetICMPv6Code)</ICMPv6Code>"
            }
            default {
                throw "Unknown service type '$targetType' for Service '$Name'."
            }
        }

        $xmlDescription = if ($targetDescription) {
            "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>"
        }
        else {
            ''
        }

        $inner = "<Set operation='update'><Services><Name>$nameEsc</Name>$xmlDescription<Type>$targetType</Type><ServiceDetails><ServiceDetail>$detailXml</ServiceDetail></ServiceDetails></Services></Set>"

        if (-not $PSCmdlet.ShouldProcess("Service '$($Name)' on $($params.Firewall)", 'Update')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck
            $XmlResponse = [xml]$response.Content
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Services' -Action 'update' -Target $Name
        }
        catch {
            throw "Failed to update Service '$Name': $($_.Exception.Message)"
        }
    }
}


<#
        .SYNOPSIS
        Removes a Service object from the Sophos Firewall.

        .DESCRIPTION
        Removes a Service object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosService -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosService -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("Service '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <Services>
    <Name>$nameEsc</Name>
  </Services>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner `
                -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch {
            throw "Failed to remove Service '$Name': $($_.Exception.Message)"
        }
        
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Services' -Action 'remove' -Target $Name
    }

    end {

    }
}

<#
        .SYNOPSIS
        Exports Service objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all Service objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Useful for backup, documentation, or migration purposes. Services include TCP/UDP, IP protocols, ICMP, and ICMPv6 definitions.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format is human-readable and Excel-compatible. JSON format preserves data structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'Service'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported Service names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all services to CSV
        Export-SfosServices -FilePath "C:\Exports\Services.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosServices -FilePath "C:\Exports\Services.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosService to retrieve the objects.

        .LINK
        Import-SfosServices

        .LINK
        Get-SfosService
#>
function Export-SfosServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '$FilePath' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve services
    try {
        $services = Get-SfosService -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving services: $($_.Exception.Message)"
    }

    # ServiceDetails is a nested object (or array of them); Export-Csv would otherwise
    # stringify it as "@{SourcePort=...; Protocol=TCP}". Flatten it into columns matching
    # the New-SfosService parameter names for the object's Type, for both CSV and JSON.
    # Only the first ServiceDetail entry is considered - New-SfosService can only create
    # a single ServiceDetail per call, so a service with more than one cannot round-trip
    # through Import-SfosServices regardless.
    $servicesToExport = foreach ($serviceItem in $services) {
        $detail = @($serviceItem.ServiceDetails) | Select-Object -First 1

        [PSCustomObject]@{
            Name         = $serviceItem.Name
            Description  = $serviceItem.Description
            Type         = $serviceItem.Type
            Protocol     = if ($serviceItem.Type -eq 'TCPorUDP') { $detail.Protocol } else { '' }
            SrcPort      = if ($serviceItem.Type -eq 'TCPorUDP') { $detail.SourcePort } else { '' }
            DstPort      = if ($serviceItem.Type -eq 'TCPorUDP') { $detail.DestinationPort } else { '' }
            ProtocolName = if ($serviceItem.Type -eq 'IP') { $detail.ProtocolName } else { '' }
            ICMPType     = if ($serviceItem.Type -eq 'ICMP') { $detail.ICMPType } else { '' }
            ICMPCode     = if ($serviceItem.Type -eq 'ICMP') { $detail.ICMPCode } else { '' }
            ICMPv6Type   = if ($serviceItem.Type -eq 'ICMPv6') { $detail.ICMPv6Type } else { '' }
            ICMPv6Code   = if ($serviceItem.Type -eq 'ICMPv6') { $detail.ICMPv6Code } else { '' }
        }
    }

    # Export to CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $servicesToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $servicesToExport | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of services to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation    = 'Export'
            ObjectType   = 'Service'
            Total        = $services.Count
            Success      = $services.Count
            Failed       = 0
            SuccessItems = @($services.Name)
            FailedItems  = @()
        }
    }
    catch {
        throw "Error exporting services to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports Service objects from a CSV or JSON file.

        .DESCRIPTION
        Reads Service objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosService cmdlet.
        The file must have flat columns matching the Type of the service: Name, Description, Type,
        Protocol/SrcPort/DstPort (TCPorUDP), ProtocolName (IP), ICMPType/ICMPCode (ICMP), ICMPv6Type/ICMPv6Code (ICMPv6).

        LIMITATION: Get-SfosService (and therefore Export-SfosServices) returns ICMPType/ICMPv6Type as text
        (e.g. 'Echo'), while New-SfosService requires the numeric code via ValidateSet (e.g. '8'). There is no
        reliable mapping between the two, so ICMP and ICMPv6 services cannot be round-tripped automatically.
        Rows with Type 'ICMP' or 'ICMPv6' are reported as failed items; recreate those services manually with
        New-SfosService. TCPorUDP and IP services import without restriction.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'Service'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported Service names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import services from CSV
        Import-SfosServices -FilePath "C:\Imports\Services.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosServices -FilePath "C:\Imports\Services.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosService to create the objects.

        .LINK
        Export-SfosServices

        .LINK
        New-SfosService
#>
function Import-SfosServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '$FilePath' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $services = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $services = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing services from '$FilePath': $($_.Exception.Message)"
    }

    # Ensure services is an array
    if ($services -isnot [array]) {
        $services = @($services)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create services on the Sophos Firewall. New-SfosService uses parameter sets, so
    # only the parameters for the object's Type may be passed - mixing in parameters
    # from other sets makes parameter set resolution fail.
    foreach ($service in $services) {
        try {
            switch ($service.Type) {
                'TCPorUDP' {
                    New-SfosService -Name $service.Name `
                        -Type 'TCPorUDP' `
                        -Protocol $service.Protocol `
                        -DstPort $service.DstPort `
                        -SrcPort $service.SrcPort `
                        -Description $service.Description `
                        -Firewall $params.Firewall `
                        -Port $params.Port `
                        -Username $params.Username `
                        -Password $params.Password `
                        -SkipCertificateCheck:$params.SkipCertificateCheck
                }
                'IP' {
                    New-SfosService -Name $service.Name `
                        -ProtocolName $service.ProtocolName `
                        -Description $service.Description `
                        -Firewall $params.Firewall `
                        -Port $params.Port `
                        -Username $params.Username `
                        -Password $params.Password `
                        -SkipCertificateCheck:$params.SkipCertificateCheck
                }
                'ICMP' {
                    # Get-SfosService returns ICMPType/ICMPCode as text (e.g. 'Echo'), but
                    # New-SfosService's ValidateSet requires the numeric code (e.g. '8').
                    # There is no reliable mapping between the two, so this Type cannot be
                    # round-tripped automatically; report it and let the caller recreate
                    # it manually with New-SfosService.
                    throw "Service '$($service.Name)': ICMP services cannot be imported automatically. Get-SfosService returns ICMPType/ICMPCode as text (e.g. 'Echo'), while New-SfosService requires the numeric code (e.g. '8'). Recreate this service manually with New-SfosService."
                }
                'ICMPv6' {
                    throw "Service '$($service.Name)': ICMPv6 services cannot be imported automatically. Get-SfosService returns ICMPv6Type/ICMPv6Code as text, while New-SfosService requires the numeric code. Recreate this service manually with New-SfosService."
                }
                default {
                    throw "Service '$($service.Name)': unknown or missing Type '$($service.Type)'."
                }
            }

            $successItems += $service.Name
            Write-Information "Imported: $($service.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $service.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($service.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation    = 'Import'
        ObjectType   = 'Service'
        Total        = $services.Count
        Success      = $successItems.Count
        Failed       = $failedItems.Count
        SuccessItems = $successItems
        FailedItems  = $failedItems
    }
}

#endregion Service

#region ServiceGroup
# --- ServiceGroup ---

<#
        .SYNOPSIS
        Retrieves ServiceGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ServiceGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.
    
        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosServiceGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosServiceGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosServiceGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosServiceGroup {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,
        
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        
        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <ServiceGroup>
    $filterXml
  </ServiceGroup>
</Get>
"@

    $response = Invoke-SfosApi -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -InnerXml $inner `
        -SkipCertificateCheck:$params.SkipCertificateCheck
        
    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    
Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'get'
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ServiceGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }
    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $serviceGroupObjects = @()
    foreach ($node in $nodes) {
        $serviceGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            ServiceList = [string[]]@($node.ServiceList | Select-Object -ExpandProperty Service)
        }
    }

    return $serviceGroupObjects
}

<#
        .SYNOPSIS
        Creates a new service group on the Sophos Firewall.

        .DESCRIPTION
        Creates a service group to logically organize multiple service definitions.
        Use service groups in firewall rules to:
        - Simplify rule management (one group instead of many services)
        - Standardize application access (e.g., "WebServices" group)
        - Reduce rule count and improve readability
        
        After creation, use Add-SfosServiceGroupMember to add additional services.

        .PARAMETER Name
        Name of the service group (1-50 characters, no commas).

        .PARAMETER Members
        Array of service names to include in the group.
        Services must already exist on the firewall.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)
        
        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create service group for web services
        New-SfosServiceGroup -Name "WebServices" -Members @('HTTP', 'HTTPS') -Description "Standard web traffic"

        .EXAMPLE
        # Create service group for Microsoft services
        New-SfosServiceGroup -Name "Microsoft365" -Members @('HTTPS', 'SMTP', 'IMAPS') -Description "Office 365 services"

        .EXAMPLE
        # Start with one member and add more later. A ServiceGroup cannot be created empty:
        # the API marks its member list mandatory, unlike IPHostGroup or FQDNHostGroup.
        New-SfosServiceGroup -Name "CustomApps" -Members @('CustomHTTPS') -Description "Custom application ports"
        Add-SfosServiceGroupMember -Name "CustomApps" -Members @('AppPort-8080')

        .EXAMPLE
        # Create service group for database services
        New-SfosServiceGroup -Name "DatabaseServices" -Members @('MSSQL', 'MySQL', 'PostgreSQL') -Description "Database access ports"

        .EXAMPLE
        # Create service group for remote access
        New-SfosServiceGroup -Name "RemoteAccess" -Members @('RDP', 'SSH', 'VNC') -Description "Remote desktop protocols"

        .NOTES
        Minimum supported PowerShell version: 5.1
        All member services must exist before creating the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
        
        .LINK
        Get-SfosServiceGroup
        
        .LINK
        Set-SfosServiceGroup
        
        .LINK
        Add-SfosServiceGroupMember
        
        .LINK
        Remove-SfosServiceGroup
#>
function New-SfosServiceGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # SFOS refuses a service group without members (code 501), so at least one
        # service has to be supplied at creation time.
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    # Setup Description XML
    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # Setup Members XML
    $xmlMember = ''
    foreach ($member in $members) {
        if (-not $member) {
            continue
        }
        if ($member.Length -gt 50) {
            throw "Member '$member' must be 50 characters or fewer."
        }
        if ($member -match ',') {
            throw "Member '$member' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<Service>$mEsc</Service>"
    }

    # Setup Members XML List
    $xmlServiceList = ''
    if ( $xmlMember ) {
        $xmlServiceList = @"
<ServiceList>
    $xmlMember
</ServiceList>
"@
    }

    # Build final XML    
    $inner = @"
<Set operation="add">
  <ServiceGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlServiceList
  </ServiceGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("ServiceGroup '$($Name)' on $($params.Firewall)", 'Create')) {
        return
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Failed to create ServiceGroup '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing ServiceGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a ServiceGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline (when supported by the function's parameters).

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more member object names to include.

        .PARAMETER Description
        Optional description text.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Update an object by name
        Set-SfosServiceGroup -Name "Example" -members @('HTTP', 'HTTPS')

        .EXAMPLE
        # Update using pipeline input
        Get-SfosServiceGroup -NameLike "Example" | Set-SfosServiceGroup

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosServiceGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServiceList')]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Setup Description XML
        # SFOS replaces the whole entity on update, so a description that is not sent
        # gets cleared. Read the current object and keep it unless the caller passes one.
        $existing = @(Get-SfosServiceGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        
if ($existing.Count -eq 0) {
            throw "The ServiceGroup object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Setup Members XML
        $xmlMember = ''
        foreach ($member in $members) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Service>$mEsc</Service>"
        }
        
        # Setup Members XML List
        $xmlServiceList = ''
        if ( $xmlMember ) {
            $xmlServiceList = @"
<ServiceList>
    $xmlMember
</ServiceList>
"@
        }

        # Build final XML
        $inner = @"
<Set operation="update">
  <ServiceGroup>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlServiceList
  </ServiceGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ServiceGroup '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner `
                -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch {
            throw "Failed to update ServiceGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a ServiceGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a ServiceGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Preview removal
        Remove-SfosServiceGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Pipeline removal preview
        Remove-SfosServiceGroup -Name "Example" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosServiceGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("ServiceGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <ServiceGroup>
    <Name>$nameEsc</Name>
  </ServiceGroup>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner `
                -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch {
            throw "Failed to remove ServiceGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds members to a ServiceGroup on the Sophos Firewall.

        .DESCRIPTION
        Adds one or more members to a ServiceGroup using the Sophos Firewall XML API.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER ServiceGroupName
        Name of the target ServiceGroup.

        .PARAMETER Members
        One or more member object names to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Add members to a ServiceGroup
        Add-SfosServiceGroupMember -Name "ExampleGroup" -Members "Service1", "Service2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Add-SfosServiceGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [Alias('ServiceGroupName')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS applies the member list as a whole - a <Set> replaces it instead of appending -
        # so the current members are read first and written back with the new ones.
        # -NameLike is a substring match, hence the exact-name filter.
        $serviceGroup = @(Get-SfosServiceGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($serviceGroup.Count -eq 0) {
            throw "The ServiceGroup object '$Name' was not found."
        }

        $targetMembers = @(@($serviceGroup[0].ServiceList) + @($members) |
                Where-Object -FilterScript { $_ } |
                Select-Object -Unique)

        # Setup Members XML
        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Service>$mEsc</Service>"
        }

        # Build final XML
        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        $descriptionXml = ''
        if ($serviceGroup[0].Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $serviceGroup[0].Description)</Description>"
        }

        $inner = @"
<Set operation="update">
  <ServiceGroup>
    <Name>$groupNameEsc</Name>
    $descriptionXml
    <ServiceList>
        $xmlMember
    </ServiceList>
  </ServiceGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ServiceGroup '$($Name)' on $($params.Firewall)", 'Add members')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner `
                -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch {
            throw "Failed to add members to ServiceGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'add members' -Target $Name
    }
}

<#      
        .SYNOPSIS
        Removes members from a ServiceGroup on the Sophos Firewall.

        .DESCRIPTION
        Removes one or more members from a ServiceGroup using the Sophos Firewall XML API.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target ServiceGroup.

        .PARAMETER Members
        One or more member object names to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        PSCustomObject or API status information depending on implementation.

        .EXAMPLE
        # Remove members from a ServiceGroup
        Remove-SfosServiceGroupMember -Name "ExampleGroup" -Members "Service1", "Service2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosServiceGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )
    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $groupNameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the member list with whatever is sent, so removal means writing back
        # the remaining members - a <Set operation="remove"> carrying the members to drop
        # would keep exactly those and discard the rest.
        $serviceGroup = @(Get-SfosServiceGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($serviceGroup.Count -eq 0) {
            throw "The ServiceGroup object '$Name' was not found."
        }

        $currentMembers = @($serviceGroup[0].ServiceList)
        if ($currentMembers.Count -eq 0) {
            # Nothing to remove
            return
        }

        $targetMembers = @($currentMembers | Where-Object -FilterScript { $members -notcontains $_ })

        # SFOS refuses a service group with an empty member list (code 501). Emptying the
        # group is therefore not possible - the group itself has to be removed instead.
        if ($targetMembers.Count -eq 0) {
            throw ("Removing these members would leave ServiceGroup '{0}' empty, which SFOS does not allow. " -f $Name +
                "Use Remove-SfosServiceGroup to delete the group instead.")
        }

        # Setup Members XML
        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 50) {
                throw "Member '$member' must be 50 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<Service>$mEsc</Service>"
        }

        # Build final XML
        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        $descriptionXml = ''
        if ($serviceGroup[0].Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $serviceGroup[0].Description)</Description>"
        }

        $inner = @"
<Set operation="update">
  <ServiceGroup>
    <Name>$groupNameEsc</Name>
    $descriptionXml
    <ServiceList>
        $xmlMember
    </ServiceList>
  </ServiceGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ServiceGroup '$($Name)' on $($params.Firewall)", 'Remove members')) {
            return
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner `
                -SkipCertificateCheck:$params.SkipCertificateCheck
        }
        catch {
            throw "Failed to remove members from ServiceGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ServiceGroup' -Action 'remove members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Exports ServiceGroup objects to a CSV or JSON file.

        .DESCRIPTION
        Retrieves all ServiceGroup objects from the Sophos Firewall and exports them to a file in CSV or JSON format.
        Group members are stored as JSON arrays within the file for proper handling of multiple members.
        Useful for backup, documentation, or migration purposes.

        .PARAMETER FilePath
        Full path where the export file will be saved. The file extension should match the format (.csv for CSV, .json for JSON).

        .PARAMETER Format
        Export format: 'AsCSV' (default) or 'AsJSON'. CSV format stores member arrays as JSON strings. JSON format preserves nested structure.

        .PARAMETER Overwrite
        If specified, overwrite the file if it already exists. Without this switch, the function throws an error if the file exists.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Export'
        - ObjectType: 'ServiceGroup'
        - Total: Number of objects exported
        - Success: Number of successful exports
        - Failed: Always 0 for export operations
        - SuccessItems: Array of exported ServiceGroup names
        - FailedItems: Empty array for export operations

        .EXAMPLE
        # Export all service groups to CSV
        Export-SfosServiceGroups -FilePath "C:\Exports\ServiceGroups.csv"

        .EXAMPLE
        # Export to JSON with overwrite
        Export-SfosServiceGroups -FilePath "C:\Exports\ServiceGroups.json" -Format AsJSON -Overwrite

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on Get-SfosServiceGroup to retrieve the objects.
        Group members are stored as JSON arrays within CSV fields for proper serialization.

        .LINK
        Import-SfosServiceGroups

        .LINK
        Get-SfosServiceGroup
#>
function Export-SfosServiceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "File '$FilePath' already exists. Provide a different file name or use -Overwrite."
        }
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Retrieve service groups
    try {
        $serviceGroups = Get-SfosServiceGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
    catch {
        throw "Error retrieving service groups: $($_.Exception.Message)"
    }

    # Flatten ServiceList (an array) to a comma-separated string for CSV export.
    try {
        $groupsToExport = @()
        foreach ($group in $serviceGroups) {
            $groupObj = $group | Select-Object * -ExcludeProperty ServiceList
            $groupObj | Add-Member -NotePropertyName ServiceList -NotePropertyValue ($group.ServiceList -join ',')
            $groupsToExport += $groupObj
        }

        if ($Format -eq 'AsCSV') {
            $groupsToExport | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $serviceGroups | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Export of service groups to '$FilePath' successful." -InformationAction Continue

        # Return summary object
        return [PSCustomObject]@{
            Operation    = 'Export'
            ObjectType   = 'ServiceGroup'
            Total        = $serviceGroups.Count
            Success      = $serviceGroups.Count
            Failed       = 0
            SuccessItems = @($serviceGroups.Name)
            FailedItems  = @()
        }
    }
    catch {
        throw "Error exporting service groups to '$FilePath': $($_.Exception.Message)"
    }
}

<#
        .SYNOPSIS
        Imports ServiceGroup objects from a CSV or JSON file.

        .DESCRIPTION
        Reads ServiceGroup objects from a specified CSV or JSON file and creates them on the Sophos Firewall using the New-SfosServiceGroup cmdlet.
        The file must have the appropriate headers/structure. In CSV files, the ServiceList member list is a single comma-separated string.

        .PARAMETER FilePath
        Full path to the input CSV or JSON file.

        .PARAMETER Format
        Import format: 'AsCSV' (default) or 'AsJSON'. Must match the file format.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, uses the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skip SSL/TLS certificate validation for self-signed certificates.

        .OUTPUTS
        PSCustomObject with properties:
        - Operation: 'Import'
        - ObjectType: 'ServiceGroup'
        - Total: Number of objects in import file
        - Success: Number of successfully created objects
        - Failed: Number of failed creations
        - SuccessItems: Array of successfully imported ServiceGroup names
        - FailedItems: Array of PSCustomObjects with Name and Error details for failed items

        .EXAMPLE
        # Import service groups from CSV
        Import-SfosServiceGroups -FilePath "C:\Imports\ServiceGroups.csv"

        .EXAMPLE
        # Import from JSON with explicit connection
        $result = Import-SfosServiceGroups -FilePath "C:\Imports\ServiceGroups.json" -Format AsJSON -Firewall "192.168.1.1"
        $result | Format-Table

        .NOTES
        Minimum supported PowerShell version: 5.1
        This function depends on New-SfosServiceGroup to create the objects.
        Members in CSV files are a single comma-separated string, e.g. "Service1,Service2"

        .LINK
        Export-SfosServiceGroups

        .LINK
        New-SfosServiceGroup
#>
function Import-SfosServiceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [ValidateNotNullOrEmpty()]
        [string]$Format = 'AsCSV',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    # Check if file exists
    if (-not (Test-Path -Path $FilePath)) {
        throw "File '$FilePath' was not found."
    }

    # Resolve connection parameters
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Import data from CSV or JSON
    try {
        if ($Format -eq 'AsCSV') {
            $serviceGroups = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $serviceGroups = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        }
    }
    catch {
        throw "Error importing service groups from '$FilePath': $($_.Exception.Message)"
    }

    # Ensure serviceGroups is an array
    if ($serviceGroups -isnot [array]) {
        $serviceGroups = @($serviceGroups)
    }

    # Track success and failures
    $successItems = @()
    $failedItems = @()

    # Create service groups on the Sophos Firewall
    foreach ($group in $serviceGroups) {
        try {
            # ServiceList comes back as a comma-separated string (see Export-SfosServiceGroups).
            # Split it into an array and drop empty entries.
            $members = @($group.ServiceList -split ',' | Where-Object -FilterScript { $_ })

            New-SfosServiceGroup -Name $group.Name `
                -Description $group.Description `
                -Members $members `
                -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck
            
            $successItems += $group.Name
            Write-Information "Imported: $($group.Name)" -InformationAction Continue
        }
        catch {
            $failedItems += [PSCustomObject]@{
                Name  = $group.Name
                Error = $_.Exception.Message
            }
            Write-Information "Error importing '$($group.Name)': $($_.Exception.Message)" -InformationAction Continue
        }
    }

    # Return summary object
    return [PSCustomObject]@{
        Operation    = 'Import'
        ObjectType   = 'ServiceGroup'
        Total        = $serviceGroups.Count
        Success      = $successItems.Count
        Failed       = $failedItems.Count
        SuccessItems = $successItems
        FailedItems  = $failedItems
    }
}

#endregion ServiceGroup



