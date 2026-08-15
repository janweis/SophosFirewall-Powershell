#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }
<#
        .SYNOPSIS
        Manages IP hosts, FQDN hosts, MAC hosts, host groups, services, and service groups on Sophos Firewall.

        .DESCRIPTION
        Manages the network objects of a Sophos XGS / SFOS 22.0 firewall through the
        management API: IP hosts, IP host groups, FQDN hosts, FQDN host groups, MAC hosts,
        country groups, services, and service groups. Each object type has Get/New/Set/Remove
        cmdlets, and every group or list-based type also has Export/Import and, where it has
        members, Add-/Remove-Member cmdlets.

        Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
        repeating the connection parameters.

        .EXAMPLE
        Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosIPHost

        Connects to the firewall and lists every IP host object.

        .EXAMPLE
        New-SfosIPHost -Name 'WebServer01' -IPAddress '10.0.1.100' -HostType IP -Description 'Production web server'
        Add-SfosIPHostGroupMember -Name 'WebServers' -members 'WebServer01'

        Creates an IP host object and adds it to an existing group.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'Web' -IPAddressLike '10.0.'
        Get-SfosFQDNHost -FqdnLike '.example.com'

        Finds objects by a substring match. Every -*Like filter matches anywhere in the
        value and is not a wildcard pattern.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'OldServer' | Remove-SfosIPHost -WhatIf
        Get-SfosService -NameLike 'Deprecated' | Remove-SfosService -WhatIf

        Previews a bulk removal through the pipeline before running it for real.

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
        Retrieves IP host objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the IP host objects that are defined on the firewall. An IP host object
        stands for a single address, a network, an address range or a list of addresses,
        and is used as source or destination in firewall rules and other policies. Use this
        cmdlet to review the existing objects, to feed them into another cmdlet through the
        pipeline, or to copy them to a second firewall. The cmdlet only reads; nothing on
        the firewall is changed. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the name is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER IPAddressLike
        Optional. Returns only objects whose IP address contains the given text anywhere,
        for example '192.168.10.' to match a whole subnet. If omitted, the address is not
        used to filter.

        .PARAMETER HostTypeLike
        Optional. Returns only objects of one host type. Unlike the other filters this is an
        exact match. Valid values: IP, Network, IPRange, IPList, System Host. If omitted,
        all host types are returned.

        .PARAMETER SubnetLike
        Optional. Returns only objects whose subnet mask contains the given text anywhere,
        for example '255.255.255.0'. Applies to objects of type Network. If omitted, the
        subnet is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        host objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per IP host, with the
        properties Name, Description, IPFamily, HostType, IPAddress, Subnet, StartIPAddress,
        EndIPAddress and ListOfIPAddresses. Returns System.Xml.XmlElement when -AsXml is
        used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosIPHost

        Lists every IP host object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'Branch' -HostTypeLike Network

        Lists all network objects whose name contains 'Branch'.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'Server-01' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'Branch' -Session 'fw2'

        Reads the matching host objects from a second firewall that was registered earlier
        with Connect-SfosFirewall -Name 'fw2'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPHost

        .LINK
        Set-SfosIPHost
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
        [object]$Session,
        
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
        Creates an IP host object on a Sophos Firewall.

        .DESCRIPTION
        Creates an IP host object of one of four types: a single address, a network with a
        subnet mask, an address range, or a list of addresses. Use this cmdlet to define an
        object once and reuse it as source or destination in firewall rules and other
        policies. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the new IP host object. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER IPFamily
        Optional. Address family of the object, IPv4 or IPv6. Defaults to IPv4.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER HostType
        Required. Type of the object: IP, Network, IPRange or IPList. Determines which of
        the address parameters below is required.

        .PARAMETER IPAddress
        Required for HostType IP or Network. The IP address.

        .PARAMETER Subnet
        Required for HostType Network. The subnet mask, for example 255.255.255.0.

        .PARAMETER StartIPAddress
        Required for HostType IPRange. The first address of the range.

        .PARAMETER EndIPAddress
        Required for HostType IPRange. The last address of the range.

        .PARAMETER ListOfIPAddresses
        Required for HostType IPList. One or more IP addresses.

        .PARAMETER HostGroupList
        Optional. Names of existing IP host groups to add the new object to. If omitted, the
        object is created without group membership.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosIPHost -Name 'WebServer01' -HostType IP -IPAddress '10.0.1.100' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosIPHost -Name 'WebServer01' -HostType IP -IPAddress '10.0.1.100' -Description 'Production web server'

        Creates a single-address IP host object.

        .EXAMPLE
        New-SfosIPHost -Name 'Office-LAN' -HostType Network -IPAddress '192.168.10.0' -Subnet '255.255.255.0'

        Creates a network object.

        .EXAMPLE
        New-SfosIPHost -Name 'DHCP-Pool' -HostType IPRange -StartIPAddress '192.168.10.100' -EndIPAddress '192.168.10.200'

        Creates an address range object.

        .EXAMPLE
        New-SfosIPHost -Name 'DMZ-Servers' -HostType IPList -ListOfIPAddresses '10.1.1.10', '10.1.1.20', '10.1.1.30'

        Creates an object holding several individual addresses.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an IP host object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing IP host object. The cmdlet reads the current object first and
        sends back a complete object, keeping every field the caller does not pass. Only the
        fields you actually supply are changed; pass a field explicitly to clear it. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the object to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosIPHost can be piped in directly.

        .PARAMETER IPFamily
        Optional. Address family of the object, IPv4 or IPv6. If omitted, the current value
        is kept.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER HostType
        Required. Type of the object: IP, Network, IPRange or IPList. Determines which of
        the address parameters below is required.

        .PARAMETER IPAddress
        Optional. The IP address, for HostType IP or Network. If omitted, the current value
        is kept.

        .PARAMETER Subnet
        Optional. The subnet mask, for HostType Network, for example 255.255.255.0. If
        omitted, the current value is kept.

        .PARAMETER StartIPAddress
        Optional. The first address of the range, for HostType IPRange. If omitted, the
        current value is kept.

        .PARAMETER EndIPAddress
        Optional. The last address of the range, for HostType IPRange. If omitted, the
        current value is kept.

        .PARAMETER ListOfIPAddresses
        Optional. One or more IP addresses, for HostType IPList. Accepts either an array of
        addresses or the single comma-separated string that Get-SfosIPHost returns. If
        omitted, the current value is kept.

        .PARAMETER HostGroupList
        Optional. Names of the IP host groups the object should belong to. Replaces the
        current group membership. If omitted, the current membership is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of an IP host object such as the ones returned
        by Get-SfosIPHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosIPHost -Name 'Example' -HostType IP -IPAddress '10.0.1.101' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosIPHost -Name 'Example' -HostType IP -IPAddress '10.0.1.101' -Description 'Updated web server'

        Changes the address and description of an existing object. HostType and the matching
        address parameter are mandatory even when only the description changes.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'Example' | Set-SfosIPHost -HostType IP -IPAddress '10.0.1.102'

        Updates the matching object through the pipeline.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHost

        .LINK
        New-SfosIPHost
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes an IP host object from a Sophos Firewall.

        .DESCRIPTION
        Deletes an IP host object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the object to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosIPHost can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        IP host object such as the ones returned by Get-SfosIPHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosIPHost -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosIPHost -NameLike 'OldServer' | Remove-SfosIPHost -WhatIf

        Previews the removal of every object whose name contains 'OldServer'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHost
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports IP host objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every IP host object from the firewall and writes it to a CSV or JSON file.
        Use this cmdlet for backup, documentation, or as input for Import-SfosIPHosts on the
        same or a different firewall. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        host objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes the file and throws an error if the export fails.

        .EXAMPLE
        Export-SfosIPHosts -FilePath 'C:\Exports\SophosIPHosts.csv'

        Exports every IP host object to a CSV file.

        .EXAMPLE
        Export-SfosIPHosts -FilePath 'C:\Exports\SophosIPHosts.csv' -Overwrite

        Exports the objects again, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHost

        .LINK
        Import-SfosIPHosts
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports IP host objects from a CSV file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV file written by Export-SfosIPHosts, or one with matching columns, and
        creates an IP host object on the firewall for each row through New-SfosIPHost. Rows
        without a name, rows whose name starts with '#', and rows with a missing or invalid
        HostType or address field are skipped and reported. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER FilePath
        Required. Full path of the CSV file to read.

        .PARAMETER Format
        Optional. The cmdlet always reads the file as CSV, whatever value is passed here.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet creates objects on the firewall and reports each success or failure
        as an information message.

        .EXAMPLE
        Import-SfosIPHosts -FilePath 'C:\Imports\SophosIPHosts.csv'

        Creates an IP host object for every valid row in the file.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPHost

        .LINK
        Export-SfosIPHosts
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves IP host group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the IP host groups that are defined on the firewall, including their member
        list. An IP host group bundles several IP host objects under one name for use in
        firewall rules and other policies. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        host group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per IP host group, with the
        properties Name, IPFamily, Description and HostList. Returns System.Xml.XmlElement
        when -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosIPHostGroup

        Lists every IP host group on the firewall of the current connection.

        .EXAMPLE
        Get-SfosIPHostGroup -NameLike 'Web'

        Lists all groups whose name contains 'Web'.

        .EXAMPLE
        (Get-SfosIPHostGroup -NameLike 'Web').HostList

        Shows the member list of the matching group or groups.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPHostGroup

        .LINK
        Set-SfosIPHostGroup

        .LINK
        Add-SfosIPHostGroupMember
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
        [object]$Session,
        
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
        Creates an IP host group on a Sophos Firewall.

        .DESCRIPTION
        Creates an IP host group, optionally with an initial set of members. Use a group to
        refer to several IP host objects at once in firewall rules and other policies. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the new group. 1 to 50 characters, must not contain a comma.

        .PARAMETER IPFamily
        Optional. Address family of the group, IPv4 or IPv6. Defaults to IPv4.

        .PARAMETER members
        Optional. Names of existing IP host objects to add as initial members. If omitted,
        the group is created empty.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosIPHostGroup -Name 'WebServers' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosIPHostGroup -Name 'WebServers' -Description 'Production web server farm'

        Creates an empty group.

        .EXAMPLE
        New-SfosIPHostGroup -Name 'DatabaseServers' -members 'DB-Primary', 'DB-Secondary' -Description 'Database cluster'

        Creates a group with two initial members.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an IP host group on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing IP host group. The cmdlet reads the current group first and
        sends back a complete object, keeping every field the caller does not pass. Only the
        fields you actually supply are changed; pass a field explicitly to clear it. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the group to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosIPHostGroup can be piped in directly.

        .PARAMETER IPFamily
        Optional. Address family of the group, IPv4 or IPv6. If omitted, the current value
        is kept.

        .PARAMETER members
        Optional. Names of the IP host objects the group should contain. Replaces the
        current member list. If omitted, the current members are kept.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of an IP host group object such as the ones
        returned by Get-SfosIPHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosIPHostGroup -Name 'Example' -Description 'Updated group' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosIPHostGroup -Name 'Example' -Description 'Updated group'

        Changes the description and keeps the current members.

        .EXAMPLE
        Get-SfosIPHostGroup -NameLike 'Example' | Set-SfosIPHostGroup -members 'Host1', 'Host2'

        Replaces the member list of the matching group through the pipeline.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHostGroup

        .LINK
        Add-SfosIPHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes an IP host group from a Sophos Firewall.

        .DESCRIPTION
        Deletes an IP host group by name. This does not delete the IP host objects that were
        members of the group. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with administrative
        permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the group to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosIPHostGroup can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        IP host group object such as the ones returned by Get-SfosIPHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosIPHostGroup -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosIPHostGroup -NameLike 'OldGroup' | Remove-SfosIPHostGroup -WhatIf

        Previews the removal of every group whose name contains 'OldGroup'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHostGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Adds members to an IP host group on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more IP host objects to an existing group, keeping the members that are
        already there. The cmdlet reads the current group first and sends back the combined
        member list, together with the current description and address family. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the group to add members to. Accepts pipeline input by value or by
        property name.

        .PARAMETER members
        Required. Names of the IP host objects to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        IP host group object such as the ones returned by Get-SfosIPHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosIPHostGroupMember -Name 'Example' -members 'Host1', 'Host2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosIPHostGroupMember -Name 'Example' -members 'Host1', 'Host2'

        Adds two IP host objects to the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHostGroup

        .LINK
        Remove-SfosIPHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes members from an IP host group on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more IP host objects from an existing group, keeping every other
        member. The cmdlet reads the current group first and sends back the reduced member
        list, together with the current description and address family. Names that are not
        currently members are ignored. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly, and an account with administrative
        permission.

        .PARAMETER Name
        Required. Name of the group to remove members from. Accepts pipeline input by value
        or by property name.

        .PARAMETER members
        Required. Names of the IP host objects to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        IP host group object such as the ones returned by Get-SfosIPHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosIPHostGroupMember -Name 'Example' -members 'Host1', 'Host2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosIPHostGroupMember -Name 'Example' -members 'Host1', 'Host2'

        Removes two IP host objects from the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHostGroup

        .LINK
        Add-SfosIPHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports IP host group objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every IP host group from the firewall and writes it to a CSV or JSON file,
        with the member list flattened to a comma-separated string. Use this cmdlet for
        backup, documentation, or as input for Import-SfosIPHostGroups on the same or a
        different firewall. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        host group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. The
        cmdlet also throws an error if the export itself fails.

        .EXAMPLE
        Export-SfosIPHostGroups -FilePath 'C:\Exports\IPHostGroups.csv'

        Exports every IP host group to a CSV file.

        .EXAMPLE
        Export-SfosIPHostGroups -FilePath 'C:\Exports\IPHostGroups.json' -Format AsJSON -Overwrite

        Exports the groups to a JSON file, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPHostGroup

        .LINK
        Import-SfosIPHostGroups
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports IP host group objects from a file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV or JSON file written by Export-SfosIPHostGroups, or one with matching
        structure, and creates an IP host group for each row through New-SfosIPHostGroup. In
        a CSV file, the member list is a single comma-separated string, for example
        'Host1,Host2'. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with administrative
        permission.

        .PARAMETER FilePath
        Required. Full path of the file to read.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Must match the file. Defaults to AsCSV.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. Each
        entry in FailedItems carries the object Name and the error message.

        .EXAMPLE
        Import-SfosIPHostGroups -FilePath 'C:\Imports\IPHostGroups.csv'

        Creates an IP host group for every row in the file.

        .EXAMPLE
        $result = Import-SfosIPHostGroups -FilePath 'C:\Imports\IPHostGroups.json' -Format AsJSON
        $result | Format-Table

        Imports from a JSON file and shows the summary.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPHostGroup

        .LINK
        Export-SfosIPHostGroups
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves FQDN host objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the FQDN host objects that are defined on the firewall. An FQDN host object
        stands for a domain name that the firewall resolves to its current IP addresses, and
        is used as source or destination in firewall rules and other policies where the
        address behind a name changes. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER FqdnLike
        Optional. Returns only objects whose domain name contains the given text anywhere.
        Applied on the client. If omitted, the domain name is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        FQDN host objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per FQDN host, with the
        properties Name, Description, FQDN and FQDNHostGroupList. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosFQDNHost

        Lists every FQDN host object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosFQDNHost -FqdnLike '.example.com'

        Lists all objects whose domain name contains '.example.com'.

        .EXAMPLE
        Get-SfosFQDNHost -NameLike 'Example' -AsXml

        Returns the raw XML of the matching objects.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosFQDNHost

        .LINK
        Set-SfosFQDNHost
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
        [object]$Session,
        
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
        Creates an FQDN host object on a Sophos Firewall.

        .DESCRIPTION
        Creates an FQDN host object for a domain name. The firewall resolves the name to its
        current IP addresses on its own; use this for cloud services, dynamic addresses or
        SaaS applications whose IP addresses change over time. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with administrative permission.

        .PARAMETER Name
        Required. Name of the new FQDN host object. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER FQDN
        Required. The domain name, up to 255 characters, for example 'mail.example.com' or
        '*.cloudapp.azure.com'.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER HostGroup
        Optional. Names of existing FQDN host groups to add the new object to. If omitted,
        the object is created without group membership.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosFQDNHost -Name 'Office365-Outlook' -FQDN 'outlook.office365.com' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosFQDNHost -Name 'Office365-Outlook' -FQDN 'outlook.office365.com' -Description 'Microsoft Office 365 Outlook'

        Creates an FQDN host object.

        .EXAMPLE
        New-SfosFQDNHost -Name 'SalesforceAPI' -FQDN 'api.salesforce.com' -HostGroup 'SaaSServices', 'CriticalServices'

        Creates an object and adds it to two FQDN host groups.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an FQDN host object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing FQDN host object. The cmdlet reads the current object first and
        sends back a complete object, keeping every field the caller does not pass. Only the
        fields you actually supply are changed; pass a field explicitly to clear it. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the object to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosFQDNHost can be piped in directly.

        .PARAMETER FQDN
        Required. The domain name, up to 255 characters.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER HostGroup
        Optional. Names of the FQDN host groups the object should belong to. Replaces the
        current group membership. If omitted, the current membership is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of an FQDN host object such as the ones returned
        by Get-SfosFQDNHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosFQDNHost -Name 'Example' -FQDN 'www.example.com' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFQDNHost -Name 'Example' -FQDN 'www.example.com'

        Changes the domain name of an existing object.

        .EXAMPLE
        Get-SfosFQDNHost -NameLike 'Example' | Set-SfosFQDNHost -FQDN 'app.example.com'

        Updates the matching object through the pipeline.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHost

        .LINK
        New-SfosFQDNHost
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes an FQDN host object from a Sophos Firewall.

        .DESCRIPTION
        Deletes an FQDN host object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the object to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosFQDNHost can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        FQDN host object such as the ones returned by Get-SfosFQDNHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosFQDNHost -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosFQDNHost -NameLike 'OldService' | Remove-SfosFQDNHost -WhatIf

        Previews the removal of every object whose name contains 'OldService'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHost

        .LINK
        Remove-SfosFQDNHostMass
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes several FQDN host objects from a Sophos Firewall in one request.

        .DESCRIPTION
        Deletes one or more FQDN host objects by name in a single call to the firewall,
        instead of one call per object. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Names
        Required. Names of the objects to remove. Accepts pipeline input by value or by
        property name.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts one or more FQDN host names, for example from the Name
        property of Get-SfosFQDNHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosFQDNHostMass -Names 'Host1', 'Host2', 'Host3' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        (Get-SfosFQDNHost -NameLike 'Old').Name | Remove-SfosFQDNHostMass -WhatIf

        Previews the removal of every object whose name contains 'Old', in a single request.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHost

        .LINK
        Remove-SfosFQDNHost
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports FQDN host objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every FQDN host object from the firewall and writes it to a CSV or JSON
        file. Use this cmdlet for backup, documentation, or as input for Import-SfosFQDNHosts
        on the same or a different firewall. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        FQDN host objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. The
        cmdlet also throws an error if the export itself fails.

        .EXAMPLE
        Export-SfosFQDNHosts -FilePath 'C:\Exports\FQDNHosts.csv'

        Exports every FQDN host object to a CSV file.

        .EXAMPLE
        Export-SfosFQDNHosts -FilePath 'C:\Exports\FQDNHosts.json' -Format AsJSON -Overwrite

        Exports the objects to a JSON file, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHost

        .LINK
        Import-SfosFQDNHosts
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports FQDN host objects from a file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV or JSON file written by Export-SfosFQDNHosts, or one with matching
        structure, and creates an FQDN host object for each row through New-SfosFQDNHost. In
        a CSV file, the group membership is a single comma-separated string, for example
        'Group1,Group2'. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with administrative
        permission.

        .PARAMETER FilePath
        Required. Full path of the file to read.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Must match the file. Defaults to AsCSV.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. Each
        entry in FailedItems carries the object Name and the error message.

        .EXAMPLE
        Import-SfosFQDNHosts -FilePath 'C:\Imports\FQDNHosts.csv'

        Creates an FQDN host object for every row in the file.

        .EXAMPLE
        $result = Import-SfosFQDNHosts -FilePath 'C:\Imports\FQDNHosts.json' -Format AsJSON
        $result | Format-Table

        Imports from a JSON file and shows the summary.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosFQDNHost

        .LINK
        Export-SfosFQDNHosts
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves FQDN host group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the FQDN host groups that are defined on the firewall, including their
        member list. An FQDN host group bundles several FQDN host objects under one name for
        use in firewall rules and other policies. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        FQDN host group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per FQDN host group, with the
        properties Name, Description and FQDNHostList. Returns System.Xml.XmlElement when
        -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosFQDNHostGroup

        Lists every FQDN host group on the firewall of the current connection.

        .EXAMPLE
        Get-SfosFQDNHostGroup -NameLike 'SaaS'

        Lists all groups whose name contains 'SaaS'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosFQDNHostGroup

        .LINK
        Add-SfosFQDNHostGroupMember
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
        [object]$Session,
        
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
        Creates an FQDN host group on a Sophos Firewall.

        .DESCRIPTION
        Creates an FQDN host group, optionally with an initial set of members. Use a group to
        refer to several FQDN host objects at once in firewall rules and other policies. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the new group. 1 to 50 characters, must not contain a comma.

        .PARAMETER members
        Optional. Names of existing FQDN host objects to add as initial members. If omitted,
        the group is created empty.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosFQDNHostGroup -Name 'Example' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosFQDNHostGroup -Name 'SaaSServices' -members 'Office365-Outlook', 'SalesforceAPI'

        Creates a group with two initial members.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHostGroup

        .LINK
        Add-SfosFQDNHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an FQDN host group on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing FQDN host group. The cmdlet reads the current group first and
        sends back a complete object, keeping every field the caller does not pass. Only the
        fields you actually supply are changed; pass a field explicitly to clear it. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the group to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosFQDNHostGroup can be piped in directly.

        .PARAMETER members
        Optional. Names of the FQDN host objects the group should contain. Replaces the
        current member list. If omitted, the current members are kept.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of an FQDN host group object such as the ones
        returned by Get-SfosFQDNHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosFQDNHostGroup -Name 'Example' -Description 'Updated group' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFQDNHostGroup -Name 'Example' -Description 'Updated group'

        Changes the description and keeps the current members.

        .EXAMPLE
        Get-SfosFQDNHostGroup -NameLike 'Example' | Set-SfosFQDNHostGroup -members 'Host1', 'Host2'

        Replaces the member list of the matching group through the pipeline.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHostGroup

        .LINK
        Add-SfosFQDNHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes an FQDN host group from a Sophos Firewall.

        .DESCRIPTION
        Deletes an FQDN host group by name. This does not delete the FQDN host objects that
        were members of the group. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with administrative
        permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the group to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosFQDNHostGroup can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        FQDN host group object such as the ones returned by Get-SfosFQDNHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosFQDNHostGroup -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosFQDNHostGroup -NameLike 'OldGroup' | Remove-SfosFQDNHostGroup -WhatIf

        Previews the removal of every group whose name contains 'OldGroup'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHostGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Adds members to an FQDN host group on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more FQDN host objects to an existing group, keeping the members that are
        already there. The cmdlet reads the current group first and sends back the combined
        member list, together with the current description. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the group to add members to. Accepts pipeline input by value or by
        property name.

        .PARAMETER members
        Required. Names of the FQDN host objects to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        FQDN host group object such as the ones returned by Get-SfosFQDNHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosFQDNHostGroupMember -Name 'Example' -members 'Host1', 'Host2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosFQDNHostGroupMember -Name 'Example' -members 'Host1', 'Host2'

        Adds two FQDN host objects to the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHostGroup

        .LINK
        Remove-SfosFQDNHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes members from an FQDN host group on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more FQDN host objects from an existing group, keeping every other
        member. The cmdlet reads the current group first and sends back the reduced member
        list, together with the current description. Names that are not currently members
        are ignored. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the group to remove members from. Accepts pipeline input by value
        or by property name.

        .PARAMETER members
        Required. Names of the FQDN host objects to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of an
        FQDN host group object such as the ones returned by Get-SfosFQDNHostGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosFQDNHostGroupMember -Name 'Example' -members 'Host1', 'Host2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosFQDNHostGroupMember -Name 'Example' -members 'Host1', 'Host2'

        Removes two FQDN host objects from the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHostGroup

        .LINK
        Add-SfosFQDNHostGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports FQDN host group objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every FQDN host group from the firewall and writes it to a CSV or JSON
        file, with the member list flattened to a comma-separated string. Use this cmdlet for
        backup, documentation, or as input for Import-SfosFQDNHostGroups on the same or a
        different firewall. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        FQDN host group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. The
        cmdlet also throws an error if the export itself fails.

        .EXAMPLE
        Export-SfosFQDNHostGroups -FilePath 'C:\Exports\FQDNHostGroups.csv'

        Exports every FQDN host group to a CSV file.

        .EXAMPLE
        Export-SfosFQDNHostGroups -FilePath 'C:\Exports\FQDNHostGroups.json' -Format AsJSON -Overwrite

        Exports the groups to a JSON file, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFQDNHostGroup

        .LINK
        Import-SfosFQDNHostGroups
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports FQDN host group objects from a file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV or JSON file written by Export-SfosFQDNHostGroups, or one with matching
        structure, and creates an FQDN host group for each row through New-SfosFQDNHostGroup.
        In a CSV file, the member list is a JSON array, for example ["Host1","Host2"]. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with administrative permission.

        .PARAMETER FilePath
        Required. Full path of the file to read.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Must match the file. Defaults to AsCSV.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. Each
        entry in FailedItems carries the object Name and the error message.

        .EXAMPLE
        Import-SfosFQDNHostGroups -FilePath 'C:\Imports\FQDNHostGroups.csv'

        Creates an FQDN host group for every row in the file.

        .EXAMPLE
        $result = Import-SfosFQDNHostGroups -FilePath 'C:\Imports\FQDNHostGroups.json' -Format AsJSON
        $result | Format-Table

        Imports from a JSON file and shows the summary.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosFQDNHostGroup

        .LINK
        Export-SfosFQDNHostGroups
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves MAC host objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the MAC host objects that are defined on the firewall. A MAC host object
        identifies a device by its hardware address instead of an IP address, and is used as
        source or destination in firewall rules and other policies where the address should
        not depend on IP assignment. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER MACAddressLike
        Optional. Returns only objects whose MAC address contains the given text anywhere.
        Applied on the client. If omitted, the address is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        MAC host objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per MAC host, with the
        properties Name, Type, MACAddress, MACList and Description. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosMACHost

        Lists every MAC host object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosMACHost -NameLike 'Laptop'

        Lists all objects whose name contains 'Laptop'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosMACHost

        .LINK
        Set-SfosMACHost
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
        [object]$Session,
        
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
        Creates a MAC host object on a Sophos Firewall.

        .DESCRIPTION
        Creates a MAC host object that identifies one or more devices by their hardware
        address. Use this for device-based firewall rules, guest network management, IoT
        device control or BYOD policies where the rule should not depend on IP assignment.
        It needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the new MAC host object. 1 to 60 characters, must not contain a
        comma.

        .PARAMETER MACAddress
        Required. One MAC address, or several separated by commas, for example
        '00:11:22:33:44:55' or '00:11:22:33:44:55,AA:BB:CC:DD:EE:FF'. Colon-separated,
        hyphen-separated and unseparated notation are all accepted.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosMACHost -Name 'CEO-Laptop' -MACAddress '00:11:22:33:44:55' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosMACHost -Name 'CEO-Laptop' -MACAddress '00:11:22:33:44:55' -Description 'Executive laptop'

        Creates a MAC host object for a single device.

        .EXAMPLE
        New-SfosMACHost -Name 'Server-Dual-NIC' -MACAddress '00:11:22:33:44:55,00:11:22:33:44:66' -Description 'Server with two network cards'

        Creates a MAC host object covering two addresses of the same device.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a MAC host object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing MAC host object. The cmdlet reads the current object first and
        sends back a complete object, keeping the current description unless the caller
        passes one. Pass an empty description explicitly to clear it. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the object to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosMACHost can be piped in directly.

        .PARAMETER MACAddress
        Required. One MAC address, or several separated by commas, replacing the current
        address or address list, for example '00:11:22:33:44:55' or
        '00:11:22:33:44:55,AA:BB:CC:DD:EE:FF'.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        MACAddress, by property name, of a MAC host object such as the ones returned by
        Get-SfosMACHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosMACHost -Name 'Example' -MACAddress '00:11:22:33:44:55' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosMACHost -Name 'Example' -MACAddress '00:11:22:33:44:55'

        Changes the address of an existing object.

        .EXAMPLE
        Get-SfosMACHost -NameLike 'Example' | Set-SfosMACHost

        Rewrites the matching object through the pipeline, unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosMACHost

        .LINK
        New-SfosMACHost
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a MAC host object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a MAC host object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the object to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosMACHost can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of a
        MAC host object such as the ones returned by Get-SfosMACHost.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosMACHost -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosMACHost -NameLike 'OldDevice' | Remove-SfosMACHost -WhatIf

        Previews the removal of every object whose name contains 'OldDevice'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosMACHost
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports MAC host objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every MAC host object from the firewall and writes it to a CSV or JSON
        file, with a single-address object and a multi-address object both flattened to the
        same comma-separated MACAddress column that New-SfosMACHost expects. Use this cmdlet
        for backup, documentation, or as input for Import-SfosMACHosts on the same or a
        different firewall. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        MAC host objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. The
        cmdlet also throws an error if the export itself fails.

        .EXAMPLE
        Export-SfosMACHosts -FilePath 'C:\Exports\MACHosts.csv'

        Exports every MAC host object to a CSV file.

        .EXAMPLE
        Export-SfosMACHosts -FilePath 'C:\Exports\MACHosts.json' -Format AsJSON -Overwrite

        Exports the objects to a JSON file, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosMACHost

        .LINK
        Import-SfosMACHosts
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports MAC host objects from a file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV or JSON file written by Export-SfosMACHosts, or one with matching
        structure, and creates a MAC host object for each row through New-SfosMACHost. The
        MACAddress column holds a single address or a comma-separated list. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with administrative permission.

        .PARAMETER FilePath
        Required. Full path of the file to read.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Must match the file. Defaults to AsCSV.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. Each
        entry in FailedItems carries the object Name and the error message.

        .EXAMPLE
        Import-SfosMACHosts -FilePath 'C:\Imports\MACHosts.csv'

        Creates a MAC host object for every row in the file.

        .EXAMPLE
        $result = Import-SfosMACHosts -FilePath 'C:\Imports\MACHosts.json' -Format AsJSON
        $result | Format-Table

        Imports from a JSON file and shows the summary.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosMACHost

        .LINK
        Export-SfosMACHosts
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves country group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the country groups that are defined on the firewall. A country group bundles
        one or more countries, matched by the firewall's Geo-IP database, for use in firewall
        rules and other policies, for example to restrict access by geography. The cmdlet
        only reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        country group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per country group, with the
        properties Name, Description and Countries. The Countries property holds the group's
        member list, named after the underlying CountryList element. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosCountryGroup

        Lists every country group on the firewall of the current connection.

        .EXAMPLE
        (Get-SfosCountryGroup -NameLike 'Blocklist').Countries

        Shows the member countries of the matching group or groups.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosCountryGroup

        .LINK
        Set-SfosCountryGroup
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
        [object]$Session,
        
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
        Creates a country group on a Sophos Firewall.

        .DESCRIPTION
        Creates a country group backed by the firewall's Geo-IP database. Use a country
        group for geographic access restrictions, compliance requirements or blocking
        high-risk regions in firewall rules and other policies. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with administrative permission.

        .PARAMETER Name
        Required. Name of the new group. 1 to 50 characters, must not contain a comma.

        .PARAMETER countries
        Optional. Country names as the firewall spells them, for example 'Germany' or
        'United Kingdom'. Use Get-SfosCountryGroup on an existing group to see the exact
        spelling the firewall expects. If omitted, the group is created empty.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosCountryGroup -Name 'EU-Countries' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosCountryGroup -Name 'EU-Countries' -countries 'Germany', 'France', 'Italy', 'Spain', 'Netherlands' -Description 'European Union member states'

        Creates a group covering several countries.

        .EXAMPLE
        New-SfosCountryGroup -Name 'Germany-Only' -countries 'Germany' -Description 'German IP addresses only'

        Creates a single-country group.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a country group on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing country group. The cmdlet reads the current group first and
        sends back a complete object, keeping the current description unless the caller
        passes one. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the group to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosCountryGroup can be piped in directly.

        .PARAMETER countries
        Required. Country names as the firewall spells them, for example 'Germany' or
        'United Kingdom', replacing the current member list.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of a country group object such as the ones
        returned by Get-SfosCountryGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosCountryGroup -Name 'Example' -countries 'Germany', 'France' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosCountryGroup -Name 'Example' -countries 'Germany', 'France'

        Replaces the member list of an existing group.

        .EXAMPLE
        Get-SfosCountryGroup -NameLike 'Example' | Set-SfosCountryGroup

        Rewrites the matching group through the pipeline, keeping its current members and
        description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosCountryGroup

        .LINK
        New-SfosCountryGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a country group from a Sophos Firewall.

        .DESCRIPTION
        Deletes a country group by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the group to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosCountryGroup can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of a
        country group object such as the ones returned by Get-SfosCountryGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosCountryGroup -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosCountryGroup -NameLike 'OldGroup' | Remove-SfosCountryGroup -WhatIf

        Previews the removal of every group whose name contains 'OldGroup'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosCountryGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves service objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the service objects that are defined on the firewall. A service object
        stands for a TCP or UDP port or port range, an IP protocol, or an ICMP or ICMPv6
        type and code, and is used in firewall rules to define the traffic a rule matches.
        The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly.

        Returns the service's ICMP type as text, for example 'Echo', while New-SfosService
        and Set-SfosService expect the numeric code. A value read with this cmdlet cannot be
        passed straight into New-SfosService for an ICMP service.

        You can combine several filters. NameLike, DescriptionLike and TypeLike are sent to
        the firewall, but it evaluates at most one of them, so every filter you supply is
        applied again on the client. ProtocolLike, SourcePortLike and DestinationPortLike are
        always applied on the client. The result always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        If omitted, the description is not used to filter.

        .PARAMETER TypeLike
        Optional. Returns only objects of one service type. Valid values: TCPorUDP, IP,
        ICMP, ICMPv6. If omitted, all service types are returned.

        .PARAMETER ProtocolLike
        Optional. Returns only TCP or UDP services whose protocol contains the given text
        anywhere, for example 'TCP'. Applied on the client. If omitted, the protocol is not
        used to filter.

        .PARAMETER SourcePortLike
        Optional. Returns only TCP or UDP services whose source port contains the given text
        anywhere. Applied on the client. If omitted, the source port is not used to filter.

        .PARAMETER DestinationPortLike
        Optional. Returns only TCP or UDP services whose destination port contains the given
        text anywhere. Applied on the client. If omitted, the destination port is not used
        to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        service objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per service, with the
        properties Name, Description, Type and ServiceDetails. ServiceDetails holds the
        type-specific fields (for example SourcePort/DestinationPort/Protocol for a TCP or
        UDP service). Returns System.Xml.XmlElement when -AsXml is used, and an empty array
        when no object matches.

        .EXAMPLE
        Get-SfosService

        Lists every service object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosService -NameLike 'HTTP'

        Lists all services whose name contains 'HTTP'.

        .EXAMPLE
        Get-SfosService -TypeLike TCPorUDP -DestinationPortLike '443'

        Lists all TCP or UDP services whose destination port contains '443'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosService

        .LINK
        Set-SfosService
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
        [object]$Session,
        
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
        Creates a service object on a Sophos Firewall.

        .DESCRIPTION
        Creates a service object for a TCP or UDP port or port range, an IP protocol, or an
        ICMP or ICMPv6 type and code. Use a service object in firewall rules to define the
        traffic the rule matches. The parameters below fall into four groups, one per service
        type; supply the group that matches -Type. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the new service. 1 to 50 characters, must not contain a comma.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER Type
        Optional. Service type for the TCP/UDP group, TCPorUDP, IP, ICMP or ICMPv6. Defaults
        to TCPorUDP. For the IP, ICMP and ICMPv6 groups the type follows from the parameters
        supplied and does not need to be set here.

        .PARAMETER Protocol
        Required for a TCP or UDP service. The protocol, TCP or UDP.

        .PARAMETER DstPort
        Required for a TCP or UDP service. The destination port or port range, for example
        '443' or '8080-8090'.

        .PARAMETER SrcPort
        Optional. The source port or port range, for a TCP or UDP service. Defaults to
        '1:65535' (all ports).

        .PARAMETER ProtocolName
        Required for an IP protocol service. The protocol name, for example 'GRE', 'ESP' or
        'OSPFIGP'.

        .PARAMETER ICMPType
        Required for an ICMP service. One or more ICMP types. Use -1 for any type.

        .PARAMETER ICMPCode
        Optional. One or more ICMP codes, for an ICMP service. Use -1 for any code. If
        omitted, the service is created with code -1 (any code).

        .PARAMETER ICMPv6Type
        Required for an ICMPv6 service. One or more ICMPv6 types. Use -1 for any type.

        .PARAMETER ICMPv6Code
        Optional. One or more ICMPv6 codes, for an ICMPv6 service. Use -1 for any code. If
        omitted, the service is created with code -1 (any code).

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosService -Name 'HTTPS-Custom' -Protocol TCP -DstPort 8443 -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosService -Name 'HTTPS-Custom' -Protocol TCP -DstPort 8443 -Description 'Custom HTTPS port'

        Creates a TCP service for a single port.

        .EXAMPLE
        New-SfosService -Name 'GRE-Protocol' -ProtocolName 'GRE' -Description 'Generic Routing Encapsulation'

        Creates an IP protocol service.

        .EXAMPLE
        New-SfosService -Name 'ICMP-Echo' -ICMPType '8' -ICMPCode '0' -Description 'Ping requests'

        Creates an ICMP service. -ICMPType selects the ICMP group on its own; -Type is not
        needed here.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosService

        .LINK
        Set-SfosService

        .LINK
        Remove-SfosService
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
            # is rejected with 501 by the firewall.
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
        Updates a service object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing service object. The cmdlet reads the current object first and
        sends back a complete object, keeping every field the caller does not pass -
        Description, Type, and whichever detail fields belong to the current type. Only the
        fields you actually supply are changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the service to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosService can be piped in directly.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Type
        Optional. Service type, TCPorUDP, IP, ICMP or ICMPv6. If omitted, the current type is
        kept.

        .PARAMETER Protocol
        Optional. The protocol, TCP or UDP, for a TCPorUDP service. If omitted, the current
        value is kept.

        .PARAMETER DstPort
        Optional. The destination port or port range, for a TCPorUDP service. If omitted,
        the current value is kept.

        .PARAMETER SrcPort
        Optional. The source port or port range, for a TCPorUDP service. If omitted, the
        current value is kept.

        .PARAMETER ProtocolName
        Optional. The protocol name, for an IP service. If omitted, the current value is
        kept.

        .PARAMETER ICMPType
        Optional. One or more ICMP types, for an ICMP service. If omitted, the current value
        is kept.

        .PARAMETER ICMPCode
        Optional. One or more ICMP codes, for an ICMP service. If omitted, the current value
        is kept.

        .PARAMETER ICMPv6Type
        Optional. One or more ICMPv6 types, for an ICMPv6 service. If omitted, the current
        value is kept.

        .PARAMETER ICMPv6Code
        Optional. One or more ICMPv6 codes, for an ICMPv6 service. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of a service object such as the ones returned by
        Get-SfosService.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosService -Name 'HTTPS-Custom' -DstPort 8444 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosService -Name 'HTTPS-Custom' -DstPort 8444

        Changes the destination port of an existing TCP or UDP service, keeping its protocol
        and source port.

        .EXAMPLE
        Set-SfosService -Name 'ICMP-Echo' -Description 'Ping requests, updated'

        Changes the description of an existing ICMP service, keeping its type and code.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a service object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a service object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the object to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosService can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of a
        service object such as the ones returned by Get-SfosService.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosService -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosService -NameLike 'Deprecated' | Remove-SfosService -WhatIf

        Previews the removal of every object whose name contains 'Deprecated'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosService
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports service objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every service object from the firewall and writes it to a CSV or JSON
        file, with the nested ServiceDetails flattened into columns that match the
        New-SfosService parameter names for the object's type. Only the first detail entry
        of a service is exported; New-SfosService can only create one detail entry per call,
        so a service with more than one cannot round-trip through Import-SfosServices in any
        case. Use this cmdlet for backup, documentation, or as input for Import-SfosServices
        on the same or a different firewall. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        service objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. The
        cmdlet also throws an error if the export itself fails.

        .EXAMPLE
        Export-SfosServices -FilePath 'C:\Exports\Services.csv'

        Exports every service object to a CSV file.

        .EXAMPLE
        Export-SfosServices -FilePath 'C:\Exports\Services.json' -Format AsJSON -Overwrite

        Exports the objects to a JSON file, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosService

        .LINK
        Import-SfosServices
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports service objects from a file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV or JSON file written by Export-SfosServices, or one with matching flat
        columns, and creates a service object for each row through New-SfosService. The
        columns are Name, Description, Type, and then Protocol/SrcPort/DstPort for a
        TCPorUDP row, ProtocolName for an IP row, or ICMPType/ICMPCode and
        ICMPv6Type/ICMPv6Code for the ICMP families.

        A row of Type ICMP or ICMPv6 is always reported as a failed item and no object is
        created for it: Get-SfosService returns the ICMP type as text (for example 'Echo'),
        while New-SfosService requires the numeric code, so the two sides cannot be matched
        automatically. Recreate those services with New-SfosService directly. TCPorUDP and
        IP rows import without this restriction. The cmdlet needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER FilePath
        Required. Full path of the file to read.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Must match the file. Defaults to AsCSV.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. Each
        entry in FailedItems carries the object Name and the error message.

        .EXAMPLE
        Import-SfosServices -FilePath 'C:\Imports\Services.csv'

        Creates a service object for every row in the file that Type allows.

        .EXAMPLE
        $result = Import-SfosServices -FilePath 'C:\Imports\Services.json' -Format AsJSON
        $result | Format-Table

        Imports from a JSON file and shows the summary, including any ICMP or ICMPv6 rows
        that were reported as failed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosService

        .LINK
        Export-SfosServices
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves service group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the service groups that are defined on the firewall. A service group bundles
        several service objects under one name for use in firewall rules and other policies.
        The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        service group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per service group, with the
        properties Name, Description and ServiceList. Returns System.Xml.XmlElement when
        -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosServiceGroup

        Lists every service group on the firewall of the current connection.

        .EXAMPLE
        Get-SfosServiceGroup -NameLike 'Web'

        Lists all groups whose name contains 'Web'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosServiceGroup

        .LINK
        Add-SfosServiceGroupMember
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
        [object]$Session,
        
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
        Creates a service group on a Sophos Firewall.

        .DESCRIPTION
        Creates a service group with an initial set of member services. Use a group to refer
        to several service objects at once in firewall rules and other policies. The firewall
        requires at least one member at creation, unlike an IP host group or an FQDN host
        group, which may be created empty. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the new group. 1 to 50 characters, must not contain a comma.

        .PARAMETER members
        Required. Names of existing service objects to add as members. At least one is
        required.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosServiceGroup -Name 'WebServices' -members 'HTTP', 'HTTPS' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosServiceGroup -Name 'WebServices' -members 'HTTP', 'HTTPS' -Description 'Standard web traffic'

        Creates a group with two member services.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosServiceGroup

        .LINK
        Add-SfosServiceGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a service group on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing service group. The cmdlet reads the current group first and
        sends back a complete object, keeping the current description unless the caller
        passes one. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the group to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosServiceGroup can be piped in directly.

        .PARAMETER members
        Required. Names of the service objects the group should contain, replacing the
        current member list.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name and
        other properties, by property name, of a service group object such as the ones
        returned by Get-SfosServiceGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosServiceGroup -Name 'Example' -members 'HTTP', 'HTTPS' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosServiceGroup -Name 'Example' -members 'HTTP', 'HTTPS'

        Replaces the member list of an existing group.

        .EXAMPLE
        Get-SfosServiceGroup -NameLike 'Example' | Set-SfosServiceGroup

        Rewrites the matching group through the pipeline, using its current member list and
        description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosServiceGroup

        .LINK
        Add-SfosServiceGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a service group from a Sophos Firewall.

        .DESCRIPTION
        Deletes a service group by name. This does not delete the service objects that were
        members of the group. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with administrative
        permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the group to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosServiceGroup can be piped in directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of a
        service group object such as the ones returned by Get-SfosServiceGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosServiceGroup -Name 'Example' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosServiceGroup -NameLike 'OldGroup' | Remove-SfosServiceGroup -WhatIf

        Previews the removal of every group whose name contains 'OldGroup'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosServiceGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Adds members to a service group on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more service objects to an existing group, keeping the members that are
        already there. The cmdlet reads the current group first and sends back the combined
        member list, together with the current description. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the group to add members to. Accepts pipeline input by value or by
        property name. The alias ServiceGroupName is also accepted.

        .PARAMETER members
        Required. Names of the service objects to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of a
        service group object such as the ones returned by Get-SfosServiceGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosServiceGroupMember -Name 'ExampleGroup' -members 'Service1', 'Service2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosServiceGroupMember -Name 'ExampleGroup' -members 'Service1', 'Service2'

        Adds two service objects to the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosServiceGroup

        .LINK
        Remove-SfosServiceGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes members from a service group on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more service objects from an existing group, keeping every other
        member. The cmdlet reads the current group first and sends back the reduced member
        list, together with the current description. Names that are not currently members
        are ignored. The firewall does not allow a service group to end up with no members;
        removing the last remaining members throws an error instead, and the group has to be
        deleted with Remove-SfosServiceGroup. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the group to remove members from. Accepts pipeline input by value
        or by property name.

        .PARAMETER members
        Required. Names of the service objects to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String or System.Management.Automation.PSCustomObject. Accepts the Name of a
        service group object such as the ones returned by Get-SfosServiceGroup.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosServiceGroupMember -Name 'ExampleGroup' -members 'Service1', 'Service2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosServiceGroupMember -Name 'ExampleGroup' -members 'Service1', 'Service2'

        Removes two service objects from the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosServiceGroup

        .LINK
        Add-SfosServiceGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports service group objects from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every service group from the firewall and writes it to a CSV or JSON file,
        with the member list flattened to a comma-separated string. Use this cmdlet for
        backup, documentation, or as input for Import-SfosServiceGroups on the same or a
        different firewall. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path of the file to write.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Defaults to AsCSV.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, the cmdlet throws an
        error when the file exists.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        service group objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. The
        cmdlet also throws an error if the export itself fails.

        .EXAMPLE
        Export-SfosServiceGroups -FilePath 'C:\Exports\ServiceGroups.csv'

        Exports every service group to a CSV file.

        .EXAMPLE
        Export-SfosServiceGroups -FilePath 'C:\Exports\ServiceGroups.json' -Format AsJSON -Overwrite

        Exports the groups to a JSON file, replacing a file left over from a previous run.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosServiceGroup

        .LINK
        Import-SfosServiceGroups
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports service group objects from a file onto a Sophos Firewall.

        .DESCRIPTION
        Reads a CSV or JSON file written by Export-SfosServiceGroups, or one with matching
        structure, and creates a service group for each row through New-SfosServiceGroup. In
        a CSV file, the member list is a single comma-separated string, for example
        'Service1,Service2'. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with administrative
        permission.

        .PARAMETER FilePath
        Required. Full path of the file to read.

        .PARAMETER Format
        Optional. File format, AsCSV or AsJSON. Must match the file. Defaults to AsCSV.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs administrative permission.
        If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A summary with the properties
        Operation, ObjectType, Total, Success, Failed, SuccessItems and FailedItems. Each
        entry in FailedItems carries the object Name and the error message.

        .EXAMPLE
        Import-SfosServiceGroups -FilePath 'C:\Imports\ServiceGroups.csv'

        Creates a service group for every row in the file.

        .EXAMPLE
        $result = Import-SfosServiceGroups -FilePath 'C:\Imports\ServiceGroups.json' -Format AsJSON
        $result | Format-Table

        Imports from a JSON file and shows the summary.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosServiceGroup

        .LINK
        Export-SfosServiceGroups
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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



