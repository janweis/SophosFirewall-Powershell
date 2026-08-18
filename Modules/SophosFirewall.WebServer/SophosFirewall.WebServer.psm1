#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.1' }

<#
.SYNOPSIS
    Manages Web Server Protection (WAF) on a Sophos Firewall: web servers, protection
    policies, authentication policies and templates, and slow HTTP protection.

.DESCRIPTION
    Functions for the PROTECT > Web server area of the Sophos Firewall XML API (SFOS 22.0),
    the reverse proxy that publishes an internal web server to the outside and filters the
    traffic on its way in.

    A web server names the internal machine and the port it listens on. A protection policy
    decides what the firewall does with a request before it reaches that machine - request
    size limits, form and URL hardening, virus scanning and the threat filters. An
    authentication policy puts a login in front of the published server and can pass the
    credentials on to it; an authentication template supplies the HTML form such a policy
    shows. Slow HTTP protection guards against clients that hold connections open by sending
    their request headers a byte at a time.

    Total Functions: 22 (18 exported, 4 internal helpers) - see README.md for the full
    cmdlet table.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

    Two limitations are inherent to the API, not to this module:

    - An authentication template can be created, changed and read, but not removed - the
      firewall answers every removal with 200 whether or not it did anything.
    - Reading a template that exists returns the raw archive the firewall sends
      (application/octet-stream), not parsed fields.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosWebServer

    Connects to the firewall and lists every published web server.

.EXAMPLE
    New-SfosWebServer -Name 'IntranetServer' -HostName 'IntranetServerHost' -PortNumber 8080
    New-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Mode Reject -RequestSizeLimitMB 10

    Publishes an internal web server and creates a protection policy for it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>

#region RealServers

<#
.SYNOPSIS
    Builds the Set request body for a Web Server (RealServers) entity.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on a RealServers entity, so New- and
    Set-SfosWebServer send the same entity shape. The firewall replaces the whole entity on
    update, so the caller merges every field it wants to keep into -WebServer first.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER WebServer
    The object to convert, with the properties Name, Description, Host, Type, Port,
    KeepAlive, TimeOut and DisableReuse.
#>
function ConvertTo-SfosWebServerEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$WebServer
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$WebServer.Name)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$WebServer.Description)
    $hostEsc = ConvertTo-SfosXmlEscaped -Text ([string]$WebServer.Host)
    $typeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$WebServer.Type)
    $keepAliveEsc = ConvertTo-SfosXmlEscaped -Text ([string]$WebServer.KeepAlive)
    $disableReuseEsc = ConvertTo-SfosXmlEscaped -Text ([string]$WebServer.DisableReuse)

    return @"
<Set operation="$Operation">
  <RealServers>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <Host>$hostEsc</Host>
    <Type>$typeEsc</Type>
    <Port>$([int]$WebServer.Port)</Port>
    <KeepAlive>$keepAliveEsc</KeepAlive>
    <TimeOut>$([int]$WebServer.TimeOut)</TimeOut>
    <DisableReuse>$disableReuseEsc</DisableReuse>
  </RealServers>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves Web Server (real server / backend) objects from a Sophos Firewall.

.DESCRIPTION
    Returns Web Server objects (PROTECT > Web Server > Web Servers). A Web Server object
    describes one backend real server behind the WAF: which host to forward to, on which
    port and protocol, and the keep-alive/reuse behaviour of the connection to it. It is
    referenced by name from a Protection Policy assignment on the firewall's web server
    protection configuration.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern, sent to the firewall as a server-side pre-filter
    and re-applied client-side. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per Web Server, with the
    properties Name, Description, Host, Type, Port, KeepAlive, TimeOut and DisableReuse.
    Host is the name of the referenced IPHost/FQDNHost object, not an IP address. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosWebServer

    Lists every Web Server object on the firewall of the current connection.

.EXAMPLE
    Get-SfosWebServer -NameLike 'Exchange'

    Lists all Web Server objects whose name contains 'Exchange'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/Backend/RealServers.html

.LINK
    New-SfosWebServer
#>
function Get-SfosWebServer {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Name is the only server-side filter key measured to work for this entity (see the
    # RealServers filter probe in the module report). Everything is also re-applied
    # client-side below, so a wrongly "supported" key here would only cost an extra row,
    # never a missed one.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <RealServers>
    $filterXml
  </RealServers>
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
        throw "Error retrieving RealServers objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RealServers' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/RealServers[Name]' | ForEach-Object -Process { $_.Node }

    $webServerObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name         = [string]$node.Name
            Description  = [string]$node.Description
            Host         = [string]$node.Host
            Type         = [string]$node.Type
            Port         = if ($node.Port) { [int]$node.Port } else { 0 }
            KeepAlive    = [string]$node.KeepAlive
            TimeOut      = if ($node.TimeOut) { [int]$node.TimeOut } else { 0 }
            DisableReuse = [string]$node.DisableReuse
        }
    }

    $webServerObjects = @($webServerObjects)
    if ($NameLike) {
        $webServerObjects = @($webServerObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($webServerObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $webServerObjects
}

<#
.SYNOPSIS
    Creates a Web Server (real server / backend) object on a Sophos Firewall.

.DESCRIPTION
    Creates a Web Server object describing one backend real server behind the WAF.

    HostName must be the name of an existing IPHost or FQDNHost object on the firewall, not
    a raw IP address or FQDN text - the firewall rejects a literal address with
    "Configuration parameters validation failed" against /RealServers/Host. Create the host
    object first (for example with New-SfosIPHost from SophosFirewall.HostsAndServices) and
    pass its name here.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Web Server area.

.PARAMETER Name
    Required. Name of the object, 1 to 60 characters, no commas.

.PARAMETER Description
    Optional. Free-text description.

.PARAMETER HostName
    Required. Name of an existing IPHost or FQDNHost object to forward traffic to - not a raw
    IP address. Wire element is Host; the parameter is not called -Host because $Host is an
    automatic PowerShell variable and a parameter of that name would shadow it inside this
    function. The alias Host is still available.

.PARAMETER Type
    Optional. Backend protocol: 'Plaintext (HTTP)' or 'Encrypted (HTTPS)' - the value goes on
    the wire exactly as written here, spaces and parentheses included. If omitted, the
    firewall applies its own default.

.PARAMETER PortNumber
    Optional. Backend TCP port, 1-65535. Defaults to 80. The wire element is Port; the
    parameter is not called -Port because that name is already used for the management API
    port in the connection parameters below, and PowerShell rejects an alias that collides
    with another parameter's own name, so no -Port alias exists for this field either.

.PARAMETER KeepAlive
    Optional. Enable or Disable. If omitted, the firewall applies its own default.

.PARAMETER TimeOut
    Optional. Connection timeout in seconds, 1-65535. Defaults to 300.

.PARAMETER DisableReuse
    Optional. Enable or Disable. If omitted, the firewall applies its own default.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name, Description and HostName (as
    Host) by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosWebServer -Name 'IntranetServer' -HostName 'IntranetServerHost' -PortNumber 8080 -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosWebServer -Name 'IntranetServer' -HostName 'IntranetServerHost' -PortNumber 8080

    Creates a Web Server object forwarding to the named host on port 8080. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/Backend/operations/RealServerAddFromApi%26RealServerEdit.html

.LINK
    Get-SfosWebServer
#>
function New-SfosWebServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(Mandatory)]
        [Alias('Host')]
        [ValidateLength(1, 255)]
        [string]$HostName,

        [ValidateSet('Plaintext (HTTP)', 'Encrypted (HTTPS)')]
        [string]$Type,

        [ValidateRange(1, 65535)]
        [int]$PortNumber = 80,

        [ValidateSet('Enable', 'Disable')]
        [string]$KeepAlive,

        [ValidateRange(1, 65535)]
        [int]$TimeOut = 300,

        [ValidateSet('Enable', 'Disable')]
        [string]$DisableReuse,

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
        if (-not $PSCmdlet.ShouldProcess("RealServers '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $webServer = [PSCustomObject]@{
            Name         = $Name
            Description  = $Description
            Host         = $HostName
            Type         = $Type
            Port         = $PortNumber
            KeepAlive    = $KeepAlive
            TimeOut      = $TimeOut
            DisableReuse = $DisableReuse
        }

        $inner = ConvertTo-SfosWebServerEntityXml -Operation 'add' -WebServer $webServer

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create RealServers object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        try {
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RealServers' -Action 'create' -Target $Name
        }
        catch {
            $invalidHost = $XmlResponse.SelectSingleNode('/Response/RealServers/InvalidParams/Params[text()="/RealServers/Host"]')
            if ($invalidHost) {
                throw "Failed to create RealServers object '$Name': -HostName must be the name of an existing IPHost or FQDNHost object on the firewall, not an IP address. $($_.Exception.Message)"
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Updates a Web Server (real server / backend) object on a Sophos Firewall.

.DESCRIPTION
    Updates a Web Server object. You can supply the target name directly or through the
    pipeline. The firewall replaces the whole object on update; this cmdlet reads the
    current object first and keeps whatever the caller does not explicitly pass.

.PARAMETER Name
    Required. Name of the target object.

.PARAMETER Description
    Optional. If omitted, the existing description is kept.

.PARAMETER HostName
    Optional. Name of an existing IPHost or FQDNHost object - not a raw IP address. If
    omitted, the existing host is kept. See New-SfosWebServer for the validation error this
    field produces when given a raw address instead of an object name.

.PARAMETER Type
    Optional. 'Plaintext (HTTP)' or 'Encrypted (HTTPS)'. If omitted, the existing value is
    kept.

.PARAMETER PortNumber
    Optional. Backend TCP port, 1-65535. If omitted, the existing port is kept.

.PARAMETER KeepAlive
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER TimeOut
    Optional. Connection timeout in seconds, 1-65535. If omitted, the existing value is kept.

.PARAMETER DisableReuse
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an object by value or by property
    name, for example from Get-SfosWebServer.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if the named object does not exist.

.EXAMPLE
    Set-SfosWebServer -Name 'IntranetServer' -PortNumber 8443 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Get-SfosWebServer -NameLike 'IntranetServer' | Set-SfosWebServer -DisableReuse Enable

    Reads the matching object and applies the change through the pipeline.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/Backend/operations/RealServerAddFromApi%26RealServerEdit.html

.LINK
    Get-SfosWebServer
#>
function Set-SfosWebServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Alias('Host')]
        [ValidateLength(1, 255)]
        [string]$HostName,

        [ValidateSet('Plaintext (HTTP)', 'Encrypted (HTTPS)')]
        [string]$Type,

        [ValidateRange(1, 65535)]
        [int]$PortNumber,

        [ValidateSet('Enable', 'Disable')]
        [string]$KeepAlive,

        [ValidateRange(1, 65535)]
        [int]$TimeOut,

        [ValidateSet('Enable', 'Disable')]
        [string]$DisableReuse,

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
        $existing = @(Get-SfosWebServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The RealServers object '$Name' was not found."
        }

        $target = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) { $target.Description = $Description }
        if ($PSBoundParameters.ContainsKey('HostName')) { $target.Host = $HostName }
        if ($PSBoundParameters.ContainsKey('Type')) { $target.Type = $Type }
        if ($PSBoundParameters.ContainsKey('PortNumber')) { $target.Port = $PortNumber }
        if ($PSBoundParameters.ContainsKey('KeepAlive')) { $target.KeepAlive = $KeepAlive }
        if ($PSBoundParameters.ContainsKey('TimeOut')) { $target.TimeOut = $TimeOut }
        if ($PSBoundParameters.ContainsKey('DisableReuse')) { $target.DisableReuse = $DisableReuse }

        $inner = ConvertTo-SfosWebServerEntityXml -Operation 'update' -WebServer $target

        if (-not $PSCmdlet.ShouldProcess("RealServers '$Name' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating RealServers object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        try {
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RealServers' -Action 'edit' -Target $Name
        }
        catch {
            $invalidHost = $XmlResponse.SelectSingleNode('/Response/RealServers/InvalidParams/Params[text()="/RealServers/Host"]')
            if ($invalidHost) {
                throw "Error updating RealServers object '$Name': -HostName must be the name of an existing IPHost or FQDNHost object on the firewall, not an IP address. $($_.Exception.Message)"
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Removes a Web Server (real server / backend) object from a Sophos Firewall.

.DESCRIPTION
    Removes a Web Server object. The cmdlet reads the object first and throws a clear error
    if the given name does not exist, rather than passing through the firewall's raw (and, on
    this entity, misleading) "Deleting entity referred by another entity" text for a
    not-found removal.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal, or if the named object does not exist.

.EXAMPLE
    Remove-SfosWebServer -Name 'IntranetServer' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosWebServer -Name 'IntranetServer'

    Removes the named object. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/Backend/operations/RealServerRemove.html

.LINK
    Get-SfosWebServer
#>
function Remove-SfosWebServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

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
        $existing = @(Get-SfosWebServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The RealServers object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("RealServers '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><RealServers><Name>$nameEsc</Name></RealServers></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove RealServers object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RealServers' -Action 'remove' -Target $Name
    }
}

#endregion


#region ProtocolSecurity

<#
.SYNOPSIS
    Builds the Set request body for a Web Server Protection Policy (ProtocolSecurity) entity.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on a ProtocolSecurity entity, so New-
    and Set-SfosWebServerProtectionPolicy send the same entity shape. The firewall replaces
    the whole entity on update, so the caller merges every field it wants to keep into
    -Policy first, including EntryURLList, SkipFilterRules and ThreatFilters.

    RequestSizeLimit goes on the wire in bytes; -Policy must already carry the byte value in
    RequestSizeLimitBytes (Get-SfosWebServerProtectionPolicy and the Set-* merge do this
    conversion, never this function). Megabytes is a separate, unrelated field and is sent
    unconverted.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Policy
    The policy object to convert, with the properties Name, Description,
    PassOutlookAnywhere, Mode, CookieSigning, StaticUrlHardening, FormHardening, AntiVirus,
    BlockClientsWithBadReputation, ThreatsFilter, HSTSEnforcement, XContentTypeOptions,
    RequestSizeLimitBytes, EntryURLType, EntryURLList, AVMode, Direction,
    BlockUnscannableContent, LimitScanSize, Megabytes, SkipRemoteLookups, ParanoiaLevel,
    SkipFilterRules and ThreatFilters.
#>
function ConvertTo-SfosWebServerProtectionPolicyEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Policy
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Name)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Description)
    $passOutlookEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.PassOutlookAnywhere)
    $modeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Mode)
    $cookieSigningEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.CookieSigning)
    $staticUrlHardeningEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.StaticUrlHardening)
    $formHardeningEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.FormHardening)
    $antiVirusEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.AntiVirus)
    $blockBadRepEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.BlockClientsWithBadReputation)
    $threatsFilterEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.ThreatsFilter)
    $hstsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.HSTSEnforcement)
    $xContentEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.XContentTypeOptions)
    $entryUrlTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.EntryURLType)
    $avModeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.AVMode)
    $directionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Direction)
    $blockUnscannableEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.BlockUnscannableContent)
    $limitScanSizeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.LimitScanSize)
    $skipRemoteLookupsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SkipRemoteLookups)
    $paranoiaLevelEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.ParanoiaLevel)

    $entryUrlXml = ''
    foreach ($url in @($Policy.EntryURLList)) {
        if (-not $url) { continue }
        $entryUrlXml += "<EntryURL>$(ConvertTo-SfosXmlEscaped -Text $url)</EntryURL>"
    }

    $skipFilterXml = ''
    foreach ($rule in @($Policy.SkipFilterRules)) {
        if ($null -eq $rule -or $rule -eq '') { continue }
        $skipFilterXml += "<FilterRules>$(ConvertTo-SfosXmlEscaped -Text ([string]$rule))</FilterRules>"
    }

    $threatFiltersXml = ''
    foreach ($filter in @($Policy.ThreatFilters)) {
        if (-not $filter) { continue }
        $threatFiltersXml += "<Filter>$(ConvertTo-SfosXmlEscaped -Text $filter)</Filter>"
    }

    $requestSizeLimitBytes = [int]$Policy.RequestSizeLimitBytes
    $megabytes = [int]$Policy.Megabytes

    return @"
<Set operation="$Operation">
  <ProtocolSecurity>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <PassOutlookAnywhere>$passOutlookEsc</PassOutlookAnywhere>
    <Mode>$modeEsc</Mode>
    <CookieSigning>$cookieSigningEsc</CookieSigning>
    <StaticUrlHardening>$staticUrlHardeningEsc</StaticUrlHardening>
    <FormHardening>$formHardeningEsc</FormHardening>
    <AntiVirus>$antiVirusEsc</AntiVirus>
    <BlockClientsWithBadReputation>$blockBadRepEsc</BlockClientsWithBadReputation>
    <ThreatsFilter>$threatsFilterEsc</ThreatsFilter>
    <HSTSEnforcement>$hstsEsc</HSTSEnforcement>
    <XContentTypeOptions>$xContentEsc</XContentTypeOptions>
    <RequestSizeLimit>$requestSizeLimitBytes</RequestSizeLimit>
    <EntryURLType>$entryUrlTypeEsc</EntryURLType>
    <EntryURLList>$entryUrlXml</EntryURLList>
    <AVMode>$avModeEsc</AVMode>
    <Direction>$directionEsc</Direction>
    <BlockUnscannableContent>$blockUnscannableEsc</BlockUnscannableContent>
    <LimitScanSize>$limitScanSizeEsc</LimitScanSize>
    <Megabytes>$megabytes</Megabytes>
    <SkipRemoteLookups>$skipRemoteLookupsEsc</SkipRemoteLookups>
    <ParanoiaLevel>$paranoiaLevelEsc</ParanoiaLevel>
    <SkipFilterRules>$skipFilterXml</SkipFilterRules>
    <ThreatFilters>$threatFiltersXml</ThreatFilters>
  </ProtocolSecurity>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves Web Server Protection Policy (ProtocolSecurity) objects from a Sophos Firewall.

.DESCRIPTION
    Returns Web Server Protection Policy objects (PROTECT > Web Server > Protection
    Policies). A protection policy groups the WAF checks (form hardening, static URL
    hardening, antivirus scanning, bad-reputation blocking, request size limit and the
    generic threat filter with its paranoia level) applied to traffic for a real server.

    RequestSizeLimit is stored on the wire in bytes even though the web admin and the value
    the caller sends are in megabytes: this cmdlet returns both RequestSizeLimitBytes (the
    raw wire value) and RequestSizeLimitMB (RequestSizeLimitBytes / 1MB) so a round trip
    through Set-SfosWebServerProtectionPolicy stays stable. Megabytes is a different,
    unrelated field (the antivirus scan size limit) and is never converted.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. Sent to the
    firewall as a server-side pre-filter and re-applied client-side. If omitted, the name is
    not used to filter.

.PARAMETER DescriptionLike
    Optional. Returns only objects whose description contains the given text anywhere. Sent
    to the firewall as a server-side pre-filter only when -NameLike is not also supplied - the
    firewall evaluates only the first filter key of the request - and always re-applied
    client-side. If omitted, the description is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per policy, with properties
    matching the wire fields plus RequestSizeLimitBytes and RequestSizeLimitMB in place of a
    single RequestSizeLimit. EntryURLList, SkipFilterRules and ThreatFilters are always
    arrays, empty when the firewall omits the wrapper. Returns System.Xml.XmlElement when
    -AsXml is used, and an empty array when no policy matches.

    The firewall ships 6 built-in policies (Exchange AutoDiscover, Exchange General,
    Microsoft Lync, Exchange Outlook Anywhere, Microsoft RDG, Microsoft RD Web). Treat them
    as read-only; Set-SfosWebServerProtectionPolicy does not warn before overwriting one.

.EXAMPLE
    Get-SfosWebServerProtectionPolicy

    Lists every protection policy on the firewall of the current connection.

.EXAMPLE
    Get-SfosWebServerProtectionPolicy -NameLike 'Exchange'

    Lists all policies whose name contains 'Exchange'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/SecurityProfile/ProtocolSecurity.html

.LINK
    New-SfosWebServerProtectionPolicy
#>
function Get-SfosWebServerProtectionPolicy {
    [CmdletBinding()]
    param(
        [string]$NameLike,
        [string]$DescriptionLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # The firewall evaluates only the first key of the first filter block.
    # Name and Description are both measured to work individually for this entity; Mode is
    # measured fail-closed (returns nothing even for an exact match) and must never be used
    # as a server-side key. Prefer Name when both are supplied, since Name is the more common
    # identifying field; both are always re-applied client-side with AND below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }
    elseif ($DescriptionLike) {
        $descLikeEsc = ConvertTo-SfosXmlEscaped -Text $DescriptionLike
        $filterXml = ('<Filter><key name="Description" criteria="like">{0}</key></Filter>' -f $descLikeEsc)
    }

    $inner = @"
<Get>
  <ProtocolSecurity>
    $filterXml
  </ProtocolSecurity>
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
        throw "Error retrieving ProtocolSecurity objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ProtocolSecurity' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ProtocolSecurity[Name]' | ForEach-Object -Process { $_.Node }

    $policyObjects = foreach ($node in @($nodes)) {
        $bytesRaw = if ($node.RequestSizeLimit) { [int]$node.RequestSizeLimit } else { 0 }

        [PSCustomObject]@{
            Name                          = [string]$node.Name
            Description                   = [string]$node.Description
            PassOutlookAnywhere           = [string]$node.PassOutlookAnywhere
            Mode                          = [string]$node.Mode
            CookieSigning                 = [string]$node.CookieSigning
            StaticUrlHardening            = [string]$node.StaticUrlHardening
            FormHardening                 = [string]$node.FormHardening
            AntiVirus                     = [string]$node.AntiVirus
            BlockClientsWithBadReputation = [string]$node.BlockClientsWithBadReputation
            ThreatsFilter                 = [string]$node.ThreatsFilter
            HSTSEnforcement               = [string]$node.HSTSEnforcement
            XContentTypeOptions           = [string]$node.XContentTypeOptions
            RequestSizeLimitBytes         = $bytesRaw
            RequestSizeLimitMB            = [int]($bytesRaw / 1MB)
            EntryURLType                  = [string]$node.EntryURLType
            EntryURLList                  = [string[]]@($node.EntryURLList.EntryURL | Where-Object -FilterScript { $_ })
            AVMode                        = [string]$node.AVMode
            Direction                     = [string]$node.Direction
            BlockUnscannableContent       = [string]$node.BlockUnscannableContent
            LimitScanSize                 = [string]$node.LimitScanSize
            Megabytes                     = if ($node.Megabytes) { [int]$node.Megabytes } else { 0 }
            SkipRemoteLookups             = [string]$node.SkipRemoteLookups
            ParanoiaLevel                 = [string]$node.ParanoiaLevel
            SkipFilterRules               = [string[]]@($node.SkipFilterRules.FilterRules | Where-Object -FilterScript { $_ })
            ThreatFilters                 = [string[]]@($node.ThreatFilters.Filter | Where-Object -FilterScript { $_ })
        }
    }

    $policyObjects = @($policyObjects)
    if ($NameLike) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        $keptNames = @($policyObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $policyObjects
}

<#
.SYNOPSIS
    Creates a Web Server Protection Policy (ProtocolSecurity) object on a Sophos Firewall.

.DESCRIPTION
    Creates a Web Server Protection Policy. RequestSizeLimitMB is given in megabytes and
    converted to the bytes the wire actually stores (RequestSizeLimitMB * 1MB); Megabytes is
    a separate, unrelated field (the antivirus scan size limit) and is sent unconverted.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Web Server area.

.PARAMETER Name
    Required. Name of the policy, 1 to 60 characters, no commas.

.PARAMETER Description
    Optional. Free-text description.

.PARAMETER Mode
    Required. Monitor or Reject.

.PARAMETER RequestSizeLimitMB
    Required. Maximum request size in megabytes, 1-2047. Stored on the wire in bytes; see
    .DESCRIPTION.

.PARAMETER PassOutlookAnywhere
    Optional. Enable or Disable. Defaults to Disable.

.PARAMETER CookieSigning
    Optional. Enable or Disable. Defaults to Disable.

.PARAMETER StaticUrlHardening
    Optional. Enable or Disable. Defaults to Disable. Controls whether EntryURLType and
    EntryURLList are used.

.PARAMETER EntryURLType
    Optional. Manual, SitemapFile or SitemapURL. Only meaningful when -StaticUrlHardening is
    Enable. Defaults to Manual.

.PARAMETER EntryURLList
    Optional. Entry URLs, used when -EntryURLType is Manual.

.PARAMETER FormHardening
    Optional. Enable or Disable. Defaults to Disable.

.PARAMETER AntiVirus
    Optional. Enable or Disable. Defaults to Disable. Controls whether AVMode, Direction,
    BlockUnscannableContent, LimitScanSize and Megabytes are used.

.PARAMETER AVMode
    Optional. Avira, Sophos or DualScan. Only meaningful when -AntiVirus is Enable. Defaults
    to DualScan.

.PARAMETER Direction
    Optional. Uploads, Downloads or UploadsAndDownloads. Defaults to UploadsAndDownloads.

.PARAMETER BlockUnscannableContent
    Optional. Enable or Disable. Defaults to Disable.

.PARAMETER LimitScanSize
    Optional. Enable or Disable. Defaults to Disable. Controls whether -Megabytes is used.

.PARAMETER Megabytes
    Optional. Antivirus scan size limit in megabytes. Only meaningful when -LimitScanSize is
    Enable. This is not the same field as -RequestSizeLimitMB and is never converted; a value
    of 20 is stored and read back as 20. Defaults to 0.

.PARAMETER BlockClientsWithBadReputation
    Optional. Enable or Disable. Defaults to Disable. Controls whether -SkipRemoteLookups is
    used.

.PARAMETER SkipRemoteLookups
    Optional. Enable or Disable. Only meaningful when -BlockClientsWithBadReputation is
    Enable. Defaults to Disable.

.PARAMETER ThreatsFilter
    Optional. Enable or Disable. Defaults to Disable. Controls whether ParanoiaLevel,
    SkipFilterRules and ThreatFilters are used.

.PARAMETER ParanoiaLevel
    Optional. 1-4. Only meaningful when -ThreatsFilter is Enable. Defaults to 1.

.PARAMETER SkipFilterRules
    Optional. Numeric filter rule IDs to skip, for example 920300. Only meaningful when
    -ThreatsFilter is Enable.

.PARAMETER ThreatFilters
    Optional. One or more of: Application attacks, SQL injection attacks, XSS attacks,
    Protocol enforcement, Scanner detection, Data leakages. Only meaningful when
    -ThreatsFilter is Enable.

.PARAMETER HSTSEnforcement
    Optional. Enable or Disable. Defaults to Disable.

.PARAMETER XContentTypeOptions
    Optional. Enable or Disable. Defaults to Disable.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name, Description and Mode by
    property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Mode Reject -RequestSizeLimitMB 10 -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Mode Reject -RequestSizeLimitMB 10

    Creates a minimal protection policy. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/SecurityProfile/operations/ProtocolSecurityAddFromApi%26ProtocolSecurityEdit.html

.LINK
    Get-SfosWebServerProtectionPolicy
#>
function New-SfosWebServerProtectionPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Monitor', 'Reject')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [ValidateRange(1, 2047)]
        [int]$RequestSizeLimitMB,

        [ValidateSet('Enable', 'Disable')]
        [string]$PassOutlookAnywhere = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$CookieSigning = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$StaticUrlHardening = 'Disable',

        [ValidateSet('Manual', 'SitemapFile', 'SitemapURL')]
        [string]$EntryURLType = 'Manual',

        [string[]]$EntryURLList,

        [ValidateSet('Enable', 'Disable')]
        [string]$FormHardening = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$AntiVirus = 'Disable',

        [ValidateSet('Avira', 'Sophos', 'DualScan')]
        [string]$AVMode = 'DualScan',

        [ValidateSet('Uploads', 'Downloads', 'UploadsAndDownloads')]
        [string]$Direction = 'UploadsAndDownloads',

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockUnscannableContent = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$LimitScanSize = 'Disable',

        [int]$Megabytes = 0,

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockClientsWithBadReputation = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$SkipRemoteLookups = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ThreatsFilter = 'Disable',

        [ValidateRange(1, 4)]
        [int]$ParanoiaLevel = 1,

        [int[]]$SkipFilterRules,

        [ValidateSet('Application attacks', 'SQL injection attacks', 'XSS attacks', 'Protocol enforcement', 'Scanner detection', 'Data leakages')]
        [string[]]$ThreatFilters,

        [ValidateSet('Enable', 'Disable')]
        [string]$HSTSEnforcement = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$XContentTypeOptions = 'Disable',

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
        if (-not $PSCmdlet.ShouldProcess("ProtocolSecurity '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $policy = [PSCustomObject]@{
            Name                           = $Name
            Description                    = $Description
            PassOutlookAnywhere            = $PassOutlookAnywhere
            Mode                           = $Mode
            CookieSigning                  = $CookieSigning
            StaticUrlHardening             = $StaticUrlHardening
            FormHardening                  = $FormHardening
            AntiVirus                      = $AntiVirus
            BlockClientsWithBadReputation  = $BlockClientsWithBadReputation
            ThreatsFilter                  = $ThreatsFilter
            HSTSEnforcement                = $HSTSEnforcement
            XContentTypeOptions            = $XContentTypeOptions
            RequestSizeLimitBytes          = ($RequestSizeLimitMB * 1MB)
            EntryURLType                   = $EntryURLType
            EntryURLList                   = @($EntryURLList)
            AVMode                         = $AVMode
            Direction                      = $Direction
            BlockUnscannableContent        = $BlockUnscannableContent
            LimitScanSize                  = $LimitScanSize
            Megabytes                      = $Megabytes
            SkipRemoteLookups              = $SkipRemoteLookups
            ParanoiaLevel                  = $ParanoiaLevel
            SkipFilterRules                = @($SkipFilterRules)
            ThreatFilters                  = @($ThreatFilters)
        }

        $inner = ConvertTo-SfosWebServerProtectionPolicyEntityXml -Operation 'add' -Policy $policy

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create ProtocolSecurity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ProtocolSecurity' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a Web Server Protection Policy (ProtocolSecurity) object on a Sophos Firewall.

.DESCRIPTION
    Updates a Web Server Protection Policy. You can supply the target name directly or
    through the pipeline. The firewall replaces the whole object on update; this cmdlet reads
    the current object first and keeps whatever the caller does not explicitly pass -
    including the EntryURLList, SkipFilterRules and ThreatFilters lists, which are otherwise
    cleared by an update that omits them.

    -RequestSizeLimitMB is given in megabytes and converted to the bytes the wire stores; if
    omitted, the existing byte value is kept unconverted, so repeated updates that do not
    touch this field cannot drift. -Megabytes (the antivirus scan size limit) is unrelated
    and never converted.

    The firewall built-in policies (Exchange AutoDiscover, Exchange General, Microsoft Lync,
    Exchange Outlook Anywhere, Microsoft RDG, Microsoft RD Web) have no write protection;
    this cmdlet overwrites one without a warning from the firewall.

.PARAMETER Name
    Required. Name of the target policy.

.PARAMETER Description
    Optional. If omitted, the existing description is kept.

.PARAMETER Mode
    Optional. Monitor or Reject. If omitted, the existing value is kept.

.PARAMETER RequestSizeLimitMB
    Optional. Maximum request size in megabytes. If omitted, the existing byte value is kept.

.PARAMETER PassOutlookAnywhere
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER CookieSigning
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER StaticUrlHardening
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER EntryURLType
    Optional. Manual, SitemapFile or SitemapURL. If omitted, the existing value is kept.

.PARAMETER EntryURLList
    Optional. Complete replacement list of entry URLs. If omitted, the existing list is kept.

.PARAMETER FormHardening
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER AntiVirus
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER AVMode
    Optional. Avira, Sophos or DualScan. If omitted, the existing value is kept.

.PARAMETER Direction
    Optional. Uploads, Downloads or UploadsAndDownloads. If omitted, the existing value is
    kept.

.PARAMETER BlockUnscannableContent
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER LimitScanSize
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER Megabytes
    Optional. Antivirus scan size limit in megabytes, unconverted. If omitted, the existing
    value is kept.

.PARAMETER BlockClientsWithBadReputation
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER SkipRemoteLookups
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER ThreatsFilter
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER ParanoiaLevel
    Optional. 1-4. If omitted, the existing value is kept.

.PARAMETER SkipFilterRules
    Optional. Complete replacement list of skipped filter rule IDs. If omitted, the existing
    list is kept.

.PARAMETER ThreatFilters
    Optional. Complete replacement list of threat filter categories. If omitted, the existing
    list is kept.

.PARAMETER HSTSEnforcement
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER XContentTypeOptions
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts a policy object by value or by
    property name, for example from Get-SfosWebServerProtectionPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if the named object does not exist.

.EXAMPLE
    Set-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Mode Monitor -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Get-SfosWebServerProtectionPolicy -NameLike 'IntranetProtection' | Set-SfosWebServerProtectionPolicy -Description 'Updated'

    Reads the matching policy and applies the change through the pipeline, keeping every
    other field including its lists unchanged.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/SecurityProfile/operations/ProtocolSecurityAddFromApi%26ProtocolSecurityEdit.html

.LINK
    Get-SfosWebServerProtectionPolicy
#>
function Set-SfosWebServerProtectionPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [ValidateSet('Monitor', 'Reject')]
        [string]$Mode,

        [ValidateRange(1, 2047)]
        [int]$RequestSizeLimitMB,

        [ValidateSet('Enable', 'Disable')]
        [string]$PassOutlookAnywhere,

        [ValidateSet('Enable', 'Disable')]
        [string]$CookieSigning,

        [ValidateSet('Enable', 'Disable')]
        [string]$StaticUrlHardening,

        [ValidateSet('Manual', 'SitemapFile', 'SitemapURL')]
        [string]$EntryURLType,

        [string[]]$EntryURLList,

        [ValidateSet('Enable', 'Disable')]
        [string]$FormHardening,

        [ValidateSet('Enable', 'Disable')]
        [string]$AntiVirus,

        [ValidateSet('Avira', 'Sophos', 'DualScan')]
        [string]$AVMode,

        [ValidateSet('Uploads', 'Downloads', 'UploadsAndDownloads')]
        [string]$Direction,

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockUnscannableContent,

        [ValidateSet('Enable', 'Disable')]
        [string]$LimitScanSize,

        [int]$Megabytes,

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockClientsWithBadReputation,

        [ValidateSet('Enable', 'Disable')]
        [string]$SkipRemoteLookups,

        [ValidateSet('Enable', 'Disable')]
        [string]$ThreatsFilter,

        [ValidateRange(1, 4)]
        [int]$ParanoiaLevel,

        [int[]]$SkipFilterRules,

        [ValidateSet('Application attacks', 'SQL injection attacks', 'XSS attacks', 'Protocol enforcement', 'Scanner detection', 'Data leakages')]
        [string[]]$ThreatFilters,

        [ValidateSet('Enable', 'Disable')]
        [string]$HSTSEnforcement,

        [ValidateSet('Enable', 'Disable')]
        [string]$XContentTypeOptions,

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
        $existing = @(Get-SfosWebServerProtectionPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ProtocolSecurity object '$Name' was not found."
        }

        $target = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) { $target.Description = $Description }
        if ($PSBoundParameters.ContainsKey('Mode')) { $target.Mode = $Mode }
        if ($PSBoundParameters.ContainsKey('RequestSizeLimitMB')) { $target.RequestSizeLimitBytes = ($RequestSizeLimitMB * 1MB) }
        if ($PSBoundParameters.ContainsKey('PassOutlookAnywhere')) { $target.PassOutlookAnywhere = $PassOutlookAnywhere }
        if ($PSBoundParameters.ContainsKey('CookieSigning')) { $target.CookieSigning = $CookieSigning }
        if ($PSBoundParameters.ContainsKey('StaticUrlHardening')) { $target.StaticUrlHardening = $StaticUrlHardening }
        if ($PSBoundParameters.ContainsKey('EntryURLType')) { $target.EntryURLType = $EntryURLType }
        if ($PSBoundParameters.ContainsKey('EntryURLList')) { $target.EntryURLList = @($EntryURLList) }
        if ($PSBoundParameters.ContainsKey('FormHardening')) { $target.FormHardening = $FormHardening }
        if ($PSBoundParameters.ContainsKey('AntiVirus')) { $target.AntiVirus = $AntiVirus }
        if ($PSBoundParameters.ContainsKey('AVMode')) { $target.AVMode = $AVMode }
        if ($PSBoundParameters.ContainsKey('Direction')) { $target.Direction = $Direction }
        if ($PSBoundParameters.ContainsKey('BlockUnscannableContent')) { $target.BlockUnscannableContent = $BlockUnscannableContent }
        if ($PSBoundParameters.ContainsKey('LimitScanSize')) { $target.LimitScanSize = $LimitScanSize }
        if ($PSBoundParameters.ContainsKey('Megabytes')) { $target.Megabytes = $Megabytes }
        if ($PSBoundParameters.ContainsKey('BlockClientsWithBadReputation')) { $target.BlockClientsWithBadReputation = $BlockClientsWithBadReputation }
        if ($PSBoundParameters.ContainsKey('SkipRemoteLookups')) { $target.SkipRemoteLookups = $SkipRemoteLookups }
        if ($PSBoundParameters.ContainsKey('ThreatsFilter')) { $target.ThreatsFilter = $ThreatsFilter }
        if ($PSBoundParameters.ContainsKey('ParanoiaLevel')) { $target.ParanoiaLevel = $ParanoiaLevel }
        if ($PSBoundParameters.ContainsKey('SkipFilterRules')) { $target.SkipFilterRules = @($SkipFilterRules) }
        if ($PSBoundParameters.ContainsKey('ThreatFilters')) { $target.ThreatFilters = @($ThreatFilters) }
        if ($PSBoundParameters.ContainsKey('HSTSEnforcement')) { $target.HSTSEnforcement = $HSTSEnforcement }
        if ($PSBoundParameters.ContainsKey('XContentTypeOptions')) { $target.XContentTypeOptions = $XContentTypeOptions }

        $inner = ConvertTo-SfosWebServerProtectionPolicyEntityXml -Operation 'update' -Policy $target

        if (-not $PSCmdlet.ShouldProcess("ProtocolSecurity '$Name' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating ProtocolSecurity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ProtocolSecurity' -Action 'edit' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a Web Server Protection Policy (ProtocolSecurity) object from a Sophos Firewall.

.DESCRIPTION
    Removes a Web Server Protection Policy object. The cmdlet reads the object first and
    throws a clear error if the given name does not exist, rather than passing through the
    firewall's raw (and, on this entity, misleading) "Deleting entity referred by another
    entity" text for a not-found removal. Do not target the six firewall built-in policies
    (Exchange AutoDiscover, Exchange General, Microsoft Lync, Exchange Outlook Anywhere,
    Microsoft RDG, Microsoft RD Web) with this cmdlet.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Web
    Server area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal, or if the named object does not exist.

.EXAMPLE
    Remove-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosWebServerProtectionPolicy -Name 'IntranetProtection'

    Removes the named object. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Web%20Server/SecurityProfile/operations/ProtocolSecurityRemove.html

.LINK
    Get-SfosWebServerProtectionPolicy
#>
function Remove-SfosWebServerProtectionPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

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
        $existing = @(Get-SfosWebServerProtectionPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ProtocolSecurity object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ProtocolSecurity '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><ProtocolSecurity><Name>$nameEsc</Name></ProtocolSecurity></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove ProtocolSecurity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ProtocolSecurity' -Action 'remove' -Target $Name
    }
}

#endregion
#region ReverseAuthentication shared helper

<#
.SYNOPSIS
    Builds the Set request body for a Web Server authentication policy.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on a ReverseAuthentication entity, so
    New-SfosWebServerAuthenticationPolicy and Set-SfosWebServerAuthenticationPolicy send the
    same entity shape. The firewall replaces the whole entity on update, so the caller merges
    every field it wants to keep into -Policy before calling this function. Fields that only
    apply to one VirtualWebserverMode/RealWebserverMode/UsernameAffix combination are omitted
    when they do not apply, matching the shape the firewall itself returns from a Get.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Policy
    The policy object to convert, with the properties Name, Description,
    VirtualWebserverMode, FrontendRealm, BasicPrompt, FormTemplate, UserGroupList,
    RealWebserverMode, UsernameAffix, Prefix, Suffix, RemoveBasicHeader, SessionTimeout,
    SessionTimeoutLimit, SessionTimeoutScope, SessionLifetime, SessionLifetimeLimit,
    SessionLifetimeScope.
#>
function ConvertTo-SfosWebServerAuthenticationPolicyEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Policy
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Name)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Description)
    $modeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.VirtualWebserverMode)
    $realmEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.FrontendRealm)
    $realModeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.RealWebserverMode)
    $affixEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.UsernameAffix)

    $optionalXml = ''

    if ($Policy.VirtualWebserverMode -eq 'Basic' -and $Policy.BasicPrompt) {
        $optionalXml += "<BasicPrompt>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.BasicPrompt))</BasicPrompt>"
    }
    if ($Policy.VirtualWebserverMode -eq 'Form' -and $Policy.FormTemplate) {
        $optionalXml += "<FormTemplate>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.FormTemplate))</FormTemplate>"
    }

    $groupXml = ''
    foreach ($group in @($Policy.UserGroupList)) {
        if (-not $group) { continue }
        $groupXml += "<UserGroup>$(ConvertTo-SfosXmlEscaped -Text $group)</UserGroup>"
    }
    if ($groupXml) { $optionalXml += "<UserGroupList>$groupXml</UserGroupList>" }

    if ($Policy.RealWebserverMode -eq 'None' -and $Policy.RemoveBasicHeader) {
        $optionalXml += "<RemoveBasicHeader>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.RemoveBasicHeader))</RemoveBasicHeader>"
    }

    if ($Policy.UsernameAffix -in @('Prefix', 'PrefixAndSuffix') -and $Policy.Prefix) {
        $optionalXml += "<Prefix>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Prefix))</Prefix>"
    }
    if ($Policy.UsernameAffix -in @('Suffix', 'PrefixAndSuffix') -and $Policy.Suffix) {
        $optionalXml += "<Suffix>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Suffix))</Suffix>"
    }

    if ($Policy.VirtualWebserverMode -eq 'Form') {
        if ($Policy.SessionTimeout) {
            $optionalXml += "<SessionTimeout>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SessionTimeout))</SessionTimeout>"
            if ($Policy.SessionTimeout -eq 'Enable') {
                $optionalXml += "<SessionTimeoutLimit>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SessionTimeoutLimit))</SessionTimeoutLimit>"
                $optionalXml += "<SessionTimeoutScope>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SessionTimeoutScope))</SessionTimeoutScope>"
            }
        }
        if ($Policy.SessionLifetime) {
            $optionalXml += "<SessionLifetime>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SessionLifetime))</SessionLifetime>"
            if ($Policy.SessionLifetime -eq 'Enable') {
                $optionalXml += "<SessionLifetimeLimit>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SessionLifetimeLimit))</SessionLifetimeLimit>"
                $optionalXml += "<SessionLifetimeScope>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.SessionLifetimeScope))</SessionLifetimeScope>"
            }
        }
    }

    return @"
<Set operation="$Operation">
  <ReverseAuthentication>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <VirtualWebserverMode>$modeEsc</VirtualWebserverMode>
    <FrontendRealm>$realmEsc</FrontendRealm>
    $optionalXml
    <RealWebserverMode>$realModeEsc</RealWebserverMode>
    <UsernameAffix>$affixEsc</UsernameAffix>
  </ReverseAuthentication>
</Set>
"@
}

#endregion


#region ReverseAuthentication

<#
.SYNOPSIS
    Retrieves Web Server authentication policy objects from a Sophos Firewall.

.DESCRIPTION
    Returns Web Server (WAF) authentication policy objects (PROTECT > Web Server >
    Authentication Policy). An authentication policy tells a reverse-authentication virtual
    web server how to authenticate a client - either directly with Basic authentication, or
    with a login form backed by a FormTemplate object - before forwarding the request to the
    real web server.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only policies whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER VirtualWebserverMode
    Optional. Returns only policies with this exact authentication mode, Basic or Form. If
    omitted, the mode is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for Web Server
    authentication policies. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per policy, with the properties
    Name, Description, VirtualWebserverMode, FrontendRealm, BasicPrompt, FormTemplate,
    UserGroupList, RealWebserverMode, UsernameAffix, Prefix, Suffix, RemoveBasicHeader,
    SessionTimeout, SessionTimeoutLimit, SessionTimeoutScope, SessionLifetime,
    SessionLifetimeLimit, SessionLifetimeScope. A field that does not apply to the policy's
    mode is returned empty or zero. Returns System.Xml.XmlElement when -AsXml is used, and an
    empty array when no policy matches.

.EXAMPLE
    Get-SfosWebServerAuthenticationPolicy

    Lists every Web Server authentication policy on the firewall of the current connection.

.EXAMPLE
    Get-SfosWebServerAuthenticationPolicy -VirtualWebserverMode Form

    Lists every policy that authenticates with a login form.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosWebServerAuthenticationPolicy
#>
function Get-SfosWebServerAuthenticationPolicy {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [ValidateSet('Basic', 'Form')]
        [string]$VirtualWebserverMode,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter. SFOS evaluates only the first <key> of the first <Filter>;
    # additional keys and blocks are silently dropped, so every requested filter is applied
    # again client-side below. Name is preferred server-side when both are given; both
    # confirmed supported individually (see module Sondierung, section 4).
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }
    elseif ($VirtualWebserverMode) {
        $modeEsc = ConvertTo-SfosXmlEscaped -Text $VirtualWebserverMode
        $filterXml = ('<Filter><key name="VirtualWebserverMode" criteria="=">{0}</key></Filter>' -f $modeEsc)
    }

    $inner = @"
<Get>
  <ReverseAuthentication>
    $filterXml
  </ReverseAuthentication>
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
        throw "Error retrieving ReverseAuthentication objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ReverseAuthentication' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ReverseAuthentication[Name]' | ForEach-Object -Process {
        $_.Node
    }

    $policyObjects = foreach ($node in @($nodes)) {
        $groups = [string[]]@($node.UserGroupList.UserGroup | Where-Object -FilterScript { $_ })

        [PSCustomObject]@{
            Name                  = [string]$node.Name
            Description           = [string]$node.Description
            VirtualWebserverMode  = [string]$node.VirtualWebserverMode
            FrontendRealm         = [string]$node.FrontendRealm
            BasicPrompt           = [string]$node.BasicPrompt
            FormTemplate          = [string]$node.FormTemplate
            UserGroupList         = $groups
            RealWebserverMode     = [string]$node.RealWebserverMode
            UsernameAffix         = [string]$node.UsernameAffix
            Prefix                = [string]$node.Prefix
            Suffix                = [string]$node.Suffix
            RemoveBasicHeader     = [string]$node.RemoveBasicHeader
            SessionTimeout        = [string]$node.SessionTimeout
            SessionTimeoutLimit   = [int]$node.SessionTimeoutLimit
            SessionTimeoutScope   = [string]$node.SessionTimeoutScope
            SessionLifetime       = [string]$node.SessionLifetime
            SessionLifetimeLimit  = [int]$node.SessionLifetimeLimit
            SessionLifetimeScope  = [string]$node.SessionLifetimeScope
        }
    }

    $policyObjects = @($policyObjects)
    if ($NameLike) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($VirtualWebserverMode) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.VirtualWebserverMode -eq $VirtualWebserverMode })
    }

    if ($AsXml) {
        $keptNames = @($policyObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $policyObjects
}

<#
.SYNOPSIS
    Creates a Web Server authentication policy on a Sophos Firewall.

.DESCRIPTION
    Creates an authentication policy for a reverse-authentication virtual web server. Choose
    -VirtualWebserverMode Basic for a plain HTTP Basic prompt, or Form for a login form backed
    by a FormTemplate object.

    -FrontendRealm is required by the firewall even though the operation's own documentation
    page does not mention it; a create without it is rejected with a 501 naming
    /ReverseAuthentication/FrontendRealm as invalid. The web admin generates a random value
    for it; this cmdlet requires the caller to supply one instead.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for Web Server authentication
    policies.

.PARAMETER Name
    Required. Name of the policy, 1 to 60 characters, no commas.

.PARAMETER Description
    Optional. Free-text description.

.PARAMETER VirtualWebserverMode
    Required. How the virtual web server authenticates the client: Basic or Form.

.PARAMETER FrontendRealm
    Required. Realm string sent to the client. Undocumented but mandatory - see
    .DESCRIPTION. Any non-empty value is accepted.

.PARAMETER BasicPrompt
    Text shown in the Basic authentication prompt, up to 255 characters. Only applies when
    -VirtualWebserverMode is Basic, and required in that case: the firewall refuses such a
    policy without a prompt text even though the documentation calls the field optional.

.PARAMETER FormTemplate
    Optional. Name of an existing FormTemplate object, as returned by
    Get-SfosWebServerAuthenticationTemplate. Only applies when -VirtualWebserverMode is Form.

.PARAMETER UserGroup
    Optional. Names of user groups allowed to authenticate. If omitted, no group restriction
    is sent.

.PARAMETER RealWebserverMode
    Required. How the credentials are forwarded to the real web server: Basic or None.

.PARAMETER UsernameAffix
    Required. How the user name is transformed before being forwarded: None, Basic, Prefix,
    Suffix or PrefixAndSuffix. Only None and Basic are confirmed against a live firewall; the
    other three come from the operation's sample XML, which contradicts the field's own
    attribute table on which values are valid, and have not been tested.

.PARAMETER Prefix
    Optional. Prefix text, up to 255 characters. Only applies when -UsernameAffix is Prefix or
    PrefixAndSuffix.

.PARAMETER Suffix
    Optional. Suffix text, up to 255 characters. Only applies when -UsernameAffix is Suffix or
    PrefixAndSuffix.

.PARAMETER RemoveBasicHeader
    Optional. Enable or Disable. Only applies when -RealWebserverMode is None.

.PARAMETER SessionTimeout
    Optional. Enable or Disable an idle session timeout. Only applies when
    -VirtualWebserverMode is Form.

.PARAMETER SessionTimeoutLimit
    Optional. Idle timeout value, 1 to 9999. Required when -SessionTimeout is Enable.

.PARAMETER SessionTimeoutScope
    Optional. Unit for -SessionTimeoutLimit: Hours, Minutes or Days. Required when
    -SessionTimeout is Enable.

.PARAMETER SessionLifetime
    Optional. Enable or Disable a maximum session lifetime. Only applies when
    -VirtualWebserverMode is Form.

.PARAMETER SessionLifetimeLimit
    Optional. Session lifetime value, 1 to 9999. Required when -SessionLifetime is Enable.

.PARAMETER SessionLifetimeScope
    Optional. Unit for -SessionLifetimeLimit: Hours, Minutes or Days. Required when
    -SessionLifetime is Enable.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for Web Server
    authentication policies. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name, Description and
    VirtualWebserverMode by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth' -VirtualWebserverMode Basic -FrontendRealm 'intranetrealm' -BasicPrompt 'Please sign in.' -RealWebserverMode Basic -UsernameAffix Basic -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth' -VirtualWebserverMode Basic -FrontendRealm 'intranetrealm' -BasicPrompt 'Please sign in.' -RealWebserverMode Basic -UsernameAffix Basic

    Creates a Basic authentication policy. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerAuthenticationPolicy
#>
function New-SfosWebServerAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Basic', 'Form')]
        [string]$VirtualWebserverMode,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FrontendRealm,

        [ValidateLength(0, 255)]
        [string]$BasicPrompt,

        [string]$FormTemplate,

        [string[]]$UserGroup,

        [Parameter(Mandatory)]
        [ValidateSet('Basic', 'None')]
        [string]$RealWebserverMode,

        [Parameter(Mandatory)]
        [ValidateSet('None', 'Basic', 'Prefix', 'Suffix', 'PrefixAndSuffix')]
        [string]$UsernameAffix,

        [ValidateLength(0, 255)]
        [string]$Prefix,

        [ValidateLength(0, 255)]
        [string]$Suffix,

        [ValidateSet('Enable', 'Disable')]
        [string]$RemoveBasicHeader,

        [ValidateSet('Enable', 'Disable')]
        [string]$SessionTimeout,

        [ValidateRange(1, 9999)]
        [int]$SessionTimeoutLimit,

        [ValidateSet('Hours', 'Minutes', 'Days')]
        [string]$SessionTimeoutScope,

        [ValidateSet('Enable', 'Disable')]
        [string]$SessionLifetime,

        [ValidateRange(1, 9999)]
        [int]$SessionLifetimeLimit,

        [ValidateSet('Hours', 'Minutes', 'Days')]
        [string]$SessionLifetimeScope,

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
        # The firewall refuses a Basic policy without a prompt text, although the
        # documentation lists BasicPrompt as optional.
        if ($VirtualWebserverMode -eq 'Basic' -and -not $PSBoundParameters.ContainsKey('BasicPrompt')) {
            throw "The ReverseAuthentication object '$Name' cannot be created: -BasicPrompt is required when -VirtualWebserverMode is 'Basic'."
        }

        if (-not $PSCmdlet.ShouldProcess("ReverseAuthentication '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $policy = [PSCustomObject]@{
            Name                  = $Name
            Description           = $Description
            VirtualWebserverMode  = $VirtualWebserverMode
            FrontendRealm         = $FrontendRealm
            BasicPrompt           = $BasicPrompt
            FormTemplate          = $FormTemplate
            UserGroupList         = @($UserGroup)
            RealWebserverMode     = $RealWebserverMode
            UsernameAffix         = $UsernameAffix
            Prefix                = $Prefix
            Suffix                = $Suffix
            RemoveBasicHeader     = $RemoveBasicHeader
            SessionTimeout        = $SessionTimeout
            SessionTimeoutLimit   = $SessionTimeoutLimit
            SessionTimeoutScope   = $SessionTimeoutScope
            SessionLifetime       = $SessionLifetime
            SessionLifetimeLimit  = $SessionLifetimeLimit
            SessionLifetimeScope  = $SessionLifetimeScope
        }

        $inner = ConvertTo-SfosWebServerAuthenticationPolicyEntityXml -Operation 'add' -Policy $policy

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create ReverseAuthentication object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ReverseAuthentication' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a Web Server authentication policy on a Sophos Firewall.

.DESCRIPTION
    Updates a Web Server authentication policy. You can supply the target policy name
    directly or through the pipeline.

    The firewall replaces the whole policy on update; any field not sent is cleared. This
    cmdlet reads the current policy first and keeps whatever the caller does not explicitly
    pass.

.PARAMETER Name
    Required. Name of the target policy.

.PARAMETER Description
    Optional. Free-text description. If omitted, the existing description is kept.

.PARAMETER VirtualWebserverMode
    Optional. Basic or Form. If omitted, the existing value is kept.

.PARAMETER FrontendRealm
    Optional. Realm string sent to the client. If omitted, the existing value is kept.

.PARAMETER BasicPrompt
    Optional. Text shown in the Basic authentication prompt, up to 255 characters. If
    omitted, the existing value is kept.

.PARAMETER FormTemplate
    Optional. Name of an existing FormTemplate object. If omitted, the existing value is
    kept.

.PARAMETER UserGroup
    Optional. Complete replacement list of allowed user groups. If omitted, the existing list
    is kept. Pass an empty array to clear it.

.PARAMETER RealWebserverMode
    Optional. Basic or None. If omitted, the existing value is kept.

.PARAMETER UsernameAffix
    Optional. None, Basic, Prefix, Suffix or PrefixAndSuffix. If omitted, the existing value
    is kept. See New-SfosWebServerAuthenticationPolicy for which values are confirmed.

.PARAMETER Prefix
    Optional. Prefix text, up to 255 characters. If omitted, the existing value is kept.

.PARAMETER Suffix
    Optional. Suffix text, up to 255 characters. If omitted, the existing value is kept.

.PARAMETER RemoveBasicHeader
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER SessionTimeout
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER SessionTimeoutLimit
    Optional. 1 to 9999. If omitted, the existing value is kept.

.PARAMETER SessionTimeoutScope
    Optional. Hours, Minutes or Days. If omitted, the existing value is kept.

.PARAMETER SessionLifetime
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER SessionLifetimeLimit
    Optional. 1 to 9999. If omitted, the existing value is kept.

.PARAMETER SessionLifetimeScope
    Optional. Hours, Minutes or Days. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for Web Server
    authentication policies. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts a policy object by value or by
    property name, for example from Get-SfosWebServerAuthenticationPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth' -Description 'Updated' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Get-SfosWebServerAuthenticationPolicy -NameLike 'IntranetAuth' | Set-SfosWebServerAuthenticationPolicy -Description 'Updated'

    Reads the matching policy and applies the same change through the pipeline.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerAuthenticationPolicy
#>
function Set-SfosWebServerAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Basic', 'Form')]
        [string]$VirtualWebserverMode,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$FrontendRealm,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$BasicPrompt,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$FormTemplate,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('UserGroupList')]
        [string[]]$UserGroup,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Basic', 'None')]
        [string]$RealWebserverMode,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('None', 'Basic', 'Prefix', 'Suffix', 'PrefixAndSuffix')]
        [string]$UsernameAffix,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Prefix,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Suffix,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$RemoveBasicHeader,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$SessionTimeout,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 9999)]
        [int]$SessionTimeoutLimit,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Hours', 'Minutes', 'Days')]
        [string]$SessionTimeoutScope,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$SessionLifetime,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1, 9999)]
        [int]$SessionLifetimeLimit,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Hours', 'Minutes', 'Days')]
        [string]$SessionLifetimeScope,

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
        $existing = @(Get-SfosWebServerAuthenticationPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ReverseAuthentication object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $bp = $PSBoundParameters

        if ($bp.ContainsKey('Description')) { $targetPolicy.Description = $Description }
        if ($bp.ContainsKey('VirtualWebserverMode')) { $targetPolicy.VirtualWebserverMode = $VirtualWebserverMode }
        if ($bp.ContainsKey('FrontendRealm')) { $targetPolicy.FrontendRealm = $FrontendRealm }
        if ($bp.ContainsKey('BasicPrompt')) { $targetPolicy.BasicPrompt = $BasicPrompt }
        if ($bp.ContainsKey('FormTemplate')) { $targetPolicy.FormTemplate = $FormTemplate }
        if ($bp.ContainsKey('UserGroup')) { $targetPolicy.UserGroupList = @($UserGroup) }
        if ($bp.ContainsKey('RealWebserverMode')) { $targetPolicy.RealWebserverMode = $RealWebserverMode }
        if ($bp.ContainsKey('UsernameAffix')) { $targetPolicy.UsernameAffix = $UsernameAffix }
        if ($bp.ContainsKey('Prefix')) { $targetPolicy.Prefix = $Prefix }
        if ($bp.ContainsKey('Suffix')) { $targetPolicy.Suffix = $Suffix }
        if ($bp.ContainsKey('RemoveBasicHeader')) { $targetPolicy.RemoveBasicHeader = $RemoveBasicHeader }
        if ($bp.ContainsKey('SessionTimeout')) { $targetPolicy.SessionTimeout = $SessionTimeout }
        if ($bp.ContainsKey('SessionTimeoutLimit')) { $targetPolicy.SessionTimeoutLimit = $SessionTimeoutLimit }
        if ($bp.ContainsKey('SessionTimeoutScope')) { $targetPolicy.SessionTimeoutScope = $SessionTimeoutScope }
        if ($bp.ContainsKey('SessionLifetime')) { $targetPolicy.SessionLifetime = $SessionLifetime }
        if ($bp.ContainsKey('SessionLifetimeLimit')) { $targetPolicy.SessionLifetimeLimit = $SessionLifetimeLimit }
        if ($bp.ContainsKey('SessionLifetimeScope')) { $targetPolicy.SessionLifetimeScope = $SessionLifetimeScope }

        $inner = ConvertTo-SfosWebServerAuthenticationPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("ReverseAuthentication '$($Name)' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating ReverseAuthentication object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ReverseAuthentication' -Action 'edit' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a Web Server authentication policy from a Sophos Firewall.

.DESCRIPTION
    Removes a Web Server authentication policy. The cmdlet reads the policy first and throws
    an error if the given name does not exist, so the caller gets a clear reason for the
    failure rather than the firewall's own misleading text for this case (a 504 "Deleting
    entity referred by another entity", which is unrelated to the actual cause).

.PARAMETER Name
    Required. Name of the policy to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for Web Server
    authentication policies. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts a policy object by value or by
    property name, for example from Get-SfosWebServerAuthenticationPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal, or if the named policy does not exist.

.EXAMPLE
    Remove-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth'

    Removes the named policy. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerAuthenticationPolicy
#>
function Remove-SfosWebServerAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

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
        $existing = @(Get-SfosWebServerAuthenticationPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ReverseAuthentication object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ReverseAuthentication '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><ReverseAuthentication><Name>$nameEsc</Name></ReverseAuthentication></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove ReverseAuthentication object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ReverseAuthentication' -Action 'remove' -Target $Name
    }
}

#endregion


#region FormTemplate

<#
.SYNOPSIS
    Checks whether a Web Server authentication template exists on a Sophos Firewall.
    Internal helper, not exported.

.DESCRIPTION
    FormTemplate is a binary-transport entity: a Get with a matching object answers with a
    tar archive (Content-Type application/octet-stream), not XML, and a Get with no match
    answers regular XML containing "No. of records Zero.". This helper turns that into a
    simple boolean by sending an exact-name filter and looking at the shape of the response,
    without extracting the archive. Used by Remove-SfosWebServerAuthenticationTemplate both
    before removal (to give a clear "not found" error) and after removal (because the
    firewall answers a Remove of a nonexistent template with 200, as if it had done
    something).

.PARAMETER Name
    Required. Exact name of the template to check for.

.PARAMETER ConnectionParameters
    Required. The resolved connection parameter hashtable from Resolve-SfosParameters.
#>
function Test-SfosWebServerAuthenticationTemplatePresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [hashtable]$ConnectionParameters
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $inner = "<Get><FormTemplate><Filter><key name=`"Name`" criteria=`"=`">$nameEsc</key></Filter></FormTemplate></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $ConnectionParameters.Firewall `
            -Port $ConnectionParameters.Port `
            -Username $ConnectionParameters.Username `
            -Password $ConnectionParameters.Password `
            -InnerXml $inner -SkipCertificateCheck:$ConnectionParameters.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error checking FormTemplate object '$Name': $($_.Exception.Message)"
    }

    if ($response.Content -isnot [string]) {
        # A binary body means the firewall found something to return for this exact name -
        # a nonexistent name is confirmed (measured) to answer with plain "no records" XML
        # instead, never with a file.
        return $true
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FormTemplate' -Action 'get'
    return $false
}

<#
.SYNOPSIS
    Retrieves Web Server authentication template files from a Sophos Firewall.

.DESCRIPTION
    Returns Web Server (WAF) authentication template objects (PROTECT > Web Server >
    Authentication Template). A FormTemplate object is the HTML login form (and its CSS
    asset) a Form-mode ReverseAuthentication policy shows to the client.

    This entity does not answer a matching Get with XML. The firewall instead answers with a
    tar archive (Content-Type application/octet-stream) containing the template's HTML file,
    its asset file(s), and an internal Entities.xml with the object's Name, Description,
    Template and Assets fields - the module does not extract or parse this archive, and
    returns it to the caller as raw bytes to extract with any tar-capable tool. Only a Get
    that matches nothing answers with regular XML ("No. of records Zero."), which this
    cmdlet turns into an empty array.

    Whether the -NameLike filter narrows the returned archive to just the matching
    template(s), or the firewall always returns every FormTemplate object in one archive
    once any name matches, was not measurable in the lab - only one FormTemplate object
    ("Default Template") exists there. A nonexistent name is confirmed to correctly answer
    with the "no records" XML rather than the full archive.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Sent to the firewall as a substring filter. If omitted, every FormTemplate
    object is requested.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for Web Server
    authentication templates. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties RawContent (the tar
    archive as a byte array) and ContentType, when at least one template matches. An empty
    array when nothing matches.

.EXAMPLE
    Get-SfosWebServerAuthenticationTemplate -NameLike 'Default'

    Retrieves the archive containing the built-in default login form.

.EXAMPLE
    $bundle = Get-SfosWebServerAuthenticationTemplate -NameLike 'Default'
    [IO.File]::WriteAllBytes('C:\Temp\formtemplate.tar', $bundle.RawContent)

    Saves the returned archive to disk for extraction with an external tar-capable tool.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Remove-SfosWebServerAuthenticationTemplate
#>
function Get-SfosWebServerAuthenticationTemplate {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <FormTemplate>
    $filterXml
  </FormTemplate>
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
        throw "Error retrieving FormTemplate objects: $($_.Exception.Message)"
    }

    if ($response.Content -isnot [string]) {
        return [PSCustomObject]@{
            RawContent  = [byte[]]$response.Content
            ContentType = [string]$response.Headers['Content-Type']
        }
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FormTemplate' -Action 'get'

    # A non-binary response from this entity means no template matched (measured: the only
    # observed non-binary text is "No. of records Zero."); anything else already threw above.
    return @()
}

<#
.SYNOPSIS
    Creates a Web Server authentication template on a Sophos Firewall.

.DESCRIPTION
    Uploads an HTML login form as a new FormTemplate object (PROTECT > Web Server >
    Authentication Template). This is a true multipart file upload, not a text-only API
    call: the request XML only references the file by name, the file itself travels as a
    separate part of the same request. -TemplateFile is checked for existence before
    anything is sent.

    Content the firewall stores in a template is not returned unchanged: any byte 0x80 or
    higher comes back corrupted on a later Get, independent of the upload transport - a
    defect in FormTemplate's own tar export on the firmware this was measured against.
    Plain-ASCII HTML round-trips correctly; text with accented characters, curly quotes,
    or other non-ASCII content does not.

.PARAMETER Name
    Required. Name for the new template.

.PARAMETER TemplateFile
    Required. Path to the HTML template file to upload. The firewall stores the file's
    name (not its directory) as the Template reference.

.PARAMETER AssetFile
    Optional. Path to one or more asset files, such as a stylesheet, meant to accompany
    the template - sent exactly as the API documentation describes (its own Asset
    multipart part per file, referenced from an Assets/Asset list in the request XML).
    Measured against a live firewall, on this firmware the request succeeds with no error
    but the asset is silently not stored: it is absent from both the returned archive and
    the Entities.xml inside it, regardless of the asset file's extension or the order of
    the multipart parts. -AssetFile is kept because it matches the documented contract and
    a future firmware may honor it, but do not rely on it doing anything today.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for Web Server
    authentication templates. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if a local file is missing or the
    firewall rejects the upload, for example if a template of that name already exists.

.EXAMPLE
    New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile 'C:\Templates\login.html'

    Uploads a new template built from a local HTML file.

.EXAMPLE
    New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile 'C:\Templates\login.html' -AssetFile 'C:\Templates\login.css' -WhatIf

    Shows what the call would create, including the asset file, without sending it to the
    firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerAuthenticationTemplate

.LINK
    Set-SfosWebServerAuthenticationTemplate
#>
function New-SfosWebServerAuthenticationTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$TemplateFile,

        [string[]]$AssetFile,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not (Test-Path -LiteralPath $TemplateFile -PathType Leaf)) {
        throw "Failed to create FormTemplate object '$Name': template file not found: $TemplateFile"
    }
    foreach ($asset in $AssetFile) {
        if (-not (Test-Path -LiteralPath $asset -PathType Leaf)) {
            throw "Failed to create FormTemplate object '$Name': asset file not found: $asset"
        }
    }

    if (-not $PSCmdlet.ShouldProcess("FormTemplate '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $templateNameEsc = ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $TemplateFile -Leaf)

    $multipartFile = @{ Template = $TemplateFile }
    $assetsXml = ''
    if ($AssetFile) {
        $multipartFile['Asset'] = $AssetFile
        $assetElements = foreach ($asset in $AssetFile) {
            '<Asset>{0}</Asset>' -f (ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $asset -Leaf))
        }
        $assetsXml = '<Assets>{0}</Assets>' -f ($assetElements -join '')
    }

    $inner = "<Set operation=`"add`"><FormTemplate><Name>$nameEsc</Name><Template>$templateNameEsc</Template>$assetsXml</FormTemplate></Set>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -MultipartFile $multipartFile `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create FormTemplate object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FormTemplate' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates a Web Server authentication template on a Sophos Firewall.

.DESCRIPTION
    Replaces the HTML template of an existing FormTemplate object. -TemplateFile and every
    -AssetFile path is checked for existence before anything is sent.

    The usual read-modify-write rule this suite otherwise applies to every Set-* cmdlet
    does not work here: a Get on this entity answers with a tar archive, not a field set,
    so there is nothing to read back and merge. An update is a straight replacement of the
    uploaded template, not a partial change. Documenting that plainly, rather than
    pretending to preserve fields this cmdlet cannot see, is the same choice already made
    for the raw Get output above.

.PARAMETER Name
    Required. Name of the template to update.

.PARAMETER TemplateFile
    Required. Path to the HTML template file that replaces the stored one. The firewall
    stores the file's name (not its directory) as the Template reference.

.PARAMETER AssetFile
    Optional. Path to one or more asset files, sent exactly as the API documentation
    describes. Measured against a live firewall, on this firmware the request succeeds
    with no error but the asset is silently not stored - see New-SfosWebServerAuthenticationTemplate
    for the same finding in more detail. -AssetFile is kept because it matches the
    documented contract, but do not rely on it doing anything today.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for Web Server
    authentication templates. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the template name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the named template does not
    exist, if a local file is missing, or if the firewall rejects the upload.

.EXAMPLE
    Set-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile 'C:\Templates\login-v2.html' -WhatIf

    Shows what the call would replace without sending it to the firewall.

.EXAMPLE
    Set-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile 'C:\Templates\login-v2.html'

    Replaces the stored template with the given HTML file. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerAuthenticationTemplate

.LINK
    New-SfosWebServerAuthenticationTemplate
#>
function Set-SfosWebServerAuthenticationTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$TemplateFile,

        [string[]]$AssetFile,

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
        if (-not (Test-SfosWebServerAuthenticationTemplatePresent -Name $Name -ConnectionParameters $params)) {
            throw "The FormTemplate object '$Name' was not found."
        }

        if (-not (Test-Path -LiteralPath $TemplateFile -PathType Leaf)) {
            throw "Failed to update FormTemplate object '$Name': template file not found: $TemplateFile"
        }
        foreach ($asset in $AssetFile) {
            if (-not (Test-Path -LiteralPath $asset -PathType Leaf)) {
                throw "Failed to update FormTemplate object '$Name': asset file not found: $asset"
            }
        }

        if (-not $PSCmdlet.ShouldProcess("FormTemplate '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $templateNameEsc = ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $TemplateFile -Leaf)

        $multipartFile = @{ Template = $TemplateFile }
        $assetsXml = ''
        if ($AssetFile) {
            $multipartFile['Asset'] = $AssetFile
            $assetElements = foreach ($asset in $AssetFile) {
                '<Asset>{0}</Asset>' -f (ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $asset -Leaf))
            }
            $assetsXml = '<Assets>{0}</Assets>' -f ($assetElements -join '')
        }

        $inner = "<Set operation=`"update`"><FormTemplate><Name>$nameEsc</Name><Template>$templateNameEsc</Template>$assetsXml</FormTemplate></Set>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -MultipartFile $multipartFile `
                -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update FormTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FormTemplate' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a Web Server authentication template from a Sophos Firewall.

.DESCRIPTION
    Removes a FormTemplate object. The firewall answers every removal with a plain 200,
    whether or not it performed one - a name that never existed is reported as removed, and
    on the tested firmware an existing template is reported as removed and is still there
    afterwards. This cmdlet does not trust that response. It checks for the object's
    existence before sending the Remove, so a nonexistent name fails with a clear error
    instead of a false success, and reads the object back afterwards, throwing if it is
    still present. Where the firewall refuses to remove a template, the web admin console
    is the remaining way to do it.

.PARAMETER Name
    Required. Name of the template to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for Web Server
    authentication templates. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the template name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the named template does not
    exist, if the firewall rejects the removal, or if the object is still present after a
    reported success.

.EXAMPLE
    Remove-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm'

    Removes the named template. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerAuthenticationTemplate
#>
function Remove-SfosWebServerAuthenticationTemplate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

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
        if (-not (Test-SfosWebServerAuthenticationTemplatePresent -Name $Name -ConnectionParameters $params)) {
            throw "The FormTemplate object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("FormTemplate '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><FormTemplate><Name>$nameEsc</Name></FormTemplate></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove FormTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FormTemplate' -Action 'remove' -Target $Name

        # The firewall answers 200 for a Remove of a template that was never there (measured)
        # - a status-only check would report success for a no-op. Read back and throw.
        if (Test-SfosWebServerAuthenticationTemplatePresent -Name $Name -ConnectionParameters $params) {
            throw "Removing FormTemplate '$Name' reported success, but the object is still present on the firewall."
        }
    }
}

#endregion


#region WAFSlowHTTP

<#
.SYNOPSIS
    Retrieves the WAF slow HTTP protection settings of a Sophos Firewall.

.DESCRIPTION
    Returns the WAF slow HTTP (Slowloris-style) protection settings singleton (PROTECT >
    Web Server > SlowHTTP Protection settings). There is exactly one instance of this object
    per firewall. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the WAF slow
    HTTP protection settings. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties
    RequestHeaderTimeoutEnabled, RequestHeaderTimeoutSoftLimit, RequestHeaderTimeoutHardLimit,
    RequestHeaderTimeoutExtensionRate and NetworkExceptionHost. NetworkExceptionHost is an
    empty array when the firewall has no exception hosts configured - it omits the wrapper
    element entirely in that case rather than sending it empty. Returns
    System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosWebServerSlowHTTPProtectionSettings

    Returns the current slow HTTP protection settings.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosWebServerSlowHTTPProtectionSettings
#>
function Get-SfosWebServerSlowHTTPProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'ProtectionSettings' is not a plural
    # container here but part of the entity's own name - the API element is <WAFSlowHTTP>, a
    # singleton holding one configuration, with no per-item child to make plural meaningful.
    # The Sophos spelling goes above PowerShell habit here; the singular concession is
    # reserved for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><WAFSlowHTTP></WAFSlowHTTP></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WAFSlowHTTP: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WAFSlowHTTP' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WAFSlowHTTP')
    if (-not $node) {
        throw 'WAFSlowHTTP could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $hosts = @()
    if ($node.NetworkExceptions) {
        $hosts = @($node.NetworkExceptions.Host | Where-Object -FilterScript { $_ })
    }

    return [PSCustomObject]@{
        RequestHeaderTimeoutEnabled       = [string]$node.RequestHeaderTimeoutEnabled
        RequestHeaderTimeoutSoftLimit      = [int]$node.RequestHeaderTimeoutSoftLimit
        RequestHeaderTimeoutHardLimit      = [int]$node.RequestHeaderTimeoutHardLimit
        RequestHeaderTimeoutExtensionRate  = [int]$node.RequestHeaderTimeoutExtensionRate
        NetworkExceptionHost               = [string[]]$hosts
    }
}

<#
.SYNOPSIS
    Updates the WAF slow HTTP protection settings of a Sophos Firewall.

.DESCRIPTION
    Changes the slow HTTP (Slowloris-style) protection settings singleton. The cmdlet reads
    the current settings first and sends them back complete, so a field you do not pass keeps
    its current value - the firewall replaces this whole object on every update, and an
    incomplete write has been observed elsewhere in this API to silently clear unrelated
    fields.

    NetworkExceptionHost is a full replace, not append-only: sending an empty array after a
    populated list actually clears it (measured), unlike some other list fields in this API.

.PARAMETER RequestHeaderTimeoutEnabled
    Optional. Enable or Disable. If omitted, the current value is kept.

.PARAMETER RequestHeaderTimeoutSoftLimit
    Optional. Soft timeout in seconds. If omitted, the current value is kept.

.PARAMETER RequestHeaderTimeoutHardLimit
    Optional. Hard timeout in seconds. If omitted, the current value is kept.

.PARAMETER RequestHeaderTimeoutExtensionRate
    Optional. Extension rate. If omitted, the current value is kept.

.PARAMETER NetworkExceptionHost
    Optional. Complete replacement list of host object names exempted from slow HTTP
    protection. If omitted, the current list is kept. Pass an empty array to clear it.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the WAF
    slow HTTP protection settings. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosWebServerSlowHTTPProtectionSettings -RequestHeaderTimeoutSoftLimit 10 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosWebServerSlowHTTPProtectionSettings -RequestHeaderTimeoutSoftLimit 10

    Changes only the soft timeout; every other field is kept. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosWebServerSlowHTTPProtectionSettings
#>
function Set-SfosWebServerSlowHTTPProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. See Get-SfosWebServerSlowHTTPProtectionSettings
    # for the reason - the entity itself is named WAFSlowHTTP, a singleton with no plural child.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$RequestHeaderTimeoutEnabled,

        [int]$RequestHeaderTimeoutSoftLimit,
        [int]$RequestHeaderTimeoutHardLimit,
        [int]$RequestHeaderTimeoutExtensionRate,

        [string[]]$NetworkExceptionHost,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosWebServerSlowHTTPProtectionSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetEnabled = if ($bp.ContainsKey('RequestHeaderTimeoutEnabled')) { $RequestHeaderTimeoutEnabled } else { $existing.RequestHeaderTimeoutEnabled }
    $targetSoft = if ($bp.ContainsKey('RequestHeaderTimeoutSoftLimit')) { $RequestHeaderTimeoutSoftLimit } else { $existing.RequestHeaderTimeoutSoftLimit }
    $targetHard = if ($bp.ContainsKey('RequestHeaderTimeoutHardLimit')) { $RequestHeaderTimeoutHardLimit } else { $existing.RequestHeaderTimeoutHardLimit }
    $targetRate = if ($bp.ContainsKey('RequestHeaderTimeoutExtensionRate')) { $RequestHeaderTimeoutExtensionRate } else { $existing.RequestHeaderTimeoutExtensionRate }
    $targetHosts = @(if ($bp.ContainsKey('NetworkExceptionHost')) { $NetworkExceptionHost } else { $existing.NetworkExceptionHost })

    if (-not $PSCmdlet.ShouldProcess("WAFSlowHTTP on $($params.Firewall)", 'Update')) {
        return
    }

    $hostsXml = ''
    foreach ($hostValue in $targetHosts) {
        if (-not $hostValue) { continue }
        $hostsXml += "<Host>$(ConvertTo-SfosXmlEscaped -Text $hostValue)</Host>"
    }
    $networkExceptionsXml = ''
    if ($hostsXml) {
        $networkExceptionsXml = "<NetworkExceptions>$hostsXml</NetworkExceptions>"
    }

    $inner = @"
<Set operation="update">
  <WAFSlowHTTP>
    <RequestHeaderTimeoutEnabled>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetEnabled))</RequestHeaderTimeoutEnabled>
    <RequestHeaderTimeoutSoftLimit>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetSoft))</RequestHeaderTimeoutSoftLimit>
    <RequestHeaderTimeoutHardLimit>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetHard))</RequestHeaderTimeoutHardLimit>
    <RequestHeaderTimeoutExtensionRate>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetRate))</RequestHeaderTimeoutExtensionRate>
    $networkExceptionsXml
  </WAFSlowHTTP>
</Set>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating WAFSlowHTTP: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WAFSlowHTTP' -Action 'update'
}

#endregion
