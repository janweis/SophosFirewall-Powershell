#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.ActiveThreatResponse
    ====================================
    PowerShell module for the Sophos Firewall (SFOS) PROTECT > Active threat response area
    via the XML API: the device-wide ATP (Sophos X-Ops threat feeds) singleton, including its
    HostException and ThreatException lists, and ThirdPartyFeed objects.

    Total Functions: 10 - see README.md for the full cmdlet table.

    Requires SophosFirewall.Core (>= 1.3.0) for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S) happens
    in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>

#region ATP

<#
        .SYNOPSIS
        Retrieves the ATP (Sophos X-Ops threat feeds) settings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the ATP singleton (PROTECT > Active threat
        response > Sophos X-Ops threat feeds - the wire element and API documentation folder
        are still named ATP, a naming leftover from the feature's former name "Advanced Threat
        Protection"). There is exactly one instance of this element per firewall. By default
        the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.
        The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER AsXml
        Optional. Returns the raw XML node sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with the properties
        ThreatProtectionStatus, InspectContent, Policy, HostExceptionList and
        ThreatExceptionList. Returns System.Xml.XmlElement when -AsXml is used. The exception
        lists are always an array, empty when no exception is configured.

        .EXAMPLE
        Get-SfosATPSettings

        Reads the device-wide ATP configuration.

        .EXAMPLE
        Get-SfosATPSettings -AsXml

        Returns the raw XML node, for example to check a field that the standard output does
        not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/ATP/operations/SophosX-Opsthreatfeeds.html

        .LINK
        Set-SfosATPSettings
#>
function Get-SfosATPSettings {
    # PSUseSingularNouns is suppressed on purpose: <ATP> settings form one singleton
    # configuration object (Sophos X-Ops threat feeds), not a plural container - the same
    # reasoning as the WebFilterSettings precedent.
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

    $inner = '<Get><ATP></ATP></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve ATP settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ATP' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/ATP')
    if (-not $node) {
        throw 'ATP settings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $hostNodes = @($node.SelectNodes('HostException/Host'))
    $threatNodes = @($node.SelectNodes('ThreatException/Threat'))

    return [PSCustomObject]@{
        ThreatProtectionStatus = [string]$node.ThreatProtectionStatus
        InspectContent         = [string]$node.InspectContent
        Policy                 = [string]$node.Policy
        HostExceptionList      = @($hostNodes | ForEach-Object -Process { [string]$_.InnerText })
        ThreatExceptionList    = @($threatNodes | ForEach-Object -Process { [string]$_.InnerText })
    }
}

<#
        .SYNOPSIS
        Updates the ATP (Sophos X-Ops threat feeds) settings on the Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide ATP singleton using the Sophos Firewall XML API. Reads the
        current object first and resends every field, overriding only what the caller
        explicitly passed. Fields left out keep their current value on the firewall.

        This is a device-wide security switch that controls threat feed enforcement for the
        whole appliance. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with administrative
        permission.

        .PARAMETER ThreatProtectionStatus
        Optional. 'Enable' or 'Disable'. If omitted, the existing value is kept.

        .PARAMETER InspectContent
        Optional. 'all' or 'untrusted'. If omitted, the existing value is kept.

        .PARAMETER Policy
        Optional. 'Log Only' or 'Log and Drop'. If omitted, the existing value is kept.

        .PARAMETER HostException
        Optional. Complete replacement list of HostException entries. Each entry must be the
        name of an existing IPHost object on the firewall. If omitted, the existing list is
        kept. Pass an empty array to clear the list.

        .PARAMETER ThreatException
        Optional. Complete replacement list of ThreatException entries. Each entry is free
        text. If omitted, the existing list is kept. Pass an empty array to clear the list.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

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

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosATPSettings -InspectContent all -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosATPSettings -InspectContent all

        Switches content inspection from untrusted-only to all traffic. Every other field
        keeps its current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/ATP/operations/SophosX-Opsthreatfeeds.html

        .LINK
        Get-SfosATPSettings
#>
function Set-SfosATPSettings {
    # PSUseSingularNouns is suppressed on purpose: see Get-SfosATPSettings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$ThreatProtectionStatus,

        [ValidateSet('all', 'untrusted')]
        [string]$InspectContent,

        [ValidateSet('Log Only', 'Log and Drop')]
        [string]$Policy,

        [string[]]$HostException,

        [string[]]$ThreatException,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    $current = Get-SfosATPSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetThreatProtectionStatus = if ($bp.ContainsKey('ThreatProtectionStatus')) { $ThreatProtectionStatus } else { $current.ThreatProtectionStatus }
    $targetInspectContent = if ($bp.ContainsKey('InspectContent')) { $InspectContent } else { $current.InspectContent }
    $targetPolicy = if ($bp.ContainsKey('Policy')) { $Policy } else { $current.Policy }
    # @() wraps the whole if/else: a one-element array from a branch unrolls to a scalar
    # on assignment.
    $targetHostException = @(if ($bp.ContainsKey('HostException')) { $HostException } else { $current.HostExceptionList })
    $targetThreatException = @(if ($bp.ContainsKey('ThreatException')) { $ThreatException } else { $current.ThreatExceptionList })

    if (-not $PSCmdlet.ShouldProcess("ATP settings on $($params.Firewall)", 'Update')) {
        return
    }

    $policyEsc = ConvertTo-SfosXmlEscaped -Text $targetPolicy

    $hostXml = ''
    if ($targetHostException.Count -gt 0) {
        $hostItems = foreach ($item in $targetHostException) {
            $itemEsc = ConvertTo-SfosXmlEscaped -Text $item
            "<Host>$itemEsc</Host>"
        }
        $hostXml = "<HostException>$($hostItems -join '')</HostException>"
    }

    $threatXml = ''
    if ($targetThreatException.Count -gt 0) {
        $threatItems = foreach ($item in $targetThreatException) {
            $itemEsc = ConvertTo-SfosXmlEscaped -Text $item
            "<Threat>$itemEsc</Threat>"
        }
        $threatXml = "<ThreatException>$($threatItems -join '')</ThreatException>"
    }

    $inner = @"
<Set operation="update">
  <ATP>
    <ThreatProtectionStatus>$targetThreatProtectionStatus</ThreatProtectionStatus>
    <InspectContent>$targetInspectContent</InspectContent>
    <Policy>$policyEsc</Policy>
    $hostXml
    $threatXml
  </ATP>
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
        throw "Failed to update ATP settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ATP' -Action 'update'
}

<#
        .SYNOPSIS
        Adds an IPHost exception to the ATP settings on the Sophos Firewall.

        .DESCRIPTION
        Adds an entry to the ATP HostException list using the Sophos Firewall XML API. Reads
        the current ATP object first and resends it complete with the new host appended. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        HostException expects the name of an already existing IPHost object, while
        ThreatException accepts free text.

        .PARAMETER HostName
        Required. Name of an existing IPHost object on the firewall to except from ATP
        inspection. Accepts pipeline input by value or by property name, aliased 'Host' so
        Get-SfosIPHost | Add-SfosATPHostException binds.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .INPUTS
        System.String. HostName can be supplied by value or by property name, for example
        from Get-SfosIPHost.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosATPHostException -HostName 'WebServer01' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosATPHostException -HostName 'WebServer01'

        Adds the IPHost object 'WebServer01' to the ATP HostException list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/ATP/operations/SophosX-Opsthreatfeeds.html

        .LINK
        Get-SfosATPSettings

        .LINK
        Remove-SfosATPHostException
#>
function Add-SfosATPHostException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Host')]
        [string]$HostName,

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
        $current = Get-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        if (-not $PSCmdlet.ShouldProcess("ATP HostException '$HostName' on $($params.Firewall)", 'Add')) {
            return
        }

        $newList = @($current.HostExceptionList) + $HostName

        Set-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck `
            -HostException $newList `
            -Confirm:$false
    }
}

<#
        .SYNOPSIS
        Removes an IPHost exception from the ATP settings on the Sophos Firewall.

        .DESCRIPTION
        Removes an entry from the ATP HostException list using the Sophos Firewall XML API.
        Reads the current ATP object first, throws if the host is not currently listed, and
        otherwise resends the ATP object complete with the host filtered out. Reads the
        object back afterwards and throws if the host is still present. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER HostName
        Required. Name of the IPHost object to remove from the HostException list. Accepts
        pipeline input by value or by property name, aliased 'Host'.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .INPUTS
        System.String. HostName can be supplied by value or by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the update fails or the host
        is still present afterwards.

        .EXAMPLE
        Remove-SfosATPHostException -HostName 'WebServer01' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosATPHostException -HostName 'WebServer01'

        Removes the IPHost object 'WebServer01' from the ATP HostException list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/ATP/operations/SophosX-Opsthreatfeeds.html

        .LINK
        Get-SfosATPSettings

        .LINK
        Add-SfosATPHostException
#>
function Remove-SfosATPHostException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Host')]
        [string]$HostName,

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
        $current = Get-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        if (@($current.HostExceptionList) -notcontains $HostName) {
            throw "The ATP HostException '$HostName' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ATP HostException '$HostName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $newList = @($current.HostExceptionList | Where-Object -FilterScript { $_ -ne $HostName })

        Set-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck `
            -HostException $newList `
            -Confirm:$false

        $after = Get-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        if (@($after.HostExceptionList) -contains $HostName) {
            throw "Failed to remove ATP HostException '$HostName': the firewall reported success but the host is still present."
        }
    }
}

<#
        .SYNOPSIS
        Adds a threat exception to the ATP settings on the Sophos Firewall.

        .DESCRIPTION
        Adds an entry to the ATP ThreatException list using the Sophos Firewall XML API.
        Reads the current ATP object first and resends it complete with the new threat
        identifier appended. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        HostException expects the name of an already existing IPHost object, while
        ThreatException accepts free text.

        .PARAMETER Threat
        Required. Threat identifier text to except from ATP enforcement. Accepts pipeline
        input by value or by property name.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .INPUTS
        System.String. Threat can be supplied by value or by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosATPThreatException -Threat 'C2/Generic-A' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosATPThreatException -Threat 'C2/Generic-A'

        Adds the threat identifier 'C2/Generic-A' to the ATP ThreatException list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/ATP/operations/SophosX-Opsthreatfeeds.html

        .LINK
        Get-SfosATPSettings

        .LINK
        Remove-SfosATPThreatException
#>
function Add-SfosATPThreatException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Threat,

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
        $current = Get-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        if (-not $PSCmdlet.ShouldProcess("ATP ThreatException '$Threat' on $($params.Firewall)", 'Add')) {
            return
        }

        $newList = @($current.ThreatExceptionList) + $Threat

        Set-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck `
            -ThreatException $newList `
            -Confirm:$false
    }
}

<#
        .SYNOPSIS
        Removes a threat exception from the ATP settings on the Sophos Firewall.

        .DESCRIPTION
        Removes an entry from the ATP ThreatException list using the Sophos Firewall XML API.
        Reads the current ATP object first, throws if the threat is not currently listed, and
        otherwise resends the ATP object complete with the threat filtered out. Reads the
        object back afterwards and throws if the threat is still present. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Threat
        Required. Threat identifier text to remove from the ThreatException list. Accepts
        pipeline input by value or by property name.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .INPUTS
        System.String. Threat can be supplied by value or by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the update fails or the
        threat is still present afterwards.

        .EXAMPLE
        Remove-SfosATPThreatException -Threat 'C2/Generic-A' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosATPThreatException -Threat 'C2/Generic-A'

        Removes the threat identifier 'C2/Generic-A' from the ATP ThreatException list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/ATP/operations/SophosX-Opsthreatfeeds.html

        .LINK
        Get-SfosATPSettings

        .LINK
        Add-SfosATPThreatException
#>
function Remove-SfosATPThreatException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Threat,

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
        $current = Get-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        if (@($current.ThreatExceptionList) -notcontains $Threat) {
            throw "The ATP ThreatException '$Threat' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ATP ThreatException '$Threat' on $($params.Firewall)", 'Remove')) {
            return
        }

        $newList = @($current.ThreatExceptionList | Where-Object -FilterScript { $_ -ne $Threat })

        Set-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck `
            -ThreatException $newList `
            -Confirm:$false

        $after = Get-SfosATPSettings -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        if (@($after.ThreatExceptionList) -contains $Threat) {
            throw "Failed to remove ATP ThreatException '$Threat': the firewall reported success but the threat is still present."
        }
    }
}

#endregion

#region ThirdPartyFeed

<#
        .SYNOPSIS
        Retrieves ThirdPartyFeed objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ThirdPartyFeed objects (PROTECT > Active
        threat response > Third party threat feed). A ThirdPartyFeed polls an external URL
        for threat indicators and feeds them into the firewall's own enforcement. By default
        the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML
        nodes. The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        Position is a write-only field and Get-SfosThirdPartyFeed never returns it, so
        Set-SfosThirdPartyFeed has no -Position parameter.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern. If omitted, the name is not used to filter.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER AsXml
        Optional. Returns the raw XML nodes sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per feed, with the properties
        Id, Name, Description, Action, IndicatorType, ExternalURL, Authorization, Username,
        PasswordHash, Key, ValueHash, AddTo, ValidateServerCertificate, PollingInterval and
        Enabled. PasswordHash and ValueHash carry the firewall's hashed secret for
        troubleshooting only; they are never usable as a credential. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosThirdPartyFeed

        Lists every configured third-party threat feed.

        .EXAMPLE
        Get-SfosThirdPartyFeed -NameLike 'Feed'

        Lists all feeds whose name contains 'Feed'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/thirdpartyfeeds/thirdpartyfeeds.html

        .LINK
        New-SfosThirdPartyFeed
#>
function Get-SfosThirdPartyFeed {
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

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <ThirdPartyFeed>
    $filterXml
  </ThirdPartyFeed>
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
        throw "Failed to retrieve ThirdPartyFeed objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ThirdPartyFeed' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ThirdPartyFeed[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $passwordNode = $node.SelectSingleNode('Password')
        $valueNode = $node.SelectSingleNode('Value')

        [PSCustomObject]@{
            Id                        = [string]$node.Id
            Name                      = [string]$node.Name
            Description               = [string]$node.Description
            Action                    = [string]$node.Action
            IndicatorType             = [string]$node.IndicatorType
            ExternalURL               = [string]$node.ExternalURL
            Authorization             = [string]$node.Authorization
            Username                  = [string]$node.Username
            PasswordHash              = if ($passwordNode) { [string]$passwordNode.InnerText } else { '' }
            Key                       = [string]$node.Key
            ValueHash                 = if ($valueNode) { [string]$valueNode.InnerText } else { '' }
            AddTo                     = [string]$node.AddTo
            ValidateServerCertificate = [string]$node.ValidateServerCertificate
            PollingInterval           = [string]$node.PollingInterval
            Enabled                   = [string]$node.Enabled
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
        .SYNOPSIS
        Creates a new ThirdPartyFeed object on the Sophos Firewall.

        .DESCRIPTION
        Creates a ThirdPartyFeed (PROTECT > Active threat response > Third party threat feed)
        using the Sophos Firewall XML API. Use this cmdlet to add an external threat
        indicator feed for the firewall to poll. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the feed. Maximum 63 characters, letters, digits, underscore and
        hyphen only.

        .PARAMETER Description
        Optional. Free-text description. Maximum 255 characters. If omitted, an empty
        description is stored.

        .PARAMETER Action
        Optional. 'block' or 'monitor'. Default 'monitor'.

        .PARAMETER Position
        Optional. 'top' or 'bottom'. Default 'top'. This field is write-only; Get-* never
        returns it, so it can only be set here at creation, not changed afterwards.

        .PARAMETER IndicatorType
        Optional. 'ip', 'domain' or 'url'. Default 'ip'.

        .PARAMETER ExternalURL
        Required. URL the firewall polls for indicator data. Maximum 1024 characters.

        .PARAMETER Authorization
        Optional. 'noAuthentication', 'basicAuthentication' or 'apiKey'. Default
        'noAuthentication'. Determines which of -FeedUsername/-FeedPassword or
        -ApiKeyName/-ApiKeyValue/-AddTo are required; see those parameters.

        .PARAMETER FeedUsername
        Optional. Username for -Authorization basicAuthentication. Named differently from the
        connection parameter -Username because that name is reserved for the API login
        identity. Ignored for other -Authorization values.

        .PARAMETER FeedPassword
        Optional. Password for -Authorization basicAuthentication, as a SecureString. Named
        differently from the connection parameter -Password because that name is reserved for
        the API login secret. Required when -Authorization is basicAuthentication.

        .PARAMETER ApiKeyName
        Optional. The API key field or header name for -Authorization apiKey. Required when
        -Authorization is apiKey.

        .PARAMETER ApiKeyValue
        Optional. The API key secret value for -Authorization apiKey, as a SecureString.
        Required when -Authorization is apiKey.

        .PARAMETER AddTo
        Optional. 'header' or 'queryParam' for -Authorization apiKey. Required when
        -Authorization is apiKey.

        .PARAMETER ValidateServerCertificate
        Required. '1' or '0'. Whether the firewall validates the TLS certificate of
        -ExternalURL when polling.

        .PARAMETER PollingInterval
        Required. One of '5m','15m','30m','1h','6h','24h','7d','30d'.

        .PARAMETER Enabled
        Optional. '1' or '0'. Default '1'.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

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

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if creation fails.

        .EXAMPLE
        New-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Action monitor -IndicatorType ip -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization noAuthentication -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1 -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Action monitor -IndicatorType ip -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization noAuthentication -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

        Creates a feed with no authentication.

        .EXAMPLE
        $pw = ConvertTo-SecureString 'FeedSecret1!' -AsPlainText -Force
        New-SfosThirdPartyFeed -Name 'VendorIPFeed' -Action monitor -IndicatorType ip -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization basicAuthentication -FeedUsername 'feedreader' -FeedPassword $pw -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

        Creates a feed that authenticates with a username and password.

        .EXAMPLE
        $key = ConvertTo-SecureString 'MyApiKeyValue123' -AsPlainText -Force
        New-SfosThirdPartyFeed -Name 'PartnerIPFeed' -Action monitor -IndicatorType ip -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization apiKey -ApiKeyName 'X-Api-Key' -ApiKeyValue $key -AddTo header -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

        Creates a feed that authenticates with an API key.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/thirdpartyfeeds/operations/AddThird-partythreatfeed%26EditThird-partythreatfeed.html

        .LINK
        Get-SfosThirdPartyFeed
#>
function New-SfosThirdPartyFeed {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 63)]
        [ValidatePattern('^[A-Za-z0-9_-]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description = '',

        [ValidateSet('block', 'monitor')]
        [string]$Action = 'monitor',

        [ValidateSet('top', 'bottom')]
        [string]$Position = 'top',

        [ValidateSet('ip', 'domain', 'url')]
        [string]$IndicatorType = 'ip',

        [Parameter(Mandatory)]
        [ValidateLength(1, 1024)]
        [string]$ExternalURL,

        [ValidateSet('noAuthentication', 'basicAuthentication', 'apiKey')]
        [string]$Authorization = 'noAuthentication',

        [string]$FeedUsername,

        [SecureString]$FeedPassword,

        [string]$ApiKeyName,

        [SecureString]$ApiKeyValue,

        [ValidateSet('header', 'queryParam')]
        [string]$AddTo,

        [Parameter(Mandatory)]
        [ValidateSet('1', '0')]
        [string]$ValidateServerCertificate,

        [Parameter(Mandatory)]
        [ValidateSet('5m', '15m', '30m', '1h', '6h', '24h', '7d', '30d')]
        [string]$PollingInterval,

        [ValidateSet('1', '0')]
        [string]$Enabled = '1',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($Authorization -eq 'basicAuthentication' -and -not $FeedPassword) {
        throw "ThirdPartyFeed '$Name': -Authorization basicAuthentication requires -FeedPassword."
    }
    if ($Authorization -eq 'apiKey' -and (-not $ApiKeyName -or -not $ApiKeyValue -or -not $AddTo)) {
        throw "ThirdPartyFeed '$Name': -Authorization apiKey requires -ApiKeyName, -ApiKeyValue and -AddTo."
    }

    if (-not $PSCmdlet.ShouldProcess("ThirdPartyFeed '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descriptionEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $externalUrlEsc = ConvertTo-SfosXmlEscaped -Text $ExternalURL

    $authXml = ''
    if ($Authorization -eq 'basicAuthentication') {
        $usernameEsc = ConvertTo-SfosXmlEscaped -Text $FeedUsername
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($FeedPassword)
        try {
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
        $passwordEsc = ConvertTo-SfosXmlEscaped -Text $plainPassword
        $authXml = "<Username>$usernameEsc</Username><Password>$passwordEsc</Password>"
    }
    elseif ($Authorization -eq 'apiKey') {
        $keyEsc = ConvertTo-SfosXmlEscaped -Text $ApiKeyName
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKeyValue)
        try {
            $plainValue = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
        $valueEsc = ConvertTo-SfosXmlEscaped -Text $plainValue
        $authXml = "<Key>$keyEsc</Key><Value>$valueEsc</Value><AddTo>$AddTo</AddTo>"
    }

    $inner = @"
<Set operation="add">
  <ThirdPartyFeed>
    <Name>$nameEsc</Name>
    <Description>$descriptionEsc</Description>
    <Action>$Action</Action>
    <Position>$Position</Position>
    <IndicatorType>$IndicatorType</IndicatorType>
    <ExternalURL>$externalUrlEsc</ExternalURL>
    <Authorization>$Authorization</Authorization>
    $authXml
    <ValidateServerCertificate>$ValidateServerCertificate</ValidateServerCertificate>
    <PollingInterval>$PollingInterval</PollingInterval>
    <Enabled>$Enabled</Enabled>
  </ThirdPartyFeed>
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
        throw "Failed to create ThirdPartyFeed object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ThirdPartyFeed' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing ThirdPartyFeed object on the Sophos Firewall.

        .DESCRIPTION
        Updates a ThirdPartyFeed using the Sophos Firewall XML API. Reads the current object
        first and resends every field, overriding only what the caller explicitly passed.
        Fields left out keep their current value on the firewall.

        Resending a password or API key value that was read back from Get-SfosThirdPartyFeed
        makes the whole update fail; leaving the secret parameter out keeps the stored secret
        unchanged. This cmdlet never resends the value Get-SfosThirdPartyFeed returns, so pass
        -FeedPassword or -ApiKeyValue only when you want to set a new secret.

        .PARAMETER Name
        Required. Name of the target feed. Accepts pipeline input by property name.

        .PARAMETER Description
        Optional. Free-text description. If omitted, the existing value is kept.

        .PARAMETER Action
        Optional. 'block' or 'monitor'. If omitted, the existing value is kept.

        .PARAMETER IndicatorType
        Optional. 'ip', 'domain' or 'url'. If omitted, the existing value is kept.

        .PARAMETER ExternalURL
        Optional. URL the firewall polls for indicator data. If omitted, the existing value
        is kept.

        .PARAMETER Authorization
        Optional. 'noAuthentication', 'basicAuthentication' or 'apiKey'. If omitted, the
        existing value is kept. Switching to basicAuthentication or apiKey without a previous
        value of that type requires the matching secret parameter; see
        -FeedPassword/-ApiKeyValue.

        .PARAMETER FeedUsername
        Optional. Username for -Authorization basicAuthentication. Named differently from the
        connection parameter -Username because that name is reserved for the API login
        identity. If omitted, the existing value is kept.

        .PARAMETER FeedPassword
        Optional. New password for -Authorization basicAuthentication, as a SecureString. If
        omitted and the feed is already, or remains, basicAuthentication, the existing
        password is left unchanged on the firewall. Required when switching from a different
        -Authorization value to basicAuthentication in the same call.

        .PARAMETER ApiKeyName
        Optional. The API key field or header name for -Authorization apiKey. If omitted, the
        existing value is kept.

        .PARAMETER ApiKeyValue
        Optional. New API key secret value for -Authorization apiKey, as a SecureString. If
        omitted and the feed is already, or remains, apiKey, the existing value is left
        unchanged on the firewall. Required when switching from a different -Authorization
        value to apiKey in the same call.

        .PARAMETER AddTo
        Optional. 'header' or 'queryParam' for -Authorization apiKey. If omitted, the existing
        value is kept.

        .PARAMETER ValidateServerCertificate
        Optional. '1' or '0'. If omitted, the existing value is kept.

        .PARAMETER PollingInterval
        Optional. One of '5m','15m','30m','1h','6h','24h','7d','30d'. If omitted, the existing
        value is kept.

        .PARAMETER Enabled
        Optional. '1' or '0'. If omitted, the existing value is kept.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

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

        .INPUTS
        System.Management.Automation.PSCustomObject. Name is bound by property name, for
        example from Get-SfosThirdPartyFeed.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the update fails.

        .EXAMPLE
        Set-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Enabled 0 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Enabled 0

        Disables a feed, leaving every other field, including any stored secret, unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/thirdpartyfeeds/operations/AddThird-partythreatfeed%26EditThird-partythreatfeed.html

        .LINK
        Get-SfosThirdPartyFeed
#>
function Set-SfosThirdPartyFeed {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$Description,

        [ValidateSet('block', 'monitor')]
        [string]$Action,

        [ValidateSet('ip', 'domain', 'url')]
        [string]$IndicatorType,

        [string]$ExternalURL,

        [ValidateSet('noAuthentication', 'basicAuthentication', 'apiKey')]
        [string]$Authorization,

        [string]$FeedUsername,

        [SecureString]$FeedPassword,

        [string]$ApiKeyName,

        [SecureString]$ApiKeyValue,

        [ValidateSet('header', 'queryParam')]
        [string]$AddTo,

        [ValidateSet('1', '0')]
        [string]$ValidateServerCertificate,

        [ValidateSet('5m', '15m', '30m', '1h', '6h', '24h', '7d', '30d')]
        [string]$PollingInterval,

        [ValidateSet('1', '0')]
        [string]$Enabled,

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
        $bp = $PSBoundParameters

        $existing = @(Get-SfosThirdPartyFeed -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ThirdPartyFeed object '$Name' was not found."
        }
        $current = $existing[0]

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$current.Description }
        $targetAction = if ($bp.ContainsKey('Action')) { $Action } else { $current.Action }
        $targetIndicatorType = if ($bp.ContainsKey('IndicatorType')) { $IndicatorType } else { $current.IndicatorType }
        $targetExternalURL = if ($bp.ContainsKey('ExternalURL')) { $ExternalURL } else { $current.ExternalURL }
        $targetAuthorization = if ($bp.ContainsKey('Authorization')) { $Authorization } else { $current.Authorization }
        $targetValidateServerCertificate = if ($bp.ContainsKey('ValidateServerCertificate')) { $ValidateServerCertificate } else { $current.ValidateServerCertificate }
        $targetPollingInterval = if ($bp.ContainsKey('PollingInterval')) { $PollingInterval } else { $current.PollingInterval }
        $targetEnabled = if ($bp.ContainsKey('Enabled')) { $Enabled } else { $current.Enabled }

        $authXml = ''
        if ($targetAuthorization -eq 'basicAuthentication') {
            $targetUsername = if ($bp.ContainsKey('FeedUsername')) { $FeedUsername } else { [string]$current.Username }
            $usernameEsc = ConvertTo-SfosXmlEscaped -Text $targetUsername

            if ($bp.ContainsKey('FeedPassword')) {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($FeedPassword)
                try {
                    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                }
                finally {
                    [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
                }
                $passwordEsc = ConvertTo-SfosXmlEscaped -Text $plainPassword
                $authXml = "<Username>$usernameEsc</Username><Password>$passwordEsc</Password>"
            }
            elseif ($current.Authorization -eq 'basicAuthentication') {
                # Omitting Password here, while staying basicAuthentication, preserves the
                # stored secret. Resending PasswordHash silently drops the whole update instead.
                $authXml = "<Username>$usernameEsc</Username>"
            }
            else {
                throw "ThirdPartyFeed '$Name': switching -Authorization to basicAuthentication requires -FeedPassword."
            }
        }
        elseif ($targetAuthorization -eq 'apiKey') {
            $targetApiKeyName = if ($bp.ContainsKey('ApiKeyName')) { $ApiKeyName } else { [string]$current.Key }
            $keyEsc = ConvertTo-SfosXmlEscaped -Text $targetApiKeyName
            $targetAddTo = if ($bp.ContainsKey('AddTo')) { $AddTo } else { $current.AddTo }

            if ($bp.ContainsKey('ApiKeyValue')) {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKeyValue)
                try {
                    $plainValue = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                }
                finally {
                    [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
                }
                $valueEsc = ConvertTo-SfosXmlEscaped -Text $plainValue
                $authXml = "<Key>$keyEsc</Key><Value>$valueEsc</Value><AddTo>$targetAddTo</AddTo>"
            }
            elseif ($current.Authorization -eq 'apiKey') {
                # Same preserve-on-omit behaviour as Password above.
                $authXml = "<Key>$keyEsc</Key><AddTo>$targetAddTo</AddTo>"
            }
            else {
                throw "ThirdPartyFeed '$Name': switching -Authorization to apiKey requires -ApiKeyName, -ApiKeyValue and -AddTo."
            }
        }

        if (-not $PSCmdlet.ShouldProcess("ThirdPartyFeed '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $descriptionEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
        $externalUrlEsc = ConvertTo-SfosXmlEscaped -Text $targetExternalURL

        $inner = @"
<Set operation="update">
  <ThirdPartyFeed>
    <Name>$nameEsc</Name>
    <Description>$descriptionEsc</Description>
    <Action>$targetAction</Action>
    <IndicatorType>$targetIndicatorType</IndicatorType>
    <ExternalURL>$externalUrlEsc</ExternalURL>
    <Authorization>$targetAuthorization</Authorization>
    $authXml
    <ValidateServerCertificate>$targetValidateServerCertificate</ValidateServerCertificate>
    <PollingInterval>$targetPollingInterval</PollingInterval>
    <Enabled>$targetEnabled</Enabled>
  </ThirdPartyFeed>
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
            throw "Failed to update ThirdPartyFeed object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ThirdPartyFeed' -Action 'update' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a ThirdPartyFeed object from the Sophos Firewall.

        .DESCRIPTION
        Removes a ThirdPartyFeed using the Sophos Firewall XML API. Reads the object first and
        throws a clear "not found" error if it does not exist. Remove-SfosThirdPartyFeed
        decides whether the removal succeeded by reading the object back afterwards, because
        the firewall's own delete response for this entity does not reliably indicate success
        or failure.

        .PARAMETER Name
        Required. Name of the feed to remove. Accepts pipeline input by property name.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

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

        .INPUTS
        System.Management.Automation.PSCustomObject. Name is bound by property name, for
        example from Get-SfosThirdPartyFeed.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the removal fails or cannot
        be confirmed.

        .EXAMPLE
        Remove-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosThirdPartyFeed -Name 'AbuseChIPFeed'

        Removes the ThirdPartyFeed object 'AbuseChIPFeed'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Active%20threat%20response/thirdpartyfeeds/operations/Delete%20Third-party%20threat%20feed.html

        .LINK
        Get-SfosThirdPartyFeed
#>
function Remove-SfosThirdPartyFeed {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
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
        $existing = @(Get-SfosThirdPartyFeed -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ThirdPartyFeed object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ThirdPartyFeed '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <ThirdPartyFeed>
    <Name>$nameEsc</Name>
  </ThirdPartyFeed>
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
            throw "Failed to remove ThirdPartyFeed object '$Name': $($_.Exception.Message)"
        }

        # The status code/message this entity returns on Remove cannot distinguish success
        # from failure, so only the login is checked here and the real outcome is confirmed
        # below with a follow-up Get.
        $XmlResponse = [xml]$response.Content
        $loginNode = $XmlResponse.SelectSingleNode('/Response/Login/status')
        if ($loginNode -and [string]$loginNode.InnerText -notmatch 'Success') {
            throw "Sophos API login failed while trying to remove ThirdPartyFeed object '$Name'. $([string]$loginNode.InnerText)"
        }

        $stillThere = @(Get-SfosThirdPartyFeed -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($stillThere.Count -gt 0) {
            throw "Failed to remove ThirdPartyFeed object '$Name': the firewall's delete response cannot be trusted for this entity and the object is still present."
        }
    }
}

#endregion

