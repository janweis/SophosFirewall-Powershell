#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
        .SYNOPSIS
        Manages Active Threat Response settings on Sophos Firewall: Sophos X-Ops threat feeds (ATP) and third-party threat feeds.

        .DESCRIPTION
        PowerShell module for the PROTECT > Active threat response area of the Sophos XGS / SFOS 22.0
        XML API.

        This module provides functions to read and update the device-wide ATP (Sophos X-Ops threat
        feeds) singleton, including its HostException and ThreatException lists, and to create, read,
        update, and delete ThirdPartyFeed objects.

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect and read the device-wide ATP configuration
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosATPSettings

        .EXAMPLE
        # List every configured third-party threat feed
        Get-SfosThirdPartyFeed

        .NOTES
        Module Name: SophosFirewall.ActiveThreatResponse
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+

        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)

        API Compatibility:
        - Sophos SFOS 22.0
        - Sophos XGS Firewall Series

        Total Functions: 10
        - 6 ATP (Sophos X-Ops threat feeds) functions, including HostException/ThreatException members
        - 4 ThirdPartyFeed functions

        Behaviour that differs from the vendor documentation was measured against a live appliance
        and is recorded in the .NOTES of the affected function. See the module README for the
        cmdlet table and known behaviour/limitations.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>

#region ATP

<#
        .SYNOPSIS
        Retrieves the ATP (Sophos X-Ops threat feeds) settings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the ATP singleton (PROTECT > Active threat
        response > Sophos X-Ops threat feeds - the wire element and doc folder are still named
        ATP, a rebranding leftover from "Advanced Threat Protection" [measured/doc]). There is
        exactly one instance of this element per firewall. By default the cmdlet returns a
        PowerShell-friendly object. Use -AsXml to return the raw XML node.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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

        .PARAMETER AsXml
        Returns the raw XML node instead of a PowerShell-friendly object.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Read the device-wide ATP configuration
        Get-SfosATPSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: the response carries no <Status> data field for this entity - fields
        are named ThreatProtectionStatus/InspectContent/Policy, not Status - so Core's generic
        Assert-SfosApiReturnSuccess/Get-SfosApiStatus heuristic needs no special-casing here
        (unlike IPSSwitch, whose single field actually is named <Status>). A live-provoked
        error (invalid Policy value) confirmed the status node sits at the expected
        /Response/ATP/Status[@code] path and is picked up correctly.
        HostException/Host and ThreatException/Threat come back as empty (no wrapper element
        at all) when no exceptions are configured; this cmdlet returns @() for both in that
        case, never $null.

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
        explicitly passed (read-modify-write - SFOS replaces the whole entity on update).
        Supports ShouldProcess; use -WhatIf to preview.

        This is a device-wide security switch (advanced threat protection / IPS threat feed
        enforcement for the whole appliance) - test any change against a maintenance window
        and verify the result.

        .PARAMETER ThreatProtectionStatus
        'Enable' or 'Disable' [doc]. If omitted, the existing value is kept.

        .PARAMETER InspectContent
        'all' or 'untrusted' [doc]. If omitted, the existing value is kept. Both values
        confirmed live.

        .PARAMETER Policy
        'Log Only' or 'Log and Drop' [doc - the wire uses this exact UI wording, not the
        sample XML's 'alert'/'drop' placeholders, both confirmed live]. If omitted, the
        existing value is kept.

        .PARAMETER HostException
        Complete replacement list of HostException entries [doc]. Each entry must be the
        Name of an existing IPHost object on the firewall - an arbitrary string is rejected
        with a field-precise 501 naming /ATP/HostException/Host [measured]. If omitted, the
        existing list is kept. Pass an empty array to clear the list - measured to be a
        genuine full replace for this field (not append-only): omitting the wrapper entirely
        or sending an explicit empty <HostException/> both clear a previously set list, and a
        duplicate entry sent twice is silently de-duplicated by the firewall.

        .PARAMETER ThreatException
        Complete replacement list of ThreatException entries [doc]. Unlike HostException, an
        arbitrary string value is accepted here (no existing-object requirement) [measured].
        If omitted, the existing list is kept. Pass an empty array to clear the list - same
        full-replace behaviour as HostException.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Switch content inspection from untrusted-only to all traffic, leaving everything else unchanged
        Set-SfosATPSettings -InspectContent all

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live end to end: baseline captured (ThreatProtectionStatus=Enable,
        InspectContent=untrusted, Policy='Log and Drop'), written back unchanged (round trip
        byte-identical), InspectContent toggled to 'all' and reverted, Policy toggled to
        'Log Only' and reverted to 'Log and Drop' - every write answered code 200 and the
        final read matched the captured baseline exactly. See the task report for the raw
        responses.

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
    # on assignment (measured on PS 5.1).
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
        the current ATP object first and resends it complete with the new host appended
        (read-modify-write, per Set-SfosATPSettings). Supports ShouldProcess; use -WhatIf to
        preview.

        .PARAMETER HostName
        Name of an existing IPHost object on the firewall to except from ATP inspection
        [measured: an arbitrary string that is not the name of an existing IPHost object is
        rejected with a field-precise 501 on /ATP/HostException/Host]. Mandatory; accepts
        pipeline input by value or by property name (aliased 'Host' so
        Get-SfosIPHost | Add-SfosATPHostException binds).

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the update fails.

        .EXAMPLE
        Add-SfosATPHostException -HostName 'WebServer01'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: created a test IPHost, added it as a HostException (code 200), read
        back and confirmed present under HostException/Host, sent the exact same host a
        second time and confirmed the firewall de-duplicates rather than storing it twice, then
        removed it and confirmed the ATP object returned to its original captured baseline
        (byte-identical). See the task report for the raw responses.

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
        otherwise resends the ATP object complete with the host filtered out
        (read-modify-write, per Set-SfosATPSettings). Reads the object back afterwards and
        throws if the host is still present - guards against the append-only-list pattern
        seen elsewhere in this API, even though this entity was measured NOT to have that
        problem (see .NOTES). Supports ShouldProcess; use -WhatIf to preview.

        .PARAMETER HostName
        Name of the IPHost object to remove from the HostException list. Mandatory; accepts
        pipeline input by value or by property name (aliased 'Host').

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the update fails or the host is still present afterwards.

        .EXAMPLE
        Remove-SfosATPHostException -HostName 'WebServer01'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: unlike the URLList/SecurityPolicyList append-only lists documented
        elsewhere in this project, ATP's HostException list is a genuine full replace on
        update - omitting the <HostException> wrapper entirely, or sending an explicit empty
        <HostException/>, both cleared a previously set entry and the object read back to
        exactly its pre-test baseline. This cmdlet's post-removal read-back is kept anyway as
        a defensive guard, per project convention for member-removal cmdlets.

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
        Adds an entry to the ATP ThreatException list using the Sophos Firewall XML API. Reads
        the current ATP object first and resends it complete with the new threat identifier
        appended (read-modify-write, per Set-SfosATPSettings). Supports ShouldProcess; use
        -WhatIf to preview.

        .PARAMETER Threat
        Threat identifier text to except from ATP enforcement [doc]. Unlike HostException, an
        arbitrary string is accepted here - no existing-object requirement was found
        [measured]. Mandatory; accepts pipeline input by value or by property name.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the update fails.

        .EXAMPLE
        Add-SfosATPThreatException -Threat 'C2/Generic-A'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: added an arbitrary threat identifier string (code 200), read back and
        confirmed present under ThreatException/Threat, then removed it and confirmed the ATP
        object returned to its original captured baseline (byte-identical). See the task
        report for the raw responses.

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
        otherwise resends the ATP object complete with the threat filtered out
        (read-modify-write, per Set-SfosATPSettings). Reads the object back afterwards and
        throws if the threat is still present. Supports ShouldProcess; use -WhatIf to preview.

        .PARAMETER Threat
        Threat identifier text to remove from the ThreatException list. Mandatory; accepts
        pipeline input by value or by property name.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the update fails or the threat is still present afterwards.

        .EXAMPLE
        Remove-SfosATPThreatException -Threat 'C2/Generic-A'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live as part of the ATP round trip - see the NOTES section of
        Remove-SfosATPHostException for the measured full-replace behaviour that applies
        identically to this list.

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
        threat response > Third party threat feed). By default the cmdlet returns
        PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        -NameLike is sent as the server-side filter key (confirmed live: 'like' criteria on
        Name works correctly, both for a matching substring and for a non-matching one, unlike
        several other entities in this API area where any filter is silently ignored or
        breaks the response) and is re-applied client-side together with every other filter,
        AND semantics, per the project's server-side filtering rule.

        .PARAMETER NameLike
        Filters by Name, substring match. Sent as the server-side filter key and re-applied
        client-side.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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

        .PARAMETER AsXml
        Returns the raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

        .EXAMPLE
        # List every configured third-party threat feed
        Get-SfosThirdPartyFeed

        .EXAMPLE
        # Find a feed by name
        Get-SfosThirdPartyFeed -NameLike 'Feed'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: an empty firewall (and a filter with no matches) answers
        '<ThirdPartyFeed><Status>No. of records Zero.</Status></ThirdPartyFeed>' - a normal
        empty result, not an error; this cmdlet returns @() for it.
        The firewall assigns a server-generated <Id> (a GUID) to every feed on create; it is
        exposed here read-only and is not accepted as input by New-/Set-SfosThirdPartyFeed.
        <Position> is accepted on write (New-/Set-*) but is never returned by this Get - it
        does not appear as a property here; see New-SfosThirdPartyFeed's .NOTES for why
        Set-SfosThirdPartyFeed does not expose it at all.
        Username/Key are returned in plain text when the corresponding Authorization is
        configured; Password/Value (the secret half of basic/apiKey authorization) are
        returned firewall-hashed with a 'hashform' attribute, never in plain text - exposed
        here as PasswordHash/ValueHash for troubleshooting only, not usable as a credential.

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
        using the Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

        .PARAMETER Name
        Name of the feed [doc]. Mandatory. Max 63 characters, letters/digits/underscore/hyphen
        only.

        .PARAMETER Description
        Free-text description [doc]. Optional, max 255 characters.

        .PARAMETER Action
        'block' or 'monitor' [doc]. Both values confirmed live. Default 'monitor' [doc].

        .PARAMETER Position
        'top' or 'bottom' [doc]. Both values were accepted without error live, but this field
        is never returned by Get-SfosThirdPartyFeed - see .NOTES. Default 'top' [doc].

        .PARAMETER IndicatorType
        'ip', 'domain' or 'url' [doc]. 'ip' and 'domain' confirmed live; 'url' is documented
        but was not exercised. Default 'ip' [doc].

        .PARAMETER ExternalURL
        URL the firewall polls for indicator data [doc]. Mandatory, max 1024 characters. A
        syntactically valid but unreachable URL under a documentation domain was accepted
        without the firewall attempting to reach it at creation time - see .NOTES.

        .PARAMETER Authorization
        'noAuthentication', 'basicAuthentication' or 'apiKey' [doc]. Default
        'noAuthentication' [doc]. Determines which of -FeedUsername/-FeedPassword or
        -ApiKeyName/-ApiKeyValue/-AddTo are required - see those parameters.

        .PARAMETER FeedUsername
        Username for -Authorization basicAuthentication [doc; wire element is <Username>].
        Named differently from the connection parameter -Username on purpose, for the same
        reason as -FeedPassword below - an entity field named -Username would bind to the
        connection parameter instead and silently leave the entity field unset, and
        Resolve-SfosParameters would misread the entity's basic-auth username as the API
        connection identity. Ignored for other -Authorization values.

        .PARAMETER FeedPassword
        Password for -Authorization basicAuthentication, as a SecureString [doc]. Named
        differently from the connection parameter -Password on purpose: an entity secret named
        -Password would bind to the connection parameter instead and silently leave the entity
        field unset.
        Required when -Authorization is basicAuthentication.

        .PARAMETER ApiKeyName
        The API key field/header name for -Authorization apiKey [doc; wire element is <Key>].
        Required when -Authorization is apiKey.

        .PARAMETER ApiKeyValue
        The API key secret value for -Authorization apiKey, as a SecureString [doc; wire
        element is <Value>]. Named to avoid a bare -Value/-Key ambiguity next to -ApiKeyName.
        Required when -Authorization is apiKey.

        .PARAMETER AddTo
        'header' or 'queryParam' for -Authorization apiKey [doc]. 'header' confirmed live;
        'queryParam' is documented but was not exercised. Required when -Authorization is
        apiKey.

        .PARAMETER ValidateServerCertificate
        '1' or '0' [doc table - the sample XML's true/false placeholders were also accepted on
        input, but the firewall always echoes the value back as '1'/'0' regardless of which
        form was sent, so the table wins here]. Mandatory
        [doc].

        .PARAMETER PollingInterval
        One of '5m','15m','30m','1h','6h','24h','7d','30d' [doc]. '1h' and '30m' confirmed
        live. Mandatory [doc].

        .PARAMETER Enabled
        '1' or '0' [doc table; sample XML's true/false was not tested for input, but the wire
        always returns '1'/'0'. Table wins here for the same reason as
        -ValidateServerCertificate]. Optional.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Feed with no authentication
        New-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Action monitor -IndicatorType ip `
            -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization noAuthentication `
            -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

        .EXAMPLE
        # Feed with basic authentication
        $pw = ConvertTo-SecureString 'FeedSecret1!' -AsPlainText -Force
        New-SfosThirdPartyFeed -Name 'VendorIPFeed' -Action monitor -IndicatorType ip `
            -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization basicAuthentication `
            -FeedUsername 'feedreader' -FeedPassword $pw `
            -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

        .EXAMPLE
        # Feed with API key authentication
        $key = ConvertTo-SecureString 'MyApiKeyValue123' -AsPlainText -Force
        New-SfosThirdPartyFeed -Name 'PartnerIPFeed' -Action monitor -IndicatorType ip `
            -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization apiKey `
            -ApiKeyName 'X-Api-Key' -ApiKeyValue $key -AddTo header `
            -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: created with -Authorization noAuthentication (code 201, confirmed with
        a follow-up Get, all fields matched including the server-assigned Id), then updated in
        place through -Authorization basicAuthentication and apiKey to exercise those code
        paths - see Set-SfosThirdPartyFeed's .NOTES, which carries the security-relevant
        findings for the shared secret handling. The example -ExternalURL used throughout
        (feeds.example.com, syntactically valid but not a real host) was accepted by the
        firewall without any reachability check at write time - unlike WebFilterCategory,
        no 217/222 warning code was seen, just a plain 201 "Configuration applied
        successfully.".
        <Id> is server-assigned and cannot be set by the caller - not exposed as a parameter.
        <Position> is accepted here (create time) but is never returned by
        Get-SfosThirdPartyFeed: since a field a Get-* does not
        expose is impossible to preserve on update, Set-SfosThirdPartyFeed has no
        -Position parameter at all, matching the FileType/-Template precedent. Only New-* can
        set it, and only once, at creation.
        Creating a second object with a Name already in use answers a field-precise 409
        naming /ThirdPartyFeed/Name [measured] - outside the documented 200-216/500-599 status
        table, so it throws by default rather than being waved through, consistent with this
        project's fail-closed handling of undocumented codes.

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
        first and resends every field, overriding only what the caller explicitly passed
        (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
        use -WhatIf to preview.

        The Password/Key secret fields are the one measured exception to full replace on this
        entity - see .NOTES. This cmdlet never resends the hashed value Get-SfosThirdPartyFeed
        returns; when the caller does not supply a new secret and the authorization type is
        unchanged, the corresponding element is omitted entirely, which was measured to leave
        the stored secret untouched.

        .PARAMETER Name
        Name of the target feed. Mandatory; accepts pipeline input by property name.

        .PARAMETER Description
        Free-text description. If omitted, the existing value is kept.

        .PARAMETER Action
        'block' or 'monitor'. If omitted, the existing value is kept.

        .PARAMETER IndicatorType
        'ip', 'domain' or 'url'. If omitted, the existing value is kept.

        .PARAMETER ExternalURL
        URL the firewall polls for indicator data. If omitted, the existing value is kept.

        .PARAMETER Authorization
        'noAuthentication', 'basicAuthentication' or 'apiKey'. If omitted, the existing value
        is kept. Switching to basicAuthentication or apiKey without a previous value of that
        type requires the matching secret parameter - see -FeedPassword/-ApiKeyValue.

        .PARAMETER FeedUsername
        Username for -Authorization basicAuthentication [wire element <Username>]. Named
        differently from the connection parameter -Username on purpose - see
        New-SfosThirdPartyFeed's -FeedUsername for why. If omitted, the existing value is
        kept.

        .PARAMETER FeedPassword
        New password for -Authorization basicAuthentication, as a SecureString. If omitted and
        the feed is already (or remains) basicAuthentication, the existing password is left
        untouched on the firewall - see .NOTES. Required when switching from a different
        -Authorization value to basicAuthentication in the same call.

        .PARAMETER ApiKeyName
        The API key field/header name for -Authorization apiKey. If omitted, the existing
        value is kept.

        .PARAMETER ApiKeyValue
        New API key secret value for -Authorization apiKey, as a SecureString. If omitted and
        the feed is already (or remains) apiKey, the existing value is left untouched on the
        firewall - see .NOTES. Required when switching from a different -Authorization value
        to apiKey in the same call.

        .PARAMETER AddTo
        'header' or 'queryParam' for -Authorization apiKey. If omitted, the existing value is
        kept.

        .PARAMETER ValidateServerCertificate
        '1' or '0'. If omitted, the existing value is kept.

        .PARAMETER PollingInterval
        One of '5m','15m','30m','1h','6h','24h','7d','30d'. If omitted, the existing value is
        kept.

        .PARAMETER Enabled
        '1' or '0'. If omitted, the existing value is kept.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Disable a feed, leaving every other field untouched (including any stored secret)
        Set-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Enabled 0

        .NOTES
        Minimum supported PowerShell version: 5.1
        Two measured findings specific to this entity's secret fields, both reproduced twice
        against the lab appliance:

        1. Resending the Password (or Value) element exactly as Get-SfosThirdPartyFeed returns
           it - hashed text plus its 'hashform' attribute, the pattern that works for
           Set-SfosSSLBookmark - makes SFOS answer HTTP 200 with a response that contains no
           <ThirdPartyFeed> element and no <Status> at all, and the update is silently
           dropped: a Description change sent in the same request was confirmed absent on a
           follow-up Get. This is the "missing status element is not success" trap, and Core's
           generic status check cannot catch it, because there is no ThirdPartyFeed subtree in
           the response to look inside at all.
        2. Omitting the Password (or Value) element entirely, while Authorization stays the
           same authenticated type, answers a normal 200 AND the previously stored password
           hash comes back completely unchanged on the next Get. This is the opposite of the
           project's usual full-replace warning for Set-* - here NOT sending the field is what
           preserves it, and sending the read-back hash is what breaks the whole request. This
           cmdlet relies on that: it never resends PasswordHash/ValueHash, only a caller-
           supplied new SecureString or nothing at all.

        Switching Authorization to noAuthentication (with every auth sub-field omitted) was
        confirmed to properly clear Username/Password/Key/Value/AddTo - normal full-replace
        semantics apply there, only the "keep the existing secret while remaining in the same
        authenticated mode" case is special.

        Verified live: full round trip through noAuthentication -> basicAuthentication (with
        -FeedPassword) -> apiKey (with -ApiKeyValue) -> back to noAuthentication, each
        transition confirmed correct on a follow-up Get, before the test object was removed.

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
                # Measured: omitting Password here (while staying basicAuthentication)
                # preserves the stored secret - see .NOTES. Resending PasswordHash would
                # silently drop the whole update instead.
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
                # Same measured preserve-on-omit behaviour as Password above.
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
        throws a clear "not found" error if it does not exist. The firewall's own delete
        response for this entity cannot be trusted at face value - see .NOTES - so this
        cmdlet confirms the outcome with a follow-up Get instead of relying on the returned
        status code. Supports ShouldProcess; use -WhatIf to preview.

        .PARAMETER Name
        Name of the feed to remove. Mandatory; accepts pipeline input by property name.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        None. Throws an exception if the removal fails or cannot be confirmed.

        .EXAMPLE
        Remove-SfosThirdPartyFeed -Name 'AbuseChIPFeed'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live and reproduced twice: Remove on this entity always answers code 500
        "Deleted some configurations. Couldn't delete all." - for a genuinely nonexistent
        object AND for a real object that the same call actually deletes cleanly. The message
        text is identical in both cases, so the status code and message cannot distinguish
        success from failure here at all (a stricter defect than the Code-528-on-nonexistent
        pattern documented for other Remove-Sfos* cmdlets in this project, where at least the
        object legitimately not existing is the trigger). This cmdlet therefore ignores that
        status entirely (beyond checking the login itself did not fail) and determines the
        real outcome from a follow-up Get: both the "object never existed" and "object deleted
        successfully" paths were confirmed this way, twice.

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

        # See .NOTES: the status code/message this entity returns on Remove cannot
        # distinguish success from failure, so only the login is checked here and the real
        # outcome is confirmed below with a follow-up Get.
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
            throw "Failed to remove ThirdPartyFeed object '$Name': the firewall's delete response cannot be trusted for this entity (see .NOTES) and the object is still present."
        }
    }
}

#endregion

