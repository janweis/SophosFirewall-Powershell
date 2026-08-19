#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.5' }

<#
.SYNOPSIS
    Manages the zero-day protection settings of a Sophos Firewall.

.DESCRIPTION
    Functions for the MONITOR & ANALYZE > Zero-day protection area of the Sophos Firewall XML
    API (SFOS 22.0). Zero-day protection sends new downloads and email attachments to a cloud
    sandbox for analysis; this module covers the one configuration object that controls where
    that analysis happens and which file types are excluded from it.

    There is exactly one instance of this object per firewall. The wire root element is
    ZeroDayProtectionSettings; the documentation's folder name SandboxSettings is not the root
    element and is rejected by the API.

    Total Functions: 2 (2 exported, 0 internal helpers) - see README.md for the full cmdlet
    table.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosZeroDayProtectionSettings

    Connects to the firewall and reads the current zero-day protection settings.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>


#region ZeroDayProtectionSettings

<#
        .SYNOPSIS
        Retrieves the zero-day protection settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide zero-day protection settings: the cloud datacenter used for
        sandbox analysis and the file types excluded from that analysis. There is exactly one
        instance of this object per firewall. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        zero-day protection settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with the properties
        DataCenterLocation and ExcludeFileTypes. Returns System.Xml.XmlElement when -AsXml is
        used.

        .EXAMPLE
        Get-SfosZeroDayProtectionSettings

        Returns the current zero-day protection settings of the firewall of the current
        connection.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosZeroDayProtectionSettings
#>
function Get-SfosZeroDayProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <ZeroDayProtectionSettings>, a
    # singleton holding one configuration, not a plural container.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
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

    $inner = '<Get><ZeroDayProtectionSettings></ZeroDayProtectionSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ZeroDayProtectionSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ZeroDayProtectionSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/ZeroDayProtectionSettings')
    if (-not $node) {
        throw 'ZeroDayProtectionSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    # The @() wraps the whole if/else, not the branches: a branch-local @() is unwrapped
    # again by the assignment, and a single excluded file type would arrive as a string.
    $excludeFileTypes = @(if ([string]$node.ExcludeFileTypes) {
            ([string]$node.ExcludeFileTypes) -split ',' | ForEach-Object { $_.Trim() }
        }
        else {
            @()
        })

    return [PSCustomObject]@{
        DataCenterLocation = [string]$node.DataCenterLocation
        ExcludeFileTypes   = $excludeFileTypes
    }
}

<#
        .SYNOPSIS
        Updates the zero-day protection settings on a Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide zero-day protection settings: the cloud datacenter used for
        sandbox analysis and the file types excluded from that analysis. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly,
        and an account with permission to change the zero-day protection settings. The cmdlet
        reads the current settings first and resends every field, overriding only what you
        explicitly pass, so a field you do not pass keeps its current value - the firewall
        replaces the whole object on every update and clears a field that is not sent.

        Changing the datacenter may cause the loss of analysis for files that are currently
        being processed by zero-day protection (Sophos admin help).

        .PARAMETER DataCenterLocation
        Optional. Cloud datacenter used for sandbox analysis. If omitted, the current value is
        kept.

        .PARAMETER ExcludeFileTypes
        Optional. Names of the file types to exclude from zero-day protection analysis. Each
        name must match an existing FileType object on the firewall - Get-SfosFileType from the
        SophosFirewall.Web module lists the valid names; an unknown name is rejected with 501.
        The vendor sample names "Database File", which does not exist on the appliance -
        the correct name is "Database Files". Pass an empty array to clear the list. The
        firewall documents a limit of 50 file types (status 502); this cmdlet does not enforce
        it. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change the
        zero-day protection settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosZeroDayProtectionSettings -DataCenterLocation 'eu.sandbox.sophos.com' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosZeroDayProtectionSettings -ExcludeFileTypes 'Audio Files', 'Video Files' -Confirm:$false

        Sets the excluded file types, leaving the datacenter untouched, without asking for
        confirmation. Use this form only in scripts where the value has already been reviewed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosZeroDayProtectionSettings
#>
function Set-SfosZeroDayProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <ZeroDayProtectionSettings>, a
    # singleton holding one configuration, not a plural container.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('sandbox.sophos.com', 'us.sandbox.sophos.com', 'de.sandbox.sophos.com',
            'eu.sandbox.sophos.com', 'apac.sandbox.sophos.com', 'au.analysis.sophos.com')]
        [string]$DataCenterLocation,

        [string[]]$ExcludeFileTypes,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosZeroDayProtectionSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetDataCenter = if ($bp.ContainsKey('DataCenterLocation')) { $DataCenterLocation } else { $existing.DataCenterLocation }
    $targetExcludeFileTypes = @(if ($bp.ContainsKey('ExcludeFileTypes')) { $ExcludeFileTypes } else { $existing.ExcludeFileTypes })

    if (-not $PSCmdlet.ShouldProcess("ZeroDayProtectionSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $excludeFileTypesText = ConvertTo-SfosXmlEscaped -Text (($targetExcludeFileTypes | Where-Object { $_ }) -join ',')

    $inner = @"
<Set operation="update">
  <ZeroDayProtectionSettings>
    <DataCenterLocation>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDataCenter))</DataCenterLocation>
    <ExcludeFileTypes>$excludeFileTypesText</ExcludeFileTypes>
  </ZeroDayProtectionSettings>
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
        throw "Error updating ZeroDayProtectionSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ZeroDayProtectionSettings' -Action 'update'
}

#endregion
