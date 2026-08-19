#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.5' }

<#
.SYNOPSIS
    Manages remote support access on a Sophos Firewall.

.DESCRIPTION
    Functions for the MONITOR & ANALYZE > Diagnostics area of the Sophos Firewall XML API
    (SFOS 22.0). Support access lets Sophos support connect to the web admin console and the
    shell of the firewall for troubleshooting, without needing the administrator's own
    credentials, for a duration the administrator chooses. There is exactly one instance of
    this object per firewall.

    Total Functions: 2 - see README.md for the full cmdlet table.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosSupportAccess

    Connects to the firewall and reads the current support access state.

.EXAMPLE
    Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' -Confirm:$false
    Set-SfosSupportAccess -ConfigOption Disable -Confirm:$false

    Opens support access for one day, then switches it off again.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>


#region SupportAccess

<#
.SYNOPSIS
    Retrieves the support access state from a Sophos Firewall.

.DESCRIPTION
    Returns whether remote support access is currently switched on and, if it is, for how
    long it remains open. There is exactly one instance of this object per firewall. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    support access state. If omitted, the value from the current connection is used.

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
    ConfigOption and GrantAccessFor. GrantAccessFor is an empty string while support
    access is switched off, because the firewall only reports a duration while it is on.
    Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosSupportAccess

    Returns the current support access state of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosSupportAccess
#>
function Get-SfosSupportAccess {
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

    $inner = '<Get><SupportAccess></SupportAccess></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SupportAccess: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SupportAccess' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SupportAccess')
    if (-not $node) {
        throw 'SupportAccess could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        ConfigOption   = [string]$node.ConfigOption
        GrantAccessFor = [string]$node.GrantAccessFor
    }
}

<#
.SYNOPSIS
    Switches remote support access on or off on a Sophos Firewall.

.DESCRIPTION
    Turns support access on or off and, while turning it on, sets how long it stays open.
    Support access lets Sophos support reach the web admin console and the shell of the
    firewall over TCP port 22, without the administrator's own credentials, until it is
    switched off again or the chosen duration runs out. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change support access.

    The cmdlet reads the current state first. ConfigOption is always sent, even when you
    do not pass it: the firewall accepts a request that omits it, answers success, and
    leaves the setting in a state neither Enable nor Disable, which this module treats as
    a write it must not make. GrantAccessFor is sent only while the resolved ConfigOption
    is Enable, because the firewall only reports a duration while access is switched on -
    there is nothing to preserve while it is off. Switching from Disable to Enable without
    passing -GrantAccessFor therefore does not keep a previous duration; the firewall sets
    its own default of one week.

.PARAMETER ConfigOption
    Optional. Switches support access on (Enable) or off (Disable). If omitted, the current
    value is kept; if the current value on the firewall is neither Enable nor Disable, the
    cmdlet throws rather than sending an unresolved value.

.PARAMETER GrantAccessFor
    Optional. How long support access stays open once switched on: '1 day', '2 days',
    '1 week', '2 weeks', '1 month' or '2 months'. Only meaningful, and only sent, while the
    resolved ConfigOption is Enable. If omitted while switching on for the first time, or
    while already on, the firewall's own default of one week applies.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change
    support access. If omitted, the value from the current connection is used.

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
    Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' -Confirm:$false

    Switches support access on for one day, without asking for confirmation. Use this form
    only in scripts where the value has already been reviewed.

.EXAMPLE
    Set-SfosSupportAccess -ConfigOption Disable -Confirm:$false

    Switches support access off again. Always leave it off when it is no longer needed.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSupportAccess
#>
function Set-SfosSupportAccess {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$ConfigOption,

        [ValidateSet('1 day', '2 days', '1 week', '2 weeks', '1 month', '2 months')]
        [string]$GrantAccessFor,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSupportAccess -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetConfigOption = if ($bp.ContainsKey('ConfigOption')) { $ConfigOption } else { $existing.ConfigOption }

    if ($targetConfigOption -ne 'Enable' -and $targetConfigOption -ne 'Disable') {
        throw "Cannot update SupportAccess: ConfigOption could not be resolved to 'Enable' or 'Disable' (current value on the firewall: '$targetConfigOption')."
    }

    $targetGrantAccessFor = $null
    if ($targetConfigOption -eq 'Enable') {
        $targetGrantAccessFor = if ($bp.ContainsKey('GrantAccessFor')) { $GrantAccessFor } else { $existing.GrantAccessFor }
    }

    if (-not $PSCmdlet.ShouldProcess("SupportAccess on $($params.Firewall)", 'Update')) {
        return
    }

    $configOptionEsc = ConvertTo-SfosXmlEscaped -Text $targetConfigOption

    # Wire element name is GrantAccessFor (one 'r'). The vendor's attribute table spells it
    # GrantAccessForr (two 'r'); the firewall silently ignores that spelling, answers 200 and
    # resets the duration to its own default of one week instead of rejecting the request.
    $grantAccessForXml = ''
    if ($targetGrantAccessFor) {
        $grantAccessForXml = "`n    <GrantAccessFor>$(ConvertTo-SfosXmlEscaped -Text $targetGrantAccessFor)</GrantAccessFor>"
    }

    $inner = @"
<Set operation="update">
  <SupportAccess>
    <ConfigOption>$configOptionEsc</ConfigOption>$grantAccessForXml
  </SupportAccess>
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
        throw "Error updating SupportAccess: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SupportAccess' -Action 'update'
}

#endregion
