#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.4.0' }

<#
.SYNOPSIS
    Manages remote support access and reads the web admin console's log viewer on a Sophos Firewall.

.DESCRIPTION
    Functions for the MONITOR & ANALYZE > Diagnostics area of the Sophos Firewall
    (SFOS 22.0): remote support access, and read-only access to the log records shown by the
    web admin console's log viewer. Support access lets Sophos support connect to the web
    admin console and the shell of the firewall for troubleshooting, without needing the
    administrator's own credentials, for a duration the administrator chooses. There is
    exactly one instance of that object per firewall. The log viewer functions read the same
    log records an administrator sees under Log Viewer in the web admin console; there is no
    equivalent read in the XML API.

    Also included: Export-SfosLog captures a log viewer read to a file, and Import-SfosLog reads
    it back with the same field filters, any number of times, without contacting the appliance
    again.

    Total Functions: 20 (8 exported, 12 internal helpers) - see README.md for the full cmdlet
    table. The web admin console access path itself - login, CSRF, the console POST - is
    implemented in SophosFirewall.Core as Connect-SfosWebAdmin and Invoke-SfosWebAdminRequest.
    This module adds only the log-viewer-specific request and response handling on top of it.
    The device console access path - login, keystroke send/receive - is implemented in
    SophosFirewall.Core as Connect-SfosCliConsole, Send-SfosCliInput, Receive-SfosCliOutput and
    Disconnect-SfosCliConsole. This module adds only the command-and-response handling on top
    of it.

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

.EXAMPLE
    Get-SfosLog -Category firewall -MaxRecords 50

    Reads 50 firewall log records from the web admin console's log viewer.

.EXAMPLE
    Export-SfosLog -Category firewall -MaxRecords 5000 -Path 'C:\Captures\firewall.sfoslog'
    Import-SfosLog -Path 'C:\Captures\firewall.sfoslog' -SourceIP '192.0.2.10'

    Captures 5000 firewall log records once, then filters the capture by source address without
    contacting the firewall again.

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

#region LogViewerConsole

# The log viewer is not part of the XML API - it is a web console screen (Controller?mode=
# 5001/5002) reached with a session cookie and a CSRF token, not the XML request envelope.
# Connect-SfosWebAdmin and Invoke-SfosWebAdminRequest (SophosFirewall.Core) carry that access
# path; the helpers below only add the log-viewer-specific request/response shape on top of
# it. See this module's own findings file for the measured request/response shapes.

<#
.SYNOPSIS
    Builds the field filter specification consumed by Get-SfosLogViewerRecordPage's raw-text
    pre-filter and its decode fallback. Internal helper, not exported.

.DESCRIPTION
    One entry per bound field-filter parameter on Get-SfosLog, each carrying the wire field(s)
    to compare (several for AnyIP/AnyPort, which match either side of a connection), the
    value(s) to match, whether the match is a substring (MessageLike/ExcludeMessageLike/
    Text/ExcludeText only) or exact (every other field), and whether the entry is a negated
    (Exclude*) filter. Several values on one parameter are OR-combined when matched, and
    several wire fields on one entry are OR-combined the same way; several entries in the
    returned array are AND-combined - the same repository rule S:6 already applies to every
    other *Like filter in this project.

    Text/ExcludeText carry no WireFields at all - they set AnyField instead, so
    Test-SfosLogViewerRawFieldMatch and Test-SfosLogViewerDecodedFieldMatch compare Values
    against every field's value on the record, never against a fixed set of field names. An
    empty WireFields on its own would look like an oversight; AnyField says outright that
    matching every field is the intended behaviour.

.PARAMETER BoundParameters
    Required. $PSBoundParameters from Get-SfosLog.
#>
function Get-SfosLogViewerFieldFilter {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters
    )

    $map = @(
        @{ Wire = @('log_type'); Include = 'LogType'; Exclude = 'ExcludeLogType' },
        @{ Wire = @('log_component'); Include = 'LogComponent'; Exclude = 'ExcludeLogComponent' },
        @{ Wire = @('log_subtype'); Include = 'LogSubtype'; Exclude = 'ExcludeLogSubtype' },
        @{ Wire = @('status'); Include = 'Status'; Exclude = 'ExcludeStatus' },
        @{ Wire = @('user'); Include = 'User'; Exclude = 'ExcludeUser' },
        @{ Wire = @('src_ip'); Include = 'SourceIP'; Exclude = 'ExcludeSourceIP' },
        @{ Wire = @('dst_ip'); Include = 'DestinationIP'; Exclude = 'ExcludeDestinationIP' },
        @{ Wire = @('src_port'); Include = 'SourcePort'; Exclude = 'ExcludeSourcePort' },
        @{ Wire = @('dst_port'); Include = 'DestinationPort'; Exclude = 'ExcludeDestinationPort' },
        @{ Wire = @('protocol'); Include = 'Protocol'; Exclude = 'ExcludeProtocol' },
        @{ Wire = @('src_ip', 'dst_ip'); Include = 'AnyIP'; Exclude = 'ExcludeAnyIP' },
        @{ Wire = @('src_port', 'dst_port'); Include = 'AnyPort'; Exclude = 'ExcludeAnyPort' }
    )

    $filters = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $map) {
        if ($BoundParameters.ContainsKey($entry.Include)) {
            $filters.Add([PSCustomObject]@{
                    WireFields = $entry.Wire
                    AnyField   = $false
                    Values     = @($BoundParameters[$entry.Include])
                    Substring  = $false
                    Negate     = $false
                })
        }
        if ($BoundParameters.ContainsKey($entry.Exclude)) {
            $filters.Add([PSCustomObject]@{
                    WireFields = $entry.Wire
                    AnyField   = $false
                    Values     = @($BoundParameters[$entry.Exclude])
                    Substring  = $false
                    Negate     = $true
                })
        }
    }
    if ($BoundParameters.ContainsKey('MessageLike')) {
        $filters.Add([PSCustomObject]@{
                WireFields = @('message')
                AnyField   = $false
                Values     = @($BoundParameters['MessageLike'])
                Substring  = $true
                Negate     = $false
            })
    }
    if ($BoundParameters.ContainsKey('ExcludeMessageLike')) {
        $filters.Add([PSCustomObject]@{
                WireFields = @('message')
                AnyField   = $false
                Values     = @($BoundParameters['ExcludeMessageLike'])
                Substring  = $true
                Negate     = $true
            })
    }
    if ($BoundParameters.ContainsKey('Text')) {
        $filters.Add([PSCustomObject]@{
                WireFields = @()
                AnyField   = $true
                Values     = @($BoundParameters['Text'])
                Substring  = $true
                Negate     = $false
            })
    }
    if ($BoundParameters.ContainsKey('ExcludeText')) {
        $filters.Add([PSCustomObject]@{
                WireFields = @()
                AnyField   = $true
                Values     = @($BoundParameters['ExcludeText'])
                Substring  = $true
                Negate     = $true
            })
    }

    return $filters.ToArray()
}

<#
.SYNOPSIS
    Tests one raw (undecoded) log record's JSON text against a field filter. Internal helper,
    not exported.

.DESCRIPTION
    Matches directly on the JSON text as received from the appliance, before ConvertFrom-Json
    runs - this is the entire reason Get-SfosLog's built-in field filters are faster than
    filtering after decoding: a record that cannot match is never decoded (See this module's own findings file for the measured cost of decoding). Every entry in FieldFilter must match (AND
    across fields); within one entry, any of its Values matching any of its WireFields is
    enough (OR across values and OR across wire fields - AnyIP and AnyPort match either side
    of a connection this way).

    An entry with Negate set inverts the same OR-combined match: the record is rejected only
    when one of its WireFields carries one of Values, so a record that does not carry any of
    the entry's WireFields at all is never rejected by it - a record with no message field, for
    example, always survives ExcludeMessageLike.

    The comparison is a regex, not a plain substring search, because the measured wire form
    puts a space after the colon ("log_type": "Firewall") and the match has to tolerate both
    that and the compact form without one. Every value passes through [regex]::Escape first, so
    a literal '.' in an IP address is matched literally rather than as a wildcard.

    An AnyField entry (built for -Text/-ExcludeText) is matched differently: the pattern drops
    the field name entirely and only requires a colon followed by a quoted value containing the
    search text (":\s*"[^"]*VALUE[^"]*""). That is deliberate - a field's own name sits before
    the colon in the same JSON text, so anchoring the match after the colon is what keeps a
    search term such as 'port' from matching the key "dst_port" instead of an actual value. This
    assumes every field the appliance sends is a quoted JSON string, which holds for every field
    observed on real records, including numeric-looking ones such as dst_port and src_port; a
    field that ever arrives unquoted (a bare JSON number) would not be seen by this pattern, and
    falls to the decoded fallback the same way an unexpected wire form does for the named
    filters above.

.PARAMETER Raw
    Required. The exact JSON text of one log record, as received from the appliance.

.PARAMETER FieldFilter
    Required. The filter specification built by Get-SfosLogViewerFieldFilter.
#>
function Test-SfosLogViewerRawFieldMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Raw,

        [Parameter(Mandatory)]
        [object[]]$FieldFilter
    )

    foreach ($filter in $FieldFilter) {
        $fieldMatched = $false

        if ($filter.AnyField) {
            foreach ($value in $filter.Values) {
                $escapedValue = [regex]::Escape([string]$value)
                # No field name in this pattern at all - it matches only the JSON VALUE that
                # follows a colon, never the key that precedes it, so a search term that happens
                # to be part of a field name (e.g. 'port' inside "dst_port") is not a match.
                $pattern = ':\s*"[^"]*' + $escapedValue + '[^"]*"'
                if ($Raw -match $pattern) {
                    $fieldMatched = $true
                    break
                }
            }
        }
        else {
            foreach ($wireField in $filter.WireFields) {
                $escapedField = [regex]::Escape($wireField)
                foreach ($value in $filter.Values) {
                    $escapedValue = [regex]::Escape([string]$value)
                    $pattern = if ($filter.Substring) {
                        '"' + $escapedField + '"\s*:\s*"[^"]*' + $escapedValue + '[^"]*"'
                    }
                    else {
                        '"' + $escapedField + '"\s*:\s*"' + $escapedValue + '"'
                    }
                    if ($Raw -match $pattern) {
                        $fieldMatched = $true
                        break
                    }
                }
                if ($fieldMatched) {
                    break
                }
            }
        }

        if ($filter.Negate) {
            # A match implies the field was present, so no separate presence check is needed: a
            # record missing every one of WireFields never matches and is therefore never
            # rejected by an Exclude* filter.
            if ($fieldMatched) {
                return $false
            }
        }
        elseif (-not $fieldMatched) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Tests one decoded log record against a field filter. Internal helper, not exported.

.DESCRIPTION
    The fallback path Get-SfosLogViewerRecordPage takes when Test-SfosLogViewerRawFieldMatch
    matches none of the records fetched, even though the filtered field's key is literally
    present in them - a sign the raw-text spacing/quoting assumption documented in this
    module's own findings file does not hold for this response. Comparing on the parsed object instead
    cannot be fooled by formatting, at the cost of decoding every record fetched. A record that
    does not carry any of an entry's WireFields never matches it; where an entry lists more than
    one WireField (AnyIP, AnyPort), a match on either one is enough (OR).

    An entry with Negate set inverts that same match: the record is rejected only when one of
    its WireFields carries one of Values, so a record that does not carry any of the entry's
    WireFields at all is never rejected by it.

    An AnyField entry (built for -Text/-ExcludeText) is matched differently: every property the
    record actually carries is checked in turn, and a match on any one property's value is
    enough - property names themselves are never compared, only their values.

.PARAMETER Record
    Required. One decoded log record.

.PARAMETER FieldFilter
    Required. The filter specification built by Get-SfosLogViewerFieldFilter.
#>
function Test-SfosLogViewerDecodedFieldMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Record,

        [Parameter(Mandatory)]
        [object[]]$FieldFilter
    )

    foreach ($filter in $FieldFilter) {
        $fieldMatched = $false

        if ($filter.AnyField) {
            foreach ($property in $Record.PSObject.Properties) {
                $actual = [string]$property.Value
                foreach ($value in $filter.Values) {
                    if ($actual -like "*$value*") {
                        $fieldMatched = $true
                        break
                    }
                }
                if ($fieldMatched) {
                    break
                }
            }
        }
        else {
            foreach ($wireField in $filter.WireFields) {
                if ($Record.PSObject.Properties.Match($wireField).Count -eq 0) {
                    continue
                }
                $actual = [string]$Record.($wireField)

                foreach ($value in $filter.Values) {
                    if ($filter.Substring) {
                        if ($actual -like "*$value*") {
                            $fieldMatched = $true
                            break
                        }
                    }
                    elseif ($actual -eq [string]$value) {
                        $fieldMatched = $true
                        break
                    }
                }
                if ($fieldMatched) {
                    break
                }
            }
        }

        if ($filter.Negate) {
            # A match implies the field was present, so a record carrying none of WireFields is
            # never rejected by an Exclude* filter.
            if ($fieldMatched) {
                return $false
            }
        }
        elseif (-not $fieldMatched) {
            return $false
        }
    }

    return $true
}

<#
.SYNOPSIS
    Decodes one raw log viewer record into a Raw/Decoded pair. Internal helper, not exported.

.DESCRIPTION
    Wraps ConvertFrom-Json so a single malformed record cannot abort an entire page: on a
    decode failure this reports the record with Write-Verbose - not Write-Warning, which would
    be unusable noise across a page of thousands of records - and returns nothing for it, so
    the caller's ForEach-Object simply omits it from the resulting set.

.PARAMETER Raw
    Required. The exact JSON text of one log record, as received from the appliance.

.OUTPUTS
    System.Management.Automation.PSCustomObject with Raw and Decoded properties, or nothing if
    Raw could not be parsed as JSON.
#>
function ConvertTo-SfosLogViewerRecordPair {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Raw
    )

    try {
        $decoded = $Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Verbose "Get-SfosLog: skipped one log record that could not be parsed as JSON: $($_.Exception.Message)"
        return
    }

    return [PSCustomObject]@{ Raw = $Raw; Decoded = $decoded }
}

<#
.SYNOPSIS
    Fetches the most recent log records from the web console's log viewer in a single call.
    Internal helper, not exported.

.DESCRIPTION
    Wraps a single mode 5001 call. Returns Pairs and FetchedCount - see .OUTPUTS below for why
    both are needed. Each pair carries Raw (the exact JSON text the console sent for that
    record) alongside Decoded (the parsed object the rest of this module already works with).
    Raw is only needed by Get-SfosLog -Follow, to recognise a genuine repeat of an identical
    record on the wire from one it has already shown.

    The offset field is always sent as 0. Measured against a live appliance: paging with
    offset in 200-record steps repeats the same page once it reaches roughly 750 records back,
    silently, with no error and no empty result - depth is only reachable by raising Take on a
    single call, never by paging (see this module's own findings file). This module therefore never
    sends a nonzero offset; every request is the appliance's current top N records.

    When FieldFilter is given, it is applied here, on the raw JSON text, before anything is
    decoded - decoding is the expensive step (see this module's own findings file), and a record that
    cannot pass the filter is never decoded at all. If the raw-text match finds nothing at all
    while the filtered field's key is nonetheless present in the fetched records, that is
    treated as a sign the pre-filter's formatting assumption failed rather than as "no
    matches": every fetched record is decoded and matched on the parsed object instead, and a
    Verbose message says so. Get-SfosLog and Invoke-SfosLogViewerFollowPoll both pass the same
    FieldFilter through here, so -Follow benefits from the same pre-filter as an ordinary call.

.PARAMETER LogViewerConsole
    Required. The session context returned by Connect-SfosWebAdmin (SophosFirewall.Core).

.PARAMETER Take
    Required. The call's limit.

.PARAMETER FieldFilter
    Optional. The filter specification built by Get-SfosLogViewerFieldFilter. Omit or pass an
    empty array to decode every fetched record, as before this parameter existed.

.OUTPUTS
    System.Management.Automation.PSCustomObject with two properties: Pairs (the Raw/Decoded
    pairs that passed FieldFilter, or every fetched record when FieldFilter is empty) and
    FetchedCount (how many raw records the appliance actually returned for this call, BEFORE
    FieldFilter narrowed them down). Callers that decide whether the appliance has "nothing
    more to give" by comparing a count against Take must use FetchedCount, never
    Pairs.Count - Pairs is deliberately smaller than the appliance's answer whenever
    FieldFilter removes anything, and comparing that smaller count against Take would read a
    filtered page as exhausted every time.
#>
function Get-SfosLogViewerRecordPage {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$LogViewerConsole,

        [Parameter(Mandatory)]
        [int]$Take,

        [object[]]$FieldFilter
    )

    $pageJson = '{{"limit":{0},"offset":0}}' -f $Take
    $page = Invoke-SfosWebAdminRequest -WebAdminSession $LogViewerConsole -Mode 5001 -Json $pageJson
    $rawRecords = @($page.syslog)
    $fetchedCount = $rawRecords.Count

    # Measured against a live appliance: the syslog array occasionally carries an entry that
    # is $null or an empty/whitespace-only string alongside real records. Dropped here, once,
    # so no caller downstream has to guard against it separately. FetchedCount above is taken
    # before this filter runs, because it has to reflect what the appliance actually answered
    # with for the Take comparison in Get-SfosLog/Invoke-SfosLogViewerFollowPoll to stay correct.
    $rawRecords = @($rawRecords | Where-Object { $_ -and $_.Trim() -ne '' })

    if (@($FieldFilter).Count -eq 0 -or $rawRecords.Count -eq 0) {
        $pairs = @($rawRecords | ForEach-Object { ConvertTo-SfosLogViewerRecordPair -Raw $_ })
        return [PSCustomObject]@{ Pairs = $pairs; FetchedCount = $fetchedCount }
    }

    $matchingRaw = @($rawRecords | Where-Object { Test-SfosLogViewerRawFieldMatch -Raw $_ -FieldFilter $FieldFilter })

    if ($matchingRaw.Count -eq 0) {
        # Zero raw hits is ambiguous: either genuinely nothing matches, or the raw-text
        # formatting assumption failed for this response. Distinguishing the two costs one
        # substring check per filtered field against a small sample - if the field's own key
        # is not even present, "nothing matches" is the correct reading and decoding everything
        # to confirm it would only spend the exact cost this filter exists to avoid.
        $sampleCount = [Math]::Min(20, $rawRecords.Count)
        $sample = $rawRecords[0..($sampleCount - 1)]
        $suspectField = $null
        foreach ($filter in $FieldFilter) {
            if ($filter.AnyField) {
                # No single field name to check for an AnyField (-Text/-ExcludeText) entry - the
                # equivalent check is whether the search text shows up anywhere in the sample at
                # all, quoted or not; if it does, the quoted-value-only pattern above may have
                # missed it, e.g. an unquoted numeric value, and the decode fallback is warranted.
                foreach ($value in $filter.Values) {
                    if (@($sample | Where-Object { $_ -like "*$value*" }).Count -gt 0) {
                        $suspectField = 'Text'
                        break
                    }
                }
            }
            else {
                foreach ($wireField in $filter.WireFields) {
                    $token = '"' + $wireField + '"'
                    if (@($sample | Where-Object { $_ -like "*$token*" }).Count -gt 0) {
                        $suspectField = $wireField
                        break
                    }
                }
            }
            if ($suspectField) {
                break
            }
        }

        if (-not $suspectField) {
            return [PSCustomObject]@{ Pairs = @(); FetchedCount = $fetchedCount }
        }

        Write-Verbose "Get-SfosLog: the raw-text pre-filter on field '$suspectField' matched none of $($rawRecords.Count) fetched record(s), even though that field is present in the sample. Falling back to decoding every record and comparing on the parsed object."

        $pairs = @($rawRecords | ForEach-Object { ConvertTo-SfosLogViewerRecordPair -Raw $_ } |
                Where-Object { Test-SfosLogViewerDecodedFieldMatch -Record $_.Decoded -FieldFilter $FieldFilter })
        return [PSCustomObject]@{ Pairs = $pairs; FetchedCount = $fetchedCount }
    }

    $pairs = @($matchingRaw | ForEach-Object { ConvertTo-SfosLogViewerRecordPair -Raw $_ })
    return [PSCustomObject]@{ Pairs = $pairs; FetchedCount = $fetchedCount }
}

<#
.SYNOPSIS
    Evaluates a log viewer category condition against one decoded log record. Internal helper,
    not exported.

.DESCRIPTION
    The 'all' category has no condition and matches everything. Every other category's
    condition, as returned by mode 5002, is a boolean expression of quoted 'field=value'
    literals combined with AND, OR, NOT and parentheses - for example
    ( "log_type=Firewall" AND ( "log_component=Firewall Rule" OR ... ) ). Measured against a
    live appliance: the server ignores this condition on mode 5001 itself (See this module's own findings file), so Get-SfosLog evaluates it client-side, the same way the web console's own
    log viewer does. Two condition strings juxtapose a term directly after another with no
    explicit AND (" ... System" NOT (...) OR ..."), which this parser treats as an implicit
    AND - the only interpretation that reproduces the counts measured against real records.
#>
function Test-SfosLogViewerCondition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Condition,

        [Parameter(Mandatory)]
        [PSCustomObject]$Record
    )

    $tokens = @([regex]::Matches($Condition, '"[^"]*"|AND|OR|NOT|\(|\)') | ForEach-Object { $_.Value })
    $posRef = [ref]0

    function Get-SfosLogViewerToken {
        param([ref]$PosRef)
        if ($PosRef.Value -lt $tokens.Count) { return $tokens[$PosRef.Value] }
        return $null
    }

    function Read-SfosLogViewerFactor {
        param([ref]$PosRef, [PSCustomObject]$Record)
        $t = Get-SfosLogViewerToken -PosRef $PosRef
        if ($t -eq '(') {
            $PosRef.Value++
            $result = Read-SfosLogViewerOr -PosRef $PosRef -Record $Record
            if ((Get-SfosLogViewerToken -PosRef $PosRef) -eq ')') { $PosRef.Value++ }
            return $result
        }
        $PosRef.Value++
        if ($t -match '^"(.*)=(.*)"$') {
            $field = $Matches[1]
            $value = $Matches[2]
            return [bool]($Record.$field -eq $value)
        }
        return $false
    }

    function Read-SfosLogViewerNot {
        param([ref]$PosRef, [PSCustomObject]$Record)
        if ((Get-SfosLogViewerToken -PosRef $PosRef) -eq 'NOT') {
            $PosRef.Value++
            return -not (Read-SfosLogViewerFactor -PosRef $PosRef -Record $Record)
        }
        return Read-SfosLogViewerFactor -PosRef $PosRef -Record $Record
    }

    function Read-SfosLogViewerAnd {
        param([ref]$PosRef, [PSCustomObject]$Record)
        $result = Read-SfosLogViewerNot -PosRef $PosRef -Record $Record
        while ($true) {
            $t = Get-SfosLogViewerToken -PosRef $PosRef
            if ($t -eq 'AND') {
                $PosRef.Value++
                # Right-hand side is always evaluated in full, even once $result is already
                # $false: PowerShell's -and short-circuits and would otherwise skip advancing
                # $PosRef past the untaken side, desynchronising every token read after it -
                # measured to hang the parser on any condition where an early AND term is false.
                $rhs = Read-SfosLogViewerNot -PosRef $PosRef -Record $Record
                $result = $result -and $rhs
            }
            elseif ($t -eq 'NOT') {
                $rhs = Read-SfosLogViewerNot -PosRef $PosRef -Record $Record
                $result = $result -and $rhs
            }
            elseif ($t -and $t -ne 'OR' -and $t -ne ')') {
                # No explicit AND between two terms - treated as an implicit AND.
                $rhs = Read-SfosLogViewerNot -PosRef $PosRef -Record $Record
                $result = $result -and $rhs
            }
            else {
                break
            }
        }
        return $result
    }

    function Read-SfosLogViewerOr {
        param([ref]$PosRef, [PSCustomObject]$Record)
        $result = Read-SfosLogViewerAnd -PosRef $PosRef -Record $Record
        while ((Get-SfosLogViewerToken -PosRef $PosRef) -eq 'OR') {
            $PosRef.Value++
            $rhs = Read-SfosLogViewerAnd -PosRef $PosRef -Record $Record
            $result = $result -or $rhs
        }
        return $result
    }

    return Read-SfosLogViewerOr -PosRef $posRef -Record $Record
}

<#
.SYNOPSIS
    Applies the -Category and -Since filters to a set of decoded log record pairs. Internal
    helper, not exported.

.DESCRIPTION
    Shared by Get-SfosLog's own fetch loop and by Invoke-SfosLogViewerFollowPoll, so the two
    filtering passes cannot drift apart. -Category fetches the mode 5002 condition for the
    given key and evaluates it client-side with Test-SfosLogViewerCondition; -Since compares
    absolute instants, reading a zone-less cutoff on the appliance's own clock the same way
    Get-SfosLog's help documents.

.PARAMETER LogViewerConsole
    Required. The session context returned by Connect-SfosWebAdmin (SophosFirewall.Core).

.PARAMETER Pairs
    Required. The record pairs to filter, as returned by Get-SfosLogViewerRecordPage.

.PARAMETER Category
    Required. The category key as passed to Get-SfosLog, or 'all'.

.PARAMETER HasSince
    Required. Whether Get-SfosLog was called with -Since.

.PARAMETER Since
    The -Since value. Only read while HasSince is set.
#>
function Select-SfosLogViewerRecordPair {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$LogViewerConsole,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Pairs,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [bool]$HasSince,

        [datetime]$Since
    )

    $result = @($Pairs)

    if ($Category -ne 'all') {
        $catalog = Invoke-SfosWebAdminRequest -WebAdminSession $LogViewerConsole -Mode 5002 -Json '{}'
        $categoryEntry = $catalog.filter.module.val.$Category
        if (-not $categoryEntry -or -not $categoryEntry.condition) {
            throw "The Sophos Firewall web console log viewer filter catalog has no condition for category '$Category'. The console interface may have changed; use Get-SfosLogCategory to see the categories it currently offers."
        }
        $condition = [string]$categoryEntry.condition
        $result = @($result | Where-Object { Test-SfosLogViewerCondition -Condition $condition -Record $_.Decoded })
    }

    if ($HasSince) {
        $applianceOffset = $null
        foreach ($pair in $result) {
            $probe = ConvertTo-SfosLogInstant -Record $pair.Decoded
            if ($null -ne $probe) {
                $applianceOffset = $probe.Offset
                break
            }
        }
        $cutoff = if ($Since.Kind -eq [System.DateTimeKind]::Unspecified -and $null -ne $applianceOffset) {
            [datetimeoffset]::new($Since, $applianceOffset)
        }
        else {
            [datetimeoffset]$Since
        }
        $result = @($result | Where-Object {
                $instant = ConvertTo-SfosLogInstant -Record $_.Decoded
                $null -ne $instant -and $instant -ge $cutoff
            })
    }

    return $result
}

<#
.SYNOPSIS
    Fetches and filters the log records for one Get-SfosLog/Export-SfosLog request, widening the
    request as needed to satisfy -MaxRecords. Internal helper, not exported.

.DESCRIPTION
    Shared by Get-SfosLog and Export-SfosLog so the fetch/widen/sort/truncate logic that reaches
    the web admin console cannot drift between the two callers. Wraps Get-SfosLogViewerRecordPage
    (the single HTTP call) and Select-SfosLogViewerRecordPair (the -Category/-Since filtering)
    exactly the way Get-SfosLog's own fetch loop always has - see this module's own findings file
    for why depth is reached with one larger -Take rather than offset paging, and why attempts
    accumulate instead of replacing each other.

    With -All, a single request at the appliance's own ceiling is made; the returned Pairs are in
    the order the appliance sent them (already newest-first, no further sort). Without -All, the
    request widens (up to five attempts, quadrupling each time, capped at the appliance's own
    ceiling) until -MaxRecords matching records are found or the appliance and the attempt budget
    are both exhausted; the accumulated set is then sorted newest-first by each record's own
    timestamp and truncated to -MaxRecords.

.PARAMETER LogViewerConsole
    Required. The session context returned by Connect-SfosWebAdmin (SophosFirewall.Core).

.PARAMETER Category
    Required. The category key to filter on, or 'all'.

.PARAMETER HasSince
    Required. Whether a -Since cutoff applies.

.PARAMETER Since
    The -Since value. Only read while HasSince is set.

.PARAMETER FieldFilter
    Optional. The filter specification built by Get-SfosLogViewerFieldFilter.

.PARAMETER All
    Optional. Fetches everything in a single request at the appliance's own ceiling, instead of
    widening toward -MaxRecords.

.PARAMETER MaxRecords
    The number of records to return once -Category/-Since/-FieldFilter have been applied. Ignored
    while -All is set.

.OUTPUTS
    System.Management.Automation.PSCustomObject with Pairs (the final Raw/Decoded pairs),
    FetchedCount (the appliance's raw answer size of the last/only request) and Truncated (only
    meaningful with -All: whether the appliance answered with exactly its own ceiling, so the log
    may hold more than what was returned).
#>
function Get-SfosLogRecordSet {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$LogViewerConsole,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [bool]$HasSince,

        [datetime]$Since,

        [object[]]$FieldFilter,

        [switch]$All,

        [int]$MaxRecords = 200
    )

    # Depth is reached with ONE call carrying a large limit, never by paging with offset - see
    # this module's own findings file. 50000 is the appliance's own observed ceiling for a single
    # request; asking for more does not return more.
    $applianceLimitCeiling = 50000

    $filterParams = @{ Category = $Category; HasSince = $HasSince }
    if ($HasSince) { $filterParams['Since'] = $Since }

    if ($All) {
        $page = Get-SfosLogViewerRecordPage -LogViewerConsole $LogViewerConsole -Take $applianceLimitCeiling -FieldFilter $FieldFilter
        $rawPairs = @($page.Pairs)
        $truncated = $page.FetchedCount -ge $applianceLimitCeiling
        $pairs = @(Select-SfosLogViewerRecordPair -LogViewerConsole $LogViewerConsole -Pairs $rawPairs @filterParams)

        return [PSCustomObject]@{
            Pairs        = $pairs
            FetchedCount = $page.FetchedCount
            Truncated    = $truncated
        }
    }

    $limit = [Math]::Min($MaxRecords, $applianceLimitCeiling)
    $maxAttempts = 5
    $attempt = 0
    $rawFetchedCount = 0
    $pairs = @()

    # Each attempt is an independent, fresh read of the appliance's current top-N records, never
    # a continuation of the previous one - offset-based paging is unreliable past roughly 750
    # records (see this module's own findings file), so depth is reached solely by asking for a
    # larger limit. A record a narrower attempt genuinely matched can fail to reappear in a wider
    # attempt's window - new records arriving between the two calls push it further back - so
    # matches accumulate across attempts, deduplicated on the raw record text, instead of being
    # replaced by whatever the latest attempt found.
    $seenRaw = [System.Collections.Generic.HashSet[string]]::new()
    $accumulated = [System.Collections.Generic.List[object]]::new()

    while ($true) {
        $attempt++
        $page = Get-SfosLogViewerRecordPage -LogViewerConsole $LogViewerConsole -Take $limit -FieldFilter $FieldFilter
        $rawPairs = @($page.Pairs)
        $rawFetchedCount = $page.FetchedCount
        # "Exhausted" (appliance had nothing more to give) has to be read off FetchedCount, never
        # off Pairs.Count - Pairs is deliberately smaller than $limit whenever a field filter
        # removes anything, which would otherwise make every filtered page look exhausted after
        # the very first request.
        $exhausted = $rawFetchedCount -lt $limit

        $selected = @(Select-SfosLogViewerRecordPair -LogViewerConsole $LogViewerConsole -Pairs $rawPairs @filterParams)
        foreach ($pair in $selected) {
            if ($seenRaw.Add($pair.Raw)) {
                $accumulated.Add($pair)
            }
        }
        $pairs = $accumulated.ToArray()

        if ($pairs.Count -ge $MaxRecords -or $exhausted -or $limit -ge $applianceLimitCeiling -or $attempt -ge $maxAttempts) {
            break
        }
        $limit = [Math]::Min($limit * 4, $applianceLimitCeiling)
    }

    # Accumulating across attempts can interleave two independently-fetched, individually
    # newest-first windows out of order - re-sort once on the record's own instant so the
    # newest-first assumption every caller relies on still holds. A record without a parseable
    # instant sorts last rather than dropping out.
    $pairs = @($pairs | Sort-Object -Descending -Property @{
            Expression = { $instant = ConvertTo-SfosLogInstant -Record $_.Decoded; if ($null -ne $instant) { $instant } else { [datetimeoffset]::MinValue } }
        })

    if ($pairs.Count -gt $MaxRecords) {
        $pairs = $pairs[0..($MaxRecords - 1)]
    }

    return [PSCustomObject]@{
        Pairs        = $pairs
        FetchedCount = $rawFetchedCount
        Truncated    = $false
    }
}

<#
.SYNOPSIS
    Reads the category catalog of the Sophos Firewall web admin console's log viewer.

.DESCRIPTION
    Returns the log viewer's own list of categories, each with the condition the web admin
    console uses to decide which log records belong to it. This is the self-description that
    -Category on Get-SfosLog accepts; use it to see what a category key actually matches, or to
    confirm the set of keys is still current after a firmware update. This is not part of the
    XML API; it signs in to the web admin console instead, the same way Get-SfosLog does. Opens
    its own web admin console session; the session and its CSRF token are not reused across
    calls.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the web admin console login. If omitted, the value from the
    current connection is used.

.PARAMETER Password
    Optional. Password for the web admin console login, as a SecureString. If omitted, the
    value from the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AcceptLoginDisclaimer
    Optional. Confirms a login disclaimer configured on the appliance, on behalf of the
    account logging in. Without this switch, this cmdlet fails on an appliance that shows a
    login disclaimer, with an error describing the disclaimer.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per category, with the properties
    Name (the key accepted by Get-SfosLog -Category), Label (the raw, untranslated label the
    web admin console stores for it) and Condition (the boolean expression the web admin
    console evaluates against a record's fields, or $null for the 'all' category, which has
    none).

.EXAMPLE
    Get-SfosLogCategory

    Lists every category the log viewer knows, with the condition each one matches.

.EXAMPLE
    Get-SfosLogCategory | Where-Object Name -eq 'firewall' | Select-Object -ExpandProperty Condition

    Shows exactly which fields the 'firewall' category matches.

.NOTES
    Reading the log viewer's category catalog is not part of the documented XML API. It uses
    the web admin console the way a browser does and can change with a firmware update.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosLog
#>
function Get-SfosLogCategory {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AcceptLoginDisclaimer
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $console = Connect-SfosWebAdmin -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck -AcceptLoginDisclaimer:$AcceptLoginDisclaimer

    $catalog = Invoke-SfosWebAdminRequest -WebAdminSession $console -Mode 5002 -Json '{}'

    $moduleVal = $catalog.filter.module.val
    if (-not $moduleVal) {
        throw 'Sophos Firewall web console log viewer filter catalog did not contain the expected module list. The console interface may have changed.'
    }

    foreach ($property in $moduleVal.PSObject.Properties) {
        $entry = $property.Value
        $condition = $null
        if ($entry.PSObject.Properties.Match('condition').Count -gt 0) {
            $condition = [string]$entry.condition
        }

        [PSCustomObject]@{
            Name      = $property.Name
            Label     = [string]$entry.label
            Condition = $condition
        }
    }
}

# Turns a log record into an absolute point in time. The console reports its timestamps in the
# appliance's own local time and carries the matching UTC offset in tz_offset, so a caller whose
# machine runs in a different time zone can still be answered correctly. Internal helper, not
# exported.
function ConvertTo-SfosLogInstant {
    [OutputType([System.Nullable[datetimeoffset]])]
    param([Parameter(Mandatory)][object]$Record)

    if ($Record.PSObject.Properties.Match('datetime').Count -eq 0) {
        return $null
    }

    # A record that has already been through Format-SfosLogViewerRecord carries the instant
    # itself, and its 'datetime' is then a [datetime] rather than the console's string. Read
    # those back instead of failing the fixed-format parse below.
    $existing = $Record.PSObject.Properties.Match('DatetimeOffset')
    if ($existing.Count -gt 0 -and $Record.DatetimeOffset -is [datetimeoffset]) {
        return [datetimeoffset]$Record.DatetimeOffset
    }
    if ($Record.datetime -is [datetime]) {
        return [datetimeoffset]::new([datetime]$Record.datetime, [timespan]::Zero)
    }

    $local = [datetime]::MinValue
    $parsed = [datetime]::TryParseExact([string]$Record.datetime, 'yyyy-MM-dd HH:mm:ss',
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$local)
    if (-not $parsed) {
        return $null
    }

    $offset = [timespan]::Zero
    if ($Record.PSObject.Properties.Match('tz_offset').Count -gt 0) {
        $text = [string]$Record.tz_offset
        if ($text -match '^([+-])(\d{2}):?(\d{2})$') {
            $span = [timespan]::new([int]$Matches[2], [int]$Matches[3], 0)
            $offset = if ($Matches[1] -eq '-') { $span.Negate() } else { $span }
        }
    }

    return [datetimeoffset]::new($local, $offset)
}

<#
.SYNOPSIS
    Turns one decoded log record into the shape Get-SfosLog returns. Internal helper, not
    exported.

.DESCRIPTION
    Adds Datetime/DatetimeOffset the same way Get-SfosLog always has, unless -AsJson asks for
    the record exactly as decoded. Shared between Get-SfosLog's ordinary path and its -Follow
    path so the two cannot drift apart.

.PARAMETER Record
    Required. One decoded log record.

.PARAMETER AsJson
    Optional. Skip adding Datetime/DatetimeOffset.
#>
function Format-SfosLogViewerRecord {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [object]$Record,

        [switch]$AsJson
    )

    if (-not $AsJson -and $Record.PSObject.Properties.Match('datetime').Count -gt 0) {
        $instant = ConvertTo-SfosLogInstant -Record $Record
        # Datetime is the appliance's own wall clock, exactly as the console shows it.
        # DatetimeOffset carries the same moment with the offset the record reports, so
        # records from appliances in other time zones stay comparable.
        $Record | Add-Member -NotePropertyName 'Datetime' -NotePropertyValue $(
            if ($null -ne $instant) { $instant.DateTime } else { $null }
        ) -Force
        $Record | Add-Member -NotePropertyName 'DatetimeOffset' -NotePropertyValue $instant -Force
    }

    return $Record
}

<#
.SYNOPSIS
    Picks the type name suffix Get-SfosLog tags its output with, for the default table/list
    views in this module's Format.ps1xml. Internal helper, not exported.

.DESCRIPTION
    The appliance's API has no retrievable default column set for the log viewer - its
    configuration only assigns fields to categories, it does not define a view through the API.
    Sixteen of the seventeen per-category column sets in this module's Format.ps1xml instead
    reproduce the web admin console's own Log Viewer screen - its column order and labels, read
    from the console's own JavaScript configuration and cross-checked against the screen itself.
    The Firewall category is the one exception and keeps this module's own nine-column choice
    from before that comparison; see this module's own findings file.

    Deterministic selection, in this order: -Category wins when it was bound, because it is an
    explicit, unambiguous choice. Otherwise, when -LogType was bound with exactly one value, that
    value is matched against the category keys by stripping every non-letter character and
    lowercasing both sides - '"IPS"' and 'ips' compare equal this way, and so does a value such as
    'SSL/TLS' against the category key 'ssltls'. -LogType with zero or more than one value is
    ambiguous and falls through. Anything that resolves to nothing recognised - -Category 'all',
    an unmatched -LogType value, or neither parameter bound - returns $null, which Get-SfosLog
    reads as "use the Sfos.Log fallback view".

.PARAMETER BoundParameters
    Required. $PSBoundParameters from Get-SfosLog.

.PARAMETER Category
    Required. The resolved -Category value from Get-SfosLog (its default 'all' included).
#>
function Get-SfosLogViewTypeSuffix {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters,

        [Parameter(Mandatory)]
        [string]$Category
    )

    # Every key Get-SfosLog's -Category ValidateSet accepts, except 'all' - that one has no
    # column set of its own and falls through to the Sfos.Log fallback view like anything
    # unrecognised.
    $categoryKeys = @('malware', 'heartbeat', 'sandbox', 'admin', 'ssltls', 'ips',
        'applicationfilter', 'sdwan', 'webcontentpolicy', 'system', 'firewall', 'vpn',
        'atp', 'webfilter', 'waf', 'email', 'authentication')

    if ($BoundParameters.ContainsKey('Category') -and $categoryKeys -contains $Category) {
        return $Category.Substring(0, 1).ToUpperInvariant() + $Category.Substring(1)
    }

    if ($BoundParameters.ContainsKey('LogType')) {
        $logTypeValues = @($BoundParameters['LogType'])
        if ($logTypeValues.Count -eq 1) {
            $normalized = ([string]$logTypeValues[0] -replace '[^A-Za-z]', '').ToLowerInvariant()
            $match = $categoryKeys | Where-Object { $_ -eq $normalized } | Select-Object -First 1
            if ($match) {
                return $match.Substring(0, 1).ToUpperInvariant() + $match.Substring(1)
            }
        }
    }

    return $null
}

<#
.SYNOPSIS
    Runs one polling pass of Get-SfosLog -Follow. Internal helper, not exported.

.DESCRIPTION
    Fetches the appliance's most recent records with a single call, using a window that starts
    at 200 (the standard poll window). If the oldest record the call returned is still newer
    than LastInstant, the gap since the last record shown was not bridged, so the same pass is
    repeated with a limit four times as large - at most three attempts in total - before giving
    up and letting the caller warn. This is a single growing call, not offset paging: paging
    with offset repeats the same page once it reaches roughly 750 records back, silently, with
    no error and no empty result (see this module's own findings file), so depth within one poll is
    reached the same way Get-SfosLog itself reaches it - a bigger limit, never an offset.

    Applies the same client-side -Category and -Since filtering Get-SfosLog itself applies (via
    Select-SfosLogViewerRecordPair), then splits the result into records strictly newer than
    LastInstant and records that share its exact instant. The same-instant group is
    deduplicated against LastInstantRawCounts by raw JSON text: a record already output is not
    shown again, while a genuine repeat of identical content - the appliance does send
    duplicate rows - is. Everything new comes back in chronological order, oldest first.

.PARAMETER LogViewerConsole
    Required. The session context returned by Connect-SfosWebAdmin (SophosFirewall.Core).

.PARAMETER Category
    Required. The category key as passed to Get-SfosLog, or 'all'.

.PARAMETER HasSince
    Required. Whether Get-SfosLog -Follow was called with -Since.

.PARAMETER Since
    The -Since value. Only read while HasSince is set.

.PARAMETER LastInstant
    Required. The instant of the most recent record already output, or $null before anything
    has been output yet.

.PARAMETER LastInstantRawCounts
    Required. A hashtable of raw JSON text to the number of occurrences already output at
    LastInstant.

.PARAMETER FieldFilter
    Optional. The filter specification built by Get-SfosLogViewerFieldFilter, applied to every
    call this poll makes to Get-SfosLogViewerRecordPage - the same built-in field filters
    Get-SfosLog itself applies to the initial backlog also keep filtering every later poll.
#>
function Invoke-SfosLogViewerFollowPoll {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$LogViewerConsole,

        [Parameter(Mandatory)]
        [string]$Category,

        [Parameter(Mandatory)]
        [bool]$HasSince,

        [datetime]$Since,

        [System.Nullable[datetimeoffset]]$LastInstant,

        [Parameter(Mandatory)]
        [hashtable]$LastInstantRawCounts,

        [object[]]$FieldFilter
    )

    # Standard poll window and retry-widening ceiling (see this module's own findings file). A poll
    # that has not caught up to LastInstant with this window widens the SAME single call
    # instead of paging with offset, which repeats past roughly 750 records without any error
    # signal.
    $windowSize = 200
    $maxAttempts = 3

    $limit = $windowSize
    $attempt = 0
    $pagePairs = @()
    $rawFetchedCount = 0
    $bridged = $true

    while ($true) {
        $attempt++
        $page = Get-SfosLogViewerRecordPage -LogViewerConsole $LogViewerConsole -Take $limit -FieldFilter $FieldFilter
        $pagePairs = @($page.Pairs)
        $rawFetchedCount = $page.FetchedCount

        if ($pagePairs.Count -eq 0 -or $null -eq $LastInstant) {
            # Nothing to compare against yet, or the appliance has nothing at all - one call is
            # all a single poll can reason about.
            break
        }

        $oldestInPage = ConvertTo-SfosLogInstant -Record $pagePairs[$pagePairs.Count - 1].Decoded
        if ($null -eq $oldestInPage -or $oldestInPage -le $LastInstant) {
            # The window reaches back to (or past) the last record already shown - bridged.
            break
        }

        if ($rawFetchedCount -lt $limit) {
            # The appliance had nothing more to give - this response IS everything there is, so
            # there is nothing left it could be hiding beyond the anchor. Bridged, even though
            # the oldest record fetched still looks newer than LastInstant. Read off
            # FetchedCount, never off Pairs.Count - Pairs is deliberately smaller than $limit
            # whenever FieldFilter removes anything.
            break
        }

        if ($attempt -ge $maxAttempts) {
            # The page was still full and the gap still is not bridged, but the retry ceiling
            # was reached - give up on this poll and let the caller warn.
            $bridged = $false
            break
        }

        $limit *= 4
    }

    $fetchedCount = $rawFetchedCount
    $attemptsUsed = $attempt

    # -Since only added when HasSince is set: an unbound [datetime] parameter on this function
    # is $null, and Select-SfosLogViewerRecordPair's own [datetime]$Since parameter throws on
    # argument binding if handed $null directly.
    $filterParams = @{ Category = $Category; HasSince = $HasSince }
    if ($HasSince) { $filterParams['Since'] = $Since }
    $pairs = @(Select-SfosLogViewerRecordPair -LogViewerConsole $LogViewerConsole -Pairs $pagePairs @filterParams)

    $newerPairs = [System.Collections.Generic.List[object]]::new()
    $sameInstantPairs = [System.Collections.Generic.List[object]]::new()
    foreach ($pair in $pairs) {
        $instant = ConvertTo-SfosLogInstant -Record $pair.Decoded
        if ($null -eq $instant) { continue }
        if ($null -eq $LastInstant -or $instant -gt $LastInstant) {
            $newerPairs.Add($pair)
        }
        elseif ($instant -eq $LastInstant) {
            $sameInstantPairs.Add($pair)
        }
    }

    $sameInstantCounts = @{}
    foreach ($pair in $sameInstantPairs) {
        $sameInstantCounts[$pair.Raw] = [int]$sameInstantCounts[$pair.Raw] + 1
    }

    # Only the occurrences beyond what was already output for this exact raw text are new -
    # otherwise a repeat poll of an unchanged backlog would show the same rows again.
    $toOutputSame = [System.Collections.Generic.List[object]]::new()
    $emittedPerRaw = @{}
    foreach ($pair in $sameInstantPairs) {
        $already = [int]$LastInstantRawCounts[$pair.Raw]
        $emitted = [int]$emittedPerRaw[$pair.Raw]
        if ($emitted -lt ($sameInstantCounts[$pair.Raw] - $already)) {
            $toOutputSame.Add($pair)
            $emittedPerRaw[$pair.Raw] = $emitted + 1
        }
    }

    $newerAscending = @($newerPairs.ToArray())
    [array]::Reverse($newerAscending)

    $resultLastInstant = $LastInstant
    $resultLastInstantRawCounts = $LastInstantRawCounts

    if ($newerPairs.Count -gt 0) {
        # $newerPairs is still in fetch order (newest first): its first element is the newest
        # record found this poll, and becomes the new high-water mark.
        $newestInstant = ConvertTo-SfosLogInstant -Record $newerPairs[0].Decoded
        $newestGroup = @($newerPairs | Where-Object { (ConvertTo-SfosLogInstant -Record $_.Decoded) -eq $newestInstant })
        $newCounts = @{}
        foreach ($p in $newestGroup) { $newCounts[$p.Raw] = [int]$newCounts[$p.Raw] + 1 }
        $resultLastInstant = $newestInstant
        $resultLastInstantRawCounts = $newCounts
    }
    elseif ($toOutputSame.Count -gt 0) {
        $resultLastInstantRawCounts = $sameInstantCounts
    }

    return [PSCustomObject]@{
        NewPairsOrdered      = @($toOutputSame.ToArray() + $newerAscending)
        LastInstant          = $resultLastInstant
        LastInstantRawCounts = $resultLastInstantRawCounts
        FetchedCount         = $fetchedCount
        AttemptsUsed         = $attemptsUsed
        GapNotBridged        = -not $bridged
    }
}

<#
.SYNOPSIS
    Retrieves log records from the Log Viewer of a Sophos Firewall web admin console.

.DESCRIPTION
    Returns the log records an administrator sees under Log Viewer in the web admin console.
    The Sophos Firewall XML API has no equivalent read, so this cmdlet signs in to the web
    admin console instead and needs an account permitted to view logs there. The console
    offers no server-side filtering: -Category and -Since are evaluated on the client after the
    records are fetched, and the built-in field filters (-LogType, -LogComponent, -LogSubtype,
    -Status, -User, -SourceIP, -DestinationIP, -SourcePort, -DestinationPort, -Protocol, -AnyIP,
    -AnyPort, -MessageLike, -Text, and their Exclude* counterparts) are matched on each record's
    raw text before it is decoded, so a record that cannot match one of them is never decoded.
    Nothing on the firewall is changed.

    -Category and the field filters are AND-combined: a record has to satisfy every one of them
    to be returned. Several values on one field filter are OR-combined: -Status Deny,Reject
    keeps a record with either status. Every filter listed above has an Exclude* counterpart
    (-ExcludeStatus, -ExcludeSourceIP, and so on) that keeps everything except a match on the
    same terms - several values on one Exclude* parameter are OR-combined the same way, so
    -ExcludeStatus Allow,Reject drops a record matching either one, and an Exclude* filter never
    drops a record that does not carry the field it inspects at all: -ExcludeMessageLike does
    not discard the many records that have no message field.

    The Any prefix means "either side": -AnyIP and -AnyPort each compare against both sides of a
    connection at once - -AnyIP matches src_ip or dst_ip, -AnyPort matches src_port or dst_port -
    so a single value finds an address or port regardless of whether it was the source or the
    destination side. Every side-specific filter above has such a counterpart: -SourceIP and
    -DestinationIP pin down one side of an address, -AnyIP checks both; -SourcePort and
    -DestinationPort pin down one side of a port, -AnyPort checks both. -AnyPort, not -Port,
    because -Port is already this cmdlet's connection parameter (the TCP management port). Every
    field filter does exact or substring text matching on one field each; a range comparison such
    as a port range, or arithmetic across fields, is still a job for Where-Object after the
    cmdlet.

    -Text is different from every filter above: it is not tied to one wire field. It matches
    when the search text appears in the value of any field the record carries, and only in a
    value - never in a field name. A naive search over the record's whole raw text would treat
    the field name "dst_port" as a hit for -Text 'port' and return every record regardless of
    its actual content; -Text is built to search values only, so it does not do that. -Protocol
    matches the wire field protocol exactly, but its values are not consistent across the log:
    some protocols are logged by name (TCP, UDP), others by number - see -Protocol's own help
    for why this cmdlet does not translate between the two.

.PARAMETER Category
    Optional. One of the log viewer's own category keys. Default 'all', which returns every
    log type. Evaluated client-side; see Get-SfosLogCategory for what each key matches.

    A category is not the same thing as a log type, and the two are easy to confuse. -LogType
    matches one field of the record, exactly as the appliance wrote it: Firewall, Event,
    Content Filtering, Anti-Virus, IDP and so on. A category is a condition over several
    fields, defined by the web admin console itself - 'admin', for instance, is
    log_type=Event AND log_subtype=Admin.

    So they do not line up one to one. Four categories - admin, system, authentication and vpn
    - are all log_type=Event and are told apart only by further fields, which means -LogType
    Event returns all four at once. In the other direction, the applicationfilter category
    spans two log types. Get-SfosLogCategory returns each category's condition, which is the
    clearest place to see the mapping.

    Which to use: -LogType when you know the raw type - it filters before the records are
    decoded and is measurably faster. -Category when you want exactly the slice the web admin
    console shows. Both can be combined, and both can be combined with -LogSubtype and
    -LogComponent: -LogType Event -LogSubtype Admin is the fast way to what -Category admin
    selects.

.PARAMETER MaxRecords
    Optional, default 200. The number of records returned after -Category and -Since have been
    applied, not the number fetched from the appliance. Depth is reached by requesting a larger
    limit in a single call, never by paging with an offset: offset-based paging becomes
    unreliable after a few hundred records and silently repeats an earlier page instead of
    erroring or returning nothing, so this cmdlet never sends one. If filtering leaves too few
    matching records and the appliance still had at least that many to give, the request is
    repeated with four times the limit, up to five attempts and a ceiling of 50000 records for
    a single request. If the appliance runs out, or the attempt/limit ceiling is reached, before
    enough matching records were found, the cmdlet returns what it found and warns rather than
    silently returning fewer than asked for. Cannot be combined with -All.

.PARAMETER All
    Optional. Returns everything the appliance's log retention holds, in a single request with a
    limit of 50000, the ceiling for a single request. That ceiling reflects the appliance's own
    log retention, not a limit this module imposes; if the response comes back at exactly 50000
    records, the log may hold more and the cmdlet warns that the result can be truncated.
    -Category and -Since still apply. Cannot be combined with -MaxRecords or -Follow.

.PARAMETER Since
    Optional. Only returns records at or after this point in time. Applied client-side, after
    the records have been fetched.

    The firewall's clock is the reference. A plain date and time - the shape you get by copying
    a timestamp out of the log viewer, or by writing '2026-08-20 18:00' - is read on the
    firewall's own clock, using the UTC offset its records carry. A value that already knows its
    zone, such as the result of Get-Date or a DateTimeOffset, is an unambiguous moment in time
    and is used as it stands. Either way the comparison is done on absolute instants, so a
    machine in a different time zone than the firewall still gets the window it asked for.

.PARAMETER Follow
    Optional. After showing the current backlog (bounded by -MaxRecords, filtered by -Category
    and -Since exactly as without -Follow), keeps the web admin console session open and
    streams only the records that arrive afterwards, oldest first, until the caller stops the
    cmdlet - the equivalent of tail -f for this log viewer. There is no push channel for these
    records; even the web admin console's own log viewer only polls, on a fixed interval.
    -PollIntervalSeconds is therefore the only control over how quickly a new record surfaces
    here.

.PARAMETER PollIntervalSeconds
    Optional. Seconds to wait between polls while -Follow is running. Default 30, the same
    interval the web admin console's own log viewer polls on. Has no effect without -Follow.

.PARAMETER LogType
    Optional. Matches the wire field log_type exactly - the raw type the appliance wrote into
    the record: Firewall, Event, Content Filtering, Anti-Virus, IDP, ATP, SD-WAN, Sandbox,
    HeartBeat, SSL, WAF, Anti-Spam. Several values are OR-combined; combined with any other
    filter parameter, including -Category, the result is AND. Matched on the raw record text
    before it is decoded - see the description above. -ExcludeLogType is the negated
    counterpart: it drops a record matching any of its values, and never drops a record without
    a log_type field.

    This is a different thing from -Category, which is the web admin console's grouping over
    several fields. One log type can hold several categories (Event covers admin, system,
    authentication and vpn) and one category can span several log types. See -Category for the
    full comparison.

.PARAMETER ExcludeLogType
    Optional. Drops records whose log_type matches any of these values; several values are
    OR-combined. AND-combined with every other filter parameter, including -LogType itself.
    Never drops a record that has no log_type field.

.PARAMETER LogComponent
    Optional. Matches the wire field log_component exactly. Several values are OR-combined;
    matched on the raw record text before it is decoded.

.PARAMETER ExcludeLogComponent
    Optional. Drops records whose log_component matches any of these values; several values are
    OR-combined. Never drops a record that has no log_component field.

.PARAMETER LogSubtype
    Optional. Matches the wire field log_subtype exactly. Several values are OR-combined;
    matched on the raw record text before it is decoded.

.PARAMETER ExcludeLogSubtype
    Optional. Drops records whose log_subtype matches any of these values; several values are
    OR-combined. Never drops a record that has no log_subtype field.

.PARAMETER Status
    Optional. Matches the wire field status exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded.

.PARAMETER ExcludeStatus
    Optional. Drops records whose status matches any of these values; several values are
    OR-combined. Never drops a record that has no status field.

.PARAMETER User
    Optional. Matches the wire field user exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded.

.PARAMETER ExcludeUser
    Optional. Drops records whose user matches any of these values; several values are
    OR-combined. Never drops a record that has no user field.

.PARAMETER SourceIP
    Optional. Matches the wire field src_ip exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded. Matches only the source side; see -AnyIP to match
    either side of a connection.

.PARAMETER ExcludeSourceIP
    Optional. Drops records whose src_ip matches any of these values; several values are
    OR-combined. Never drops a record that has no src_ip field.

.PARAMETER DestinationIP
    Optional. Matches the wire field dst_ip exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded. Matches only the destination side; see -AnyIP to
    match either side of a connection.

.PARAMETER ExcludeDestinationIP
    Optional. Drops records whose dst_ip matches any of these values; several values are
    OR-combined. Never drops a record that has no dst_ip field.

.PARAMETER SourcePort
    Optional. Matches the wire field src_port exactly. Several values are OR-combined; matched
    on the raw record text before it is decoded. Matches only the source side; see -AnyPort
    to match either side of a connection.

.PARAMETER ExcludeSourcePort
    Optional. Drops records whose src_port matches any of these values; several values are
    OR-combined. Never drops a record that has no src_port field.

.PARAMETER DestinationPort
    Optional. Matches the wire field dst_port exactly. Several values are OR-combined; matched
    on the raw record text before it is decoded. Matches only the destination side; see
    -AnyPort to match either side of a connection.

.PARAMETER ExcludeDestinationPort
    Optional. Drops records whose dst_port matches any of these values; several values are
    OR-combined. Never drops a record that has no dst_port field.

.PARAMETER Protocol
    Optional. Matches the wire field protocol exactly. Several values are OR-combined; matched
    on the raw record text before it is decoded. The values on the wire are not consistent
    across protocols - some records carry a name (TCP, UDP), others a number (for example 2).
    This parameter compares whatever the appliance actually sent; it does not translate between
    the two forms, so -Protocol ICMP finds nothing if the appliance logged that record's
    protocol as a number instead. Inspect a few records with -AsJson first if the value used by
    a given protocol is not already known.

.PARAMETER ExcludeProtocol
    Optional. Drops records whose protocol matches any of these values; several values are
    OR-combined. Never drops a record that has no protocol field. See -Protocol for why the
    value has to match exactly what is on the wire - a name or a number, never both.

.PARAMETER AnyIP
    Optional. The Any prefix means "either side": matches either side of a connection - a
    record where src_ip or dst_ip is one of these values is kept. Several values are
    OR-combined, and a match on either field is enough (also OR-combined); matched on the raw
    record text before it is decoded. Use -SourceIP or -DestinationIP instead to pin down one
    side only.

.PARAMETER ExcludeAnyIP
    Optional. Drops records where src_ip or dst_ip matches any of these values; several values
    are OR-combined, and a match on either field is enough. Never drops a record that has
    neither field.

.PARAMETER AnyPort
    Optional. The Any prefix means "either side": matches either side of a connection - a
    record where src_port or dst_port is one of these values is kept. Several values are
    OR-combined, and a match on either field is enough (also OR-combined); matched on the raw
    record text before it is decoded. Use -SourcePort or -DestinationPort instead to pin down
    one side only.

    Named -AnyPort, not -Port, because -Port is already this cmdlet's connection parameter (the
    TCP port of the management API).

.PARAMETER ExcludeAnyPort
    Optional. Drops records where src_port or dst_port matches any of these values; several
    values are OR-combined, and a match on either field is enough. Never drops a record that has
    neither field.

.PARAMETER MessageLike
    Optional. Returns only records whose wire field message contains one of these values
    anywhere - a substring match, not a wildcard pattern. Several values are OR-combined (a
    record matches if it contains any one of them); matched on the raw record text before it
    is decoded, like every other filter parameter listed above.

.PARAMETER ExcludeMessageLike
    Optional. Drops records whose message contains any of these values anywhere - a substring
    match. Several values are OR-combined. Never drops a record that has no message field.

.PARAMETER Text
    Optional. Returns only records where at least one field's value contains one of these values
    anywhere - a substring match, not a wildcard pattern. Unlike every filter above, this is not
    tied to one wire field: every value the record carries is checked, and a match on any one of
    them is enough. Only field values are searched, never field names, so -Text 'port' does not
    match a record purely because it has a field called dst_port - it only matches when 'port'
    actually appears inside some field's value. Several values are OR-combined (a record matches
    if it contains any one of them); matched on the raw record text before it is decoded, like
    every other filter parameter listed above.

.PARAMETER ExcludeText
    Optional. Drops records where at least one field's value contains any of these values
    anywhere - a substring match, checked the same way -Text checks every field's value and
    never a field name. Several values are OR-combined. Never drops a record where the text
    appears in no field at all.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the web admin console login. If omitted, the value from the
    current connection is used.

.PARAMETER Password
    Optional. Password for the web admin console login, as a SecureString. If omitted, the
    value from the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AcceptLoginDisclaimer
    Optional. Confirms a login disclaimer configured on the appliance, on behalf of the
    account logging in. Without this switch, this cmdlet fails on an appliance that shows a
    login disclaimer, with an error describing the disclaimer.

.PARAMETER List
    Optional. Shows the default one-field-per-line list view instead of the default table view.
    Both use the same per-category columns, and neither removes any field from the returned
    object itself - Select-Object or Format-Table -Property * still show everything regardless
    of which default view was picked. Prefer -List for wide categories, such as Firewall or
    SSL/TLS inspection, in a narrow console window, where the table view wraps or truncates.

.PARAMETER AsJson
    Optional. Returns each record exactly as the web admin console decoded it, without the
    added Datetime property, and without the fields the console's own JSON happens not to have
    sent for that record type. No default view is applied to this output.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per log record, with only the
    fields that record actually carries - an Event record and a Firewall record carry
    different fields. The console's own 'datetime' field is additionally parsed and exposed as
    Datetime ([datetime]); PowerShell property names are case-insensitive, so this replaces
    rather than duplicates the original field. Records are displayed as a table matching their
    log category, chosen from -Category, or a single-valued -LogType, or a generic table when
    neither identifies one; -List shows the same fields one per line instead. Returns an empty
    array, never $null, when nothing matches. Returns the unmodified decoded record when
    -AsJson is used. With -Follow, records are written to the pipeline one at a time as they
    are found, in chronological order, and the cmdlet does not return until the caller stops
    it.

.EXAMPLE
    Get-SfosLog -MaxRecords 20

    Reads the 20 most recent log records of every type.

.EXAMPLE
    Get-SfosLog -Category firewall -MaxRecords 50

    Reads 50 records the 'firewall' category matches, widening the request as needed to find
    them.

.EXAMPLE
    Get-SfosLog -Since (Get-Date).AddHours(-1)

    Reads the 200 most recent records from the last hour, widening the request as needed to
    find that many.

.EXAMPLE
    Get-SfosLog -Category firewall -Follow -PollIntervalSeconds 15

    Shows the current firewall-category backlog, then keeps streaming newly arriving firewall
    records every 15 seconds until stopped (Ctrl+C).

.EXAMPLE
    Get-SfosLog -All | Where-Object { $_.Datetime -lt (Get-Date).AddMonths(-3) } | Select-Object -First 1

    Reads everything the appliance's log retention holds and finds the oldest record older
    than three months.

.EXAMPLE
    Get-SfosLog -SourceIP '192.0.2.10' -Status 'Deny' -MaxRecords 50

    Reads 50 records whose src_ip is exactly 192.0.2.10 and whose status is Deny, matched on the
    raw record text before it is decoded - much faster than the same filter applied afterwards
    with Where-Object, because records that cannot match are never decoded at all.

.EXAMPLE
    Get-SfosLog -Category firewall -MaxRecords 10

    Shows the 10 most recent firewall-category records in this module's default firewall table
    (Datetime, log_component, log_subtype, in_interface, src_ip, src_port, out_interface, dst_ip,
    dst_port).

.EXAMPLE
    Get-SfosLog -Category firewall -MaxRecords 10 -List

    Shows the same 10 records and the same columns as the previous example, one field per line
    instead of a table.

.EXAMPLE
    Get-SfosLog -Category firewall -ExcludeSourceIP '192.0.2.10' -MaxRecords 50

    Reads 50 firewall-category records, dropping the ones whose src_ip is 192.0.2.10. A record
    with no src_ip field is kept.

.EXAMPLE
    Get-SfosLog -AnyIP '192.0.2.10' -MaxRecords 50

    Reads 50 records where 192.0.2.10 appears as either the source or the destination address.

.EXAMPLE
    Get-SfosLog -AnyIP '192.0.2.10' -DestinationPort '443' -MaxRecords 50

    Reads 50 records involving 192.0.2.10 on either side of the connection, further narrowed to
    those whose destination port is 443.

.EXAMPLE
    Get-SfosLog -AnyPort '3389' -ExcludeSourceIP '192.0.2.10' -MaxRecords 50

    Reads 50 records where port 3389 appears as either the source or the destination port,
    dropping the ones whose source address is 192.0.2.10.

.EXAMPLE
    Get-SfosLog -Protocol 'TCP' -MaxRecords 50

    Reads 50 records whose protocol field is exactly 'TCP', matched on the raw record text
    before it is decoded.

.EXAMPLE
    Get-SfosLog -Text '192.0.2.10' -MaxRecords 50

    Reads 50 records where '192.0.2.10' appears in the value of any field - src_ip, dst_ip, or
    any other field that happens to carry it - not only the fields -SourceIP/-DestinationIP/
    -AnyIP inspect specifically.

.NOTES
    Reading the Log Viewer is not part of the documented XML API. It uses the web admin
    console the way a browser does and can change with a firmware update.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosLogCategory
#>
function Get-SfosLog {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [ValidateSet('all', 'malware', 'heartbeat', 'sandbox', 'admin', 'ssltls', 'ips',
            'applicationfilter', 'sdwan', 'webcontentpolicy', 'system', 'firewall', 'vpn',
            'atp', 'webfilter', 'waf', 'email', 'authentication')]
        [string]$Category = 'all',

        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxRecords = 200,

        [switch]$All,

        [datetime]$Since,

        [switch]$Follow,

        [ValidateRange(5, 3600)]
        [int]$PollIntervalSeconds = 30,

        [string[]]$LogType,
        [string[]]$ExcludeLogType,
        [string[]]$LogComponent,
        [string[]]$ExcludeLogComponent,
        [string[]]$LogSubtype,
        [string[]]$ExcludeLogSubtype,
        [string[]]$Status,
        [string[]]$ExcludeStatus,
        [string[]]$User,
        [string[]]$ExcludeUser,
        [string[]]$SourceIP,
        [string[]]$ExcludeSourceIP,
        [string[]]$DestinationIP,
        [string[]]$ExcludeDestinationIP,
        [string[]]$SourcePort,
        [string[]]$ExcludeSourcePort,
        [string[]]$DestinationPort,
        [string[]]$ExcludeDestinationPort,

        [string[]]$Protocol,
        [string[]]$ExcludeProtocol,

        [string[]]$AnyIP,
        [string[]]$ExcludeAnyIP,

        # Named -AnyPort, not -Port, because -Port is already this function's connection
        # parameter (the TCP management port).
        [string[]]$AnyPort,
        [string[]]$ExcludeAnyPort,

        [string[]]$MessageLike,
        [string[]]$ExcludeMessageLike,

        [string[]]$Text,
        [string[]]$ExcludeText,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,
        [switch]$AcceptLoginDisclaimer,

        # Output parameters
        [switch]$List,
        [switch]$AsJson
    )

    if ($PSBoundParameters.ContainsKey('All') -and $PSBoundParameters.ContainsKey('MaxRecords')) {
        throw 'Get-SfosLog: -All and -MaxRecords cannot be combined - -All already fetches everything the appliance''s log retention holds, in one request.'
    }
    if ($All -and $Follow) {
        throw 'Get-SfosLog: -All and -Follow cannot be combined - -All is a single bounded read, -Follow streams indefinitely.'
    }

    # Decides which default view (table or, with -List, list) this call's output is tagged
    # with - see Get-SfosLogViewTypeSuffix and this function's own .DESCRIPTION for the
    # selection rule. Not used at all under -AsJson, which returns records exactly as decoded.
    $viewTypeSuffix = Get-SfosLogViewTypeSuffix -BoundParameters $PSBoundParameters -Category $Category
    $viewTypeName = if ($viewTypeSuffix) { "Sfos.Log.$viewTypeSuffix" } else { 'Sfos.Log' }
    if ($List) { $viewTypeName = "$viewTypeName.List" }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $console = Connect-SfosWebAdmin -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck -AcceptLoginDisclaimer:$AcceptLoginDisclaimer

    $hasSince = $PSBoundParameters.ContainsKey('Since')

    # Splatted, and -Since only added when it was actually bound: an unbound [datetime]
    # parameter in this function is $null, and Select-SfosLogViewerRecordPair's own
    # [datetime]$Since parameter throws on argument binding if handed $null directly.
    $filterParams = @{ Category = $Category; HasSince = $hasSince }
    if ($hasSince) { $filterParams['Since'] = $Since }

    # The built-in field filters (-LogType, -SourceIP, -MessageLike, ...) are applied inside
    # Get-SfosLogViewerRecordPage, on the raw record text, before anything is decoded - see
    # that function and this module's own findings file for why that order is the entire point.
    # Wrapped in @() deliberately: Get-SfosLogViewerFieldFilter emitting zero objects (no field
    # filter was bound) would otherwise unwrap this assignment to $null instead of an empty
    # array, and -FieldFilter below rejects an explicit $null argument.
    $fieldFilter = @(Get-SfosLogViewerFieldFilter -BoundParameters $PSBoundParameters)

    # Get-SfosLogRecordSet does the fetch/widen/sort/truncate work - shared with Export-SfosLog so
    # the two cannot drift apart. See its own header and this module's own findings file for why
    # depth is reached with one larger -Take rather than offset paging, and why attempts
    # accumulate instead of replacing each other; losing an already-found match this way is what
    # made -MessageLike (and every other built-in field filter) intermittently report "found only
    # 0" for a record known to be on the appliance.
    $recordSetParams = @{
        LogViewerConsole = $console
        Category         = $Category
        HasSince         = $hasSince
        FieldFilter      = $fieldFilter
    }
    if ($hasSince) { $recordSetParams['Since'] = $Since }
    if ($All) { $recordSetParams['All'] = $true } else { $recordSetParams['MaxRecords'] = $MaxRecords }

    $recordSet = Get-SfosLogRecordSet @recordSetParams
    $pairs = $recordSet.Pairs
    $fetchedCount = $recordSet.FetchedCount

    if ($All) {
        # FetchedCount, not Pairs.Count, decides the truncation warning: Pairs is narrower than
        # what the appliance actually returned whenever a field filter removes anything, and
        # the warning is about the appliance's own ceiling, unrelated to filtering.
        if ($recordSet.Truncated) {
            Write-Warning "Get-SfosLog -All received $fetchedCount record(s), the appliance's own ceiling for a single request. The log may hold more than that, so this result can be truncated."
        }
    }
    elseif ($pairs.Count -lt $MaxRecords) {
        Write-Warning "Get-SfosLog found only $($pairs.Count) of the requested $MaxRecords record(s). The log has nothing more to give, or -Category/-Since is too narrow."
    }

    if (-not $Follow) {
        if ($AsJson) {
            return @($pairs | ForEach-Object { $_.Decoded })
        }

        $output = [System.Collections.Generic.List[object]]::new()
        foreach ($pair in $pairs) {
            $formatted = Format-SfosLogViewerRecord -Record $pair.Decoded
            $formatted.PSObject.TypeNames.Insert(0, $viewTypeName)
            $output.Add($formatted)
        }

        return $output.ToArray()
    }

    # -Follow: stream the current backlog chronologically (oldest first), then keep polling for
    # only what is newer than the last record already shown. There is no push channel for these
    # records - even the web console's own log viewer only polls, on a fixed interval - so
    # -PollIntervalSeconds is the only knob for how quickly a new record surfaces here.
    $ordered = @($pairs)
    [array]::Reverse($ordered)

    # The high-water mark is taken BEFORE anything is formatted. Format-SfosLogViewerRecord adds
    # a 'Datetime' member, and because PowerShell matches property names case-insensitively that
    # replaces the record's own 'datetime' string with a [datetime] - after which the fixed-format
    # parse in ConvertTo-SfosLogInstant no longer matches and the anchor comes out empty. An empty
    # anchor makes the first poll treat its whole page as new, which is exactly the backwards
    # replay this ordering prevents.
    $lastInstant = $null
    $lastInstantRawCounts = @{}
    if ($ordered.Count -gt 0) {
        $lastInstant = ConvertTo-SfosLogInstant -Record $ordered[-1].Decoded
        $sameGroup = @($ordered | Where-Object { (ConvertTo-SfosLogInstant -Record $_.Decoded) -eq $lastInstant })
        foreach ($pair in $sameGroup) {
            $lastInstantRawCounts[$pair.Raw] = [int]$lastInstantRawCounts[$pair.Raw] + 1
        }
    }

    foreach ($pair in $ordered) {
        $formatted = Format-SfosLogViewerRecord -Record $pair.Decoded -AsJson:$AsJson
        if (-not $AsJson) { $formatted.PSObject.TypeNames.Insert(0, $viewTypeName) }
        $formatted
    }

    Write-Verbose ("Get-SfosLog -Follow: initial pass fetched {0} record(s), output {1}, newest shown {2}." -f `
            $fetchedCount, $ordered.Count, $(if ($null -ne $lastInstant) { $lastInstant.ToString('yyyy-MM-dd HH:mm:sszzz') } else { 'none' }))

    while ($true) {
        Start-Sleep -Seconds $PollIntervalSeconds

        # Splatted, and -Since only added when it was actually bound: an unbound [datetime]
        # parameter in this function is $null, not DateTime.MinValue, and Invoke-
        # SfosLogViewerFollowPoll's own [datetime]$Since parameter throws on argument binding
        # if handed $null directly.
        $pollParams = @{
            LogViewerConsole     = $console
            Category             = $Category
            HasSince             = $hasSince
            LastInstant          = $lastInstant
            LastInstantRawCounts = $lastInstantRawCounts
            FieldFilter          = $fieldFilter
        }
        if ($hasSince) { $pollParams['Since'] = $Since }

        try {
            $poll = Invoke-SfosLogViewerFollowPoll @pollParams
        }
        catch {
            if ($_.Exception.Message -notmatch 'received the login page instead of data') {
                throw
            }
            # The console session was discarded by the appliance between polls - log in once
            # more and repeat this exact pass. A second failure is not retried again; it
            # surfaces as the same error Invoke-SfosWebAdminRequest (SophosFirewall.Core)
            # already throws.
            $console = Connect-SfosWebAdmin -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck -AcceptLoginDisclaimer:$AcceptLoginDisclaimer
            $pollParams['LogViewerConsole'] = $console
            $poll = Invoke-SfosLogViewerFollowPoll @pollParams
        }

        foreach ($pair in $poll.NewPairsOrdered) {
            $formatted = Format-SfosLogViewerRecord -Record $pair.Decoded -AsJson:$AsJson
            if (-not $AsJson) { $formatted.PSObject.TypeNames.Insert(0, $viewTypeName) }
            $formatted
        }

        if (@($poll.NewPairsOrdered).Count -gt 0) {
            $lastInstant = $poll.LastInstant
            $lastInstantRawCounts = $poll.LastInstantRawCounts
        }

        if ($poll.GapNotBridged) {
            Write-Warning "Get-SfosLog -Follow could not bridge the gap since the last record shown after three attempts widening the polling window. Records may have been skipped; lower -PollIntervalSeconds (currently $PollIntervalSeconds seconds) so each poll has fewer new records to catch up on."
        }

        Write-Verbose ("Get-SfosLog -Follow: poll fetched {0} record(s) across {1} attempt(s), output {2}." -f $poll.FetchedCount, $poll.AttemptsUsed, @($poll.NewPairsOrdered).Count)
    }
}

<#
.SYNOPSIS
    Captures log records from a Sophos Firewall's web admin console log viewer into a file.

.DESCRIPTION
    Fetches log records the same way Get-SfosLog does - the same category pre-filter, the same
    client-side -Since cutoff, and the same built-in field filters matched on the raw record text
    before decoding - and writes the exact raw text of every selected record to a file, instead of
    returning them to the pipeline. Once captured, the file can be read repeatedly with
    Import-SfosLog, applying different field filters each time, without contacting the appliance
    again: useful when the log viewer's own retention window might rotate a record out before a
    second question about it occurs, or when the appliance should not be queried again for every
    follow-up filter. Nothing on the firewall is changed.

    The file also records when the capture was taken (the newest captured record's own timestamp,
    on the appliance's own clock - this cmdlet has no other way to ask the appliance for its
    current time, so the field is left out entirely when nothing was captured, rather than
    substituted with the exporting machine's own clock), which firewall it came from, which
    category was requested and which field filters and -Since cutoff were already applied during
    the capture. Import-SfosLog reads that record back and warns about it, so a filtered capture
    is never mistaken for a complete one.

.PARAMETER Path
    Required. Path of the file to write. Refused without -Force if a file already exists there.

.PARAMETER Category
    Optional. One of the log viewer's own category keys. Default 'all', which captures every log
    type. Evaluated client-side; see Get-SfosLogCategory for what each key matches. See Get-SfosLog
    for the full comparison between -Category and -LogType.

.PARAMETER MaxRecords
    Optional, default 200. The number of records captured after -Category and -Since have been
    applied, not the number fetched from the appliance. Reached the same way Get-SfosLog reaches
    it: a single request with a larger limit, widened up to five times if too few records survive
    filtering, never by paging with an offset. If fewer than -MaxRecords records could be found,
    the cmdlet captures what it found and warns rather than silently writing fewer than asked for.
    Cannot be combined with -All.

.PARAMETER All
    Optional. Captures everything the appliance's log retention holds, in a single request with a
    limit of 50000, the appliance's own ceiling for a single request. If the response comes back at
    exactly 50000 records, the log may hold more and the cmdlet warns that the capture can be
    truncated. -Category and -Since still apply. Cannot be combined with -MaxRecords.

.PARAMETER Since
    Optional. Only captures records at or after this point in time. See Get-SfosLog for how a
    plain, zone-less value is read on the firewall's own clock.

.PARAMETER LogType
    Optional. Matches the wire field log_type exactly. See Get-SfosLog for the full description of
    this and every other field filter parameter below - they behave identically here.

.PARAMETER ExcludeLogType
    Optional. Drops records whose log_type matches any of these values.

.PARAMETER LogComponent
    Optional. Matches the wire field log_component exactly.

.PARAMETER ExcludeLogComponent
    Optional. Drops records whose log_component matches any of these values.

.PARAMETER LogSubtype
    Optional. Matches the wire field log_subtype exactly.

.PARAMETER ExcludeLogSubtype
    Optional. Drops records whose log_subtype matches any of these values.

.PARAMETER Status
    Optional. Matches the wire field status exactly.

.PARAMETER ExcludeStatus
    Optional. Drops records whose status matches any of these values.

.PARAMETER User
    Optional. Matches the wire field user exactly.

.PARAMETER ExcludeUser
    Optional. Drops records whose user matches any of these values.

.PARAMETER SourceIP
    Optional. Matches the wire field src_ip exactly.

.PARAMETER ExcludeSourceIP
    Optional. Drops records whose src_ip matches any of these values.

.PARAMETER DestinationIP
    Optional. Matches the wire field dst_ip exactly.

.PARAMETER ExcludeDestinationIP
    Optional. Drops records whose dst_ip matches any of these values.

.PARAMETER SourcePort
    Optional. Matches the wire field src_port exactly.

.PARAMETER ExcludeSourcePort
    Optional. Drops records whose src_port matches any of these values.

.PARAMETER DestinationPort
    Optional. Matches the wire field dst_port exactly.

.PARAMETER ExcludeDestinationPort
    Optional. Drops records whose dst_port matches any of these values.

.PARAMETER Protocol
    Optional. Matches the wire field protocol exactly. The values on the wire are not
    consistent across protocols - some records carry a name (TCP, UDP), others a number. This
    parameter compares whatever the appliance actually sent, without translating between the
    two forms; see Get-SfosLog for the full explanation.

.PARAMETER ExcludeProtocol
    Optional. Drops records whose protocol matches any of these values.

.PARAMETER AnyIP
    Optional. The Any prefix means "either side": matches either side of a connection - src_ip
    or dst_ip.

.PARAMETER ExcludeAnyIP
    Optional. Drops records where src_ip or dst_ip matches any of these values.

.PARAMETER AnyPort
    Optional. The Any prefix means "either side": matches either side of a connection - src_port
    or dst_port.

.PARAMETER ExcludeAnyPort
    Optional. Drops records where src_port or dst_port matches any of these values.

.PARAMETER MessageLike
    Optional. Captures only records whose wire field message contains one of these values
    anywhere - a substring match.

.PARAMETER ExcludeMessageLike
    Optional. Drops records whose message contains any of these values anywhere.

.PARAMETER Text
    Optional. Captures only records where at least one field's value contains one of these
    values anywhere - a substring match over every field's value, never over a field name; see
    Get-SfosLog for the full explanation.

.PARAMETER ExcludeText
    Optional. Drops records where at least one field's value contains any of these values
    anywhere.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the web admin console login. If omitted, the value from the current
    connection is used.

.PARAMETER Password
    Optional. Password for the web admin console login, as a SecureString. If omitted, the value
    from the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.PARAMETER AcceptLoginDisclaimer
    Optional. Confirms a login disclaimer configured on the appliance, on behalf of the account
    logging in. Without this switch, this cmdlet fails on an appliance that shows a login
    disclaimer, with an error describing the disclaimer.

.PARAMETER Force
    Optional. Overwrites -Path if a file already exists there. Without this switch, an existing
    file is left untouched and the cmdlet throws instead.

.PARAMETER PassThru
    Optional. Returns the written file as a System.IO.FileInfo. Without this switch, the cmdlet
    returns nothing.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None by default. System.IO.FileInfo when -PassThru is used.

.EXAMPLE
    Export-SfosLog -Category firewall -MaxRecords 5000 -Path 'C:\Captures\firewall.sfoslog'

    Captures 5000 firewall-category records into a file for later, repeated filtering with
    Import-SfosLog.

.EXAMPLE
    Export-SfosLog -Category firewall -MaxRecords 5000 -Path 'C:\Captures\firewall.sfoslog' -WhatIf

    Reads the records from the firewall's log viewer as usual, but shows what would be written
    instead of actually writing the file.

.EXAMPLE
    Export-SfosLog -All -Path 'C:\Captures\everything.sfoslog' -Force

    Captures everything the appliance's log retention holds, overwriting a previous capture at the
    same path.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Import-SfosLog

.LINK
    Get-SfosLog
#>
function Export-SfosLog {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet('all', 'malware', 'heartbeat', 'sandbox', 'admin', 'ssltls', 'ips',
            'applicationfilter', 'sdwan', 'webcontentpolicy', 'system', 'firewall', 'vpn',
            'atp', 'webfilter', 'waf', 'email', 'authentication')]
        [string]$Category = 'all',

        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxRecords = 200,

        [switch]$All,

        [datetime]$Since,

        [string[]]$LogType,
        [string[]]$ExcludeLogType,
        [string[]]$LogComponent,
        [string[]]$ExcludeLogComponent,
        [string[]]$LogSubtype,
        [string[]]$ExcludeLogSubtype,
        [string[]]$Status,
        [string[]]$ExcludeStatus,
        [string[]]$User,
        [string[]]$ExcludeUser,
        [string[]]$SourceIP,
        [string[]]$ExcludeSourceIP,
        [string[]]$DestinationIP,
        [string[]]$ExcludeDestinationIP,
        [string[]]$SourcePort,
        [string[]]$ExcludeSourcePort,
        [string[]]$DestinationPort,
        [string[]]$ExcludeDestinationPort,

        [string[]]$Protocol,
        [string[]]$ExcludeProtocol,

        [string[]]$AnyIP,
        [string[]]$ExcludeAnyIP,

        [string[]]$AnyPort,
        [string[]]$ExcludeAnyPort,

        [string[]]$MessageLike,
        [string[]]$ExcludeMessageLike,

        [string[]]$Text,
        [string[]]$ExcludeText,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,
        [switch]$AcceptLoginDisclaimer,

        [switch]$Force,
        [switch]$PassThru
    )

    if ($PSBoundParameters.ContainsKey('All') -and $PSBoundParameters.ContainsKey('MaxRecords')) {
        throw 'Export-SfosLog: -All and -MaxRecords cannot be combined - -All already fetches everything the appliance''s log retention holds, in one request.'
    }

    if (-not $Force -and (Test-Path -LiteralPath $Path)) {
        throw "Export-SfosLog: '$Path' already exists. Use -Force to overwrite it."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $console = Connect-SfosWebAdmin -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck -AcceptLoginDisclaimer:$AcceptLoginDisclaimer

    $hasSince = $PSBoundParameters.ContainsKey('Since')

    # The built-in field filters are applied inside Get-SfosLogRecordSet, on the raw record text,
    # before anything is decoded - see Get-SfosLogViewerRecordPage and this module's own findings
    # file for why that order is the entire point. Wrapped in @() deliberately: zero bound field
    # filters would otherwise unwrap this assignment to $null instead of an empty array.
    $fieldFilter = @(Get-SfosLogViewerFieldFilter -BoundParameters $PSBoundParameters)

    $recordSetParams = @{
        LogViewerConsole = $console
        Category         = $Category
        HasSince         = $hasSince
        FieldFilter      = $fieldFilter
    }
    if ($hasSince) { $recordSetParams['Since'] = $Since }
    if ($All) { $recordSetParams['All'] = $true } else { $recordSetParams['MaxRecords'] = $MaxRecords }

    $recordSet = Get-SfosLogRecordSet @recordSetParams
    $pairs = $recordSet.Pairs

    if ($All) {
        if ($recordSet.Truncated) {
            Write-Warning "Export-SfosLog -All received $($recordSet.FetchedCount) record(s), the appliance's own ceiling for a single request. The log may hold more than that, so this export can be truncated."
        }
    }
    elseif ($pairs.Count -lt $MaxRecords) {
        Write-Warning "Export-SfosLog found only $($pairs.Count) of the requested $MaxRecords record(s). The log has nothing more to give, or -Category/-Since is too narrow."
    }

    # ExportedAt is read off the newest captured record's own timestamp, on the appliance's own
    # clock - never the exporting machine's. There is no other way to ask the appliance for its
    # current time through this transport, so when nothing was captured this field is left out
    # entirely rather than substituted with a guess.
    $exportedAt = $null
    if ($pairs.Count -gt 0) {
        $newestInstant = ConvertTo-SfosLogInstant -Record $pairs[0].Decoded
        if ($null -ne $newestInstant) {
            $exportedAt = $newestInstant.ToString('o')
        }
    }

    # A human-readable record of exactly what was already applied during the capture - reusing
    # the same $fieldFilter objects the fetch itself used, not a second description built from
    # the bound parameter names, so this cannot drift from what was actually sent to the
    # appliance. Import-SfosLog surfaces this list in a warning so a filtered capture is never
    # mistaken for a complete one.
    $filterDescriptions = [System.Collections.Generic.List[string]]::new()
    # Scope - what was asked for - is recorded on its own, not as a filter. Every capture has a
    # category, so counting it as a filter would make the "already filtered" warning fire every
    # single time, and a warning that always fires is one nobody reads.
    foreach ($filter in $fieldFilter) {
        $fieldsText = if ($filter.AnyField) { 'any field' } else { $filter.WireFields -join '/' }
        $verb = if ($filter.Negate) { '!=' } elseif ($filter.Substring) { 'contains' } else { '=' }
        $filterDescriptions.Add("$fieldsText $verb $($filter.Values -join ',')")
    }

    $fileObject = [ordered]@{
        FormatVersion = 1
        Firewall      = $params.Firewall
        Port          = $params.Port
        Category      = $Category
        Since         = $(if ($hasSince) { $Since.ToString("o") } else { $null })
        RecordLimit   = $(if ($All) { "all" } else { $MaxRecords })
        ExportedAt    = $exportedAt
        RecordCount   = $pairs.Count
        Filters       = @($filterDescriptions.ToArray())
        Records       = @($pairs | ForEach-Object { $_.Raw })
    }

    if (-not $PSCmdlet.ShouldProcess($Path, "Export $($pairs.Count) Sophos Firewall log record(s) from $($params.Firewall)")) {
        return
    }

    $json = $fileObject | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $Path -Value $json -Encoding utf8

    if ($PassThru) {
        return Get-Item -LiteralPath $Path
    }
}

<#
.SYNOPSIS
    Reads log records back out of a file written by Export-SfosLog.

.DESCRIPTION
    Returns the log records captured by an earlier Export-SfosLog call, applying the same built-in
    field filters Get-SfosLog offers - matched with the very same helpers Get-SfosLog itself uses,
    so filtering a captured file never disagrees with filtering the appliance live. Does not
    contact any firewall; everything comes from -Path. This is the point of capturing a log once
    with Export-SfosLog and reading it back with this cmdlet as many times as needed, with a
    different field filter each time, instead of asking the appliance again for every question.

    -Category, -Since, -MaxRecords and -All are not parameters here: they already determined which
    records ended up in the file when Export-SfosLog ran, and cannot be widened afterwards without
    contacting the appliance again. If the file was captured with any of them narrowing the
    result, or with any field filter already applied at capture time, this cmdlet warns and names
    exactly what was already applied, so a filtered capture is never mistaken for a complete one.

    -Text, like on Get-SfosLog, searches only field values, never field names: a search term
    that happens to be part of a field's name (for example 'port' inside dst_port) does not by
    itself make every record in the file match.

.PARAMETER Path
    Required. Path of the file written by Export-SfosLog.

.PARAMETER LogType
    Optional. Matches the wire field log_type exactly. See Get-SfosLog for the full description of
    this and every other field filter parameter below - they behave identically here, applied to
    the records already stored in the file instead of a live fetch.

.PARAMETER ExcludeLogType
    Optional. Drops records whose log_type matches any of these values.

.PARAMETER LogComponent
    Optional. Matches the wire field log_component exactly.

.PARAMETER ExcludeLogComponent
    Optional. Drops records whose log_component matches any of these values.

.PARAMETER LogSubtype
    Optional. Matches the wire field log_subtype exactly.

.PARAMETER ExcludeLogSubtype
    Optional. Drops records whose log_subtype matches any of these values.

.PARAMETER Status
    Optional. Matches the wire field status exactly.

.PARAMETER ExcludeStatus
    Optional. Drops records whose status matches any of these values.

.PARAMETER User
    Optional. Matches the wire field user exactly.

.PARAMETER ExcludeUser
    Optional. Drops records whose user matches any of these values.

.PARAMETER SourceIP
    Optional. Matches the wire field src_ip exactly.

.PARAMETER ExcludeSourceIP
    Optional. Drops records whose src_ip matches any of these values.

.PARAMETER DestinationIP
    Optional. Matches the wire field dst_ip exactly.

.PARAMETER ExcludeDestinationIP
    Optional. Drops records whose dst_ip matches any of these values.

.PARAMETER SourcePort
    Optional. Matches the wire field src_port exactly.

.PARAMETER ExcludeSourcePort
    Optional. Drops records whose src_port matches any of these values.

.PARAMETER DestinationPort
    Optional. Matches the wire field dst_port exactly.

.PARAMETER ExcludeDestinationPort
    Optional. Drops records whose dst_port matches any of these values.

.PARAMETER Protocol
    Optional. Matches the wire field protocol exactly. The values on the wire are not
    consistent across protocols - some records carry a name (TCP, UDP), others a number. This
    parameter compares whatever was captured, without translating between the two forms; see
    Get-SfosLog for the full explanation.

.PARAMETER ExcludeProtocol
    Optional. Drops records whose protocol matches any of these values.

.PARAMETER AnyIP
    Optional. The Any prefix means "either side": matches either side of a connection - src_ip
    or dst_ip.

.PARAMETER ExcludeAnyIP
    Optional. Drops records where src_ip or dst_ip matches any of these values.

.PARAMETER AnyPort
    Optional. The Any prefix means "either side": matches either side of a connection - src_port
    or dst_port.

.PARAMETER ExcludeAnyPort
    Optional. Drops records where src_port or dst_port matches any of these values.

.PARAMETER MessageLike
    Optional. Returns only records whose wire field message contains one of these values
    anywhere - a substring match.

.PARAMETER ExcludeMessageLike
    Optional. Drops records whose message contains any of these values anywhere.

.PARAMETER Text
    Optional. Returns only records where at least one field's value contains one of these
    values anywhere - a substring match over every field's value, never over a field name; see
    Get-SfosLog for the full explanation.

.PARAMETER ExcludeText
    Optional. Drops records where at least one field's value contains any of these values
    anywhere.

.PARAMETER List
    Optional. Shows the default one-field-per-line list view instead of the default table view,
    the same as Get-SfosLog -List. The view is chosen from the category recorded in the file.

.PARAMETER AsJson
    Optional. Returns each record exactly as captured, without the added Datetime property, the
    same as Get-SfosLog -AsJson.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per log record, in the same shape
    Get-SfosLog returns for the same category. Returns an empty array, never $null, when nothing
    in the file matches.

.EXAMPLE
    Import-SfosLog -Path 'C:\Captures\firewall.sfoslog' -SourceIP '192.0.2.10'

    Reads the capture back, keeping only the records whose src_ip is 192.0.2.10 - without
    contacting the firewall again.

.EXAMPLE
    Import-SfosLog -Path 'C:\Captures\firewall.sfoslog' -ExcludeUser 'svc-backup' -List

    Reads the capture back, dropping records for one account, shown one field per line.

.EXAMPLE
    Import-SfosLog -Path 'C:\Captures\firewall.sfoslog' -Text '192.0.2.10'

    Reads the capture back, keeping only the records where '192.0.2.10' appears in the value of
    any field, without contacting the firewall again.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Export-SfosLog

.LINK
    Get-SfosLog
#>
function Import-SfosLog {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string[]]$LogType,
        [string[]]$ExcludeLogType,
        [string[]]$LogComponent,
        [string[]]$ExcludeLogComponent,
        [string[]]$LogSubtype,
        [string[]]$ExcludeLogSubtype,
        [string[]]$Status,
        [string[]]$ExcludeStatus,
        [string[]]$User,
        [string[]]$ExcludeUser,
        [string[]]$SourceIP,
        [string[]]$ExcludeSourceIP,
        [string[]]$DestinationIP,
        [string[]]$ExcludeDestinationIP,
        [string[]]$SourcePort,
        [string[]]$ExcludeSourcePort,
        [string[]]$DestinationPort,
        [string[]]$ExcludeDestinationPort,

        [string[]]$Protocol,
        [string[]]$ExcludeProtocol,

        [string[]]$AnyIP,
        [string[]]$ExcludeAnyIP,

        [string[]]$AnyPort,
        [string[]]$ExcludeAnyPort,

        [string[]]$MessageLike,
        [string[]]$ExcludeMessageLike,

        [string[]]$Text,
        [string[]]$ExcludeText,

        [switch]$List,
        [switch]$AsJson
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Import-SfosLog: '$Path' does not exist."
    }

    try {
        $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $fileObject = $content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Import-SfosLog: '$Path' could not be read as a Sophos Firewall log export: $($_.Exception.Message)"
    }

    if (-not $fileObject -or
        $fileObject.PSObject.Properties.Match('FormatVersion').Count -eq 0 -or
        $fileObject.PSObject.Properties.Match('Records').Count -eq 0) {
        throw "Import-SfosLog: '$Path' is not a log export written by Export-SfosLog - the expected FormatVersion/Records structure is missing."
    }

    $records = @($fileObject.Records)
    $recordedCategory = if ($fileObject.PSObject.Properties.Match('Category').Count -gt 0) { [string]$fileObject.Category } else { 'all' }
    $recordedFilters = @()
    if ($fileObject.PSObject.Properties.Match('Filters').Count -gt 0) {
        $recordedFilters = @($fileObject.Filters)
    }

    if ($recordedFilters.Count -gt 0) {
        Write-Warning "Import-SfosLog: '$Path' was recorded with filters already applied - $($recordedFilters -join '; '). It does not necessarily contain every record from that recording session."
    }

    # Same helper Get-SfosLog uses to turn its own bound parameters into a filter specification -
    # not a second comparison written for this cmdlet, so filtering a captured file cannot
    # disagree with filtering the appliance live.
    $fieldFilter = @(Get-SfosLogViewerFieldFilter -BoundParameters $PSBoundParameters)

    # Mirrors Get-SfosLogViewerRecordPage's own raw-text-first strategy: try the fast raw-text
    # match first, and only fall back to decoding and comparing on the parsed object - the same
    # fallback Get-SfosLog itself takes - when the raw match found nothing at all while the
    # filtered field's own key is nonetheless present in the file, a sign the raw-text formatting
    # assumption does not hold for this capture.
    $useDecodedMatch = $false
    if ($fieldFilter.Count -gt 0 -and $records.Count -gt 0) {
        $rawMatchFound = $false
        foreach ($raw in $records) {
            if ($raw -and (Test-SfosLogViewerRawFieldMatch -Raw ([string]$raw) -FieldFilter $fieldFilter)) {
                $rawMatchFound = $true
                break
            }
        }
        if (-not $rawMatchFound) {
            $sampleCount = [Math]::Min(20, $records.Count)
            $sample = @($records | Select-Object -First $sampleCount)
            $suspectField = $null
            foreach ($filter in $fieldFilter) {
                if ($filter.AnyField) {
                    foreach ($value in $filter.Values) {
                        if (@($sample | Where-Object { $_ -and [string]$_ -like "*$value*" }).Count -gt 0) {
                            $suspectField = 'Text'
                            break
                        }
                    }
                }
                else {
                    foreach ($wireField in $filter.WireFields) {
                        $token = '"' + $wireField + '"'
                        if (@($sample | Where-Object { $_ -and [string]$_ -like "*$token*" }).Count -gt 0) {
                            $suspectField = $wireField
                            break
                        }
                    }
                }
                if ($suspectField) { break }
            }
            if ($suspectField) {
                Write-Verbose "Import-SfosLog: the raw-text pre-filter on field '$suspectField' matched none of $($records.Count) record(s) in '$Path', even though that field is present in the sample. Falling back to decoding every record and comparing on the parsed object."
                $useDecodedMatch = $true
            }
        }
    }

    $viewBoundParams = @{ Category = $recordedCategory }
    if ($PSBoundParameters.ContainsKey('LogType')) { $viewBoundParams['LogType'] = $LogType }
    $viewTypeSuffix = Get-SfosLogViewTypeSuffix -BoundParameters $viewBoundParams -Category $recordedCategory
    $viewTypeName = if ($viewTypeSuffix) { "Sfos.Log.$viewTypeSuffix" } else { 'Sfos.Log' }
    if ($List) { $viewTypeName = "$viewTypeName.List" }

    $output = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in $records) {
        if (-not $raw -or [string]$raw -eq '') { continue }
        $rawText = [string]$raw

        if ($fieldFilter.Count -gt 0 -and -not $useDecodedMatch -and -not (Test-SfosLogViewerRawFieldMatch -Raw $rawText -FieldFilter $fieldFilter)) {
            continue
        }

        $pair = ConvertTo-SfosLogViewerRecordPair -Raw $rawText
        if (-not $pair) { continue }

        if ($fieldFilter.Count -gt 0 -and $useDecodedMatch -and -not (Test-SfosLogViewerDecodedFieldMatch -Record $pair.Decoded -FieldFilter $fieldFilter)) {
            continue
        }

        if ($AsJson) {
            $output.Add($pair.Decoded)
            continue
        }

        $formatted = Format-SfosLogViewerRecord -Record $pair.Decoded
        $formatted.PSObject.TypeNames.Insert(0, $viewTypeName)
        $output.Add($formatted)
    }

    return $output.ToArray()
}

#endregion

#region DeviceConsole

# The device console is a third access path alongside the XML API and the web admin console: a
# menu-driven, keystroke-based interface reached the same way an administrator would reach it
# from a physical or serial console. Per repository rule S:1, the transport - login, sending
# keystrokes, collecting output - is implemented once in SophosFirewall.Core (Connect-
# SfosCliConsole, Send-SfosCliInput, Receive-SfosCliOutput, Disconnect-SfosCliConsole). This
# module only adds the command-and-response handling and the interactive pass-through on top of
# it, never calling Invoke-WebRequest directly.

<#
.SYNOPSIS
    Runs one or more commands on a Sophos Firewall's device console and returns their output.

.DESCRIPTION
    Sends each command to the device console prompt and returns the text the console printed in
    response. Opens a device console session with Connect-SfosCliConsole when -CliSession is not
    supplied, and closes that session again once every command has run or as soon as a command
    fails; passing an existing -CliSession instead keeps that session open for further use once
    this cmdlet returns. Only the admin and support accounts can open the device console, and the
    console asks for that account's password again as a separate step, even though the caller
    already authenticated to reach it.

    The device console runs every command immediately, without a confirmation prompt of its own,
    and its main menu carries an entry that shuts down or restarts the appliance. Review a
    command before sending it - this cmdlet's own -WhatIf/-Confirm only guards the sending of the
    command, not what the device console does with it once received.

.PARAMETER Command
    Required, accepts pipeline input. One or more command lines to send to the device console,
    each sent on its own and followed by Enter. Every command produces one output string.

.PARAMETER CliSession
    Optional. An existing device console session, as returned by Connect-SfosCliConsole. When
    supplied, that session is reused and left open when this cmdlet returns; when omitted, this
    cmdlet opens its own session and closes it again once it is done, including when a command
    fails.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used. Ignored when -CliSession is supplied.

.PARAMETER Port
    Optional. TCP port used to reach the firewall, usually 4444. If omitted, the value from the
    current connection is used. Ignored when -CliSession is supplied.

.PARAMETER Username
    Optional. Account used to open the device console. Only the admin and support accounts can
    open it; the console then asks for that account's password again as a separate step. If
    omitted, the value from the current connection is used. Ignored when -CliSession is supplied.

.PARAMETER Password
    Optional. Password for the account above, as a SecureString - supplied once here and used
    again by the console's own password prompt. If omitted, the value from the current
    connection is used. Ignored when -CliSession is supplied.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. Ignored when -CliSession is
    supplied.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Used to resolve the connection parameters above
    when they are not supplied directly. Ignored when -CliSession is supplied.

.PARAMETER AcceptLoginDisclaimer
    Optional. Confirms a login disclaimer configured on the appliance, on behalf of the
    account logging in. Without this switch, opening a new console session on an appliance
    that shows a login disclaimer fails with an error describing the disclaimer. Ignored when
    -CliSession is supplied.

.PARAMETER SkipMenu
    Optional. Skips navigating from the device console's main menu to the console prompt before
    the first command is sent, on the assumption that -CliSession already sits at a prompt - for
    example because a previous call already navigated it. Without this switch, the cmdlet
    selects the Device Console entry from the main menu once, before sending any command.

.PARAMETER Prompt
    Optional, default 'console>\s*$'. Regular expression that recognises the end of the
    console's response to a command. Change this only if the console prompt in use differs from
    the default.

.PARAMETER TimeoutSeconds
    Optional, default 30. How long to wait for -Prompt to appear after sending a command, in
    seconds.

.INPUTS
    System.String. Command lines can be piped in.

.OUTPUTS
    System.String. One string per command, holding the console's response with the command's own
    echo and the following prompt line removed, and terminal escape sequences stripped.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Invoke-SfosCliCommand -Command 'show version' -Confirm:$false

    Runs one command on the device console using the current connection and returns its output.

.EXAMPLE
    Invoke-SfosCliCommand -Command 'show version' -WhatIf

    Shows which command would be sent, without actually sending it.

.EXAMPLE
    'show version', 'show system diagnostic' | Invoke-SfosCliCommand -Confirm:$false

    Runs two commands over a single device console session and returns one string per command.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>
function Invoke-SfosCliCommand {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$Command,

        [object]$CliSession,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,
        [switch]$AcceptLoginDisclaimer,

        [switch]$SkipMenu,
        [string]$Prompt = 'console>\s*$',
        [int]$TimeoutSeconds = 30
    )

    begin {
        $commands = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($item in $Command) {
            $commands.Add($item)
        }
    }

    end {
        $ownSession = -not $PSBoundParameters.ContainsKey('CliSession')
        $cliSession = $CliSession

        try {
            if ($ownSession) {
                $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
                $cliSession = Connect-SfosCliConsole -Firewall $params.Firewall -Port $params.Port `
                    -Username $params.Username -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck -AcceptLoginDisclaimer:$AcceptLoginDisclaimer
            }

            if (-not $SkipMenu) {
                # Selects menu entry 4, Device Console, and waits for its prompt - once per
                # call, regardless of how many commands are sent afterwards.
                Send-SfosCliInput -CliSession $cliSession -Text '4'
                Send-SfosCliInput -CliSession $cliSession -Key 'Enter'
                $null = Receive-SfosCliOutput -CliSession $cliSession -TimeoutSeconds $TimeoutSeconds -Until $Prompt
            }

            foreach ($cmd in $commands) {
                if (-not $PSCmdlet.ShouldProcess("CLI command '$cmd' on $($cliSession.BaseUri)", 'Invoke')) {
                    continue
                }

                Send-SfosCliInput -CliSession $cliSession -Text $cmd
                Send-SfosCliInput -CliSession $cliSession -Key 'Enter'
                $raw = Receive-SfosCliOutput -CliSession $cliSession -TimeoutSeconds $TimeoutSeconds -Until $Prompt

                # The captured text carries the console's own echo of the typed command as its
                # first line and the next prompt as its last line; neither belongs to the
                # command's actual output.
                $lines = @($raw -split "`r?`n")
                if ($lines.Count -gt 0) { $lines = @($lines[1..($lines.Count - 1)]) }
                if ($lines.Count -gt 0) { $lines = @($lines[0..($lines.Count - 2)]) }
                $cleaned = ($lines -join "`n") -replace '\x1B\[[0-9;]*[A-Za-z]', ''

                $cleaned
            }
        }
        finally {
            if ($ownSession -and $cliSession) {
                Disconnect-SfosCliConsole -CliSession $cliSession
            }
        }
    }
}

<#
.SYNOPSIS
    Opens an interactive keyboard session on a Sophos Firewall's device console.

.DESCRIPTION
    Hands the keyboard to the device console and passes every keystroke and console response
    through, the same way an administrator would work at a physical or serial console, until the
    caller ends the session with Ctrl+Q. Opens a device console session with Connect-
    SfosCliConsole when -CliSession is not supplied, and closes that session again once the
    interactive session ends; passing an existing -CliSession instead keeps that session open for
    further use once this cmdlet returns. Only the admin and support accounts can open the device
    console, and the console asks for that account's password again as a separate step, even
    though the caller already authenticated to reach it.

    The console runs every command immediately, without a confirmation prompt of its own, and its
    main menu carries an entry that shuts down or restarts the appliance - that entry is reachable
    from this interactive session exactly as it would be at a physical console.

    Requires an interactive host with keyboard input. Running this cmdlet from a non-interactive
    session throws instead of waiting indefinitely for a key press that will never arrive.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used. Ignored when -CliSession is supplied.

.PARAMETER Port
    Optional. TCP port used to reach the firewall, usually 4444. If omitted, the value from the
    current connection is used. Ignored when -CliSession is supplied.

.PARAMETER Username
    Optional. Account used to open the device console. Only the admin and support accounts can
    open it; the console then asks for that account's password again as a separate step. If
    omitted, the value from the current connection is used. Ignored when -CliSession is supplied.

.PARAMETER Password
    Optional. Password for the account above, as a SecureString - supplied once here and used
    again by the console's own password prompt. If omitted, the value from the current
    connection is used. Ignored when -CliSession is supplied.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. Ignored when -CliSession is
    supplied.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Used to resolve the connection parameters above
    when they are not supplied directly. Ignored when -CliSession is supplied.

.PARAMETER AcceptLoginDisclaimer
    Optional. Confirms a login disclaimer configured on the appliance, on behalf of the
    account logging in. Without this switch, opening a new console session on an appliance
    that shows a login disclaimer fails with an error describing the disclaimer. Ignored when
    -CliSession is supplied.

.PARAMETER CliSession
    Optional. An existing device console session, as returned by Connect-SfosCliConsole. When
    supplied, that session is reused and left open when this cmdlet returns; when omitted, this
    cmdlet opens its own session and closes it again once the interactive session ends.

.INPUTS
    None. This cmdlet reads the keyboard directly and does not accept pipeline input.

.OUTPUTS
    None. Console output is written directly to the host as it arrives; nothing is returned to
    the pipeline.

.EXAMPLE
    Enter-SfosCliConsole -Firewall '192.0.2.1' -Username 'admin' -Password (Read-Host -AsSecureString) -SkipCertificateCheck

    Opens the device console's main menu interactively. Navigate it with the keyboard as at a
    physical console, and press Ctrl+Q to end the session.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Invoke-SfosCliCommand
#>
function Enter-SfosCliConsole {
    # PSAvoidUsingWriteHost is suppressed on purpose: this cmdlet is an interactive keyboard
    # pass-through, not a pipeline producer. Console output has to reach the terminal
    # synchronously, in the exact bytes the device console sent, which Write-Output cannot do.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,
        [switch]$AcceptLoginDisclaimer,

        [object]$CliSession
    )

    try {
        $null = $Host.UI.RawUI.KeyAvailable
    }
    catch {
        throw "Enter-SfosCliConsole needs an interactive console with keyboard input. This host ('$($Host.Name)') does not provide one; run this cmdlet from a console host, not from a non-interactive session."
    }

    $ownSession = -not $PSBoundParameters.ContainsKey('CliSession')
    $cliSession = $CliSession
    $originalTreatControlCAsInput = [Console]::TreatControlCAsInput

    try {
        if ($ownSession) {
            $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
            $cliSession = Connect-SfosCliConsole -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck -AcceptLoginDisclaimer:$AcceptLoginDisclaimer
        }

        [Console]::Write($cliSession.Banner)

        # Ctrl+C would otherwise raise the console's CancelKeyPress event and terminate this
        # cmdlet outright instead of being read as a key; capturing it here lets it be forwarded
        # to the device console as a Break, and Ctrl+Q remains the only way out of this loop.
        [Console]::TreatControlCAsInput = $true

        while ($true) {
            if (-not [Console]::KeyAvailable) {
                Start-Sleep -Milliseconds 50
                continue
            }

            $key = [Console]::ReadKey($true)

            if ($key.Modifiers -band [ConsoleModifiers]::Control) {
                if ($key.Key -eq [ConsoleKey]::Q) {
                    break
                }
                if ($key.Key -eq [ConsoleKey]::C) {
                    $output = Send-SfosCliInput -CliSession $cliSession -Key 'Break'
                    if ($output) { [Console]::Write($output) }
                    continue
                }
            }

            $mappedKey = switch ($key.Key) {
                'Enter' { 'Enter' }
                'Backspace' { 'Backspace' }
                'Tab' { 'Tab' }
                'Delete' { 'Delete' }
                'Home' { 'Home' }
                'End' { 'End' }
                'LeftArrow' { 'LeftArrow' }
                'RightArrow' { 'RightArrow' }
                'UpArrow' { 'UpArrow' }
                'DownArrow' { 'DownArrow' }
                'Escape' { 'Escape' }
                default { $null }
            }

            if ($mappedKey) {
                $output = Send-SfosCliInput -CliSession $cliSession -Key $mappedKey
            }
            elseif ($key.KeyChar) {
                $output = Send-SfosCliInput -CliSession $cliSession -Text ([string]$key.KeyChar)
            }
            else {
                continue
            }

            if ($output) {
                [Console]::Write($output)
            }
        }
    }
    finally {
        [Console]::TreatControlCAsInput = $originalTreatControlCAsInput
        if ($ownSession -and $cliSession) {
            Disconnect-SfosCliConsole -CliSession $cliSession
        }
    }
}

#endregion
