#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.4.0' }

<#
.SYNOPSIS
    Manages remote support access and reads the web console's log viewer on a Sophos Firewall.

.DESCRIPTION
    Functions for the MONITOR & ANALYZE > Diagnostics area of the Sophos Firewall
    (SFOS 22.0): remote support access, and read-only access to the log records shown by the
    web admin console's log viewer. Support access lets Sophos support connect to the web
    admin console and the shell of the firewall for troubleshooting, without needing the
    administrator's own credentials, for a duration the administrator chooses. There is
    exactly one instance of that object per firewall. The log viewer functions read the same
    log records an administrator sees under Log Viewer in the web console; there is no
    equivalent read in the XML API.

    Total Functions: 14 (4 exported, 10 internal helpers) - see README.md for the full cmdlet
    table. The web console access path itself (login, CSRF, the console POST) now lives in
    SophosFirewall.Core as Connect-SfosWebAdmin and Invoke-SfosWebAdminRequest; this module only
    adds the log-viewer-specific request/response handling on top of it.

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

    Reads 50 firewall log records from the web console's log viewer.

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
    One entry per bound field-filter parameter on Get-SfosLog (LogType, LogComponent,
    LogSubtype, Status, User, SourceIP, DestinationIP, DestinationPort, MessageLike), each
    carrying the field's wire name, the value(s) to match, and whether the match is a substring
    (MessageLike only) or exact (every other field). Several values on one parameter are
    OR-combined when matched; several entries in the returned array are AND-combined - the same
    rule repository rule S:6 already applies to every other *Like filter in this project.

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
        @{ Param = 'LogType'; Wire = 'log_type' },
        @{ Param = 'LogComponent'; Wire = 'log_component' },
        @{ Param = 'LogSubtype'; Wire = 'log_subtype' },
        @{ Param = 'Status'; Wire = 'status' },
        @{ Param = 'User'; Wire = 'user' },
        @{ Param = 'SourceIP'; Wire = 'src_ip' },
        @{ Param = 'DestinationIP'; Wire = 'dst_ip' },
        @{ Param = 'DestinationPort'; Wire = 'dst_port' }
    )

    $filters = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $map) {
        if ($BoundParameters.ContainsKey($entry.Param)) {
            $filters.Add([PSCustomObject]@{
                    WireField = $entry.Wire
                    Values    = @($BoundParameters[$entry.Param])
                    Substring = $false
                })
        }
    }
    if ($BoundParameters.ContainsKey('MessageLike')) {
        $filters.Add([PSCustomObject]@{
                WireField = 'message'
                Values    = @($BoundParameters['MessageLike'])
                Substring = $true
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
    across fields); within one entry, any of its Values matching is enough (OR across values).

    The comparison is a regex, not a plain substring search, because the measured wire form
    puts a space after the colon ("log_type": "Firewall") and the match has to tolerate both
    that and the compact form without one. Every value passes through [regex]::Escape first, so
    a literal '.' in an IP address is matched literally rather than as a wildcard.

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
        $escapedField = [regex]::Escape($filter.WireField)
        $fieldMatched = $false

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

        if (-not $fieldMatched) {
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
    does not carry the field at all never matches it.

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
        if ($Record.PSObject.Properties.Match($filter.WireField).Count -eq 0) {
            return $false
        }
        $actual = [string]$Record.($filter.WireField)

        $fieldMatched = $false
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

        if (-not $fieldMatched) {
            return $false
        }
    }

    return $true
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

    if (@($FieldFilter).Count -eq 0 -or $rawRecords.Count -eq 0) {
        $pairs = @($rawRecords | ForEach-Object {
                [PSCustomObject]@{ Raw = $_; Decoded = ($_ | ConvertFrom-Json) }
            })
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
        $suspect = $FieldFilter | Where-Object {
            $token = '"' + $_.WireField + '"'
            @($sample | Where-Object { $_ -like "*$token*" }).Count -gt 0
        } | Select-Object -First 1

        if (-not $suspect) {
            return [PSCustomObject]@{ Pairs = @(); FetchedCount = $fetchedCount }
        }

        Write-Verbose "Get-SfosLog: the raw-text pre-filter on field '$($suspect.WireField)' matched none of $($rawRecords.Count) fetched record(s), even though that field is present in the sample. Falling back to decoding every record and comparing on the parsed object."

        $pairs = @($rawRecords | ForEach-Object {
                [PSCustomObject]@{ Raw = $_; Decoded = ($_ | ConvertFrom-Json) }
            } | Where-Object { Test-SfosLogViewerDecodedFieldMatch -Record $_.Decoded -FieldFilter $FieldFilter })
        return [PSCustomObject]@{ Pairs = $pairs; FetchedCount = $fetchedCount }
    }

    $pairs = @($matchingRaw | ForEach-Object {
            [PSCustomObject]@{ Raw = $_; Decoded = ($_ | ConvertFrom-Json) }
        })
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
    Reads the category catalog of the Sophos Firewall web console's log viewer.

.DESCRIPTION
    Returns the log viewer's own list of categories (mode 5002 of the console controller),
    each with the condition the console uses to decide which log records belong to it. This is
    the self-description that -Category on Get-SfosLog accepts; use it to see what a category
    key actually matches, or to confirm the set of keys is still current after a firmware
    update. This is not part of the XML API - see this module's own findings file for the measured
    access path. Opens its own web console session; the session and its CSRF token are not
    reused across calls.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the console login. If omitted, the value from the current
    connection is used.

.PARAMETER Password
    Optional. Password for the console login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.Management.Automation.PSCustomObject. One object per category, with the properties
    Name (the key accepted by Get-SfosLog -Category), Label (the raw, untranslated label the
    console stores for it) and Condition (the boolean expression the console evaluates against
    a record's fields, or $null for the 'all' category, which has none).

.EXAMPLE
    Get-SfosLogCategory

    Lists every category the log viewer knows, with the condition each one matches.

.EXAMPLE
    Get-SfosLogCategory | Where-Object Name -eq 'firewall' | Select-Object -ExpandProperty Condition

    Shows exactly which fields the 'firewall' category matches.

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
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $console = Connect-SfosWebAdmin -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

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
    Reads log records from the Sophos Firewall web console's log viewer.

.DESCRIPTION
    Returns the log records shown by the web admin console under Log Viewer - the same records
    an administrator sees there, not the XML API, which has no equivalent read for this data.
    See this module's own findings file for the measured access path and its limits.

    -Category is a pre-filter only: the console controller ignores it on the server, so it is
    evaluated here against every fetched record, the same way the console's own log viewer
    does (see Get-SfosLogCategory for the condition each category actually matches). -Since is
    likewise applied client-side.

    Depth is reached with ONE call carrying a large limit, never by paging with offset: measured
    against a live appliance, offset-based paging repeats the same page once it reaches roughly
    750 records back, silently, with no error and no empty result (see this module's own findings file).
    -MaxRecords therefore counts the records actually RETURNED, after -Category and -Since have
    been applied - not the raw records fetched. To reach that count, the cmdlet asks for
    -MaxRecords records first; if filtering leaves too few and the appliance still had at least
    that many to give, it asks again with four times the limit, up to five attempts and a limit
    of 50000 - the appliance's own observed ceiling for a single request (roughly half a year of
    records on the appliance this was measured against). If the appliance runs out, or the
    attempt/limit ceiling is reached, before enough matching records were found, the cmdlet warns
    with the number it did find rather than silently returning fewer than asked for.

    -LogType, -LogComponent, -LogSubtype, -Status, -User, -SourceIP, -DestinationIP,
    -DestinationPort and -MessageLike are built-in field filters. Unlike -Category and -Since,
    which are evaluated after every fetched record has already been decoded, these are matched
    directly on each record's raw JSON text before ConvertFrom-Json runs, so a record that
    cannot match one of them is never decoded at all - decoding is the expensive part of this
    cmdlet, measured at roughly 2.5 times the cost of everything else combined (see this
    module's own findings file). Several values on one of these parameters are OR-combined; different
    parameters, -Category included, are AND-combined, never accumulated into an OR. They only
    do exact or substring text matching on one field each; a range comparison such as a port
    range, or arithmetic across fields, is still a job for Where-Object after the cmdlet, same
    as it always was.

    By default, each record is displayed in a table sized to that record's own log category -
    the firewall category shows source/destination address and port columns, the web filter
    category shows category/url/bytes columns, and so on; a category this module has no table
    for, and every record shown without -Category or a single-valued -LogType to identify one,
    falls back to a generic table. Sixteen of the seventeen category views reproduce the column
    order and labels of the web admin console's own Log Viewer screen; the Firewall view is the
    one exception and keeps this module's own nine-column choice - see this module's own findings file.
    Wide categories (Firewall's nine columns, SSL/TLS inspection's fourteen) wrap or truncate in
    a narrow console window; -List or Select-Object show the same fields without that. -List
    switches to a one-field-per-line view of the same columns instead of a table; either way,
    every field the record actually carries is still on the object itself, so
    Select-Object/Format-Table -Property * still shows everything regardless of which default
    view was picked.

.PARAMETER Category
    Optional. One of the log viewer's own category keys. Default 'all', which returns every
    log type. Evaluated client-side; see Get-SfosLogCategory for what each key matches.

    A category is not the same thing as a log type, and the two are easy to confuse. -LogType
    matches one field of the record, exactly as the appliance wrote it: Firewall, Event,
    Content Filtering, Anti-Virus, IDP and so on. A category is a condition over several
    fields, defined by the web console itself - 'admin', for instance, is
    log_type=Event AND log_subtype=Admin.

    So they do not line up one to one. Four categories - admin, system, authentication and vpn
    - are all log_type=Event and are told apart only by further fields, which means -LogType
    Event returns all four at once. In the other direction, the applicationfilter category
    spans two log types. Get-SfosLogCategory returns each category's condition, which is the
    clearest place to see the mapping.

    Which to use: -LogType when you know the raw type - it filters before the records are
    decoded and is measurably faster. -Category when you want exactly the slice the web console
    shows. Both can be combined, and both can be combined with -LogSubtype and -LogComponent:
    -LogType Event -LogSubtype Admin is the fast way to what -Category admin selects.

.PARAMETER MaxRecords
    Optional. Number of records to return, counted after -Category and -Since have been
    applied. Default 200. Reaching this count can take more than one request to the appliance -
    see the description. Cannot be combined with -All.

.PARAMETER All
    Optional. Returns everything the appliance's log retention holds, in a single request with
    limit 50000 - the appliance's own observed ceiling (measured at roughly 24600 records, about
    half a year, taking about 5 seconds). That ceiling is the appliance's log retention, not a
    limit this module imposes; if the response comes back at exactly 50000 records, the log may
    hold more and the cmdlet warns that the result can be truncated. -Category and -Since still
    apply. Cannot be combined with -MaxRecords or -Follow.

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
    and -Since exactly as without -Follow), keeps the console session open and streams only the
    records that arrive afterwards, oldest first, until the caller stops the cmdlet - the
    equivalent of tail -f for this log viewer. There is no push channel for these records; even
    the web console's own log viewer only polls, on a fixed interval. -PollIntervalSeconds is
    therefore the only control over how quickly a new record surfaces here.

.PARAMETER PollIntervalSeconds
    Optional. Seconds to wait between polls while -Follow is running. Default 30, the same
    interval the web console's own log viewer polls on. Has no effect without -Follow.

.PARAMETER LogType
    Optional. Matches the wire field log_type exactly - the raw type the appliance wrote into
    the record: Firewall, Event, Content Filtering, Anti-Virus, IDP, ATP, SD-WAN, Sandbox,
    HeartBeat, SSL, WAF, Anti-Spam. Several values are OR-combined; combined with any other
    filter parameter, including -Category, the result is AND. Matched on the raw record text
    before it is decoded - see the description above.

    This is a different thing from -Category, which is the web console's grouping over several
    fields. One log type can hold several categories (Event covers admin, system,
    authentication and vpn) and one category can span several log types. See -Category for the
    full comparison.

.PARAMETER LogComponent
    Optional. Matches the wire field log_component exactly. Several values are OR-combined;
    matched on the raw record text before it is decoded.

.PARAMETER LogSubtype
    Optional. Matches the wire field log_subtype exactly. Several values are OR-combined;
    matched on the raw record text before it is decoded.

.PARAMETER Status
    Optional. Matches the wire field status exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded.

.PARAMETER User
    Optional. Matches the wire field user exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded.

.PARAMETER SourceIP
    Optional. Matches the wire field src_ip exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded.

.PARAMETER DestinationIP
    Optional. Matches the wire field dst_ip exactly. Several values are OR-combined; matched on
    the raw record text before it is decoded.

.PARAMETER DestinationPort
    Optional. Matches the wire field dst_port exactly. Several values are OR-combined; matched
    on the raw record text before it is decoded.

.PARAMETER MessageLike
    Optional. Returns only records whose wire field message contains this text anywhere - a
    substring match, not a wildcard pattern. Matched on the raw record text before it is
    decoded, like every other filter parameter listed above.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the console login. If omitted, the value from the current
    connection is used.

.PARAMETER Password
    Optional. Password for the console login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER List
    Optional. Shows the default one-field-per-line list view instead of the default table view.
    Both use the same per-category columns - see the description above - and neither one removes
    any field from the returned object itself. Prefer -List for the wider categories (Firewall,
    SSL/TLS inspection) in a narrow console window, where the table view wraps.

.PARAMETER AsJson
    Optional. Returns each record exactly as the console decoded it, without the added
    Datetime property, and without the fields the console's own JSON happens not to have sent
    for that record type. No default view is applied to this output.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per log record, with only the
    fields that record actually carries - an Event record and a Firewall record carry
    different fields. The console's own 'datetime' field is additionally parsed and exposed as
    Datetime ([datetime]); PowerShell property names are case-insensitive, so this replaces
    rather than duplicates the original field. Returns an empty array, never $null, when
    nothing matches. Returns the unmodified decoded record when -AsJson is used. With -Follow,
    records are written to the pipeline one at a time as they are found, in chronological
    order, and the cmdlet does not return until the caller stops it.

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

    Reads everything the appliance's log retention holds - typically a few tens of thousands of
    records, a handful of seconds - and finds the oldest record older than three months.

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
        [string[]]$LogComponent,
        [string[]]$LogSubtype,
        [string[]]$Status,
        [string[]]$User,
        [string[]]$SourceIP,
        [string[]]$DestinationIP,
        [string[]]$DestinationPort,
        [string]$MessageLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

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
        -SkipCertificateCheck:$params.SkipCertificateCheck

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

    # Depth is reached with ONE call carrying a large limit, never by paging with offset -
    # offset-based paging repeats the same page past roughly 750 records with no error and no
    # empty result to signal it (see this module's own findings file). 50000 is the appliance's own
    # observed ceiling for a single request; asking for more does not return more.
    $applianceLimitCeiling = 50000

    if ($All) {
        # FetchedCount, not Pairs.Count, decides the truncation warning: Pairs is narrower than
        # what the appliance actually returned whenever a field filter removes anything, and
        # the warning is about the appliance's own ceiling, unrelated to filtering.
        $page = Get-SfosLogViewerRecordPage -LogViewerConsole $console -Take $applianceLimitCeiling -FieldFilter $fieldFilter
        $rawPairs = @($page.Pairs)
        if ($page.FetchedCount -ge $applianceLimitCeiling) {
            Write-Warning "Get-SfosLog -All received $($page.FetchedCount) record(s), the appliance's own ceiling for a single request. The log may hold more than that, so this result can be truncated."
        }
        $pairs = @(Select-SfosLogViewerRecordPair -LogViewerConsole $console -Pairs $rawPairs @filterParams)
        $fetchedCount = $page.FetchedCount
    }
    else {
        $limit = [Math]::Min($MaxRecords, $applianceLimitCeiling)
        $maxAttempts = 5
        $attempt = 0
        $rawPairs = @()
        $rawFetchedCount = 0
        $pairs = @()

        while ($true) {
            $attempt++
            $page = Get-SfosLogViewerRecordPage -LogViewerConsole $console -Take $limit -FieldFilter $fieldFilter
            $rawPairs = @($page.Pairs)
            $rawFetchedCount = $page.FetchedCount
            # "Exhausted" (appliance had nothing more to give) has to be read off FetchedCount,
            # never off Pairs.Count - Pairs is deliberately smaller than $limit whenever a field
            # filter removes anything, which would otherwise make every filtered page look
            # exhausted after the very first request.
            $exhausted = $rawFetchedCount -lt $limit

            $pairs = @(Select-SfosLogViewerRecordPair -LogViewerConsole $console -Pairs $rawPairs @filterParams)

            if ($pairs.Count -ge $MaxRecords -or $exhausted -or $limit -ge $applianceLimitCeiling -or $attempt -ge $maxAttempts) {
                break
            }
            $limit = [Math]::Min($limit * 4, $applianceLimitCeiling)
        }

        $fetchedCount = $rawFetchedCount

        if ($pairs.Count -lt $MaxRecords) {
            Write-Warning "Get-SfosLog found only $($pairs.Count) of the requested $MaxRecords record(s). The log has nothing more to give, or -Category/-Since is too narrow."
        }
        elseif ($pairs.Count -gt $MaxRecords) {
            $pairs = $pairs[0..($MaxRecords - 1)]
        }
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
                -SkipCertificateCheck:$params.SkipCertificateCheck
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

#endregion
