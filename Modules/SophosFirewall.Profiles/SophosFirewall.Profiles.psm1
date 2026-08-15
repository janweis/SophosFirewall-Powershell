#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.1' }

<#
.SYNOPSIS
    Manages the reusable profiles of a Sophos Firewall: schedules, access time, data
    transfer, decryption and administrator roles.

.DESCRIPTION
    Functions for the SYSTEM > Profiles area of the Sophos Firewall XML API (SFOS 22.0).
    A profile is an object that other rules point at instead of repeating the same settings:
    a schedule names the times a rule is active, an access time policy allows or denies
    internet access during a schedule, a data transfer policy caps how much a user may
    transfer, a decryption profile decides how TLS connections are inspected, and an
    administration profile is the role that decides what an administrator may see and change.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosSchedule

    Connects to the firewall and lists every schedule.

.EXAMPLE
    New-SfosSchedule -Name 'Night shift' -Type Recurring -Days 'Week Days' -StartTime '22:00' -StopTime '06:00'
    New-SfosAccessTimePolicy -Name 'Night access' -Strategy Allow -Schedule 'Night shift'

    Creates a schedule and an access time policy that uses it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>

# Fragment for SophosFirewall.Profiles: Schedule and AccessTimePolicy.
# No documented Get exists for either entity (the operation pages list only
# Add/Edit and Delete); a plain <Get> answers on both roots regardless, the same
# pattern already known from the Authentication module. The XPath of the write
# status was not confirmed against a live firewall from this fragment, so every
# Assert-SfosApiReturnSuccess call below carries a reminder comment.

#region Schedule

<#
        .SYNOPSIS
        Retrieves schedule objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the schedule objects that are defined on the firewall. A schedule describes
        one or more time windows, each made of a day selector, a start time and a stop time,
        and is used by access time policies and other time-based rules to decide when they
        apply. Use this cmdlet to review the existing schedules, to feed them into another
        cmdlet through the pipeline, or to copy them to a second firewall. The cmdlet only
        reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        Several built-in schedules, among them "All the time", are accepted as a reference by
        other objects but do not exist as a readable schedule object themselves; a Get for
        one of them returns no result even though it is in active use elsewhere.

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

        .PARAMETER TypeLike
        Optional. Returns only objects of one schedule type, Recurring or OneTime. This is an
        exact match, applied on the client. If omitted, both types are returned.

        .PARAMETER DaysLike
        Optional. Returns only objects that have at least one time window whose day selector
        contains the given text anywhere, for example 'Week' to match 'Week Days' and
        'Weekdays Including Saturday'. Applied on the client. If omitted, days are not used
        to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        schedule objects. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. One object per schedule, with the
        properties Name, Description, Type, Days, StartTime, StopTime, StartDate and EndDate.
        Days, StartTime and StopTime are parallel arrays, one entry per time window. StartDate
        and EndDate are populated only for a OneTime schedule. Returns System.Xml.XmlElement
        when -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosSchedule

        Lists every schedule object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosSchedule -NameLike 'Work hours'

        Lists all schedules whose name contains 'Work hours'.

        .EXAMPLE
        Get-SfosSchedule -DaysLike 'Weekend'

        Lists schedules that have a time window whose day selector mentions weekends.

        .EXAMPLE
        Get-SfosSchedule -NameLike 'Work hours (5 Day week)' -AsXml

        Returns the raw XML of the matching object, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosSchedule

        .LINK
        Set-SfosSchedule
#>
function Get-SfosSchedule {
    [CmdletBinding()]
    param(
        # Functional parameters
        [ValidateLength(1, 50)]
        [string]$NameLike,

        [ValidateLength(1, 255)]
        [string]$DescriptionLike,

        [ValidateSet('Recurring', 'OneTime')]
        [string]$TypeLike,

        [ValidateLength(1, 50)]
        [string]$DaysLike,

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

    # Server-side pre-filter. Only Name is sent; every other filter is applied again
    # client-side below, per the one-key rule in section 6.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<key name="Name" criteria="like">{0}</key>' -f $nameLikeEsc)
    }

    $xmlFilterAdvanced = ''
    if ($filterXml) {
        $xmlFilterAdvanced = @"
<Filter>
    $filterXml
</Filter>
"@
    }

    $inner = @"
<Get>
  <Schedule>
    $xmlFilterAdvanced
  </Schedule>
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
        throw "Failed to retrieve Schedule objects: $($_.Exception.Message)"
    }
    $XmlResponse = [xml]($response.Content)

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Schedule' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/Schedule[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }
    if ($TypeLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Type -eq $TypeLike })
    }
    if ($DaysLike) {
        $nodes = @($nodes | Where-Object -FilterScript {
                $detailNodes = @($_.ScheduleDetails.ScheduleDetail)
                @($detailNodes | Where-Object -FilterScript { $_.Days -like "*$DaysLike*" }).Count -gt 0
            })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $scheduleObjects = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $detailNodes = @()
        if ($node.ScheduleDetails -and $node.ScheduleDetails.ScheduleDetail) {
            $detailNodes = @($node.ScheduleDetails.ScheduleDetail)
        }

        $scheduleObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            Type        = $node.Type
            Days        = @($detailNodes | ForEach-Object -Process { $_.Days })
            StartTime   = @($detailNodes | ForEach-Object -Process { $_.StartTime })
            StopTime    = @($detailNodes | ForEach-Object -Process { $_.StopTime })
            StartDate   = $node.ScheduleDetails.StartDate
            EndDate     = $node.ScheduleDetails.EndDate
        }
    }

    return $scheduleObjects
}

<#
        .SYNOPSIS
        Creates a schedule object on a Sophos Firewall.

        .DESCRIPTION
        Creates a schedule object of one of two types: Recurring, made of one or more time
        windows that repeat on the selected days, or OneTime, valid only between a start and
        an end date. Use this cmdlet to define a time pattern once and reuse it in access
        time policies and other time-based rules. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        Days, StartTime and StopTime are parallel arrays: the first day, start time and stop
        time together describe one time window, the second entries describe the next window,
        and so on. All three arrays must have the same number of entries.

        A OneTime schedule runs once between a start and an end date instead of repeating
        every week. Check the result in the web admin console after creating one.

        .PARAMETER Name
        Required. Name of the new schedule object. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER Description
        Optional. Free-text description.

        .PARAMETER Type
        Required. Type of the schedule: Recurring or OneTime. Determines whether StartDate
        and EndDate are required.

        .PARAMETER Days
        Required. Day selector for each time window, one entry per window. Valid values:
        Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Week Days, Weekdays
        Including Saturday, All Days of week.

        .PARAMETER StartTime
        Required. Start time for each time window, one entry per window, in 24-hour HH:MM
        format. The web admin offers only a 15-minute grid, but existing schedule objects on
        a live firewall carry values such as 23:59 that do not sit on that grid, so this
        cmdlet does not enforce the step client-side.

        .PARAMETER StopTime
        Required. Stop time for each time window, one entry per window, in 24-hour HH:MM
        format. Same notes as StartTime.

        .PARAMETER StartDate
        Required for Type OneTime. Start of the validity period, format 'YYYY-MM-DD
        HH:MM:SS'.

        .PARAMETER EndDate
        Required for Type OneTime. End of the validity period, format 'YYYY-MM-DD HH:MM:SS'.

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
        New-SfosSchedule -Name 'Weekend Allhours' -Type Recurring -Days 'Saturday','Sunday' -StartTime '00:00','00:00' -StopTime '23:59','23:59' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosSchedule -Name 'Weekend Allhours' -Type Recurring -Days 'Saturday','Sunday' -StartTime '00:00','00:00' -StopTime '23:59','23:59'

        Creates a recurring schedule with one time window per weekend day.

        .EXAMPLE
        New-SfosSchedule -Name 'Maintenance Window' -Type OneTime -Days 'Sunday' -StartTime '01:00' -StopTime '03:00' -StartDate '2026-09-06 01:00:00' -EndDate '2026-09-06 03:00:00'

        Creates a one-time schedule valid for a single maintenance window.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSchedule

        .LINK
        Set-SfosSchedule

        .LINK
        Remove-SfosSchedule
#>
function New-SfosSchedule {
    [CmdletBinding(DefaultParameterSetName = 'Recurring', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Description,

        [Parameter(Mandatory, ParameterSetName = 'Recurring')]
        [Parameter(Mandatory, ParameterSetName = 'OneTime')]
        [Parameter(Mandatory)]
        [ValidateSet('Recurring', 'OneTime')]
        [string]$Type,

        [Parameter(Mandatory)]
        [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday',
            'Week Days', 'Weekdays Including Saturday', 'All Days of week')]
        [string[]]$Days,

        [Parameter(Mandatory)]
        [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
        [string[]]$StartTime,

        [Parameter(Mandatory)]
        [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
        [string[]]$StopTime,

        [Parameter(Mandatory, ParameterSetName = 'OneTime')]
        [ValidatePattern('^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')]
        [string]$StartDate,

        [Parameter(Mandatory, ParameterSetName = 'OneTime')]
        [ValidatePattern('^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')]
        [string]$EndDate,

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

    # Same contradiction guard as New-SfosIPHost: -Type is a separate parameter from the
    # set-specific StartDate/EndDate pair, so a caller could otherwise pass -Type OneTime
    # without dates and silently land in the Recurring set.
    if ($Type -ne $PSCmdlet.ParameterSetName) {
        throw ("Type '{0}' does not match the supplied parameters, which describe a '{1}' schedule. " -f $Type, $PSCmdlet.ParameterSetName +
            "Type 'OneTime' needs -StartDate and -EndDate." -f $Type)
    }

    if ($Days.Count -ne $StartTime.Count -or $Days.Count -ne $StopTime.Count) {
        throw "Schedule '$Name' needs -Days, -StartTime and -StopTime with the same number of entries; one entry describes one time window."
    }

    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $scheduleDetailXml = ''
    for ($i = 0; $i -lt $Days.Count; $i++) {
        $daysEsc = ConvertTo-SfosXmlEscaped -Text $Days[$i]
        $startEsc = ConvertTo-SfosXmlEscaped -Text $StartTime[$i]
        $stopEsc = ConvertTo-SfosXmlEscaped -Text $StopTime[$i]
        $scheduleDetailXml += @"
<ScheduleDetail>
    <Days>$daysEsc</Days>
    <StartTime>$startEsc</StartTime>
    <StopTime>$stopEsc</StopTime>
</ScheduleDetail>
"@
    }

    $xmlDates = ''
    if ($Type -eq 'OneTime') {
        $startDateEsc = ConvertTo-SfosXmlEscaped -Text $StartDate
        $endDateEsc = ConvertTo-SfosXmlEscaped -Text $EndDate
        $xmlDates = "<StartDate>$startDateEsc</StartDate><EndDate>$endDateEsc</EndDate>"
    }

    $inner = @"
<Set operation="add">
    <Schedule>
        <Name>$nameEsc</Name>
        $xmlDescription
        <Type>$Type</Type>
        <ScheduleDetails>
            $xmlDates
            $scheduleDetailXml
        </ScheduleDetails>
    </Schedule>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("Schedule '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create Schedule object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Schedule' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates a schedule object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing schedule object. The cmdlet reads the current object first and
        sends back a complete object, keeping every field the caller does not pass. Only the
        fields you actually supply are changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        Days, StartTime and StopTime always replace the whole list of time windows together;
        pass all three or none of them. Passing only one of the three throws, because a
        partial replacement cannot be reconstructed into complete time windows.

        .PARAMETER Name
        Required. Name of the object to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosSchedule can be piped in directly.

        .PARAMETER Description
        Optional. Free-text description. If omitted, the current value is kept.

        .PARAMETER Type
        Optional. Type of the schedule, Recurring or OneTime. If omitted, the current value
        is kept.

        .PARAMETER Days
        Optional. Day selector for each time window, one entry per window. Replaces the
        current list of time windows together with StartTime and StopTime; all three must be
        supplied together. If omitted, the current time windows are kept.

        .PARAMETER StartTime
        Optional. Start time for each time window, one entry per window, in 24-hour HH:MM
        format. See Days for how the three time-window parameters interact.

        .PARAMETER StopTime
        Optional. Stop time for each time window, one entry per window, in 24-hour HH:MM
        format. See Days for how the three time-window parameters interact.

        .PARAMETER StartDate
        Optional. Start of the validity period for Type OneTime, format 'YYYY-MM-DD
        HH:MM:SS'. If omitted, the current value is kept.

        .PARAMETER EndDate
        Optional. End of the validity period for Type OneTime, format 'YYYY-MM-DD HH:MM:SS'.
        If omitted, the current value is kept.

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
        other properties, by property name, of a schedule object such as the ones returned by
        Get-SfosSchedule.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSchedule -Name 'Weekend Allhours' -Description 'Updated' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSchedule -Name 'Weekend Allhours' -Days 'Saturday','Sunday' -StartTime '06:00','06:00' -StopTime '22:00','22:00'

        Replaces the time windows of an existing schedule.

        .EXAMPLE
        Get-SfosSchedule -NameLike 'Weekend Allhours' | Set-SfosSchedule -Description 'Reviewed 2026'

        Updates the description of the matching object through the pipeline, keeping its
        existing time windows.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSchedule

        .LINK
        New-SfosSchedule
#>
function Set-SfosSchedule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Recurring', 'OneTime')]
        [string]$Type,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday',
            'Week Days', 'Weekdays Including Saturday', 'All Days of week')]
        [string[]]$Days,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
        [string[]]$StartTime,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
        [string[]]$StopTime,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')]
        [string]$StartDate,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')]
        [string]$EndDate,

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

        $existing = @(Get-SfosSchedule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The Schedule object '$Name' was not found."
        }

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

        $usesDaysParam = $PSBoundParameters.ContainsKey('Days')
        $usesStartParam = $PSBoundParameters.ContainsKey('StartTime')
        $usesStopParam = $PSBoundParameters.ContainsKey('StopTime')

        if (($usesDaysParam -or $usesStartParam -or $usesStopParam) -and
            -not ($usesDaysParam -and $usesStartParam -and $usesStopParam)) {
            throw "Set-SfosSchedule needs -Days, -StartTime and -StopTime together to replace the time windows of Schedule '$Name'."
        }

        # Wrap the whole if/else, not just each branch: PowerShell collapses a one-element
        # array returned from an if/else assignment back to a scalar, and StartTime[0] on a
        # scalar string indexes it character by character instead of by schedule detail row.
        $targetDays = @(if ($usesDaysParam) { $Days } else { $existing[0].Days })
        $targetStartTime = @(if ($usesStartParam) { $StartTime } else { $existing[0].StartTime })
        $targetStopTime = @(if ($usesStopParam) { $StopTime } else { $existing[0].StopTime })

        if ($targetDays.Count -ne $targetStartTime.Count -or $targetDays.Count -ne $targetStopTime.Count) {
            throw "Schedule '$Name' needs -Days, -StartTime and -StopTime with the same number of entries; one entry describes one time window."
        }

        $targetStartDate = if ($PSBoundParameters.ContainsKey('StartDate')) {
            $StartDate
        }
        else {
            [string]$existing[0].StartDate
        }

        $targetEndDate = if ($PSBoundParameters.ContainsKey('EndDate')) {
            $EndDate
        }
        else {
            [string]$existing[0].EndDate
        }

        if ($targetType -eq 'OneTime' -and (-not $targetStartDate -or -not $targetEndDate)) {
            throw "Schedule '$Name' has Type 'OneTime' and needs -StartDate and -EndDate."
        }

        if (-not $PSCmdlet.ShouldProcess("Schedule '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        $scheduleDetailXml = ''
        for ($i = 0; $i -lt $targetDays.Count; $i++) {
            $daysEsc = ConvertTo-SfosXmlEscaped -Text $targetDays[$i]
            $startEsc = ConvertTo-SfosXmlEscaped -Text $targetStartTime[$i]
            $stopEsc = ConvertTo-SfosXmlEscaped -Text $targetStopTime[$i]
            $scheduleDetailXml += @"
<ScheduleDetail>
    <Days>$daysEsc</Days>
    <StartTime>$startEsc</StartTime>
    <StopTime>$stopEsc</StopTime>
</ScheduleDetail>
"@
        }

        $xmlDates = ''
        if ($targetType -eq 'OneTime') {
            $startDateEsc = ConvertTo-SfosXmlEscaped -Text $targetStartDate
            $endDateEsc = ConvertTo-SfosXmlEscaped -Text $targetEndDate
            $xmlDates = "<StartDate>$startDateEsc</StartDate><EndDate>$endDateEsc</EndDate>"
        }

        $inner = @"
<Set operation="update">
    <Schedule>
        <Name>$nameEsc</Name>
        $xmlDescription
        <Type>$targetType</Type>
        <ScheduleDetails>
            $xmlDates
            $scheduleDetailXml
        </ScheduleDetails>
    </Schedule>
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
            throw "Failed to update Schedule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Schedule' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a schedule object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a schedule object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal. A schedule that
        is still referenced by an access time policy or another rule may be refused by the
        firewall; check the references first if the removal fails.

        .PARAMETER Name
        Required. Name of the object to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosSchedule can be piped in directly.

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
        schedule object such as the ones returned by Get-SfosSchedule.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosSchedule -Name 'Maintenance Window' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosSchedule -NameLike 'Maintenance' | Remove-SfosSchedule -WhatIf

        Previews the removal of every schedule whose name contains 'Maintenance'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSchedule
#>
function Remove-SfosSchedule {
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
        if (-not $PSCmdlet.ShouldProcess("Schedule '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <Schedule>
    <Name>$nameEsc</Name>
  </Schedule>
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
            throw "Error removing Schedule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Schedule' -Action 'remove' -Target $Name
    }
}

#endregion Schedule

#region AccessTimePolicy

<#
        .SYNOPSIS
        Retrieves access time policy objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the access time policy objects that are defined on the firewall. An access
        time policy allows or denies access during the time windows of a referenced schedule,
        and is used by other policies to restrict when they take effect. Use this cmdlet to
        review the existing policies, to feed them into another cmdlet through the pipeline,
        or to copy them to a second firewall. The cmdlet only reads; nothing on the firewall
        is changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the name is not used to filter.

        .PARAMETER StrategyLike
        Optional. Returns only objects with one strategy, Allow or Deny. Unlike the other
        filters this is an exact match. If omitted, both strategies are returned.

        .PARAMETER ScheduleLike
        Optional. Returns only objects whose referenced schedule name contains the given text
        anywhere. Applied on the client. If omitted, the schedule reference is not used to
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
        access time policy objects. If omitted, the value from the current connection is
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
        System.Management.Automation.PSCustomObject. One object per access time policy, with
        the properties Name, Strategy, Schedule and Description. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosAccessTimePolicy

        Lists every access time policy on the firewall of the current connection.

        .EXAMPLE
        Get-SfosAccessTimePolicy -StrategyLike Deny

        Lists all policies that deny access during their schedule.

        .EXAMPLE
        Get-SfosAccessTimePolicy -ScheduleLike 'Work hours'

        Lists policies that reference a schedule whose name mentions work hours.

        .EXAMPLE
        Get-SfosAccessTimePolicy -NameLike 'Denied all the time' -AsXml

        Returns the raw XML of the matching object, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosAccessTimePolicy

        .LINK
        Set-SfosAccessTimePolicy
#>
function Get-SfosAccessTimePolicy {
    [CmdletBinding()]
    param(
        # Functional parameters
        [ValidateLength(1, 50)]
        [string]$NameLike,

        [ValidateSet('Allow', 'Deny')]
        [string]$StrategyLike,

        [ValidateLength(1, 50)]
        [string]$ScheduleLike,

        [ValidateLength(1, 255)]
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
        $filterXml = ('<key name="Name" criteria="like">{0}</key>' -f $nameLikeEsc)
    }

    $xmlFilterAdvanced = ''
    if ($filterXml) {
        $xmlFilterAdvanced = @"
<Filter>
    $filterXml
</Filter>
"@
    }

    $inner = @"
<Get>
  <AccessTimePolicy>
    $xmlFilterAdvanced
  </AccessTimePolicy>
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
        throw "Failed to retrieve AccessTimePolicy objects: $($_.Exception.Message)"
    }
    $XmlResponse = [xml]($response.Content)

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AccessTimePolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AccessTimePolicy[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($StrategyLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Strategy -eq $StrategyLike })
    }
    if ($ScheduleLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Schedule -like "*$ScheduleLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $policyObjects = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $policyObjects += [PSCustomObject]@{
            Name        = $node.Name
            Strategy    = $node.Strategy
            Schedule    = $node.Schedule
            Description = $node.Description
        }
    }

    return $policyObjects
}

<#
        .SYNOPSIS
        Creates an access time policy on a Sophos Firewall.

        .DESCRIPTION
        Creates an access time policy that allows or denies access during the time windows of
        a referenced schedule. Use this cmdlet to define a time-based restriction once and
        reuse it in firewall rules and other policies. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        The Schedule value is a plain reference by name and is not checked against the
        objects Get-SfosSchedule returns. Several built-in schedules, among them
        "All the time", are valid targets even though they do not exist as a readable
        schedule object themselves.

        .PARAMETER Name
        Required. Name of the new access time policy. 1 to 50 characters, must not contain a
        comma.

        .PARAMETER Strategy
        Optional. Allow or Deny access during the referenced schedule. Defaults to Allow.

        .PARAMETER Schedule
        Optional. Name of the schedule object whose time windows the policy applies to. Not
        checked against existing schedule objects; see the description. If omitted, the
        policy is created without a schedule reference.

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
        New-SfosAccessTimePolicy -Name 'Allowed Work Hours' -Strategy Allow -Schedule 'Work hours (5 Day week)' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosAccessTimePolicy -Name 'Allowed Work Hours' -Strategy Allow -Schedule 'Work hours (5 Day week)'

        Creates a policy that allows access only during the referenced work-hours schedule.

        .EXAMPLE
        New-SfosAccessTimePolicy -Name 'Denied all the time' -Strategy Deny -Schedule 'All the time' -Description 'Blanket block'

        Creates a policy that denies access at all times, referencing the built-in
        "All the time" schedule.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAccessTimePolicy

        .LINK
        Set-SfosAccessTimePolicy

        .LINK
        Remove-SfosAccessTimePolicy
#>
function New-SfosAccessTimePolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('Allow', 'Deny')]
        [string]$Strategy = 'Allow',

        [ValidateLength(1, 50)]
        [string]$Schedule,

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

    $xmlSchedule = ''
    if ($Schedule) {
        $scheduleEsc = ConvertTo-SfosXmlEscaped -Text $Schedule
        $xmlSchedule = "<Schedule>$scheduleEsc</Schedule>"
    }

    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $inner = @"
<Set operation="add">
    <AccessTimePolicy>
        <Name>$nameEsc</Name>
        <Strategy>$Strategy</Strategy>
        $xmlSchedule
        $xmlDescription
    </AccessTimePolicy>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("AccessTimePolicy '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create AccessTimePolicy object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AccessTimePolicy' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an access time policy on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing access time policy. The cmdlet reads the current object first and
        sends back a complete object, keeping every field the caller does not pass. Only the
        fields you actually supply are changed; pass a field explicitly to clear it. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with administrative permission.

        .PARAMETER Name
        Required. Name of the object to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosAccessTimePolicy can be piped in directly.

        .PARAMETER Strategy
        Optional. Allow or Deny access during the referenced schedule. If omitted, the
        current value is kept.

        .PARAMETER Schedule
        Optional. Name of the schedule object whose time windows the policy applies to. Not
        checked against existing schedule objects. If omitted, the current value is kept.

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
        other properties, by property name, of an access time policy object such as the ones
        returned by Get-SfosAccessTimePolicy.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosAccessTimePolicy -Name 'Allowed Work Hours' -Strategy Deny -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosAccessTimePolicy -Name 'Allowed Work Hours' -Schedule 'Work hours (6 Day week)'

        Points an existing policy at a different schedule, keeping its strategy and
        description.

        .EXAMPLE
        Get-SfosAccessTimePolicy -NameLike 'Allowed Work Hours' | Set-SfosAccessTimePolicy -Description 'Reviewed 2026'

        Updates the description of the matching object through the pipeline.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAccessTimePolicy

        .LINK
        New-SfosAccessTimePolicy
#>
function Set-SfosAccessTimePolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Allow', 'Deny')]
        [string]$Strategy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$Schedule,

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

        $existing = @(Get-SfosAccessTimePolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AccessTimePolicy object '$Name' was not found."
        }

        $targetStrategy = if ($PSBoundParameters.ContainsKey('Strategy')) {
            $Strategy
        }
        else {
            [string]$existing[0].Strategy
        }

        $targetSchedule = if ($PSBoundParameters.ContainsKey('Schedule')) {
            $Schedule
        }
        else {
            [string]$existing[0].Schedule
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        if (-not $PSCmdlet.ShouldProcess("AccessTimePolicy '$($Name)' on $($params.Firewall)", 'Edit')) {
            return
        }

        $xmlSchedule = ''
        if ($targetSchedule) {
            $scheduleEsc = ConvertTo-SfosXmlEscaped -Text $targetSchedule
            $xmlSchedule = "<Schedule>$scheduleEsc</Schedule>"
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        $inner = @"
<Set operation="update">
    <AccessTimePolicy>
        <Name>$nameEsc</Name>
        <Strategy>$targetStrategy</Strategy>
        $xmlSchedule
        $xmlDescription
    </AccessTimePolicy>
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
            throw "Failed to update AccessTimePolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AccessTimePolicy' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an access time policy from a Sophos Firewall.

        .DESCRIPTION
        Deletes an access time policy by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal. A policy that is
        still referenced by a firewall rule or another object may be refused by the firewall;
        check the references first if the removal fails.

        .PARAMETER Name
        Required. Name of the object to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosAccessTimePolicy can be piped in directly.

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
        access time policy object such as the ones returned by Get-SfosAccessTimePolicy.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosAccessTimePolicy -Name 'Allowed Work Hours' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosAccessTimePolicy -NameLike 'Deprecated' | Remove-SfosAccessTimePolicy -WhatIf

        Previews the removal of every policy whose name contains 'Deprecated'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosAccessTimePolicy
#>
function Remove-SfosAccessTimePolicy {
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
        if (-not $PSCmdlet.ShouldProcess("AccessTimePolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <AccessTimePolicy>
    <Name>$nameEsc</Name>
  </AccessTimePolicy>
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
            throw "Error removing AccessTimePolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AccessTimePolicy' -Action 'remove' -Target $Name
    }
}

#endregion AccessTimePolicy

# Fragment for the future SophosFirewall.Profiles module.
# Covers two entities: DataTransferPolicy and DecryptionProfile, four cmdlets each.
# XPath depth for Assert-SfosApiReturnSuccess is not live-confirmed for either entity in
# this fragment - every write call is marked "".

#region DataTransferPolicy

function ConvertTo-SfosDataTransferSizeXml {
    <#
        .SYNOPSIS
        Builds the paired toggle/InMB XML elements DataTransferPolicy uses for one size field.

        .DESCRIPTION
        DataTransferPolicy carries every transfer size as two elements: a toggle element that
        holds the literal text Unlimited when no limit applies, and an InMB element that holds
        the numeric limit when one applies. The two are mutually exclusive on the wire - the
        live baseline shows exactly one of the pair populated, never both. This helper emits
        both elements for one field and populates exactly one of them.

        .PARAMETER ToggleElementName
        Name of the toggle element, for example CycleDataTransfer.

        .PARAMETER InMBElementName
        Name of the numeric element, for example CycleDataTransferInMB.

        .PARAMETER InMBValue
        The numeric limit in MB to send, or $null for unlimited.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ToggleElementName,

        [Parameter(Mandatory)]
        [string]$InMBElementName,

        [AllowNull()]
        [System.Nullable[int]]$InMBValue
    )

    if ($InMBValue) {
        return "<$ToggleElementName></$ToggleElementName><$InMBElementName>$InMBValue</$InMBElementName>"
    }

    return "<$ToggleElementName>Unlimited</$ToggleElementName><$InMBElementName></$InMBElementName>"
}

<#
        .SYNOPSIS
        Retrieves data transfer policy objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the data transfer policy objects that are defined on the firewall. A data
        transfer policy caps how much traffic a user or group may move, either as one lifetime
        total or as a repeating cycle, and is applied through a firewall rule or a user
        profile. Use this cmdlet to review the existing policies or to feed them into another
        cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is changed.
        It needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only policies whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the name is not used to filter.

        .PARAMETER RestrictionBasedOnLike
        Optional. Returns only policies of one restriction mode, TotalDataTransfer or
        IndividualDataTransfer. This is an exact match. If omitted, both modes are returned.

        .PARAMETER CycleTypeLike
        Optional. Returns only policies of one cycle type, NonCyclic or Cyclic. This is an
        exact match. If omitted, both cycle types are returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        profile objects. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. One object per data transfer policy, with
        the properties Name, Description, RestrictionBasedOn, CycleType, CyclePeriod,
        CycleDataTransfer, CycleDataTransferInMB, MaximumDataTransfer, MaximumDataTransferInMB,
        CycleUploadDataTransfer, CycleUploadDataTransferInMB, CycleDownloadDataTransfer,
        CycleDownloadDataTransferInMB, MaximumUploadDataTransfer, MaximumUploadDataTransferInMB,
        MaximumDownloadDataTransfer and MaximumDownloadDataTransferInMB. Every size field is
        returned in both its toggle and its InMB form, so a Set-SfosDataTransferPolicy built on
        this output loses neither form. Returns System.Xml.XmlElement when -AsXml is used, and
        an empty array when no object matches.

        .EXAMPLE
        Get-SfosDataTransferPolicy

        Lists every data transfer policy on the firewall of the current connection.

        .EXAMPLE
        Get-SfosDataTransferPolicy -NameLike 'Daily' -CycleTypeLike Cyclic

        Lists all cyclic policies whose name contains 'Daily'.

        .EXAMPLE
        Get-SfosDataTransferPolicy -NameLike '100 MB' -AsXml

        Returns the raw XML of the matching policy, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosDataTransferPolicy

        .LINK
        Set-SfosDataTransferPolicy
#>
function Get-SfosDataTransferPolicy {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 50)]
        [string]$NameLike,

        [ValidateSet('TotalDataTransfer', 'IndividualDataTransfer')]
        [string]$RestrictionBasedOnLike,

        [ValidateSet('NonCyclic', 'Cyclic')]
        [string]$CycleTypeLike,

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

    # Server-side pre-filter. Only the Name key is sent - see the project rules, section 6. Every requested
    # filter is applied again client-side below regardless of what the server honoured.
    $xmlFilterAdvanced = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $xmlFilterAdvanced = @"
<Filter>
    <key name="Name" criteria="like">$nameLikeEsc</key>
</Filter>
"@
    }

    $inner = @"
<Get>
  <DataTransferPolicy>
    $xmlFilterAdvanced
  </DataTransferPolicy>
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
        throw "Failed to retrieve DataTransferPolicy objects: $($_.Exception.Message)"
    }
    $XmlResponse = [xml]($response.Content)

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataTransferPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DataTransferPolicy[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($RestrictionBasedOnLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.RestrictionBasedOn -eq $RestrictionBasedOnLike })
    }
    if ($CycleTypeLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.CycleType -eq $CycleTypeLike })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $policyObjects = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $policyObjects += [PSCustomObject]@{
            Name                             = $node.Name
            Description                      = $node.Description
            RestrictionBasedOn               = $node.RestrictionBasedOn
            CycleType                        = $node.CycleType
            CyclePeriod                      = $node.CyclePeriod
            CycleDataTransfer                = $node.CycleDataTransfer
            CycleDataTransferInMB            = $node.CycleDataTransferInMB
            MaximumDataTransfer              = $node.MaximumDataTransfer
            MaximumDataTransferInMB          = $node.MaximumDataTransferInMB
            CycleUploadDataTransfer          = $node.CycleUploadDataTransfer
            CycleUploadDataTransferInMB      = $node.CycleUploadDataTransferInMB
            CycleDownloadDataTransfer        = $node.CycleDownloadDataTransfer
            CycleDownloadDataTransferInMB    = $node.CycleDownloadDataTransferInMB
            MaximumUploadDataTransfer        = $node.MaximumUploadDataTransfer
            MaximumUploadDataTransferInMB    = $node.MaximumUploadDataTransferInMB
            MaximumDownloadDataTransfer      = $node.MaximumDownloadDataTransfer
            MaximumDownloadDataTransferInMB  = $node.MaximumDownloadDataTransferInMB
        }
    }

    return $policyObjects
}

<#
        .SYNOPSIS
        Creates a data transfer policy object on a Sophos Firewall.

        .DESCRIPTION
        Creates a data transfer policy that caps traffic either as one lifetime total
        (RestrictionBasedOn TotalDataTransfer) or per repeating cycle (RestrictionBasedOn
        IndividualDataTransfer). Use this cmdlet to define a cap once and apply it through a
        firewall rule or a user profile. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly, and an account with administrative
        permission.

        Every size limit is optional. Leave it out to make that particular limit unlimited;
        supply a value in megabytes to cap it. The vendor documentation marks several of these
        fields mandatory, but the two policies observed on a live appliance both leave most of
        them empty, so this cmdlet follows the live shape and treats them as optional.

        .PARAMETER Name
        Required. Name of the new policy. 1 to 50 characters, must not contain a comma.

        .PARAMETER RestrictionBasedOn
        Required. Restriction mode: TotalDataTransfer caps the lifetime total,
        IndividualDataTransfer caps upload and download separately. The vendor sample XML
        misspells this value as TotalDataTranfer; the live object and this cmdlet use the
        correctly spelled TotalDataTransfer.

        .PARAMETER CycleType
        Required. NonCyclic applies the limit once, for the policy's lifetime. Cyclic resets
        the limit at the start of every CyclePeriod.

        .PARAMETER CyclePeriod
        Required when CycleType is Cyclic, not used otherwise. Day, Week, Month or Year. The
        vendor documentation table omits Day even though both the sample XML and a live object
        use it.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER CycleDataTransferInMB
        Optional. Total transfer limit per cycle, in megabytes, 1 to 999999999. Leave out for
        an unlimited per-cycle total. Applies with RestrictionBasedOn TotalDataTransfer.

        .PARAMETER MaximumDataTransferInMB
        Optional. Lifetime transfer limit, in megabytes, 1 to 999999999. Leave out for an
        unlimited lifetime total. Applies with RestrictionBasedOn TotalDataTransfer and
        CycleType NonCyclic.

        .PARAMETER CycleUploadDataTransferInMB
        Optional. Upload limit per cycle, in megabytes, 1 to 999999999. Leave out for an
        unlimited per-cycle upload. Applies with RestrictionBasedOn IndividualDataTransfer.
        Not observed on a live object; documentation-faithful.

        .PARAMETER CycleDownloadDataTransferInMB
        Optional. Download limit per cycle, in megabytes, 1 to 999999999. Leave out for an
        unlimited per-cycle download. Applies with RestrictionBasedOn IndividualDataTransfer.
        Not observed on a live object; documentation-faithful.

        .PARAMETER MaximumUploadDataTransferInMB
        Optional. Lifetime upload limit, in megabytes, 1 to 999999999. Leave out for an
        unlimited lifetime upload. Applies with RestrictionBasedOn IndividualDataTransfer.
        Not observed on a live object; documentation-faithful.

        .PARAMETER MaximumDownloadDataTransferInMB
        Optional. Lifetime download limit, in megabytes, 1 to 999999999. Leave out for an
        unlimited lifetime download. Applies with RestrictionBasedOn IndividualDataTransfer.
        Not observed on a live object; documentation-faithful.

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
        New-SfosDataTransferPolicy -Name '100 MB Total' -RestrictionBasedOn TotalDataTransfer -CycleType NonCyclic -MaximumDataTransferInMB 100 -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosDataTransferPolicy -Name '100 MB Total' -RestrictionBasedOn TotalDataTransfer -CycleType NonCyclic -MaximumDataTransferInMB 100

        Creates a policy with a 100 MB lifetime total.

        .EXAMPLE
        New-SfosDataTransferPolicy -Name 'Daily 10 MB' -RestrictionBasedOn TotalDataTransfer -CycleType Cyclic -CyclePeriod Day -CycleDataTransferInMB 10

        Creates a policy that allows 10 MB per day and resets daily.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDataTransferPolicy

        .LINK
        Set-SfosDataTransferPolicy

        .LINK
        Remove-SfosDataTransferPolicy
#>
function New-SfosDataTransferPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('TotalDataTransfer', 'IndividualDataTransfer')]
        [string]$RestrictionBasedOn,

        [Parameter(Mandatory)]
        [ValidateSet('NonCyclic', 'Cyclic')]
        [string]$CycleType,

        [ValidateSet('Day', 'Week', 'Month', 'Year')]
        [string]$CyclePeriod,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateRange(1, 999999999)]
        [int]$CycleDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$MaximumDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$CycleUploadDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$CycleDownloadDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$MaximumUploadDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$MaximumDownloadDataTransferInMB,

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

    if ($CycleType -eq 'Cyclic' -and -not $CyclePeriod) {
        throw "DataTransferPolicy '$Name': -CyclePeriod is required when -CycleType is Cyclic."
    }

    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $xmlCyclePeriod = ''
    if ($CyclePeriod) {
        $xmlCyclePeriod = "<CyclePeriod>$CyclePeriod</CyclePeriod>"
    }

    $xmlCycleTotal = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'CycleDataTransfer' -InMBElementName 'CycleDataTransferInMB' -InMBValue $(if ($PSBoundParameters.ContainsKey('CycleDataTransferInMB')) { $CycleDataTransferInMB } else { $null })
    $xmlMaximumTotal = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'MaximumDataTransfer' -InMBElementName 'MaximumDataTransferInMB' -InMBValue $(if ($PSBoundParameters.ContainsKey('MaximumDataTransferInMB')) { $MaximumDataTransferInMB } else { $null })
    $xmlCycleUpload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'CycleUploadDataTransfer' -InMBElementName 'CycleUploadDataTransferInMB' -InMBValue $(if ($PSBoundParameters.ContainsKey('CycleUploadDataTransferInMB')) { $CycleUploadDataTransferInMB } else { $null })
    $xmlCycleDownload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'CycleDownloadDataTransfer' -InMBElementName 'CycleDownloadDataTransferInMB' -InMBValue $(if ($PSBoundParameters.ContainsKey('CycleDownloadDataTransferInMB')) { $CycleDownloadDataTransferInMB } else { $null })
    $xmlMaximumUpload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'MaximumUploadDataTransfer' -InMBElementName 'MaximumUploadDataTransferInMB' -InMBValue $(if ($PSBoundParameters.ContainsKey('MaximumUploadDataTransferInMB')) { $MaximumUploadDataTransferInMB } else { $null })
    $xmlMaximumDownload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'MaximumDownloadDataTransfer' -InMBElementName 'MaximumDownloadDataTransferInMB' -InMBValue $(if ($PSBoundParameters.ContainsKey('MaximumDownloadDataTransferInMB')) { $MaximumDownloadDataTransferInMB } else { $null })

    $inner = @"
<Set operation="add">
    <DataTransferPolicy>
        <Name>$nameEsc</Name>
        <RestrictionBasedOn>$RestrictionBasedOn</RestrictionBasedOn>
        <CycleType>$CycleType</CycleType>
        $xmlCyclePeriod
        $xmlCycleTotal
        $xmlMaximumTotal
        $xmlCycleUpload
        $xmlCycleDownload
        $xmlMaximumUpload
        $xmlMaximumDownload
        $xmlDescription
    </DataTransferPolicy>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("DataTransferPolicy '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create DataTransferPolicy object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataTransferPolicy' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates a data transfer policy object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing data transfer policy. The cmdlet reads the current policy first
        and sends back a complete object, keeping every field the caller does not pass. Only
        the fields you actually supply are changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        .PARAMETER Name
        Required. Name of the policy to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosDataTransferPolicy can be piped in directly.

        .PARAMETER RestrictionBasedOn
        Required. Restriction mode: TotalDataTransfer or IndividualDataTransfer.

        .PARAMETER CycleType
        Required. NonCyclic or Cyclic.

        .PARAMETER CyclePeriod
        Required when CycleType is Cyclic, not used otherwise. Day, Week, Month or Year. If
        omitted and CycleType is Cyclic, the current value is kept.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER CycleDataTransferInMB
        Optional. Total transfer limit per cycle, in megabytes, 1 to 999999999. If omitted,
        the current value is kept.

        .PARAMETER MaximumDataTransferInMB
        Optional. Lifetime transfer limit, in megabytes, 1 to 999999999. If omitted, the
        current value is kept.

        .PARAMETER CycleUploadDataTransferInMB
        Optional. Upload limit per cycle, in megabytes, 1 to 999999999. If omitted, the
        current value is kept.

        .PARAMETER CycleDownloadDataTransferInMB
        Optional. Download limit per cycle, in megabytes, 1 to 999999999. If omitted, the
        current value is kept.

        .PARAMETER MaximumUploadDataTransferInMB
        Optional. Lifetime upload limit, in megabytes, 1 to 999999999. If omitted, the
        current value is kept.

        .PARAMETER MaximumDownloadDataTransferInMB
        Optional. Lifetime download limit, in megabytes, 1 to 999999999. If omitted, the
        current value is kept.

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
        other properties, by property name, of a data transfer policy object such as the ones
        returned by Get-SfosDataTransferPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosDataTransferPolicy -Name '100 MB Total' -RestrictionBasedOn TotalDataTransfer -CycleType NonCyclic -MaximumDataTransferInMB 200 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDataTransferPolicy -Name '100 MB Total' -RestrictionBasedOn TotalDataTransfer -CycleType NonCyclic -MaximumDataTransferInMB 200

        Raises the lifetime cap of an existing policy to 200 MB.

        .EXAMPLE
        Get-SfosDataTransferPolicy -NameLike 'Daily 10 MB' | Set-SfosDataTransferPolicy -CycleDataTransferInMB 20

        Reads the matching policy and raises its per-cycle cap through the pipeline.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDataTransferPolicy

        .LINK
        New-SfosDataTransferPolicy
#>
function Set-SfosDataTransferPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('TotalDataTransfer', 'IndividualDataTransfer')]
        [string]$RestrictionBasedOn,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('NonCyclic', 'Cyclic')]
        [string]$CycleType,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Day', 'Week', 'Month', 'Year')]
        [string]$CyclePeriod,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateRange(1, 999999999)]
        [int]$CycleDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$MaximumDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$CycleUploadDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$CycleDownloadDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$MaximumUploadDataTransferInMB,

        [ValidateRange(1, 999999999)]
        [int]$MaximumDownloadDataTransferInMB,

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

        $existing = @(Get-SfosDataTransferPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The DataTransferPolicy object '$Name' was not found."
        }

        $targetCyclePeriod = if ($PSBoundParameters.ContainsKey('CyclePeriod')) {
            $CyclePeriod
        }
        else {
            [string]$existing[0].CyclePeriod
        }

        if ($CycleType -eq 'Cyclic' -and -not $targetCyclePeriod) {
            throw "DataTransferPolicy '$Name': -CyclePeriod is required when -CycleType is Cyclic."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        # Every size field is read back and reused unless the caller passed it explicitly -
        # otherwise a Set that only touches one field would blank out every other limit.
        $existingCycleInMB = if ($existing[0].CycleDataTransferInMB) { [int]$existing[0].CycleDataTransferInMB } else { $null }
        $existingMaximumInMB = if ($existing[0].MaximumDataTransferInMB) { [int]$existing[0].MaximumDataTransferInMB } else { $null }
        $existingCycleUploadInMB = if ($existing[0].CycleUploadDataTransferInMB) { [int]$existing[0].CycleUploadDataTransferInMB } else { $null }
        $existingCycleDownloadInMB = if ($existing[0].CycleDownloadDataTransferInMB) { [int]$existing[0].CycleDownloadDataTransferInMB } else { $null }
        $existingMaximumUploadInMB = if ($existing[0].MaximumUploadDataTransferInMB) { [int]$existing[0].MaximumUploadDataTransferInMB } else { $null }
        $existingMaximumDownloadInMB = if ($existing[0].MaximumDownloadDataTransferInMB) { [int]$existing[0].MaximumDownloadDataTransferInMB } else { $null }

        $targetCycleInMB = if ($PSBoundParameters.ContainsKey('CycleDataTransferInMB')) { $CycleDataTransferInMB } else { $existingCycleInMB }
        $targetMaximumInMB = if ($PSBoundParameters.ContainsKey('MaximumDataTransferInMB')) { $MaximumDataTransferInMB } else { $existingMaximumInMB }
        $targetCycleUploadInMB = if ($PSBoundParameters.ContainsKey('CycleUploadDataTransferInMB')) { $CycleUploadDataTransferInMB } else { $existingCycleUploadInMB }
        $targetCycleDownloadInMB = if ($PSBoundParameters.ContainsKey('CycleDownloadDataTransferInMB')) { $CycleDownloadDataTransferInMB } else { $existingCycleDownloadInMB }
        $targetMaximumUploadInMB = if ($PSBoundParameters.ContainsKey('MaximumUploadDataTransferInMB')) { $MaximumUploadDataTransferInMB } else { $existingMaximumUploadInMB }
        $targetMaximumDownloadInMB = if ($PSBoundParameters.ContainsKey('MaximumDownloadDataTransferInMB')) { $MaximumDownloadDataTransferInMB } else { $existingMaximumDownloadInMB }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        $xmlCyclePeriod = ''
        if ($targetCyclePeriod) {
            $xmlCyclePeriod = "<CyclePeriod>$targetCyclePeriod</CyclePeriod>"
        }

        $xmlCycleTotal = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'CycleDataTransfer' -InMBElementName 'CycleDataTransferInMB' -InMBValue $targetCycleInMB
        $xmlMaximumTotal = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'MaximumDataTransfer' -InMBElementName 'MaximumDataTransferInMB' -InMBValue $targetMaximumInMB
        $xmlCycleUpload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'CycleUploadDataTransfer' -InMBElementName 'CycleUploadDataTransferInMB' -InMBValue $targetCycleUploadInMB
        $xmlCycleDownload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'CycleDownloadDataTransfer' -InMBElementName 'CycleDownloadDataTransferInMB' -InMBValue $targetCycleDownloadInMB
        $xmlMaximumUpload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'MaximumUploadDataTransfer' -InMBElementName 'MaximumUploadDataTransferInMB' -InMBValue $targetMaximumUploadInMB
        $xmlMaximumDownload = ConvertTo-SfosDataTransferSizeXml -ToggleElementName 'MaximumDownloadDataTransfer' -InMBElementName 'MaximumDownloadDataTransferInMB' -InMBValue $targetMaximumDownloadInMB

        $inner = @"
<Set operation="update">
    <DataTransferPolicy>
        <Name>$nameEsc</Name>
        <RestrictionBasedOn>$RestrictionBasedOn</RestrictionBasedOn>
        <CycleType>$CycleType</CycleType>
        $xmlCyclePeriod
        $xmlCycleTotal
        $xmlMaximumTotal
        $xmlCycleUpload
        $xmlCycleDownload
        $xmlMaximumUpload
        $xmlMaximumDownload
        $xmlDescription
    </DataTransferPolicy>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("DataTransferPolicy '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Failed to update DataTransferPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataTransferPolicy' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a data transfer policy object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a data transfer policy by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the policy to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosDataTransferPolicy can be piped in directly.

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
        data transfer policy object such as the ones returned by Get-SfosDataTransferPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosDataTransferPolicy -Name 'Daily 10 MB' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosDataTransferPolicy -NameLike 'Test' | Remove-SfosDataTransferPolicy -WhatIf

        Previews the removal of every policy whose name contains 'Test'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDataTransferPolicy
#>
function Remove-SfosDataTransferPolicy {
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
        if (-not $PSCmdlet.ShouldProcess("DataTransferPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <DataTransferPolicy>
    <Name>$nameEsc</Name>
  </DataTransferPolicy>
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
            throw "Error removing DataTransferPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataTransferPolicy' -Action 'remove' -Target $Name
    }
}

#endregion DataTransferPolicy

#region DecryptionProfile

function ConvertTo-SfosBlockedAlgorithmListXml {
    <#
        .SYNOPSIS
        Builds the BlockedAlgorithmList wrapper for a DecryptionProfile.

        .DESCRIPTION
        DecryptionProfile keeps four independent lists of blocked algorithm names inside one
        BlockedAlgorithmList wrapper. The wrapper itself is optional and absent entirely on a
        profile that blocks nothing, so this helper returns an empty string when all four
        input lists are empty, and the populated wrapper otherwise.

        .PARAMETER KeyExchangeAlgorithm
        Key exchange algorithm names to block, for example DH.

        .PARAMETER AuthenticationAlgorithm
        Authentication algorithm names to block, for example ANON.

        .PARAMETER BlockAndStreamCipher
        Block and stream cipher names to block, for example RC4, 3DES or NULL.

        .PARAMETER HashAlgorithm
        Hash algorithm names to block, for example MD5.
    #>
    param(
        [string[]]$KeyExchangeAlgorithm,
        [string[]]$AuthenticationAlgorithm,
        [string[]]$BlockAndStreamCipher,
        [string[]]$HashAlgorithm
    )

    $children = ''
    foreach ($value in $KeyExchangeAlgorithm) {
        if (-not $value) { continue }
        $children += "<KeyExchangeAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $value)</KeyExchangeAlgorithm>"
    }
    foreach ($value in $AuthenticationAlgorithm) {
        if (-not $value) { continue }
        $children += "<AuthenticationAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $value)</AuthenticationAlgorithm>"
    }
    foreach ($value in $BlockAndStreamCipher) {
        if (-not $value) { continue }
        $children += "<BlockAndStreamCipher>$(ConvertTo-SfosXmlEscaped -Text $value)</BlockAndStreamCipher>"
    }
    foreach ($value in $HashAlgorithm) {
        if (-not $value) { continue }
        $children += "<HashAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $value)</HashAlgorithm>"
    }

    if (-not $children) {
        return ''
    }

    return "<BlockedAlgorithmList>$children</BlockedAlgorithmList>"
}

<#
        .SYNOPSIS
        Retrieves decryption profile objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the decryption profile objects that are defined on the firewall. A decryption
        profile controls how the firewall handles TLS inspection for a decrypt rule: which
        certificate problems it blocks, which TLS versions and ciphers it accepts, and which
        algorithms it refuses outright. Use this cmdlet to review the existing profiles or to
        feed them into another cmdlet through the pipeline. The cmdlet only reads; nothing on
        the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only profiles whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern; the characters * and ? are treated as
        ordinary characters. If omitted, the name is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only profiles whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        profile objects. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. One object per decryption profile, with
        the properties Name, Description, IsDefault, UseDefaultCAs, RSACA, ECCA,
        BlockInvalidDate, BlockUntrustedIssuer, BlockSelfSigned, BlockRevoked,
        BlockNameMismatch, BlockOtherReasons, MinRSAKeySize, MinTLSVersion, MaxTLSVersion,
        BlockAction, UnrecognizedCiphers, SSLConnectionsExceeded, SSLv2SSLv3, SSLCompression,
        KeyExchangeAlgorithm, AuthenticationAlgorithm, BlockAndStreamCipher and HashAlgorithm.
        The four algorithm properties are arrays and are empty when the profile carries no
        BlockedAlgorithmList at all. Returns System.Xml.XmlElement when -AsXml is used, and an
        empty array when no object matches.

        .EXAMPLE
        Get-SfosDecryptionProfile

        Lists every decryption profile on the firewall of the current connection.

        .EXAMPLE
        Get-SfosDecryptionProfile -NameLike 'Strict'

        Lists all profiles whose name contains 'Strict'.

        .EXAMPLE
        Get-SfosDecryptionProfile -NameLike 'Strict compliance' -AsXml

        Returns the raw XML of the matching profile, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosDecryptionProfile

        .LINK
        Set-SfosDecryptionProfile
#>
function Get-SfosDecryptionProfile {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 60)]
        [string]$NameLike,

        [ValidateLength(1, 255)]
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

    $xmlFilterAdvanced = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $xmlFilterAdvanced = @"
<Filter>
    <key name="Name" criteria="like">$nameLikeEsc</key>
</Filter>
"@
    }

    $inner = @"
<Get>
  <DecryptionProfile>
    $xmlFilterAdvanced
  </DecryptionProfile>
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
        throw "Failed to retrieve DecryptionProfile objects: $($_.Exception.Message)"
    }
    $XmlResponse = [xml]($response.Content)

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DecryptionProfile' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DecryptionProfile[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $profileObjects = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $keyExchange = @()
        $authentication = @()
        $cipher = @()
        $hash = @()
        if ($node.BlockedAlgorithmList) {
            if ($node.BlockedAlgorithmList.KeyExchangeAlgorithm) { $keyExchange = @($node.BlockedAlgorithmList.KeyExchangeAlgorithm) }
            if ($node.BlockedAlgorithmList.AuthenticationAlgorithm) { $authentication = @($node.BlockedAlgorithmList.AuthenticationAlgorithm) }
            if ($node.BlockedAlgorithmList.BlockAndStreamCipher) { $cipher = @($node.BlockedAlgorithmList.BlockAndStreamCipher) }
            if ($node.BlockedAlgorithmList.HashAlgorithm) { $hash = @($node.BlockedAlgorithmList.HashAlgorithm) }
        }

        $profileObjects += [PSCustomObject]@{
            Name                    = $node.Name
            Description             = $node.Description
            IsDefault               = $node.IsDefault
            UseDefaultCAs           = $node.UseDefaultCAs
            RSACA                   = $node.RSACA
            ECCA                    = $node.ECCA
            BlockInvalidDate        = $node.BlockInvalidDate
            BlockUntrustedIssuer    = $node.BlockUntrustedIssuer
            BlockSelfSigned         = $node.BlockSelfSigned
            BlockRevoked            = $node.BlockRevoked
            BlockNameMismatch       = $node.BlockNameMismatch
            BlockOtherReasons       = $node.BlockOtherReasons
            MinRSAKeySize           = $node.MinRSAKeySize
            MinTLSVersion           = $node.MinTLSVersion
            MaxTLSVersion           = $node.MaxTLSVersion
            BlockAction             = $node.BlockAction
            UnrecognizedCiphers     = $node.UnrecognizedCiphers
            SSLConnectionsExceeded  = $node.SSLConnectionsExceeded
            SSLv2SSLv3              = $node.SSLv2SSLv3
            SSLCompression          = $node.SSLCompression
            KeyExchangeAlgorithm    = $keyExchange
            AuthenticationAlgorithm = $authentication
            BlockAndStreamCipher    = $cipher
            HashAlgorithm           = $hash
        }
    }

    return $profileObjects
}

<#
        .SYNOPSIS
        Creates a decryption profile object on a Sophos Firewall.

        .DESCRIPTION
        Creates a decryption profile that controls how the firewall handles TLS inspection for
        a decrypt rule. Use this cmdlet to define a profile once and reuse it in one or more
        decrypt rules. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with administrative permission.

        Every field left out keeps the firewall's own default for a new profile. The vendor
        documentation table marks IsDefault as a read-only field, yet shows it in the Add
        sample XML at the same time. This cmdlet does not send IsDefault at all, so the
        create either succeeds with the firewall's own default status or fails outright if the
        field turns out to be required after all - that has not been established against a
        live appliance and needs to be settled during acceptance testing.

        .PARAMETER Name
        Required. Name of the new profile. 1 to 60 characters, must not contain a comma.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters.

        .PARAMETER UseDefaultCAs
        Optional. yes or no. Whether the profile trusts the firewall's built-in certificate
        authorities. Defaults to yes on the firewall if omitted.

        .PARAMETER RSACA
        Optional. Name of a custom RSA certificate authority to use instead of, or in addition
        to, the default CAs.

        .PARAMETER ECCA
        Optional. Name of a custom elliptic-curve certificate authority to use instead of, or
        in addition to, the default CAs.

        .PARAMETER BlockInvalidDate
        Optional. yes or no. Blocks sites whose certificate has an invalid validity period.

        .PARAMETER BlockUntrustedIssuer
        Optional. yes or no. Blocks sites whose certificate was issued by an untrusted CA.

        .PARAMETER BlockSelfSigned
        Optional. yes or no. Blocks sites presenting a self-signed certificate.

        .PARAMETER BlockRevoked
        Optional. yes or no. Blocks sites presenting a revoked certificate.

        .PARAMETER BlockNameMismatch
        Optional. yes or no. Blocks sites whose certificate name does not match the requested
        host name.

        .PARAMETER BlockOtherReasons
        Optional. yes or no. Blocks sites for any other certificate validation failure.

        .PARAMETER MinRSAKeySize
        Optional. Minimum accepted RSA key size: No minimum, 1024 or 2048. Defaults to 1024 on
        the firewall if omitted.

        .PARAMETER MinTLSVersion
        Optional. Minimum accepted TLS version: TLS v1.0, TLS v1.1, TLS v1.2 or TLS v1.3. TLS
        v1.3 is documented but was not observed on a live profile. Defaults to TLS v1.0 on the
        firewall if omitted.

        .PARAMETER MaxTLSVersion
        Optional. Maximum accepted TLS version: TLS v1.0, TLS v1.1, TLS v1.2, TLS v1.3 or
        Maximum supported. Defaults to Maximum supported on the firewall if omitted.

        .PARAMETER BlockAction
        Optional. Drop, Reject or Reject and notify. Action taken when a blocked condition is
        met. Defaults to Reject and notify on the firewall if omitted.

        .PARAMETER UnrecognizedCiphers
        Optional. Allow without decryption, Drop or Reject. Handling of ciphers the firewall
        does not recognise. Defaults to Allow without decryption on the firewall if omitted.

        .PARAMETER SSLConnectionsExceeded
        Optional. Use SSL/TLS settings default, Allow without decryption, Drop or Reject.
        Handling once the maximum number of concurrent SSL connections is reached.

        .PARAMETER SSLv2SSLv3
        Optional. Use SSL/TLS settings default, Allow without decryption, Drop or Reject.
        Handling of the obsolete SSLv2 and SSLv3 protocols.

        .PARAMETER SSLCompression
        Optional. Use SSL/TLS settings default, Allow without decryption, Drop or Reject.
        Handling of SSL/TLS compression.

        .PARAMETER KeyExchangeAlgorithm
        Optional. Key exchange algorithm names to block. No source lists the full value set;
        DH is the only value observed on a live profile.

        .PARAMETER AuthenticationAlgorithm
        Optional. Authentication algorithm names to block. No source lists the full value set;
        ANON is the only value observed on a live profile.

        .PARAMETER BlockAndStreamCipher
        Optional. Block and stream cipher names to block. No source lists the full value set;
        RC4, 3DES and NULL were observed on live profiles.

        .PARAMETER HashAlgorithm
        Optional. Hash algorithm names to block. No source lists the full value set; MD5 is
        the only value observed on a live profile.

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
        New-SfosDecryptionProfile -Name 'Custom strict' -MinTLSVersion 'TLS v1.2' -BlockSelfSigned yes -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosDecryptionProfile -Name 'Custom strict' -MinTLSVersion 'TLS v1.2' -BlockSelfSigned yes -BlockRevoked yes

        Creates a profile that requires at least TLS 1.2 and blocks self-signed and revoked
        certificates.

        .EXAMPLE
        New-SfosDecryptionProfile -Name 'No weak ciphers' -BlockAndStreamCipher 'RC4','3DES','NULL' -HashAlgorithm 'MD5'

        Creates a profile that blocks the listed weak ciphers and the MD5 hash algorithm.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDecryptionProfile

        .LINK
        Set-SfosDecryptionProfile

        .LINK
        Remove-SfosDecryptionProfile
#>
function New-SfosDecryptionProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('yes', 'no')]
        [string]$UseDefaultCAs,

        [string]$RSACA,

        [string]$ECCA,

        [ValidateSet('yes', 'no')]
        [string]$BlockInvalidDate,

        [ValidateSet('yes', 'no')]
        [string]$BlockUntrustedIssuer,

        [ValidateSet('yes', 'no')]
        [string]$BlockSelfSigned,

        [ValidateSet('yes', 'no')]
        [string]$BlockRevoked,

        [ValidateSet('yes', 'no')]
        [string]$BlockNameMismatch,

        [ValidateSet('yes', 'no')]
        [string]$BlockOtherReasons,

        [ValidateSet('No minimum', '1024', '2048')]
        [string]$MinRSAKeySize,

        [ValidateSet('TLS v1.0', 'TLS v1.1', 'TLS v1.2', 'TLS v1.3')]
        [string]$MinTLSVersion,

        [ValidateSet('TLS v1.0', 'TLS v1.1', 'TLS v1.2', 'TLS v1.3', 'Maximum supported')]
        [string]$MaxTLSVersion,

        [ValidateSet('Drop', 'Reject', 'Reject and notify')]
        [string]$BlockAction,

        [ValidateSet('Allow without decryption', 'Drop', 'Reject')]
        [string]$UnrecognizedCiphers,

        [ValidateSet('Use SSL/TLS settings default', 'Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLConnectionsExceeded,

        [ValidateSet('Use SSL/TLS settings default', 'Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLv2SSLv3,

        [ValidateSet('Use SSL/TLS settings default', 'Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLCompression,

        [ValidateSet('RSA', 'DH', 'DHE', 'ECDH', 'ECDHE')]
        [string[]]$KeyExchangeAlgorithm,

        [ValidateSet('RSA', 'DSA', 'ECDSA', 'ANON')]
        [string[]]$AuthenticationAlgorithm,

        [ValidateSet('RC4', '3DES', 'IDEA', 'AES128', 'AES256', 'Camellia',
            'ChaCha20-Poly1305', 'GCM', 'CCM', 'CBC', 'NULL')]
        [string[]]$BlockAndStreamCipher,

        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384')]
        [string[]]$HashAlgorithm,

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

    $xmlDescription = ''
    if ($Description) {
        $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $xmlUseDefaultCAs = if ($UseDefaultCAs) { "<UseDefaultCAs>$UseDefaultCAs</UseDefaultCAs>" } else { '' }
    $xmlRSACA = if ($RSACA) { "<RSACA>$(ConvertTo-SfosXmlEscaped -Text $RSACA)</RSACA>" } else { '' }
    $xmlECCA = if ($ECCA) { "<ECCA>$(ConvertTo-SfosXmlEscaped -Text $ECCA)</ECCA>" } else { '' }
    $xmlBlockInvalidDate = if ($BlockInvalidDate) { "<BlockInvalidDate>$BlockInvalidDate</BlockInvalidDate>" } else { '' }
    $xmlBlockUntrustedIssuer = if ($BlockUntrustedIssuer) { "<BlockUntrustedIssuer>$BlockUntrustedIssuer</BlockUntrustedIssuer>" } else { '' }
    $xmlBlockSelfSigned = if ($BlockSelfSigned) { "<BlockSelfSigned>$BlockSelfSigned</BlockSelfSigned>" } else { '' }
    $xmlBlockRevoked = if ($BlockRevoked) { "<BlockRevoked>$BlockRevoked</BlockRevoked>" } else { '' }
    $xmlBlockNameMismatch = if ($BlockNameMismatch) { "<BlockNameMismatch>$BlockNameMismatch</BlockNameMismatch>" } else { '' }
    $xmlBlockOtherReasons = if ($BlockOtherReasons) { "<BlockOtherReasons>$BlockOtherReasons</BlockOtherReasons>" } else { '' }
    $xmlMinRSAKeySize = if ($MinRSAKeySize) { "<MinRSAKeySize>$(ConvertTo-SfosXmlEscaped -Text $MinRSAKeySize)</MinRSAKeySize>" } else { '' }
    # The firewall only accepts the two TLS version bounds together. A request that carries
    # just one of them is refused, so the missing half is filled in with the widest value.
    $effMinTLSVersion = $MinTLSVersion
    $effMaxTLSVersion = $MaxTLSVersion
    if ($effMinTLSVersion -and -not $effMaxTLSVersion) { $effMaxTLSVersion = 'Maximum supported' }
    if ($effMaxTLSVersion -and -not $effMinTLSVersion) { $effMinTLSVersion = 'TLS v1.0' }

    $xmlMinTLSVersion = if ($effMinTLSVersion) { "<MinTLSVersion>$(ConvertTo-SfosXmlEscaped -Text $effMinTLSVersion)</MinTLSVersion>" } else { '' }
    $xmlMaxTLSVersion = if ($effMaxTLSVersion) { "<MaxTLSVersion>$(ConvertTo-SfosXmlEscaped -Text $effMaxTLSVersion)</MaxTLSVersion>" } else { '' }
    $xmlBlockAction = if ($BlockAction) { "<BlockAction>$(ConvertTo-SfosXmlEscaped -Text $BlockAction)</BlockAction>" } else { '' }
    $xmlUnrecognizedCiphers = if ($UnrecognizedCiphers) { "<UnrecognizedCiphers>$(ConvertTo-SfosXmlEscaped -Text $UnrecognizedCiphers)</UnrecognizedCiphers>" } else { '' }
    $xmlSSLConnectionsExceeded = if ($SSLConnectionsExceeded) { "<SSLConnectionsExceeded>$(ConvertTo-SfosXmlEscaped -Text $SSLConnectionsExceeded)</SSLConnectionsExceeded>" } else { '' }
    $xmlSSLv2SSLv3 = if ($SSLv2SSLv3) { "<SSLv2SSLv3>$(ConvertTo-SfosXmlEscaped -Text $SSLv2SSLv3)</SSLv2SSLv3>" } else { '' }
    $xmlSSLCompression = if ($SSLCompression) { "<SSLCompression>$(ConvertTo-SfosXmlEscaped -Text $SSLCompression)</SSLCompression>" } else { '' }

    $xmlBlockedAlgorithmList = ConvertTo-SfosBlockedAlgorithmListXml -KeyExchangeAlgorithm $KeyExchangeAlgorithm `
        -AuthenticationAlgorithm $AuthenticationAlgorithm -BlockAndStreamCipher $BlockAndStreamCipher -HashAlgorithm $HashAlgorithm

    # IsDefault wird bewusst nicht gesendet - in der Abnahme klaeren
    $inner = @"
<Set operation="add">
    <DecryptionProfile>
        <Name>$nameEsc</Name>
        $xmlDescription
        $xmlUseDefaultCAs
        $xmlRSACA
        $xmlECCA
        $xmlBlockInvalidDate
        $xmlBlockUntrustedIssuer
        $xmlBlockSelfSigned
        $xmlBlockRevoked
        $xmlBlockNameMismatch
        $xmlBlockOtherReasons
        $xmlMinRSAKeySize
        $xmlMinTLSVersion
        $xmlMaxTLSVersion
        $xmlBlockAction
        $xmlUnrecognizedCiphers
        $xmlSSLConnectionsExceeded
        $xmlSSLv2SSLv3
        $xmlSSLCompression
        $xmlBlockedAlgorithmList
    </DecryptionProfile>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("DecryptionProfile '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create DecryptionProfile object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DecryptionProfile' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates a decryption profile object on a Sophos Firewall.

        .DESCRIPTION
        Changes an existing decryption profile. The cmdlet reads the current profile first and
        sends back a complete object, keeping every field the caller does not pass, including
        every list of blocked algorithms. Only the fields you actually supply are changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with administrative permission.

        This cmdlet never sends IsDefault, for the same reason New-SfosDecryptionProfile does
        not: the vendor documentation marks it read-only. The current IsDefault status is
        therefore left to the firewall on every update.

        .PARAMETER Name
        Required. Name of the profile to update. Accepts pipeline input by value or by
        property name, so the output of Get-SfosDecryptionProfile can be piped in directly.

        .PARAMETER Description
        Optional. Free-text description, up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER UseDefaultCAs
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER RSACA
        Optional. Name of a custom RSA certificate authority. If omitted, the current value is
        kept. Pass an empty string to clear it.

        .PARAMETER ECCA
        Optional. Name of a custom elliptic-curve certificate authority. If omitted, the
        current value is kept. Pass an empty string to clear it.

        .PARAMETER BlockInvalidDate
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER BlockUntrustedIssuer
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER BlockSelfSigned
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER BlockRevoked
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER BlockNameMismatch
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER BlockOtherReasons
        Optional. yes or no. If omitted, the current value is kept.

        .PARAMETER MinRSAKeySize
        Optional. No minimum, 1024 or 2048. If omitted, the current value is kept.

        .PARAMETER MinTLSVersion
        Optional. TLS v1.0, TLS v1.1, TLS v1.2 or TLS v1.3. If omitted, the current value is
        kept.

        .PARAMETER MaxTLSVersion
        Optional. TLS v1.0, TLS v1.1, TLS v1.2, TLS v1.3 or Maximum supported. If omitted, the
        current value is kept.

        .PARAMETER BlockAction
        Optional. Drop, Reject or Reject and notify. If omitted, the current value is kept.

        .PARAMETER UnrecognizedCiphers
        Optional. Allow without decryption, Drop or Reject. If omitted, the current value is
        kept.

        .PARAMETER SSLConnectionsExceeded
        Optional. Use SSL/TLS settings default, Allow without decryption, Drop or Reject. If
        omitted, the current value is kept.

        .PARAMETER SSLv2SSLv3
        Optional. Use SSL/TLS settings default, Allow without decryption, Drop or Reject. If
        omitted, the current value is kept.

        .PARAMETER SSLCompression
        Optional. Use SSL/TLS settings default, Allow without decryption, Drop or Reject. If
        omitted, the current value is kept.

        .PARAMETER KeyExchangeAlgorithm
        Optional. Replaces the current list of blocked key exchange algorithms. If omitted,
        the current list is kept. Pass an empty array to clear it.

        .PARAMETER AuthenticationAlgorithm
        Optional. Replaces the current list of blocked authentication algorithms. If omitted,
        the current list is kept. Pass an empty array to clear it.

        .PARAMETER BlockAndStreamCipher
        Optional. Replaces the current list of blocked block and stream ciphers. If omitted,
        the current list is kept. Pass an empty array to clear it.

        .PARAMETER HashAlgorithm
        Optional. Replaces the current list of blocked hash algorithms. If omitted, the
        current list is kept. Pass an empty array to clear it.

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
        other properties, by property name, of a decryption profile object such as the ones
        returned by Get-SfosDecryptionProfile.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosDecryptionProfile -Name 'Custom strict' -MinTLSVersion 'TLS v1.3' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDecryptionProfile -Name 'Custom strict' -MinTLSVersion 'TLS v1.3'

        Raises the minimum accepted TLS version of an existing profile.

        .EXAMPLE
        Get-SfosDecryptionProfile -NameLike 'No weak ciphers' | Set-SfosDecryptionProfile -HashAlgorithm 'MD5','SHA1'

        Reads the matching profile and adds SHA1 to its blocked hash algorithms through the
        pipeline. The passed list replaces the current one, so MD5 has to be repeated to stay
        blocked.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDecryptionProfile

        .LINK
        New-SfosDecryptionProfile
#>
function Set-SfosDecryptionProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$UseDefaultCAs,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$RSACA,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$ECCA,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$BlockInvalidDate,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$BlockUntrustedIssuer,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$BlockSelfSigned,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$BlockRevoked,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$BlockNameMismatch,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('yes', 'no')]
        [string]$BlockOtherReasons,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('No minimum', '1024', '2048')]
        [string]$MinRSAKeySize,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('TLS v1.0', 'TLS v1.1', 'TLS v1.2', 'TLS v1.3')]
        [string]$MinTLSVersion,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('TLS v1.0', 'TLS v1.1', 'TLS v1.2', 'TLS v1.3', 'Maximum supported')]
        [string]$MaxTLSVersion,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Drop', 'Reject', 'Reject and notify')]
        [string]$BlockAction,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Allow without decryption', 'Drop', 'Reject')]
        [string]$UnrecognizedCiphers,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Use SSL/TLS settings default', 'Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLConnectionsExceeded,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Use SSL/TLS settings default', 'Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLv2SSLv3,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Use SSL/TLS settings default', 'Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLCompression,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('RSA', 'DH', 'DHE', 'ECDH', 'ECDHE')]
        [string[]]$KeyExchangeAlgorithm,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('RSA', 'DSA', 'ECDSA', 'ANON')]
        [string[]]$AuthenticationAlgorithm,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('RC4', '3DES', 'IDEA', 'AES128', 'AES256', 'Camellia',
            'ChaCha20-Poly1305', 'GCM', 'CCM', 'CBC', 'NULL')]
        [string[]]$BlockAndStreamCipher,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384')]
        [string[]]$HashAlgorithm,

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

        $existing = @(Get-SfosDecryptionProfile -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The DecryptionProfile object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetUseDefaultCAs = if ($PSBoundParameters.ContainsKey('UseDefaultCAs')) { $UseDefaultCAs } else { [string]$existing[0].UseDefaultCAs }
        $targetRSACA = if ($PSBoundParameters.ContainsKey('RSACA')) { $RSACA } else { [string]$existing[0].RSACA }
        $targetECCA = if ($PSBoundParameters.ContainsKey('ECCA')) { $ECCA } else { [string]$existing[0].ECCA }
        $targetBlockInvalidDate = if ($PSBoundParameters.ContainsKey('BlockInvalidDate')) { $BlockInvalidDate } else { [string]$existing[0].BlockInvalidDate }
        $targetBlockUntrustedIssuer = if ($PSBoundParameters.ContainsKey('BlockUntrustedIssuer')) { $BlockUntrustedIssuer } else { [string]$existing[0].BlockUntrustedIssuer }
        $targetBlockSelfSigned = if ($PSBoundParameters.ContainsKey('BlockSelfSigned')) { $BlockSelfSigned } else { [string]$existing[0].BlockSelfSigned }
        $targetBlockRevoked = if ($PSBoundParameters.ContainsKey('BlockRevoked')) { $BlockRevoked } else { [string]$existing[0].BlockRevoked }
        $targetBlockNameMismatch = if ($PSBoundParameters.ContainsKey('BlockNameMismatch')) { $BlockNameMismatch } else { [string]$existing[0].BlockNameMismatch }
        $targetBlockOtherReasons = if ($PSBoundParameters.ContainsKey('BlockOtherReasons')) { $BlockOtherReasons } else { [string]$existing[0].BlockOtherReasons }
        $targetMinRSAKeySize = if ($PSBoundParameters.ContainsKey('MinRSAKeySize')) { $MinRSAKeySize } else { [string]$existing[0].MinRSAKeySize }
        $targetMinTLSVersion = if ($PSBoundParameters.ContainsKey('MinTLSVersion')) { $MinTLSVersion } else { [string]$existing[0].MinTLSVersion }
        $targetMaxTLSVersion = if ($PSBoundParameters.ContainsKey('MaxTLSVersion')) { $MaxTLSVersion } else { [string]$existing[0].MaxTLSVersion }
        $targetBlockAction = if ($PSBoundParameters.ContainsKey('BlockAction')) { $BlockAction } else { [string]$existing[0].BlockAction }
        $targetUnrecognizedCiphers = if ($PSBoundParameters.ContainsKey('UnrecognizedCiphers')) { $UnrecognizedCiphers } else { [string]$existing[0].UnrecognizedCiphers }
        $targetSSLConnectionsExceeded = if ($PSBoundParameters.ContainsKey('SSLConnectionsExceeded')) { $SSLConnectionsExceeded } else { [string]$existing[0].SSLConnectionsExceeded }
        $targetSSLv2SSLv3 = if ($PSBoundParameters.ContainsKey('SSLv2SSLv3')) { $SSLv2SSLv3 } else { [string]$existing[0].SSLv2SSLv3 }
        $targetSSLCompression = if ($PSBoundParameters.ContainsKey('SSLCompression')) { $SSLCompression } else { [string]$existing[0].SSLCompression }

        $targetKeyExchange = if ($PSBoundParameters.ContainsKey('KeyExchangeAlgorithm')) { @($KeyExchangeAlgorithm) } else { @($existing[0].KeyExchangeAlgorithm) }
        $targetAuthentication = if ($PSBoundParameters.ContainsKey('AuthenticationAlgorithm')) { @($AuthenticationAlgorithm) } else { @($existing[0].AuthenticationAlgorithm) }
        $targetCipher = if ($PSBoundParameters.ContainsKey('BlockAndStreamCipher')) { @($BlockAndStreamCipher) } else { @($existing[0].BlockAndStreamCipher) }
        $targetHash = if ($PSBoundParameters.ContainsKey('HashAlgorithm')) { @($HashAlgorithm) } else { @($existing[0].HashAlgorithm) }

        $xmlDescription = if ($targetDescription) { "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>" } else { '' }
        $xmlUseDefaultCAs = if ($targetUseDefaultCAs) { "<UseDefaultCAs>$targetUseDefaultCAs</UseDefaultCAs>" } else { '' }
        $xmlRSACA = if ($targetRSACA) { "<RSACA>$(ConvertTo-SfosXmlEscaped -Text $targetRSACA)</RSACA>" } else { '' }
        $xmlECCA = if ($targetECCA) { "<ECCA>$(ConvertTo-SfosXmlEscaped -Text $targetECCA)</ECCA>" } else { '' }
        $xmlBlockInvalidDate = if ($targetBlockInvalidDate) { "<BlockInvalidDate>$targetBlockInvalidDate</BlockInvalidDate>" } else { '' }
        $xmlBlockUntrustedIssuer = if ($targetBlockUntrustedIssuer) { "<BlockUntrustedIssuer>$targetBlockUntrustedIssuer</BlockUntrustedIssuer>" } else { '' }
        $xmlBlockSelfSigned = if ($targetBlockSelfSigned) { "<BlockSelfSigned>$targetBlockSelfSigned</BlockSelfSigned>" } else { '' }
        $xmlBlockRevoked = if ($targetBlockRevoked) { "<BlockRevoked>$targetBlockRevoked</BlockRevoked>" } else { '' }
        $xmlBlockNameMismatch = if ($targetBlockNameMismatch) { "<BlockNameMismatch>$targetBlockNameMismatch</BlockNameMismatch>" } else { '' }
        $xmlBlockOtherReasons = if ($targetBlockOtherReasons) { "<BlockOtherReasons>$targetBlockOtherReasons</BlockOtherReasons>" } else { '' }
        $xmlMinRSAKeySize = if ($targetMinRSAKeySize) { "<MinRSAKeySize>$(ConvertTo-SfosXmlEscaped -Text $targetMinRSAKeySize)</MinRSAKeySize>" } else { '' }
        $xmlMinTLSVersion = if ($targetMinTLSVersion) { "<MinTLSVersion>$(ConvertTo-SfosXmlEscaped -Text $targetMinTLSVersion)</MinTLSVersion>" } else { '' }
        $xmlMaxTLSVersion = if ($targetMaxTLSVersion) { "<MaxTLSVersion>$(ConvertTo-SfosXmlEscaped -Text $targetMaxTLSVersion)</MaxTLSVersion>" } else { '' }
        $xmlBlockAction = if ($targetBlockAction) { "<BlockAction>$(ConvertTo-SfosXmlEscaped -Text $targetBlockAction)</BlockAction>" } else { '' }
        $xmlUnrecognizedCiphers = if ($targetUnrecognizedCiphers) { "<UnrecognizedCiphers>$(ConvertTo-SfosXmlEscaped -Text $targetUnrecognizedCiphers)</UnrecognizedCiphers>" } else { '' }
        $xmlSSLConnectionsExceeded = if ($targetSSLConnectionsExceeded) { "<SSLConnectionsExceeded>$(ConvertTo-SfosXmlEscaped -Text $targetSSLConnectionsExceeded)</SSLConnectionsExceeded>" } else { '' }
        $xmlSSLv2SSLv3 = if ($targetSSLv2SSLv3) { "<SSLv2SSLv3>$(ConvertTo-SfosXmlEscaped -Text $targetSSLv2SSLv3)</SSLv2SSLv3>" } else { '' }
        $xmlSSLCompression = if ($targetSSLCompression) { "<SSLCompression>$(ConvertTo-SfosXmlEscaped -Text $targetSSLCompression)</SSLCompression>" } else { '' }

        $xmlBlockedAlgorithmList = ConvertTo-SfosBlockedAlgorithmListXml -KeyExchangeAlgorithm $targetKeyExchange `
            -AuthenticationAlgorithm $targetAuthentication -BlockAndStreamCipher $targetCipher -HashAlgorithm $targetHash

        # IsDefault wird bewusst nicht gesendet - in der Abnahme klaeren
        $inner = @"
<Set operation="update">
    <DecryptionProfile>
        <Name>$nameEsc</Name>
        $xmlDescription
        $xmlUseDefaultCAs
        $xmlRSACA
        $xmlECCA
        $xmlBlockInvalidDate
        $xmlBlockUntrustedIssuer
        $xmlBlockSelfSigned
        $xmlBlockRevoked
        $xmlBlockNameMismatch
        $xmlBlockOtherReasons
        $xmlMinRSAKeySize
        $xmlMinTLSVersion
        $xmlMaxTLSVersion
        $xmlBlockAction
        $xmlUnrecognizedCiphers
        $xmlSSLConnectionsExceeded
        $xmlSSLv2SSLv3
        $xmlSSLCompression
        $xmlBlockedAlgorithmList
    </DecryptionProfile>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("DecryptionProfile '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Failed to update DecryptionProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DecryptionProfile' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a decryption profile object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a decryption profile by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission. Use -WhatIf to preview the removal.

        .PARAMETER Name
        Required. Name of the profile to remove. Accepts pipeline input by value or by
        property name, so the output of Get-SfosDecryptionProfile can be piped in directly.

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
        decryption profile object such as the ones returned by Get-SfosDecryptionProfile.

        .OUTPUTS
        None. The cmdlet writes no output and throws an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosDecryptionProfile -Name 'Custom strict' -WhatIf

        Shows what would be removed without sending the call to the firewall.

        .EXAMPLE
        Get-SfosDecryptionProfile -NameLike 'Test' | Remove-SfosDecryptionProfile -WhatIf

        Previews the removal of every profile whose name contains 'Test'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDecryptionProfile
#>
function Remove-SfosDecryptionProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        if (-not $PSCmdlet.ShouldProcess("DecryptionProfile '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <DecryptionProfile>
    <Name>$nameEsc</Name>
  </DecryptionProfile>
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
            throw "Error removing DecryptionProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DecryptionProfile' -Action 'remove' -Target $Name
    }
}

#endregion DecryptionProfile

#region AdministrationProfile
# An AdministrationProfile is a ROLE: it defines which areas of the web admin console an
# administrator account may see and change, at one of three levels per area - Read-Write,
# Read-Only or None. It is unrelated to ApplianceAccess, which is the service/zone matrix
# controlling where the management services themselves may be reached from.
#
# Wire root <AdministrationProfile>, confirmed live. Ten profiles exist on the reference
# appliance, five of them carrying a leading underscore and an "_system_created" suffix
# (_administrator_system_created, _helpdesk_system_created, _readonly_system_created,
# _partner_access_system_created, _super_admin_system_created). All ten are built-in
# reference objects and out of scope for write testing.
#
# The live object holds 50 permission fields: 14 directly under AdministrationProfile, plus
# 36 more nested under six wrapper elements (System 15, WirelessProtection 5, Identity 7,
# VPN 2, WAF 2, LogsReports 5). The vendor documentation table for this entity covers none
# of them individually - only a generic "Listofentityrole" placeholder - and the sample XML
# in the same documentation carries 16 further fields (SetSystemProfile, SetIdentityProfile,
# ExportUsers, Users, AdministratorUsers, SetVPNProfile, SetWAFProfile, a complete AntiVirus
# block, a complete AntiSpam block, SetLogsReportsProfile) that do not appear on the live
# object at all. Those sample-only fields are deliberately not implemented here - sending a
# field that may no longer exist on this firmware cannot be verified, and guessing at its
# effect is how the CountryHostGroup defect happened. Two further fields are documentation
# gaps in the other direction, present live but absent from the sample: EmailProtection and
# the entire WirelessProtection block. Both are implemented, since a live object is the
# strongest of the three sources.
#
# All 50 fields share one confirmed value set: Read-Write, Read-Only, None.
#
# Two wire names collide with a connection parameter every cmdlet in this suite already
# uses, so the PowerShell parameter is renamed on those two only (the wire element itself is
# unchanged): <Firewall> (a flat field, permission for the firewall rules area) becomes
# -FirewallAccess, because -Firewall is the appliance host name/address parameter; and
# <System><Password> (permission to change one's own administrator password) becomes
# -PasswordAccess, because -Password is the API login credential parameter. Every other
# parameter name matches its wire element name exactly, including the API's own double
# "Network" in WirelessProtectionNetworkNetwork and the hyphens in Four-EyeAuthenticationSettings
# and De-Anonymization (renamed to -FourEyeAuthenticationSettings and -DeAnonymization only
# because PowerShell parameter names cannot contain a hyphen; the wire element keeps it).
#
# A write replaces the whole role. Set-SfosAdministrationProfile therefore reads the current
# profile first and sends all 50 fields back, changing only the ones actually passed -
# anything else would silently strip permissions from an existing role, the most damaging
# form of data loss this API can produce. Removing or misconfiguring a profile that is
# currently assigned to an administrator account can lock that account out of the areas it
# needs, or out of the web admin and API entirely if the account signed in right now depends
# on it; there is no automatic guard against this, only the ConfirmImpact on Set and Remove.

<#
.SYNOPSIS
    Lists the permission fields and their wire mapping for AdministrationProfile. Internal
    helper, not exported.

.DESCRIPTION
    Returns one entry per confirmed live permission field: the PowerShell parameter name
    (Param), the wire element name (Wire), and the wrapper element it lives under, or $null
    for a field directly under AdministrationProfile (Group). Used by
    Get-SfosAdministrationProfile to read a profile and by
    Format-SfosAdministrationProfileInnerXml to write one, so both sides stay in sync with a
    single list.
#>
function Get-SfosAdministrationProfileFieldMap {
    [CmdletBinding()]
    param()

    return @(
        @{ Param = 'Dashboard'; Wire = 'Dashboard'; Group = $null }
        @{ Param = 'Wizard'; Wire = 'Wizard'; Group = $null }
        @{ Param = 'Objects'; Wire = 'Objects'; Group = $null }
        @{ Param = 'Network'; Wire = 'Network'; Group = $null }
        @{ Param = 'FirewallAccess'; Wire = 'Firewall'; Group = $null }
        @{ Param = 'IPS'; Wire = 'IPS'; Group = $null }
        @{ Param = 'WebFilter'; Wire = 'WebFilter'; Group = $null }
        @{ Param = 'CloudApplicationDashboard'; Wire = 'CloudApplicationDashboard'; Group = $null }
        @{ Param = 'ZeroDayProtection'; Wire = 'ZeroDayProtection'; Group = $null }
        @{ Param = 'ApplicationFilter'; Wire = 'ApplicationFilter'; Group = $null }
        @{ Param = 'IM'; Wire = 'IM'; Group = $null }
        @{ Param = 'QoS'; Wire = 'QoS'; Group = $null }
        @{ Param = 'EmailProtection'; Wire = 'EmailProtection'; Group = $null }
        @{ Param = 'TrafficDiscovery'; Wire = 'TrafficDiscovery'; Group = $null }

        @{ Param = 'ProfileAccess'; Wire = 'Profile'; Group = 'System' }
        @{ Param = 'PasswordAccess'; Wire = 'Password'; Group = 'System' }
        @{ Param = 'CentralManagement'; Wire = 'CentralManagement'; Group = 'System' }
        @{ Param = 'Backup'; Wire = 'Backup'; Group = 'System' }
        @{ Param = 'Restore'; Wire = 'Restore'; Group = 'System' }
        @{ Param = 'Firmware'; Wire = 'Firmware'; Group = 'System' }
        @{ Param = 'Licensing'; Wire = 'Licensing'; Group = 'System' }
        @{ Param = 'Services'; Wire = 'Services'; Group = 'System' }
        @{ Param = 'Updates'; Wire = 'Updates'; Group = 'System' }
        @{ Param = 'RebootShutdown'; Wire = 'RebootShutdown'; Group = 'System' }
        @{ Param = 'HA'; Wire = 'HA'; Group = 'System' }
        @{ Param = 'DownloadCertificates'; Wire = 'DownloadCertificates'; Group = 'System' }
        @{ Param = 'OtherCertificateConfiguration'; Wire = 'OtherCertificateConfiguration'; Group = 'System' }
        @{ Param = 'Diagnostics'; Wire = 'Diagnostics'; Group = 'System' }
        @{ Param = 'OtherSystemConfiguration'; Wire = 'OtherSystemConfiguration'; Group = 'System' }

        @{ Param = 'WirelessProtectionOverview'; Wire = 'WirelessProtectionOverview'; Group = 'WirelessProtection' }
        @{ Param = 'WirelessProtectionSettings'; Wire = 'WirelessProtectionSettings'; Group = 'WirelessProtection' }
        @{ Param = 'WirelessProtectionNetworkNetwork'; Wire = 'WirelessProtectionNetworkNetwork'; Group = 'WirelessProtection' }
        @{ Param = 'WirelessProtectionAccessPoint'; Wire = 'WirelessProtectionAccessPoint'; Group = 'WirelessProtection' }
        @{ Param = 'WirelessProtectionMesh'; Wire = 'WirelessProtectionMesh'; Group = 'WirelessProtection' }

        @{ Param = 'Authentication'; Wire = 'Authentication'; Group = 'Identity' }
        @{ Param = 'Groups'; Wire = 'Groups'; Group = 'Identity' }
        @{ Param = 'GuestUsersManagement'; Wire = 'GuestUsersManagement'; Group = 'Identity' }
        @{ Param = 'OtherGuestUserSettings'; Wire = 'OtherGuestUserSettings'; Group = 'Identity' }
        @{ Param = 'Policy'; Wire = 'Policy'; Group = 'Identity' }
        @{ Param = 'TestExternalServerConnectivity'; Wire = 'TestExternalServerConnectivity'; Group = 'Identity' }
        @{ Param = 'ManageLiveUser'; Wire = 'ManageLiveUser'; Group = 'Identity' }

        @{ Param = 'ConnectTunnel'; Wire = 'ConnectTunnel'; Group = 'VPN' }
        @{ Param = 'OtherVPNConfigurations'; Wire = 'OtherVPNConfigurations'; Group = 'VPN' }

        @{ Param = 'Alerts'; Wire = 'Alerts'; Group = 'WAF' }
        @{ Param = 'OtherWAFConfiguration'; Wire = 'OtherWAFConfiguration'; Group = 'WAF' }

        @{ Param = 'Configuration'; Wire = 'Configuration'; Group = 'LogsReports' }
        @{ Param = 'LogViewer'; Wire = 'LogViewer'; Group = 'LogsReports' }
        @{ Param = 'ReportsAccess'; Wire = 'ReportsAccess'; Group = 'LogsReports' }
        @{ Param = 'FourEyeAuthenticationSettings'; Wire = 'Four-EyeAuthenticationSettings'; Group = 'LogsReports' }
        @{ Param = 'DeAnonymization'; Wire = 'De-Anonymization'; Group = 'LogsReports' }
    )
}

<#
.SYNOPSIS
    Builds the Set request body for an AdministrationProfile object. Internal helper, not
    exported.

.DESCRIPTION
    Renders Name and all 50 permission fields, grouped under their wrapper elements, from a
    resolved value table. Shared by New-SfosAdministrationProfile (operation "add") and
    Set-SfosAdministrationProfile (operation "update") so both send the identical full shape.

.PARAMETER Name
    Required. Profile name, not yet XML-escaped.

.PARAMETER Values
    Required. Hashtable keyed by parameter name (see Get-SfosAdministrationProfileFieldMap)
    holding the resolved value for every one of the 50 fields.

.PARAMETER Operation
    Required. Either 'add' or 'update'.
#>
function Format-SfosAdministrationProfileInnerXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [hashtable]$Values,

        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $fieldMap = Get-SfosAdministrationProfileFieldMap

    $flatXml = ($fieldMap | Where-Object { -not $_.Group } | ForEach-Object {
            $valueEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Values[$_.Param])
            "  <$($_.Wire)>$valueEsc</$($_.Wire)>"
        }) -join "`n"

    $groupOrder = @('System', 'WirelessProtection', 'Identity', 'VPN', 'WAF', 'LogsReports')
    $groupsXml = ($groupOrder | ForEach-Object {
            $groupName = $_
            $groupFieldsXml = ($fieldMap | Where-Object { $_.Group -eq $groupName } | ForEach-Object {
                    $valueEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Values[$_.Param])
                    "    <$($_.Wire)>$valueEsc</$($_.Wire)>"
                }) -join "`n"
            "  <$groupName>`n$groupFieldsXml`n  </$groupName>"
        }) -join "`n"

    return @"
<Set operation="$Operation">
<AdministrationProfile>
  <Name>$nameEsc</Name>
$flatXml
$groupsXml
</AdministrationProfile>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves administration profiles from a Sophos Firewall.

.DESCRIPTION
    Returns the AdministrationProfile roles defined on the firewall. A role controls which
    areas of the web admin console an administrator account may see and change, at one of
    Read-Write, Read-Only or None per area. Use this cmdlet to review an existing role before
    changing it with Set-SfosAdministrationProfile, to feed it into New-SfosAdministrationProfile
    on a second firewall, or to check what a role grants before assigning it to an account.
    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only profiles whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
    characters. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for
    administration profiles. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per profile, with the property
    Name plus all 50 permission fields listed in Get-SfosAdministrationProfileFieldMap.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no profile
    matches.

.EXAMPLE
    Get-SfosAdministrationProfile

    Lists every administration profile on the firewall of the current connection.

.EXAMPLE
    Get-SfosAdministrationProfile -NameLike 'Admin'

    Lists all profiles whose name contains 'Admin'.

.EXAMPLE
    (Get-SfosAdministrationProfile -NameLike 'Security Admin').FirewallAccess

    Shows the access level the 'Security Admin' profile grants for the firewall rules area.

.EXAMPLE
    $fw2 = Connect-SfosFirewall -Firewall 'fw2.example.com' -Credential $cred
    Get-SfosAdministrationProfile -NameLike 'Security Admin' | New-SfosAdministrationProfile -Session $fw2

    Copies the matching profile to a second firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosAdministrationProfile

.LINK
    Set-SfosAdministrationProfile
#>
function Get-SfosAdministrationProfile {
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

    $keyXml = ''
    if ($PSBoundParameters.ContainsKey('NameLike') -and $NameLike) {
        $keyXml = "<Filter><key name=`"Name`" criteria=`"like`">$(ConvertTo-SfosXmlEscaped -Text $NameLike)</key></Filter>"
    }

    $inner = "<Get><AdministrationProfile>$keyXml</AdministrationProfile></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AdministrationProfile objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdministrationProfile' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/AdministrationProfile'))

    if ($NameLike) {
        $nodes = @($nodes | Where-Object { [string]$_.SelectSingleNode('Name').InnerText -like "*$NameLike*" })
    }

    if ($AsXml) {
        return $nodes
    }

    $fieldMap = Get-SfosAdministrationProfileFieldMap

    return @($nodes | ForEach-Object {
            $node = $_
            $result = [ordered]@{ Name = [string]$node.SelectSingleNode('Name').InnerText }
            foreach ($field in $fieldMap) {
                $xpath = if ($field.Group) { "$($field.Group)/$($field.Wire)" } else { $field.Wire }
                $valueNode = $node.SelectSingleNode($xpath)
                $result[$field.Param] = if ($valueNode) { [string]$valueNode.InnerText } else { $null }
            }
            [PSCustomObject]$result
        })
}

<#
.SYNOPSIS
    Creates an administration profile on a Sophos Firewall.

.DESCRIPTION
    Adds an AdministrationProfile role under SYSTEM > Profile > Administration. A role
    controls which areas of the web admin console an administrator account may see and
    change, at one of Read-Write, Read-Only or None per area, across 50 individually
    settable areas. Any area you do not pass is created as None - the least-privilege
    default - so a role only grants what you explicitly asked for. Assign the finished role
    to an administrator account to grant it these permissions; creating the role by itself
    changes nothing for any account. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Name
    Required. Name of the new profile. Maximum 50 characters, may not contain a comma.

.PARAMETER Dashboard
    Optional. Access level for the Dashboard area. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER Wizard
    Optional. Access level for the setup wizard. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER Objects
    Optional. Access level for host, service and other reusable objects. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER Network
    Optional. Access level for network configuration (interfaces, zones, routing). One of
    Read-Write, Read-Only, None. If omitted, the area is created with None.

.PARAMETER FirewallAccess
    Optional. Access level for the firewall rules area. Wire element Firewall, renamed here
    because -Firewall already names the connection parameter. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER IPS
    Optional. Access level for intrusion prevention. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER WebFilter
    Optional. Access level for web filtering. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER CloudApplicationDashboard
    Optional. Access level for the cloud application dashboard. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER ZeroDayProtection
    Optional. Access level for zero-day protection. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER ApplicationFilter
    Optional. Access level for application filtering. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER IM
    Optional. Access level for instant messaging control. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER QoS
    Optional. Access level for quality of service (traffic shaping). One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER EmailProtection
    Optional. Access level for email protection. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER TrafficDiscovery
    Optional. Access level for traffic discovery. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER Profile
    Optional. Access level for administration profile management (this entity itself). One
    of Read-Write, Read-Only, None. If omitted, the area is created with None.

.PARAMETER PasswordAccess
    Optional. Access level for changing the administrator's own password. Wire element
    System/Password, renamed here because -Password already names the connection parameter.
    One of Read-Write, Read-Only, None. If omitted, the area is created with None.

.PARAMETER CentralManagement
    Optional. Access level for central management. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER Backup
    Optional. Access level for backup. One of Read-Write, Read-Only, None. If omitted, the
    area is created with None.

.PARAMETER Restore
    Optional. Access level for restore. One of Read-Write, Read-Only, None. If omitted, the
    area is created with None.

.PARAMETER Firmware
    Optional. Access level for firmware management. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER Licensing
    Optional. Access level for licensing. One of Read-Write, Read-Only, None. If omitted,
    the area is created with None.

.PARAMETER Services
    Optional. Access level for system services. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER Updates
    Optional. Access level for pattern and firmware updates. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER RebootShutdown
    Optional. Access level for reboot and shutdown. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER HA
    Optional. Access level for high availability configuration. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER DownloadCertificates
    Optional. Access level for downloading certificates. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER OtherCertificateConfiguration
    Optional. Access level for other certificate configuration. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER Diagnostics
    Optional. Access level for diagnostics. One of Read-Write, Read-Only, None. If omitted,
    the area is created with None.

.PARAMETER OtherSystemConfiguration
    Optional. Access level for other system configuration. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER WirelessProtectionOverview
    Optional. Access level for the wireless protection overview. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER WirelessProtectionSettings
    Optional. Access level for wireless protection settings. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER WirelessProtectionNetworkNetwork
    Optional. Access level for wireless network configuration. The doubled "Network" in the
    name is the spelling the API itself uses. One of Read-Write, Read-Only, None. If omitted,
    the area is created with None.

.PARAMETER WirelessProtectionAccessPoint
    Optional. Access level for wireless access point management. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER WirelessProtectionMesh
    Optional. Access level for wireless mesh configuration. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER Authentication
    Optional. Access level for authentication server configuration. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER Groups
    Optional. Access level for user group configuration. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER GuestUsersManagement
    Optional. Access level for guest user management. One of Read-Write, Read-Only, None.
    If omitted, the area is created with None.

.PARAMETER OtherGuestUserSettings
    Optional. Access level for other guest user settings. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER Policy
    Optional. Access level for identity policy configuration. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER TestExternalServerConnectivity
    Optional. Access level for testing external authentication server connectivity. One of
    Read-Write, Read-Only, None. If omitted, the area is created with None.

.PARAMETER ManageLiveUser
    Optional. Access level for managing live user sessions. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER ConnectTunnel
    Optional. Access level for connecting VPN tunnels. One of Read-Write, Read-Only, None.
    If omitted, the area is created with None.

.PARAMETER OtherVPNConfigurations
    Optional. Access level for other VPN configuration. One of Read-Write, Read-Only, None.
    If omitted, the area is created with None.

.PARAMETER Alerts
    Optional. Access level for web application firewall alerts. One of Read-Write,
    Read-Only, None. If omitted, the area is created with None.

.PARAMETER OtherWAFConfiguration
    Optional. Access level for other web application firewall configuration. One of
    Read-Write, Read-Only, None. If omitted, the area is created with None.

.PARAMETER Configuration
    Optional. Access level for logs and reports configuration. One of Read-Write, Read-Only,
    None. If omitted, the area is created with None.

.PARAMETER LogViewer
    Optional. Access level for the log viewer. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER ReportsAccess
    Optional. Access level for reports access. One of Read-Write, Read-Only, None. If
    omitted, the area is created with None.

.PARAMETER FourEyeAuthenticationSettings
    Optional. Access level for four-eye authentication settings on reports. Wire element
    Four-EyeAuthenticationSettings, renamed here because PowerShell parameter names cannot
    contain a hyphen. One of Read-Write, Read-Only, None. If omitted, the area is created
    with None.

.PARAMETER DeAnonymization
    Optional. Access level for de-anonymization of reports. Wire element
    De-Anonymization, renamed here because PowerShell parameter names cannot contain a
    hyphen. One of Read-Write, Read-Only, None. If omitted, the area is created with None.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an object with a Name property and
    optionally matching field properties, such as one returned by Get-SfosAdministrationProfile,
    through the pipeline by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Only -LogViewer Read-Only -ReportsAccess Read-Only -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Only -LogViewer Read-Only -ReportsAccess Read-Only

    Creates a role that can only view the dashboard and reports. Every other area is created
    with None.

.EXAMPLE
    Get-SfosAdministrationProfile -NameLike 'Security Admin' | New-SfosAdministrationProfile -Name 'Security Admin Copy'

    Reads an existing profile and creates a copy of it under a new name.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosAdministrationProfile

.LINK
    Set-SfosAdministrationProfile
#>
function New-SfosAdministrationProfile {
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Username/Password are the fixed connection parameters every write cmdlet in this suite takes; PasswordAccess is an unrelated permission-level field (Read-Write/Read-Only/None), not a credential.')]
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingPlainTextForPassword', '', Justification = 'PasswordAccess holds one of Read-Write/Read-Only/None, not a secret. Renamed from the wire name Password only to avoid colliding with the fixed -Password connection parameter.')]
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Profile is the confirmed wire field name for this permission area; kept as-is per this project''s naming rule that the Sophos wire name wins over PowerShell habit.')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Dashboard,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Wizard,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Objects,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Network,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$FirewallAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$IPS,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WebFilter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$CloudApplicationDashboard,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ZeroDayProtection,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ApplicationFilter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$IM,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$QoS,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$EmailProtection,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$TrafficDiscovery,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ProfileAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$PasswordAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$CentralManagement,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Backup,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Restore,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Firmware,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Licensing,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Services,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Updates,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$RebootShutdown,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$HA,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$DownloadCertificates,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherCertificateConfiguration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Diagnostics,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherSystemConfiguration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionOverview,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionSettings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionNetworkNetwork,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionAccessPoint,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionMesh,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Authentication,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Groups,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$GuestUsersManagement,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherGuestUserSettings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Policy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$TestExternalServerConnectivity,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ManageLiveUser,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ConnectTunnel,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherVPNConfigurations,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Alerts,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherWAFConfiguration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Configuration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$LogViewer,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ReportsAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$FourEyeAuthenticationSettings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$DeAnonymization,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    process {
        if (-not $PSCmdlet.ShouldProcess("AdministrationProfile '$Name'", 'Create')) {
            return
        }

        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        $fieldMap = Get-SfosAdministrationProfileFieldMap
        $values = @{}
        foreach ($field in $fieldMap) {
            $values[$field.Param] = if ($PSBoundParameters.ContainsKey($field.Param)) {
                $PSBoundParameters[$field.Param]
            }
            else {
                'None'
            }
        }

        $inner = Format-SfosAdministrationProfileInnerXml -Name $Name -Values $values -Operation 'add'

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create AdministrationProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdministrationProfile' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an administration profile on a Sophos Firewall.

.DESCRIPTION
    Changes one or more permission areas of an existing AdministrationProfile role under
    SYSTEM > Profile > Administration. The cmdlet reads the current role first and sends all
    50 fields back; areas you do not pass keep their current value, and an area you do pass
    is replaced by exactly the level you name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

    This role may already be assigned to one or more administrator accounts, including the
    account you are using right now. Narrowing an area that account still needs, or the area
    covering the API and web admin themselves, can lock the account out immediately, with no
    way back except a second administrator account or local console access. Check the
    current role with Get-SfosAdministrationProfile and preview the change with -WhatIf
    before writing.

.PARAMETER Name
    Required. Name of the profile to update.

.PARAMETER Dashboard
    Optional. New access level for the Dashboard area. One of Read-Write, Read-Only, None.
    If omitted, the current value is kept.

.PARAMETER Wizard
    Optional. New access level for the setup wizard. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER Objects
    Optional. New access level for host, service and other reusable objects. One of
    Read-Write, Read-Only, None. If omitted, the current value is kept.

.PARAMETER Network
    Optional. New access level for network configuration. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER FirewallAccess
    Optional. New access level for the firewall rules area. Wire element Firewall, renamed
    here because -Firewall already names the connection parameter. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER IPS
    Optional. New access level for intrusion prevention. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER WebFilter
    Optional. New access level for web filtering. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER CloudApplicationDashboard
    Optional. New access level for the cloud application dashboard. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER ZeroDayProtection
    Optional. New access level for zero-day protection. One of Read-Write, Read-Only, None.
    If omitted, the current value is kept.

.PARAMETER ApplicationFilter
    Optional. New access level for application filtering. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER IM
    Optional. New access level for instant messaging control. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER QoS
    Optional. New access level for quality of service (traffic shaping). One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER EmailProtection
    Optional. New access level for email protection. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER TrafficDiscovery
    Optional. New access level for traffic discovery. One of Read-Write, Read-Only, None.
    If omitted, the current value is kept.

.PARAMETER Profile
    Optional. New access level for administration profile management (this entity itself).
    One of Read-Write, Read-Only, None. If omitted, the current value is kept.

.PARAMETER PasswordAccess
    Optional. New access level for changing the administrator's own password. Wire element
    System/Password, renamed here because -Password already names the connection parameter.
    One of Read-Write, Read-Only, None. If omitted, the current value is kept.

.PARAMETER CentralManagement
    Optional. New access level for central management. One of Read-Write, Read-Only, None.
    If omitted, the current value is kept.

.PARAMETER Backup
    Optional. New access level for backup. One of Read-Write, Read-Only, None. If omitted,
    the current value is kept.

.PARAMETER Restore
    Optional. New access level for restore. One of Read-Write, Read-Only, None. If omitted,
    the current value is kept.

.PARAMETER Firmware
    Optional. New access level for firmware management. One of Read-Write, Read-Only, None.
    If omitted, the current value is kept.

.PARAMETER Licensing
    Optional. New access level for licensing. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER Services
    Optional. New access level for system services. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER Updates
    Optional. New access level for pattern and firmware updates. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER RebootShutdown
    Optional. New access level for reboot and shutdown. One of Read-Write, Read-Only, None.
    If omitted, the current value is kept.

.PARAMETER HA
    Optional. New access level for high availability configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER DownloadCertificates
    Optional. New access level for downloading certificates. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER OtherCertificateConfiguration
    Optional. New access level for other certificate configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER Diagnostics
    Optional. New access level for diagnostics. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER OtherSystemConfiguration
    Optional. New access level for other system configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER WirelessProtectionOverview
    Optional. New access level for the wireless protection overview. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER WirelessProtectionSettings
    Optional. New access level for wireless protection settings. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER WirelessProtectionNetworkNetwork
    Optional. New access level for wireless network configuration. The doubled "Network" in
    the name is the spelling the API itself uses. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER WirelessProtectionAccessPoint
    Optional. New access level for wireless access point management. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER WirelessProtectionMesh
    Optional. New access level for wireless mesh configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER Authentication
    Optional. New access level for authentication server configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER Groups
    Optional. New access level for user group configuration. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER GuestUsersManagement
    Optional. New access level for guest user management. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER OtherGuestUserSettings
    Optional. New access level for other guest user settings. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER Policy
    Optional. New access level for identity policy configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER TestExternalServerConnectivity
    Optional. New access level for testing external authentication server connectivity. One
    of Read-Write, Read-Only, None. If omitted, the current value is kept.

.PARAMETER ManageLiveUser
    Optional. New access level for managing live user sessions. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER ConnectTunnel
    Optional. New access level for connecting VPN tunnels. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER OtherVPNConfigurations
    Optional. New access level for other VPN configuration. One of Read-Write, Read-Only,
    None. If omitted, the current value is kept.

.PARAMETER Alerts
    Optional. New access level for web application firewall alerts. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER OtherWAFConfiguration
    Optional. New access level for other web application firewall configuration. One of
    Read-Write, Read-Only, None. If omitted, the current value is kept.

.PARAMETER Configuration
    Optional. New access level for logs and reports configuration. One of Read-Write,
    Read-Only, None. If omitted, the current value is kept.

.PARAMETER LogViewer
    Optional. New access level for the log viewer. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER ReportsAccess
    Optional. New access level for reports access. One of Read-Write, Read-Only, None. If
    omitted, the current value is kept.

.PARAMETER FourEyeAuthenticationSettings
    Optional. New access level for four-eye authentication settings on reports. Wire element
    Four-EyeAuthenticationSettings, renamed here because PowerShell parameter names cannot
    contain a hyphen. One of Read-Write, Read-Only, None. If omitted, the current value is
    kept.

.PARAMETER DeAnonymization
    Optional. New access level for de-anonymization of reports. Wire element
    De-Anonymization, renamed here because PowerShell parameter names cannot contain a
    hyphen. One of Read-Write, Read-Only, None. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an object with a Name property,
    such as one returned by Get-SfosAdministrationProfile, through the pipeline by property
    name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Write -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Write

    Upgrades the dashboard area of the 'Report Viewer' role to Read-Write. Every other area
    keeps its current value. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    Set-SfosAdministrationProfile -Name 'Report Viewer' -ReportsAccess None -Confirm:$false

    Removes reports access from the role without asking for confirmation, for use in
    scripts.

.EXAMPLE
    Get-SfosAdministrationProfile -NameLike 'Report Viewer' | Format-List

    Shows the current role. Run this before a change so you can restore the previous state.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosAdministrationProfile
#>
function Set-SfosAdministrationProfile {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Username/Password are the fixed connection parameters every write cmdlet in this suite takes; PasswordAccess is an unrelated permission-level field (Read-Write/Read-Only/None), not a credential.')]
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidUsingPlainTextForPassword', '', Justification = 'PasswordAccess holds one of Read-Write/Read-Only/None, not a secret. Renamed from the wire name Password only to avoid colliding with the fixed -Password connection parameter.')]
    [Diagnostics.CodeAnalysis.SuppressMessage('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Profile is the confirmed wire field name for this permission area; kept as-is per this project''s naming rule that the Sophos wire name wins over PowerShell habit.')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Dashboard,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Wizard,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Objects,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Network,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$FirewallAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$IPS,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WebFilter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$CloudApplicationDashboard,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ZeroDayProtection,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ApplicationFilter,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$IM,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$QoS,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$EmailProtection,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$TrafficDiscovery,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ProfileAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$PasswordAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$CentralManagement,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Backup,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Restore,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Firmware,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Licensing,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Services,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Updates,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$RebootShutdown,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$HA,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$DownloadCertificates,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherCertificateConfiguration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Diagnostics,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherSystemConfiguration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionOverview,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionSettings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionNetworkNetwork,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionAccessPoint,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$WirelessProtectionMesh,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Authentication,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Groups,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$GuestUsersManagement,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherGuestUserSettings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Policy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$TestExternalServerConnectivity,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ManageLiveUser,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ConnectTunnel,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherVPNConfigurations,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Alerts,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$OtherWAFConfiguration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$Configuration,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$LogViewer,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$ReportsAccess,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$FourEyeAuthenticationSettings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Read-Write', 'Read-Only', 'None')]
        [string]$DeAnonymization,

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
        $existing = @(Get-SfosAdministrationProfile -NameLike $Name -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AdministrationProfile object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("AdministrationProfile '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $fieldMap = Get-SfosAdministrationProfileFieldMap
        $values = @{}
        foreach ($field in $fieldMap) {
            $values[$field.Param] = if ($PSBoundParameters.ContainsKey($field.Param)) {
                $PSBoundParameters[$field.Param]
            }
            else {
                [string]$existing[0].($field.Param)
            }
        }

        $inner = Format-SfosAdministrationProfileInnerXml -Name $Name -Values $values -Operation 'update'

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update AdministrationProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdministrationProfile' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an administration profile from a Sophos Firewall.

.DESCRIPTION
    Deletes an AdministrationProfile role under SYSTEM > Profile > Administration. It needs
    an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

    Removing a role that is still assigned to an administrator account can prevent that
    account from signing in, including the account you are using right now. There is no
    automatic check for existing assignments before the delete; confirm the role is unused
    first, and preview the call with -WhatIf.

.PARAMETER Name
    Required. Name of the profile to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an object with a Name property,
    such as one returned by Get-SfosAdministrationProfile, through the pipeline by property
    name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    delete.

.EXAMPLE
    Remove-SfosAdministrationProfile -Name 'Report Viewer' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosAdministrationProfile -Name 'Report Viewer'

    Removes the 'Report Viewer' profile. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    Remove-SfosAdministrationProfile -Name 'Report Viewer' -Confirm:$false

    Removes the profile without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosAdministrationProfile
#>
function Remove-SfosAdministrationProfile {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        if (-not $PSCmdlet.ShouldProcess("AdministrationProfile '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <AdministrationProfile>
    <Name>$nameEsc</Name>
  </AdministrationProfile>
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
            throw "Failed to remove AdministrationProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdministrationProfile' -Action 'remove' -Target $Name
    }
}

#endregion
