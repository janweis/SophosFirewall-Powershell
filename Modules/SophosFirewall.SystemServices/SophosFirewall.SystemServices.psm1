#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.SystemServices
    =============================
    PowerShell module for the Sophos Firewall (SFOS) System services area via the
    XML API: QoS (traffic shaping) policies, syslog servers, the system service
    daemon manager, High Availability, and RED configuration.

    Total Functions: 25 (21 exported, 4 internal helpers) - see
    README.md for the full cmdlet table.

    Requires SophosFirewall.Core (>= 1.3.0) for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S) happens
    in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>


#region QoSPolicy
# QoSPolicy (CONFIGURE > System Services > QoS Policy) covers traffic-shaping policies.
# Wire element is <QoSPolicy> (the doc folder name QOSPolicy is not the element name).
#
# Measured against the lab appliance:
# - BandwidthUsageType takes 'Individual' or 'Shared' as free-form text - both are accepted
#   and stored as sent [measured]. The doc table's 'on'/'off' form is silently accepted with
#   code 200 but blanks BOTH BandwidthUsageType and PolicyBasedOn on the stored object - the
#   API does not validate the enum and a bad value corrupts unrelated fields rather than
#   failing the request. The text form from the sample XML is therefore the only form used
#   here.
# - PolicyBasedOn: 'Application', 'User', 'FirewallRule' and 'WebCategory' are all accepted
#   and stored as sent [measured]. Sending the doc table's 'Firewall' is also accepted with
#   code 200, but the firewall stores it as 'FirewallRule' - so 'FirewallRule' is used
#   directly rather than relying on that undocumented normalisation.
# - Exactly one of four bandwidth field groups applies, selected by ImplementationOn +
#   PolicyType, matching the combinations already present on the appliance's default
#   policies [measured]: Total+Strict -> TotalBandwidth; Total+Committed ->
#   GuaranteedBandwidth+BurstableBandwidth; Individual+Strict -> UploadBandwidth+
#   DownloadBandwidth; Individual+Committed -> GuaranteedUploadBandwidth+
#   BurstableUploadBandwidth+GuaranteedDownloadBandwidth+BurstableDownloadBandwidth.
# - SchedulebasedPolicyRuleList/Rule carries its own PolicyType and Schedule (an existing
#   Schedule object's Name), plus the same bandwidth group as the top level, chosen by the
#   policy's own ImplementationOn combined with the Rule's own PolicyType [measured: a Rule
#   with PolicyType Strict on a Total/Individual... policy stored and read back correctly
#   using TotalBandwidth, with no ImplementationOn field of its own]. DetailId from the doc
#   sample was never required and never appears on a stored Rule.
# - A malformed request (e.g. an invalid Priority) answers a field-less-adjacent
#   <QoSPolicy><Status code="501">...</Status><InvalidParams>...) - the status node sits
#   directly under <QoSPolicy> with no <Name> sibling, so Core's default status heuristic
#   finds it without a custom -ObjectName path.
# - Add/Update/Remove of a name that does not exist yet, or removal of a name that does not
#   exist, all answer code 200; Remove was confirmed to actually delete the object and to be
#   a true no-op (no side effect) when the name does not exist.

# Builds the bandwidth XML fragment for the one field group selected by ImplementationOn +
# PolicyType, and throws naming the QoS policy and the missing field(s) if the resolved
# values (already merged with the existing object by the caller) do not cover that group.
# Internal helper, not exported.
function ConvertTo-SfosQoSBandwidthXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ImplementationOn,

        [Parameter(Mandatory)]
        [string]$PolicyType,

        [Parameter(Mandatory)]
        [hashtable]$Values
    )

    if ($ImplementationOn -eq 'Total' -and $PolicyType -eq 'Strict') {
        if ($null -eq $Values.TotalBandwidth) {
            throw "QoSPolicy '$Name': ImplementationOn=Total and PolicyType=Strict require -TotalBandwidth."
        }
        return "<TotalBandwidth>$($Values.TotalBandwidth)</TotalBandwidth>"
    }
    if ($ImplementationOn -eq 'Total' -and $PolicyType -eq 'Committed') {
        if ($null -eq $Values.GuaranteedBandwidth -or $null -eq $Values.BurstableBandwidth) {
            throw "QoSPolicy '$Name': ImplementationOn=Total and PolicyType=Committed require -GuaranteedBandwidth and -BurstableBandwidth."
        }
        return "<GuaranteedBandwidth>$($Values.GuaranteedBandwidth)</GuaranteedBandwidth><BurstableBandwidth>$($Values.BurstableBandwidth)</BurstableBandwidth>"
    }
    if ($ImplementationOn -eq 'Individual' -and $PolicyType -eq 'Strict') {
        if ($null -eq $Values.UploadBandwidth -or $null -eq $Values.DownloadBandwidth) {
            throw "QoSPolicy '$Name': ImplementationOn=Individual and PolicyType=Strict require -UploadBandwidth and -DownloadBandwidth."
        }
        return "<UploadBandwidth>$($Values.UploadBandwidth)</UploadBandwidth><DownloadBandwidth>$($Values.DownloadBandwidth)</DownloadBandwidth>"
    }
    if ($ImplementationOn -eq 'Individual' -and $PolicyType -eq 'Committed') {
        if ($null -eq $Values.GuaranteedUploadBandwidth -or $null -eq $Values.BurstableUploadBandwidth -or
            $null -eq $Values.GuaranteedDownloadBandwidth -or $null -eq $Values.BurstableDownloadBandwidth) {
            throw "QoSPolicy '$Name': ImplementationOn=Individual and PolicyType=Committed require -GuaranteedUploadBandwidth, -BurstableUploadBandwidth, -GuaranteedDownloadBandwidth and -BurstableDownloadBandwidth."
        }
        return "<GuaranteedUploadBandwidth>$($Values.GuaranteedUploadBandwidth)</GuaranteedUploadBandwidth><BurstableUploadBandwidth>$($Values.BurstableUploadBandwidth)</BurstableUploadBandwidth><GuaranteedDownloadBandwidth>$($Values.GuaranteedDownloadBandwidth)</GuaranteedDownloadBandwidth><BurstableDownloadBandwidth>$($Values.BurstableDownloadBandwidth)</BurstableDownloadBandwidth>"
    }

    throw "QoSPolicy '$Name': unrecognised ImplementationOn/PolicyType combination '$ImplementationOn'/'$PolicyType'."
}

# Builds the <SchedulebasedPolicyRuleList> XML from an array of rule objects (Name/
# PolicyType/Schedule/bandwidth fields, the shape Get-SfosQoSPolicy returns). Internal
# helper, not exported.
function ConvertTo-SfosQoSRuleListXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ImplementationOn,

        [AllowNull()]
        [object[]]$Rules
    )

    if (-not $Rules -or @($Rules).Count -eq 0) {
        return '<SchedulebasedPolicyRuleList />'
    }

    $ruleXml = ''
    foreach ($rule in @($Rules)) {
        $rulePolicyType = [string]$rule.PolicyType
        $scheduleEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Schedule)
        $values = @{
            TotalBandwidth               = $rule.TotalBandwidth
            GuaranteedBandwidth          = $rule.GuaranteedBandwidth
            BurstableBandwidth           = $rule.BurstableBandwidth
            UploadBandwidth              = $rule.UploadBandwidth
            DownloadBandwidth            = $rule.DownloadBandwidth
            GuaranteedUploadBandwidth    = $rule.GuaranteedUploadBandwidth
            BurstableUploadBandwidth     = $rule.BurstableUploadBandwidth
            GuaranteedDownloadBandwidth  = $rule.GuaranteedDownloadBandwidth
            BurstableDownloadBandwidth   = $rule.BurstableDownloadBandwidth
        }
        $bwXml = ConvertTo-SfosQoSBandwidthXml -Name "$Name (schedule rule)" -ImplementationOn $ImplementationOn -PolicyType $rulePolicyType -Values $values
        $ruleXml += "<Rule><PolicyType>$rulePolicyType</PolicyType><Schedule>$scheduleEsc</Schedule>$bwXml</Rule>"
    }

    return "<SchedulebasedPolicyRuleList>$ruleXml</SchedulebasedPolicyRuleList>"
}

<#
.SYNOPSIS
    Retrieves QoSPolicy (traffic shaping) objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for QoSPolicy objects (CONFIGURE > System Services >
    QoS Policy). By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to
    return the raw XML nodes.

    The appliance ships 43 default QoS policies; this cmdlet reads them like any other
    object, but they are not owned by this module's write tests.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key (confirmed working
    for this entity) and re-applied client-side.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it.

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
    # List every QoS policy
    Get-SfosQoSPolicy

.EXAMPLE
    # Find the built-in streaming-video policies
    Get-SfosQoSPolicy -NameLike 'Streaming Video'

.NOTES
    Minimum supported PowerShell version: 5.1

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/QOSPolicy/operations/AddQoSpolicy%26UpdateQoSpolicy.html

.LINK
    New-SfosQoSPolicy
#>
function Get-SfosQoSPolicy {
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
  <QoSPolicy>
    $filterXml
  </QoSPolicy>
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
        throw "Error retrieving QoSPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'QoSPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/QoSPolicy[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $ruleNodes = @($node.SelectNodes('SchedulebasedPolicyRuleList/Rule'))
        $ruleList = foreach ($ruleNode in $ruleNodes) {
            [PSCustomObject]@{
                PolicyType                  = [string]$ruleNode.PolicyType
                Schedule                    = [string]$ruleNode.Schedule
                TotalBandwidth               = if ($ruleNode.SelectSingleNode('TotalBandwidth')) { [string]$ruleNode.TotalBandwidth } else { $null }
                GuaranteedBandwidth          = if ($ruleNode.SelectSingleNode('GuaranteedBandwidth')) { [string]$ruleNode.GuaranteedBandwidth } else { $null }
                BurstableBandwidth           = if ($ruleNode.SelectSingleNode('BurstableBandwidth')) { [string]$ruleNode.BurstableBandwidth } else { $null }
                UploadBandwidth              = if ($ruleNode.SelectSingleNode('UploadBandwidth')) { [string]$ruleNode.UploadBandwidth } else { $null }
                DownloadBandwidth            = if ($ruleNode.SelectSingleNode('DownloadBandwidth')) { [string]$ruleNode.DownloadBandwidth } else { $null }
                GuaranteedUploadBandwidth    = if ($ruleNode.SelectSingleNode('GuaranteedUploadBandwidth')) { [string]$ruleNode.GuaranteedUploadBandwidth } else { $null }
                BurstableUploadBandwidth     = if ($ruleNode.SelectSingleNode('BurstableUploadBandwidth')) { [string]$ruleNode.BurstableUploadBandwidth } else { $null }
                GuaranteedDownloadBandwidth  = if ($ruleNode.SelectSingleNode('GuaranteedDownloadBandwidth')) { [string]$ruleNode.GuaranteedDownloadBandwidth } else { $null }
                BurstableDownloadBandwidth   = if ($ruleNode.SelectSingleNode('BurstableDownloadBandwidth')) { [string]$ruleNode.BurstableDownloadBandwidth } else { $null }
            }
        }

        [PSCustomObject]@{
            Name                         = [string]$node.Name
            PolicyBasedOn                = [string]$node.PolicyBasedOn
            BandwidthUsageType           = [string]$node.BandwidthUsageType
            ImplementationOn             = [string]$node.ImplementationOn
            PolicyType                   = [string]$node.PolicyType
            Priority                     = [string]$node.Priority
            Description                  = [string]$node.Description
            TotalBandwidth               = if ($node.SelectSingleNode('TotalBandwidth')) { [string]$node.TotalBandwidth } else { $null }
            GuaranteedBandwidth          = if ($node.SelectSingleNode('GuaranteedBandwidth')) { [string]$node.GuaranteedBandwidth } else { $null }
            BurstableBandwidth           = if ($node.SelectSingleNode('BurstableBandwidth')) { [string]$node.BurstableBandwidth } else { $null }
            UploadBandwidth              = if ($node.SelectSingleNode('UploadBandwidth')) { [string]$node.UploadBandwidth } else { $null }
            DownloadBandwidth            = if ($node.SelectSingleNode('DownloadBandwidth')) { [string]$node.DownloadBandwidth } else { $null }
            GuaranteedUploadBandwidth    = if ($node.SelectSingleNode('GuaranteedUploadBandwidth')) { [string]$node.GuaranteedUploadBandwidth } else { $null }
            BurstableUploadBandwidth     = if ($node.SelectSingleNode('BurstableUploadBandwidth')) { [string]$node.BurstableUploadBandwidth } else { $null }
            GuaranteedDownloadBandwidth  = if ($node.SelectSingleNode('GuaranteedDownloadBandwidth')) { [string]$node.GuaranteedDownloadBandwidth } else { $null }
            BurstableDownloadBandwidth   = if ($node.SelectSingleNode('BurstableDownloadBandwidth')) { [string]$node.BurstableDownloadBandwidth } else { $null }
            SchedulebasedPolicyRuleList  = @($ruleList)
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
    Creates a new QoSPolicy (traffic shaping policy) on the Sophos Firewall.

.DESCRIPTION
    Creates a QoSPolicy using the Sophos Firewall XML API. Supports ShouldProcess; use
    -WhatIf to preview.

    Exactly one bandwidth field group must be supplied, selected by -ImplementationOn and
    -PolicyType [measured]: Total+Strict needs -TotalBandwidth; Total+Committed needs
    -GuaranteedBandwidth and -BurstableBandwidth; Individual+Strict needs -UploadBandwidth
    and -DownloadBandwidth; Individual+Committed needs -GuaranteedUploadBandwidth,
    -BurstableUploadBandwidth, -GuaranteedDownloadBandwidth and -BurstableDownloadBandwidth.

.PARAMETER Name
    Name of the QoS policy [doc]. Mandatory. Max 50 characters, no commas.

.PARAMETER PolicyBasedOn
    What the policy attaches to: 'Application', 'User', 'FirewallRule' or 'WebCategory'
    [measured - all four accepted and stored as sent]. Mandatory.

.PARAMETER ImplementationOn
    'Total' (one shared allocation) or 'Individual' (per-object allocation) [doc]. Mandatory.

.PARAMETER PolicyType
    'Strict' (a hard limit) or 'Committed' (a guarantee with burst) [doc]. Mandatory.

.PARAMETER Priority
    Traffic priority: 'RealTime', 'BusinessCritical', 'Normal2', 'Normal3', 'Normal4',
    'Normal5', 'BulkyFTP' or 'BestEffort' [doc; RealTime and Normal3 confirmed live].
    Mandatory.

.PARAMETER BandwidthUsageType
    'Individual' or 'Shared' [measured - the doc table's 'on'/'off' form is silently
    accepted but blanks this field and PolicyBasedOn on the stored object]. Default:
    'Individual'.

.PARAMETER Description
    Free-text description [doc]. Optional.

.PARAMETER TotalBandwidth
    Bandwidth limit in kbps for ImplementationOn=Total, PolicyType=Strict [doc/measured].

.PARAMETER GuaranteedBandwidth
    Guaranteed bandwidth in kbps for ImplementationOn=Total, PolicyType=Committed
    [doc/measured].

.PARAMETER BurstableBandwidth
    Burstable bandwidth in kbps for ImplementationOn=Total, PolicyType=Committed
    [doc/measured].

.PARAMETER UploadBandwidth
    Upload bandwidth limit in kbps for ImplementationOn=Individual, PolicyType=Strict
    [doc/measured].

.PARAMETER DownloadBandwidth
    Download bandwidth limit in kbps for ImplementationOn=Individual, PolicyType=Strict
    [doc/measured].

.PARAMETER GuaranteedUploadBandwidth
    Guaranteed upload bandwidth in kbps for ImplementationOn=Individual,
    PolicyType=Committed [doc/measured].

.PARAMETER BurstableUploadBandwidth
    Burstable upload bandwidth in kbps for ImplementationOn=Individual,
    PolicyType=Committed [doc/measured].

.PARAMETER GuaranteedDownloadBandwidth
    Guaranteed download bandwidth in kbps for ImplementationOn=Individual,
    PolicyType=Committed [doc/measured].

.PARAMETER BurstableDownloadBandwidth
    Burstable download bandwidth in kbps for ImplementationOn=Individual,
    PolicyType=Committed [doc/measured].

.PARAMETER SchedulebasedPolicyRuleList
    Zero or more schedule-based override rules, each a PSCustomObject with PolicyType,
    Schedule (the Name of an existing Schedule object) and the bandwidth fields matching
    -ImplementationOn + the rule's own PolicyType [measured against a live create/read
    round trip]. Optional.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it.

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
    # A hard per-user total bandwidth limit
    New-SfosQoSPolicy -Name 'Branch Office Cap' -PolicyBasedOn User -ImplementationOn Total -PolicyType Strict -Priority Normal3 -TotalBandwidth 512

.EXAMPLE
    # A guaranteed-plus-burst allocation per application, individually
    New-SfosQoSPolicy -Name 'VoIP App Guarantee' -PolicyBasedOn Application -ImplementationOn Individual -PolicyType Committed -Priority RealTime -GuaranteedUploadBandwidth 64 -BurstableUploadBandwidth 128 -GuaranteedDownloadBandwidth 64 -BurstableDownloadBandwidth 128

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: create for all four ImplementationOn/PolicyType combinations, for
    PolicyBasedOn Application/User/FirewallRule/WebCategory, and with a schedule-based rule
    attached, each confirmed by a subsequent Get.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/QOSPolicy/operations/AddQoSpolicy%26UpdateQoSpolicy.html

.LINK
    Get-SfosQoSPolicy
#>
function New-SfosQoSPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Application', 'User', 'FirewallRule', 'WebCategory')]
        [string]$PolicyBasedOn,

        [Parameter(Mandatory)]
        [ValidateSet('Total', 'Individual')]
        [string]$ImplementationOn,

        [Parameter(Mandatory)]
        [ValidateSet('Strict', 'Committed')]
        [string]$PolicyType,

        [Parameter(Mandatory)]
        [ValidateSet('RealTime', 'BusinessCritical', 'Normal2', 'Normal3', 'Normal4', 'Normal5', 'BulkyFTP', 'BestEffort')]
        [string]$Priority,

        [ValidateSet('Individual', 'Shared')]
        [string]$BandwidthUsageType = 'Individual',

        [string]$Description = '',

        [int]$TotalBandwidth,
        [int]$GuaranteedBandwidth,
        [int]$BurstableBandwidth,
        [int]$UploadBandwidth,
        [int]$DownloadBandwidth,
        [int]$GuaranteedUploadBandwidth,
        [int]$BurstableUploadBandwidth,
        [int]$GuaranteedDownloadBandwidth,
        [int]$BurstableDownloadBandwidth,

        [object[]]$SchedulebasedPolicyRuleList,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("QoSPolicy '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $bp = $PSBoundParameters
    $bwValues = @{
        TotalBandwidth              = if ($bp.ContainsKey('TotalBandwidth')) { $TotalBandwidth } else { $null }
        GuaranteedBandwidth         = if ($bp.ContainsKey('GuaranteedBandwidth')) { $GuaranteedBandwidth } else { $null }
        BurstableBandwidth          = if ($bp.ContainsKey('BurstableBandwidth')) { $BurstableBandwidth } else { $null }
        UploadBandwidth             = if ($bp.ContainsKey('UploadBandwidth')) { $UploadBandwidth } else { $null }
        DownloadBandwidth           = if ($bp.ContainsKey('DownloadBandwidth')) { $DownloadBandwidth } else { $null }
        GuaranteedUploadBandwidth   = if ($bp.ContainsKey('GuaranteedUploadBandwidth')) { $GuaranteedUploadBandwidth } else { $null }
        BurstableUploadBandwidth    = if ($bp.ContainsKey('BurstableUploadBandwidth')) { $BurstableUploadBandwidth } else { $null }
        GuaranteedDownloadBandwidth = if ($bp.ContainsKey('GuaranteedDownloadBandwidth')) { $GuaranteedDownloadBandwidth } else { $null }
        BurstableDownloadBandwidth  = if ($bp.ContainsKey('BurstableDownloadBandwidth')) { $BurstableDownloadBandwidth } else { $null }
    }
    $bandwidthXml = ConvertTo-SfosQoSBandwidthXml -Name $Name -ImplementationOn $ImplementationOn -PolicyType $PolicyType -Values $bwValues
    $ruleListXml = ConvertTo-SfosQoSRuleListXml -Name $Name -ImplementationOn $ImplementationOn -Rules $SchedulebasedPolicyRuleList

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descriptionEsc = ConvertTo-SfosXmlEscaped -Text $Description

    $inner = @"
<Set operation="add">
  <QoSPolicy>
    <Name>$nameEsc</Name>
    <PolicyBasedOn>$PolicyBasedOn</PolicyBasedOn>
    <BandwidthUsageType>$BandwidthUsageType</BandwidthUsageType>
    <ImplementationOn>$ImplementationOn</ImplementationOn>
    <PolicyType>$PolicyType</PolicyType>
    <Priority>$Priority</Priority>
    <Description>$descriptionEsc</Description>
    $bandwidthXml
    $ruleListXml
  </QoSPolicy>
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
        throw "Failed to create QoSPolicy object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'QoSPolicy' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing QoSPolicy (traffic shaping policy) on the Sophos Firewall.

.DESCRIPTION
    Reads the current QoSPolicy object, merges any parameters actually supplied by the
    caller on top of it, and writes the complete object back - the API replaces the whole
    entity on update [measured, see the region header]. Supports ShouldProcess; use -WhatIf
    to preview.

    -ImplementationOn and -PolicyType are mandatory here (unlike New-SfosQoSPolicy) because
    this cmdlet accepts pipeline input and a single parameter set is required for
    ValueFromPipelineByPropertyName to bind correctly for every combination; pipe the object
    from Get-SfosQoSPolicy to supply them unchanged.

.PARAMETER Name
    Name of the QoS policy to update [doc]. Mandatory.

.PARAMETER PolicyBasedOn
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER ImplementationOn
    See New-SfosQoSPolicy. Mandatory (see DESCRIPTION).

.PARAMETER PolicyType
    See New-SfosQoSPolicy. Mandatory (see DESCRIPTION).

.PARAMETER Priority
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER BandwidthUsageType
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER Description
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted. Pass an empty
    string to clear it.

.PARAMETER TotalBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER GuaranteedBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER BurstableBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER UploadBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER DownloadBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER GuaranteedUploadBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER BurstableUploadBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER GuaranteedDownloadBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER BurstableDownloadBandwidth
    See New-SfosQoSPolicy. Optional; keeps the current value if omitted.

.PARAMETER SchedulebasedPolicyRuleList
    See New-SfosQoSPolicy. Optional; keeps the current rule list if omitted (the whole list
    is replaced when supplied - there is no partial update of individual rules).

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it. Enables piping between firewalls, e.g. Get-SfosQoSPolicy -Session $fw1 |
    Set-SfosQoSPolicy -Session fw2 -Priority RealTime -ImplementationOn Total -PolicyType Strict.

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
    None. Throws an exception if the update fails or the object does not exist.

.EXAMPLE
    # Raise the limit on an existing Total/Strict policy
    Set-SfosQoSPolicy -Name 'Branch Office Cap' -ImplementationOn Total -PolicyType Strict -TotalBandwidth 1024

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: Get-SfosQoSPolicy | Set-SfosQoSPolicy (unchanged) round trip produced an
    identical object on re-read.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/QOSPolicy/operations/AddQoSpolicy%26UpdateQoSpolicy.html

.LINK
    Get-SfosQoSPolicy
#>
function Set-SfosQoSPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [ValidateSet('Application', 'User', 'FirewallRule', 'WebCategory')]
        [string]$PolicyBasedOn,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Total', 'Individual')]
        [string]$ImplementationOn,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Strict', 'Committed')]
        [string]$PolicyType,

        [ValidateSet('RealTime', 'BusinessCritical', 'Normal2', 'Normal3', 'Normal4', 'Normal5', 'BulkyFTP', 'BestEffort')]
        [string]$Priority,

        [ValidateSet('Individual', 'Shared')]
        [string]$BandwidthUsageType,

        [string]$Description,

        [int]$TotalBandwidth,
        [int]$GuaranteedBandwidth,
        [int]$BurstableBandwidth,
        [int]$UploadBandwidth,
        [int]$DownloadBandwidth,
        [int]$GuaranteedUploadBandwidth,
        [int]$BurstableUploadBandwidth,
        [int]$GuaranteedDownloadBandwidth,
        [int]$BurstableDownloadBandwidth,

        [object[]]$SchedulebasedPolicyRuleList,

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

        $existing = @(Get-SfosQoSPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The QoSPolicy object '$Name' was not found."
        }
        $current = $existing[0]

        $targetPolicyBasedOn = if ($bp.ContainsKey('PolicyBasedOn')) { $PolicyBasedOn } else { $current.PolicyBasedOn }
        $targetPriority = if ($bp.ContainsKey('Priority')) { $Priority } else { $current.Priority }
        $targetBandwidthUsageType = if ($bp.ContainsKey('BandwidthUsageType')) { $BandwidthUsageType } else { $current.BandwidthUsageType }
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$current.Description }
        $targetRules = if ($bp.ContainsKey('SchedulebasedPolicyRuleList')) { $SchedulebasedPolicyRuleList } else { $current.SchedulebasedPolicyRuleList }

        $bwValues = @{
            TotalBandwidth              = if ($bp.ContainsKey('TotalBandwidth')) { $TotalBandwidth } else { $current.TotalBandwidth }
            GuaranteedBandwidth         = if ($bp.ContainsKey('GuaranteedBandwidth')) { $GuaranteedBandwidth } else { $current.GuaranteedBandwidth }
            BurstableBandwidth          = if ($bp.ContainsKey('BurstableBandwidth')) { $BurstableBandwidth } else { $current.BurstableBandwidth }
            UploadBandwidth             = if ($bp.ContainsKey('UploadBandwidth')) { $UploadBandwidth } else { $current.UploadBandwidth }
            DownloadBandwidth           = if ($bp.ContainsKey('DownloadBandwidth')) { $DownloadBandwidth } else { $current.DownloadBandwidth }
            GuaranteedUploadBandwidth   = if ($bp.ContainsKey('GuaranteedUploadBandwidth')) { $GuaranteedUploadBandwidth } else { $current.GuaranteedUploadBandwidth }
            BurstableUploadBandwidth    = if ($bp.ContainsKey('BurstableUploadBandwidth')) { $BurstableUploadBandwidth } else { $current.BurstableUploadBandwidth }
            GuaranteedDownloadBandwidth = if ($bp.ContainsKey('GuaranteedDownloadBandwidth')) { $GuaranteedDownloadBandwidth } else { $current.GuaranteedDownloadBandwidth }
            BurstableDownloadBandwidth  = if ($bp.ContainsKey('BurstableDownloadBandwidth')) { $BurstableDownloadBandwidth } else { $current.BurstableDownloadBandwidth }
        }

        if (-not $PSCmdlet.ShouldProcess("QoSPolicy '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $bandwidthXml = ConvertTo-SfosQoSBandwidthXml -Name $Name -ImplementationOn $ImplementationOn -PolicyType $PolicyType -Values $bwValues
        $ruleListXml = ConvertTo-SfosQoSRuleListXml -Name $Name -ImplementationOn $ImplementationOn -Rules $targetRules

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $descriptionEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $inner = @"
<Set operation="update">
  <QoSPolicy>
    <Name>$nameEsc</Name>
    <PolicyBasedOn>$targetPolicyBasedOn</PolicyBasedOn>
    <BandwidthUsageType>$targetBandwidthUsageType</BandwidthUsageType>
    <ImplementationOn>$ImplementationOn</ImplementationOn>
    <PolicyType>$PolicyType</PolicyType>
    <Priority>$targetPriority</Priority>
    <Description>$descriptionEsc</Description>
    $bandwidthXml
    $ruleListXml
  </QoSPolicy>
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
            throw "Failed to update QoSPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'QoSPolicy' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a QoSPolicy object from the Sophos Firewall.

.DESCRIPTION
    Removes a QoSPolicy using the Sophos Firewall XML API. Supports ShouldProcess; use
    -WhatIf to preview.

.PARAMETER Name
    Name of the QoS policy to remove [doc]. Mandatory.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it.

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
    None. Throws an exception if removal fails.

.EXAMPLE
    Remove-SfosQoSPolicy -Name 'Branch Office Cap'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removes an existing object and answers code 200 without side effects for
    a name that does not exist.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/QOSPolicy/operations/Delete%20QoS%20Policy.html

.LINK
    Get-SfosQoSPolicy
#>
function Remove-SfosQoSPolicy {
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
        if (-not $PSCmdlet.ShouldProcess("QoSPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <QoSPolicy>
    <Name>$nameEsc</Name>
  </QoSPolicy>
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
            throw "Failed to remove QoSPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'QoSPolicy' -Action 'remove' -Target $Name
    }
}

#endregion QoSPolicy

#region SyslogServer
# SyslogServers (CONFIGURE > System Services > Syslog Servers). Wire root element is
# <SyslogServers> (plural, unlike most entities) but each object still represents a single
# server - the noun stays singular on the cmdlets per the project's naming convention for
# container-shaped API roots.
#
# Measured against the lab appliance (3 pre-existing objects, all left untouched by this
# module's tests):
# - The server-side filter is broken for this entity: any <Filter> block - regardless of
#   key name, criteria or value, including an exact match on a real object's Name - makes
#   the appliance return exactly one fixed record ('Log_Suppress' in this lab) instead of
#   either the matching set or the full unfiltered set. This differs from the "unsupported
#   key returns everything" pattern documented for other entities, so Get-SfosSyslogServer
#   never sends a <Filter> at all; -NameLike is client-side only.
# - Facility takes the doc table's upper-case form ('DAEMON', 'LOCAL0'..'LOCAL7', 'USER'),
#   not the sample XML's mixed-case form ('Local0' etc.) - 'LOCAL3' was accepted and stored,
#   'Local3' was rejected with code 501. Facility is optional; omitting it entirely is
#   accepted and leaves it empty on the stored object.
# - Format only demonstrated one working value on this firmware, the sample's literal
#   'DeviceStandardFormat', which is accepted and stored as sent. One of the three
#   pre-existing objects instead shows a bare '3' for this field - a legacy value from
#   before the current write path existed, not a form this module writes.
# - LogSettings is a large, variable-shaped subtree (its category set differs between the
#   three pre-existing objects - the built-in local target carries no ServerAddress/Port/
#   etc. at all, only Name and LogSettings). Rather than exposing every one of its ~60 leaf
#   toggles as a cmdlet parameter, this module reads and writes the whole subtree generically
#   (ConvertFrom-SfosLogSettingsNode / ConvertTo-SfosLogSettingsXml, both internal helpers)
#   as a single nested PSCustomObject, and -LogSettings on New-/Set-SfosSyslogServer takes
#   that same shape - typically edited by taking the object Get-SfosSyslogServer returned,
#   changing one leaf property, and passing it back. Set-SfosSyslogServer treats the whole
#   subtree as one field for read-modify-write purposes: omit -LogSettings to keep the
#   current subtree unchanged, or supply a complete replacement.
# - Creating without -LogSettings at all is accepted; the appliance then fills in the full
#   category structure itself with every leaf set to 'Disable' [measured on a subsequent Get].
# - Remove was confirmed to actually delete the object, and answers code 200 without any
#   side effect for a name that does not exist.

# Recursively converts an XML element's children into a nested, ordered PSCustomObject:
# an element with only text content becomes a string property, an element with child
# elements becomes a nested PSCustomObject property. Used for the LogSettings subtree, whose
# category/leaf shape is not fixed. Internal helper, not exported.
function ConvertFrom-SfosLogSettingsNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlElement]$Node
    )

    $result = [ordered]@{}
    foreach ($child in $Node.ChildNodes) {
        if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) {
            continue
        }

        $hasElementChildren = $false
        foreach ($grandchild in $child.ChildNodes) {
            if ($grandchild.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $hasElementChildren = $true
                break
            }
        }

        if ($hasElementChildren) {
            $result[$child.Name] = ConvertFrom-SfosLogSettingsNode -Node $child
        }
        else {
            $result[$child.Name] = [string]$child.InnerText
        }
    }

    return [PSCustomObject]$result
}

# Reverses ConvertFrom-SfosLogSettingsNode: walks a nested PSCustomObject's properties and
# emits the matching XML, escaping every leaf value. Internal helper, not exported.
function ConvertTo-SfosLogSettingsXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$LogSettings
    )

    $xml = ''
    foreach ($prop in $LogSettings.PSObject.Properties) {
        $tag = $prop.Name
        $value = $prop.Value
        if ($value -is [PSCustomObject]) {
            $xml += "<$tag>" + (ConvertTo-SfosLogSettingsXml -LogSettings $value) + "</$tag>"
        }
        else {
            $escaped = ConvertTo-SfosXmlEscaped -Text ([string]$value)
            $xml += "<$tag>$escaped</$tag>"
        }
    }

    return $xml
}

<#
.SYNOPSIS
    Retrieves SyslogServers objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SyslogServers objects (CONFIGURE > System
    Services > Syslog Servers). By default the cmdlet returns PowerShell-friendly objects.
    Use -AsXml to return the raw XML nodes.

.PARAMETER NameLike
    Filters by Name, substring match. Client-side only [measured: the server-side filter is
    broken for this entity - see the region header comment - so no <Filter> is ever sent].

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it.

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
    # List every syslog server
    Get-SfosSyslogServer

.EXAMPLE
    # Inspect one server's log category settings
    (Get-SfosSyslogServer -NameLike 'Central').LogSettings.AntiVirus

.NOTES
    Minimum supported PowerShell version: 5.1

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/SyslogServers/operations/AddSyslogServers%26UpdateSyslogServers.html

.LINK
    New-SfosSyslogServer
#>
function Get-SfosSyslogServer {
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

    # No <Filter> is sent here, ever - see the region header comment.
    $inner = '<Get><SyslogServers></SyslogServers></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SyslogServers objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SyslogServers' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SyslogServers[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $logSettingsNode = $node.SelectSingleNode('LogSettings')

        [PSCustomObject]@{
            Name                   = [string]$node.Name
            ServerAddress          = [string]$node.ServerAddress
            Port                   = [string]$node.Port
            EnableSecureConnection = [string]$node.EnableSecureConnection
            Facility               = [string]$node.Facility
            SeverityLevel          = [string]$node.SeverityLevel
            Format                 = [string]$node.Format
            LogSettings            = if ($logSettingsNode) { ConvertFrom-SfosLogSettingsNode -Node $logSettingsNode } else { $null }
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
    Creates a new SyslogServers object on the Sophos Firewall.

.DESCRIPTION
    Creates a SyslogServers entry using the Sophos Firewall XML API. Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER Name
    Name of the syslog server [doc]. Mandatory. Max 50 characters, no commas.

.PARAMETER ServerAddress
    IP address or domain name of the syslog target [doc, wire element ServerAddress - the
    doc table calls this 'IP Address/Domain']. Mandatory.

.PARAMETER SyslogPort
    UDP/TCP port of the syslog target, 1-65535 [doc, wire element Port]. Named -SyslogPort,
    not -Port, because -Port is reserved for the API management port (connection
    parameter). Mandatory.

.PARAMETER EnableSecureConnection
    'Enable' or 'Disable' [doc, wire element EnableSecureConnection - the doc table calls
    this 'Secure connection']. Mandatory.

.PARAMETER Facility
    Syslog facility: 'DAEMON', 'KERNEL', 'USER' or 'LOCAL0'..'LOCAL7' [measured - upper-case
    form; the sample XML's mixed-case form ('Local0' etc.) is rejected with code 501].
    Optional; omitting it entirely is accepted.

.PARAMETER SeverityLevel
    'Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notification', 'Information' or
    'Debug' [doc]. Mandatory.

.PARAMETER Format
    Log format. Only 'DeviceStandardFormat' has been confirmed to work on this firmware
    [measured]. Default: 'DeviceStandardFormat'.

.PARAMETER LogSettings
    The per-category log-suppression subtree, as a nested PSCustomObject in the shape
    Get-SfosSyslogServer returns (see the region header comment). Optional; if omitted, the
    appliance fills in the full category structure itself with every leaf set to 'Disable'
    [measured].

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it.

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
    # A syslog target with default (all-disabled) log category settings
    New-SfosSyslogServer -Name 'Branch Syslog' -ServerAddress 'syslog.example.internal' -SyslogPort 514 -EnableSecureConnection Disable -SeverityLevel Information

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: create without -LogSettings (appliance fills in the full disabled
    category structure), create with an explicit -Facility value, and rejection of a
    mixed-case Facility value with code 501.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/SyslogServers/operations/AddSyslogServers%26UpdateSyslogServers.html

.LINK
    Get-SfosSyslogServer
#>
function New-SfosSyslogServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ServerAddress,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$SyslogPort,

        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$EnableSecureConnection,

        [ValidateSet('DAEMON', 'KERNEL', 'USER', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7')]
        [string]$Facility,

        [Parameter(Mandatory)]
        [ValidateSet('Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notification', 'Information', 'Debug')]
        [string]$SeverityLevel,

        [string]$Format = 'DeviceStandardFormat',

        [object]$LogSettings,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("SyslogServers '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $addressEsc = ConvertTo-SfosXmlEscaped -Text $ServerAddress
    $formatEsc = ConvertTo-SfosXmlEscaped -Text $Format
    $facilityXml = if ($Facility) { "<Facility>$Facility</Facility>" } else { '' }
    $logSettingsXml = if ($null -ne $LogSettings) { '<LogSettings>' + (ConvertTo-SfosLogSettingsXml -LogSettings $LogSettings) + '</LogSettings>' } else { '' }

    $inner = @"
<Set operation="add">
  <SyslogServers>
    <Name>$nameEsc</Name>
    <ServerAddress>$addressEsc</ServerAddress>
    <Port>$SyslogPort</Port>
    <EnableSecureConnection>$EnableSecureConnection</EnableSecureConnection>
    $facilityXml
    <SeverityLevel>$SeverityLevel</SeverityLevel>
    <Format>$formatEsc</Format>
    $logSettingsXml
  </SyslogServers>
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
        throw "Failed to create SyslogServers object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SyslogServers' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SyslogServers object on the Sophos Firewall.

.DESCRIPTION
    Reads the current SyslogServers object, merges any parameters actually supplied by the
    caller on top of it, and writes the complete object back - the API replaces the whole
    entity on update. -LogSettings is treated as one field: omit it to keep the current
    subtree exactly as read, or supply a complete nested replacement (see the region header
    comment). Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the syslog server to update [doc]. Mandatory.

.PARAMETER ServerAddress
    See New-SfosSyslogServer. Optional; keeps the current value if omitted.

.PARAMETER SyslogPort
    See New-SfosSyslogServer. Optional; keeps the current value if omitted. Named
    -SyslogPort, not -Port, because -Port is reserved for the API management port
    (connection parameter).

.PARAMETER EnableSecureConnection
    See New-SfosSyslogServer. Optional; keeps the current value if omitted.

.PARAMETER Facility
    See New-SfosSyslogServer. Optional; keeps the current value if omitted.

.PARAMETER SeverityLevel
    See New-SfosSyslogServer. Optional; keeps the current value if omitted.

.PARAMETER Format
    See New-SfosSyslogServer. Optional; keeps the current value if omitted.

.PARAMETER LogSettings
    See New-SfosSyslogServer. Optional; keeps the current subtree unchanged if omitted.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it. Enables piping between firewalls, e.g. Get-SfosSyslogServer -Session $fw1 |
    Set-SfosSyslogServer -Session fw2 -SeverityLevel Debug.

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
    None. Throws an exception if the update fails or the object does not exist.

.EXAMPLE
    # Change only the severity level, everything else - including LogSettings - unchanged
    Set-SfosSyslogServer -Name 'Branch Syslog' -SeverityLevel Debug

.EXAMPLE
    # Change one log category leaf and write the whole subtree back
    $srv = Get-SfosSyslogServer -NameLike 'Branch Syslog'
    $srv.LogSettings.AntiVirus.HTTP = 'Enable'
    Set-SfosSyslogServer -Name $srv.Name -LogSettings $srv.LogSettings

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: Get-SfosSyslogServer | Set-SfosSyslogServer (unchanged, LogSettings
    included) round trip produced byte-identical raw LogSettings XML on re-read.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/SyslogServers/operations/AddSyslogServers%26UpdateSyslogServers.html

.LINK
    Get-SfosSyslogServer
#>
function Set-SfosSyslogServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$ServerAddress,

        [ValidateRange(1, 65535)]
        [int]$SyslogPort,

        [ValidateSet('Enable', 'Disable')]
        [string]$EnableSecureConnection,

        [ValidateSet('DAEMON', 'KERNEL', 'USER', 'LOCAL0', 'LOCAL1', 'LOCAL2', 'LOCAL3', 'LOCAL4', 'LOCAL5', 'LOCAL6', 'LOCAL7')]
        [string]$Facility,

        [ValidateSet('Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notification', 'Information', 'Debug')]
        [string]$SeverityLevel,

        [string]$Format,

        [object]$LogSettings,

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

        $existing = @(Get-SfosSyslogServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SyslogServers object '$Name' was not found."
        }
        $current = $existing[0]

        $targetAddress = if ($bp.ContainsKey('ServerAddress')) { $ServerAddress } else { $current.ServerAddress }
        $targetPort = if ($bp.ContainsKey('SyslogPort')) { $SyslogPort } else { $current.Port }
        $targetSecure = if ($bp.ContainsKey('EnableSecureConnection')) { $EnableSecureConnection } else { $current.EnableSecureConnection }
        $targetFacility = if ($bp.ContainsKey('Facility')) { $Facility } else { $current.Facility }
        $targetSeverity = if ($bp.ContainsKey('SeverityLevel')) { $SeverityLevel } else { $current.SeverityLevel }
        $targetFormat = if ($bp.ContainsKey('Format')) { $Format } else { $current.Format }
        $targetLogSettings = if ($bp.ContainsKey('LogSettings')) { $LogSettings } else { $current.LogSettings }

        if (-not $PSCmdlet.ShouldProcess("SyslogServers '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $addressEsc = ConvertTo-SfosXmlEscaped -Text $targetAddress
        $formatEsc = ConvertTo-SfosXmlEscaped -Text $targetFormat
        $facilityXml = if ($targetFacility) { "<Facility>$targetFacility</Facility>" } else { '' }
        $logSettingsXml = if ($null -ne $targetLogSettings) { '<LogSettings>' + (ConvertTo-SfosLogSettingsXml -LogSettings $targetLogSettings) + '</LogSettings>' } else { '' }

        $inner = @"
<Set operation="update">
  <SyslogServers>
    <Name>$nameEsc</Name>
    <ServerAddress>$addressEsc</ServerAddress>
    <Port>$targetPort</Port>
    <EnableSecureConnection>$targetSecure</EnableSecureConnection>
    $facilityXml
    <SeverityLevel>$targetSeverity</SeverityLevel>
    <Format>$formatEsc</Format>
    $logSettingsXml
  </SyslogServers>
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
            throw "Failed to update SyslogServers object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SyslogServers' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a SyslogServers object from the Sophos Firewall.

.DESCRIPTION
    Removes a SyslogServers entry using the Sophos Firewall XML API. Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER Name
    Name of the syslog server to remove [doc]. Mandatory.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name. Overrides the stored default connection context; any of
    -Firewall/-Port/-Username/-Password/-SkipCertificateCheck supplied explicitly still wins
    over it.

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
    None. Throws an exception if removal fails.

.EXAMPLE
    Remove-SfosSyslogServer -Name 'Branch Syslog'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removes an existing object and answers code 200 without side effects for
    a name that does not exist.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/SyslogServers/operations/Delete%20Syslog%20Servers.html

.LINK
    Get-SfosSyslogServer
#>
function Remove-SfosSyslogServer {
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
        if (-not $PSCmdlet.ShouldProcess("SyslogServers '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <SyslogServers>
    <Name>$nameEsc</Name>
  </SyslogServers>
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
            throw "Failed to remove SyslogServers object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SyslogServers' -Action 'remove' -Target $Name
    }
}

#endregion SyslogServer

#region SystemServices

<#
.SYNOPSIS
    Retrieves the status of the Sophos Firewall daemon-managed system services.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the SystemServices singleton (CONFIGURE > System
    Services > Manage Servers), which reports the run state and last-known action for the ten
    daemon-managed services: AntiSpam, AntiVirus, Authentication, DHCPServer, DNSServer, IPS,
    WebProxy, WAF, DHCPv6Server and RouterAdvertisementService.

    The published attribute table describes a flat request/response shape (a single generic
    <Service>/<Action> pair with an internal daemon code such as 'kasd'). The actual response
    is nested instead, one named element per daemon, each carrying its own <Action> and
    <Status> children - measured live and matching the operation page's sample XML, not its
    table. This cmdlet reads that nested shape.

.PARAMETER NameLike
    Filters by daemon name, substring match, applied client-side against the ten fixed
    element names above (there is no server-side filter for this singleton).

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
    Returns the raw XML nodes (one per daemon element) instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default) with Name/Action/Status. System.Xml.XmlElement[] when -AsXml is
    specified.

.EXAMPLE
    Get-SfosSystemServiceStatus

.EXAMPLE
    Get-SfosSystemServiceStatus -NameLike 'DHCP'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: each daemon element's <Status> (RUNNING/STOPPED/UNREGISTERED/UNTOUCHED) is
    a plain data field with no code attribute and no sibling <Name> element, which is exactly
    the shape Core's generic status heuristic would otherwise misread as an unrecognised API
    status and throw on. Only a coded <Status> directly under <SystemServices> is treated as a
    real API error here; the per-daemon status text is always read as data.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/ServicesManage/operations/ManageServers.html

.LINK
    Set-SfosSystemService
#>
function Get-SfosSystemServiceStatus {
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

    $inner = '<Get><SystemServices></SystemServices></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve SystemServices daemon status: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See .NOTES: a coded status directly under SystemServices is a real error; the per-daemon
    # Status children are always data and are never passed through the generic status check.
    $codedStatus = $XmlResponse.SelectSingleNode('/Response/SystemServices/Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SystemServices' -Action 'get'
    }

    $daemonNames = @(
        'AntiSpam', 'AntiVirus', 'Authentication', 'DHCPServer', 'DNSServer',
        'IPS', 'WebProxy', 'WAF', 'DHCPv6Server', 'RouterAdvertisementService'
    )

    $nodes = @()
    foreach ($daemonName in $daemonNames) {
        $node = $XmlResponse.SelectSingleNode("/Response/SystemServices/$daemonName")
        if ($node) {
            $nodes += $node
        }
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $result = @()
    foreach ($node in $nodes) {
        $result += [PSCustomObject]@{
            Name   = [string]$node.Name
            Action = [string]$node.Action
            Status = [string]$node.Status
        }
    }

    return $result
}

<#
.SYNOPSIS
    Starts, stops or restarts a Sophos Firewall daemon-managed system service.

.DESCRIPTION
    Issues a Start, Stop or Restart action against one of the ten daemon-managed services
    exposed by the SystemServices singleton (see Get-SfosSystemServiceStatus). Supports
    ShouldProcess; use -WhatIf to preview.

    There is no 'Disable' action - only Start/Stop/Restart are documented and accepted, and
    this cmdlet's -Action parameter does not offer anything else.

.PARAMETER Name
    Daemon to act on: AntiSpam, AntiVirus, Authentication, DHCPServer, DNSServer, IPS,
    WebProxy, WAF, DHCPv6Server or RouterAdvertisementService. Aliased as 'Name' so
    Get-SfosSystemServiceStatus | Set-SfosSystemService binds by property name (the caller
    still has to supply -Action, since the pipelined object's own Action is its last-known
    value, not a request).

.PARAMETER Action
    'Start', 'Stop' or 'Restart'.

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
    None. Throws an exception if the request fails.

.EXAMPLE
    Set-SfosSystemService -Name AntiVirus -Action Restart

.EXAMPLE
    Get-SfosSystemServiceStatus -NameLike 'DHCP' | Set-SfosSystemService -Action Restart

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live against AntiVirus on a lab firewall: Stop answered code 202 'Unable to get
    status message' and the daemon was confirmed STOPPED by a follow-up
    Get-SfosSystemServiceStatus; Start subsequently answered 201 and confirmed RUNNING. Code
    202 is not in the published status table (200-216, then 500-599) and would throw as an
    unrecognised status under the shared table-driven check - it is treated as success here
    only, based on this one measured, confirmed-by-readback case, without changing the shared
    status table in Core. An invalid -Action value (probed as an out-of-range string) answers
    a normal, table-covered 501 naming /SystemServices/<Name>/Action.
    A daemon element name the API does not recognise is silently dropped from the response
    with no status at all - this cannot happen through this cmdlet, because -Name is
    restricted to the ten known daemon names.
    Also measured: the write response places <Status> flat at /Response/<Name>/Status, one
    level shallower than the nested Get response - not /Response/SystemServices/<Name>/Status.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/ServicesManage/operations/ManageServers.html

.LINK
    Get-SfosSystemServiceStatus
#>
function Set-SfosSystemService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet(
            'AntiSpam', 'AntiVirus', 'Authentication', 'DHCPServer', 'DNSServer',
            'IPS', 'WebProxy', 'WAF', 'DHCPv6Server', 'RouterAdvertisementService'
        )]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Start', 'Stop', 'Restart')]
        [string]$Action,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if (-not $PSCmdlet.ShouldProcess("SystemServices daemon '$Name' on $($params.Firewall)", "Set action $Action")) {
            return
        }

        # $Name comes from ValidateSet, never caller-composed text, so it needs no XML
        # escaping before being used as an element tag.
        $inner = @"
<Set operation="update">
  <SystemServices>
    <$Name>
      <Action>$Action</Action>
    </$Name>
  </SystemServices>
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
            throw "Failed to $Action SystemServices daemon '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Not routed through Assert-SfosApiReturnSuccess: see .NOTES on the measured, table-
        # undocumented code 202 that a normal 500-599/204-210 check would wrongly reject.
        $statusNode = $XmlResponse.SelectSingleNode("/Response/$Name/Status[@code]")
        if (-not $statusNode) {
            throw "Sophos API returned no recognisable status while trying to $Action SystemServices daemon '$Name'."
        }

        $code = 0
        [void][int]::TryParse($statusNode.GetAttribute('code'), [ref]$code)

        if (($code -ge 204 -and $code -le 210) -or $code -ge 500) {
            throw "Sophos API error while trying to $Action SystemServices daemon '$Name'. Code $code - $($statusNode.InnerText)"
        }

        if ($code -ne 200 -and $code -ne 216) {
            Write-Warning "Sophos API reported code $code while trying to $Action SystemServices daemon '$Name'. $($statusNode.InnerText)"
        }
    }
}

#endregion

#region HAConfigure

<#
.SYNOPSIS
    Retrieves the High Availability (HA) configuration of the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the HAConfigure singleton (CONFIGURE > System
    Services > HA). There is no documented Get operation for this entity - the whole "System
    Services" area has none - but, as elsewhere in this module, <Get> is accepted and follows
    the shape of the documented Set operation's sample XML.

    Measured on two lab firewalls, neither of which has an HA peer configured: the response
    is <HAConfigure><HA_Interactive><Status>Transaction fail</Status></HA_Interactive></HAConfigure>,
    with no code attribute. Per the project's general rule only the literal wording 'No. of
    records Zero.' means an empty result and every other code-less status is an error; this
    entity is a deliberate, narrowly-scoped second exception (matching the ON/OFF exception
    already made for SDWANPolicyRouteStatus): 'Transaction fail' with no other HA_Interactive
    fields present is read as "HA is not configured" and returns nothing, rather than
    throwing. Nothing else code-less is waved through.

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
    Returns the raw HA_Interactive XML node instead of a PowerShell-friendly object. $null if
    HA is not configured (see .DESCRIPTION).

.OUTPUTS
    PSCustomObject, or $null when HA is not configured. System.Xml.XmlElement (or $null) when
    -AsXml is specified.

.EXAMPLE
    Get-SfosHAConfiguration

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live and identical on both lab firewalls (neither has an HA peer): the response
    carries only <HA_Interactive><Status>Transaction fail</Status></HA_Interactive>, with none
    of the configuration fields documented in the Sample XML populated. The field parsing
    below (Device, NodeName, ClusterID, ...) has never been exercised against a configured HA
    pair and follows the operation page's Sample XML only - see the Notes section on
    Set-SfosHAConfiguration for the full field-naming disagreement between that Sample and
    the attribute table.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/HAConfiguration/operations/HAConfiguration-HASettings.html

.LINK
    Set-SfosHAConfiguration
#>
function Get-SfosHAConfiguration {
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

    $inner = '<Get><HAConfigure></HAConfigure></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve HAConfigure: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # A coded status here is a genuine API error; the code-less 'Transaction fail' case is
    # handled explicitly below and is never routed through the generic status check.
    $codedStatus = $XmlResponse.SelectSingleNode('/Response/HAConfigure//Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HAConfigure' -Action 'get'
    }

    $haInteractive = $XmlResponse.SelectSingleNode('/Response/HAConfigure/HA_Interactive')

    if (-not $haInteractive) {
        return $null
    }

    $statusText = [string]$haInteractive.Status
    $deviceNode = $haInteractive.SelectSingleNode('Device')

    # See .NOTES / .DESCRIPTION: this exact code-less wording with no configuration fields
    # present is this entity's own way of saying "not configured", not an error.
    if ($statusText -eq 'Transaction fail' -and -not $deviceNode) {
        if ($AsXml) {
            return $haInteractive
        }
        return $null
    }

    if ($AsXml) {
        return $haInteractive
    }

    [PSCustomObject]@{
        Device                 = [string]$haInteractive.Device
        NodeName               = [string]$haInteractive.NodeName
        ClusterID              = [string]$haInteractive.ClusterID
        DedicatedLink          = [string]$haInteractive.DedicatedLink
        DedicatedLinkIPAddress = [string]$haInteractive.DedicatedLinkIPAddress
        KeepAliveInterval      = [string]$haInteractive.KeepAlive_Interval
        KeepAliveAttempts      = [string]$haInteractive.KeepAlive_Attempts
        HostMAC                = [string]$haInteractive.HostMAC
        FallbackPrimaryDevice  = [string]$haInteractive.FallbackPrimaryDevice
        Status                 = $statusText
    }
}

<#
.SYNOPSIS
    Configures, disables or resets High Availability (HA) on the Sophos Firewall.

.DESCRIPTION
    [RISK - NOT EXECUTED LIVE] Builds the HAConfigure request for the documented "HA
    Configuration-HA Settings" operation. Supports ShouldProcess; use -WhatIf to preview.

    Neither lab firewall has an HA peer, and activating HA is disruptive and not reversible
    from this side alone, so this cmdlet was never run against a real appliance - only its
    generated XML was checked, by shadowing Invoke-SfosApi in the calling session and
    inspecting the captured request. It is documentation-faithful and unconfirmed.

    Three mutually exclusive operations, one parameter set each:
    - 'Interactive' (default): configure Interactive HA mode, sending an <HA_Interactive>
      block built from Sample XML field names.
    - -Disable: sends the documented empty <DisableHA/> toggle.
    - -Reset: sends the documented empty <HA_Interactive_Reset/> toggle.

    Deliberately NOT implemented: Quick HA mode (<HA_Quick>) and the <MonitorPorts>/
    <PeerAdministrationList> sub-structures of Interactive mode. The attribute table and the
    Sample XML disagree on almost every field name for this entity (see NOTES), and with no
    live object ever returned by Get-SfosHAConfiguration to settle a single one of those
    disagreements, guessing the nested list shapes risked inventing element names outright -
    the exact mistake this project's rules call out by name. The scalar fields below follow
    the Sample, which is the form Get-SfosHAConfiguration's own field parsing also assumes.

    This Set does not accept pipeline input, unlike other Set-* cmdlets in this project: a
    singleton with three mutually exclusive request shapes (build/disable/reset) cannot be
    safely round-tripped through Get-SfosHAConfiguration's output object, so the usual
    parameter-set/pipeline conflict this project avoids does not apply here in the first
    place.

.PARAMETER HAConfigurationMode
    'Active_Active', 'Active_Passive' or 'Auxilliary' [doc, table only - absent from the
    Sample XML entirely, so its placement inside <HA_Interactive> is inferred, not measured].

.PARAMETER Device
    Value of the Sample's <Device> field. Its meaning is not established by either the
    attribute table (which does not list it at all) or any live object; documented here only
    because the Sample shows it as part of both <HA_Quick> and <HA_Interactive>.

.PARAMETER NodeName
    Node name, 1-30 characters [doc, table mandatory].

.PARAMETER ClusterID
    Cluster ID, 0-63 [doc, table mandatory as 'ClusterId'; the Sample element is <ClusterID>].

.PARAMETER Passphrase
    HA passphrase, 10-20 characters per the table's complexity rule for the field it calls
    'EncryptionKey' - the Sample's element name for the same concept is <Passphrase>, which is
    what this cmdlet sends, since Get-SfosHAConfiguration's own parsing follows the Sample too.

.PARAMETER DedicatedLink
    Dedicated HA link interface [doc: table mandatory as 'DedicatedHALinkPort', Sample element
    <DedicatedLink>].

.PARAMETER DedicatedLinkIPAddress
    IPv4 address of the PEER device's dedicated HA link (the web admin labels it "IPv4 address
    of the dedicated peer HA link"). Mandatory for the primary role.

.PARAMETER MonitorPort
    Physical interfaces whose link loss triggers failover, sent as <MonitorPorts><Interface>.
    Optional. At least one monitored port must reach live network equipment for HA to form.

.PARAMETER PeerAdministrationInterface
    Interface of the peer administration settings (mandatory in the web admin's interactive
    mode), sent inside <PeerAdministrationList><PeerConfiguration>. This is what keeps the
    auxiliary reachable once the cluster forms.

.PARAMETER PeerAdministrationIPv4
    IPv4 address for the peer administration interface.

.PARAMETER PeerAdministrationIPv6
    IPv6 address for the peer administration interface.

.PARAMETER KeepAliveInterval
    Keepalive request interval in seconds, sent as <KeepAlive_Interval> [doc, Sample naming;
    the table's own range for this field is self-contradictory - one line says 8-16, the
    validation note beneath it says 16-24 - so no client-side range is enforced here].

.PARAMETER KeepAliveAttempts
    Keepalive attempts before failover, sent as <KeepAlive_Attempts> [doc, Sample naming].

.PARAMETER HostMAC
    Sent as <HostMAC> per the Sample. The table instead documents a same-purpose field named
    'DisableVMAC', with no shared wording between the two - a naming disagreement, not
    obviously the same field with a different name, so it is called out rather than merged.

.PARAMETER FallbackPrimaryDevice
    'No preference', 'Auxiliary' or 'Primary' [doc, table only]. The Sample element for the
    same field is spelled <FallbackPrimaryDevice> (double 'l' in "Fall"); the table spells the
    parameter 'FailbackPrimaryDevice' ('Fail') - a typo in the table itself, inconsistent with
    its own Sample. This cmdlet sends the Sample's spelling, <FallbackPrimaryDevice>.

.PARAMETER Quick
    Uses the QuickHA request shape instead of interactive. The HA link IPs and monitored
    ports are auto-assigned, so only Device/NodeName/DedicatedLink/Passphrase apply. Required
    when the dedicated link is an unbound physical port (interactive only accepts DMZ/LAG/VLAN).

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
    None. Throws an exception if the request fails.

.EXAMPLE
    $pw = Read-Host -AsSecureString
    Set-SfosHAConfiguration -HAConfigurationMode Active_Passive -Device 'unit1' -NodeName 'node1' `
        -ClusterID 1 -Passphrase $pw -DedicatedLink 'PortB' -WhatIf

.EXAMPLE
    Set-SfosHAConfiguration -Quick -Device Auxilliary -NodeName node2 -DedicatedLink Port4 -Passphrase (Read-Host -AsSecureString)

.NOTES
    Minimum supported PowerShell version: 5.1
    [RISK] Not executed against a live firewall - see .DESCRIPTION. Verified only by
    shadowing Invoke-SfosApi in-session and confirming the captured request XML parses and
    matches the field names documented above.
    Table vs Sample field-name disagreement for this entity is close to total - see the
    per-parameter notes above and the module's doc inventory. Nothing here should be treated
    as more than documentation-faithful until it is run once against a real HA pair.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/HAConfiguration/operations/HAConfiguration-HASettings.html

.LINK
    Get-SfosHAConfiguration
#>
function Set-SfosHAConfiguration {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Interactive')]
    param(
        # Primary-only; omitted for the Auxilliary role.
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateSet('Active_Active', 'Active_Passive', 'Auxilliary')]
        [string]$HAConfigurationMode,

        # Drives the request shape: 'Auxilliary' nests DedicatedLink/Passphrase in <Auxilliary>,
        # the two active roles use the flat primary shape. 'Primary'/'Auxiliary' are rejected.
        [Parameter(Mandatory, ParameterSetName = 'Interactive')]
        [ValidateSet('Active_Active', 'Active_Passive', 'Auxilliary')]
        [string]$Device,

        [Parameter(Mandatory, ParameterSetName = 'Interactive')]
        [ValidateLength(1, 30)]
        [string]$NodeName,

        # Primary-only; omitted for the Auxilliary role.
        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateRange(0, 63)]
        [int]$ClusterID,

        [Parameter(Mandatory, ParameterSetName = 'Interactive')]
        [SecureString]$Passphrase,

        [Parameter(Mandatory, ParameterSetName = 'Interactive')]
        [string]$DedicatedLink,

        # Uses the QuickHA request shape (flat <HA_Quick>) instead of interactive; the HA link
        # IPs and monitored ports are auto-assigned, so only Device/NodeName/DedicatedLink/
        # Passphrase apply. The dedicated link must be an unbound/DMZ/LAG/VLAN interface.
        [Parameter(ParameterSetName = 'Interactive')]
        [switch]$Quick,

        [Parameter(ParameterSetName = 'Interactive')]
        [string]$DedicatedLinkIPAddress,

        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateRange(250, 500)]
        [int]$KeepAliveInterval,

        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateRange(16, 24)]
        [int]$KeepAliveAttempts,

        [Parameter(ParameterSetName = 'Interactive')]
        [string]$HostMAC,

        [Parameter(ParameterSetName = 'Interactive')]
        [ValidateSet('No preference', 'Auxiliary', 'Primary')]
        [string]$FallbackPrimaryDevice,

        # Physical interfaces whose link loss triggers failover. Optional per the web admin.
        [Parameter(ParameterSetName = 'Interactive')]
        [string[]]$MonitorPort,

        # Interface + address that keep the auxiliary reachable after the cluster forms.
        [Parameter(ParameterSetName = 'Interactive')]
        [string]$PeerAdministrationInterface,

        [Parameter(ParameterSetName = 'Interactive')]
        [string]$PeerAdministrationIPv4,

        [Parameter(ParameterSetName = 'Interactive')]
        [string]$PeerAdministrationIPv6,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($true) {
        if (-not $PSCmdlet.ShouldProcess("HAConfigure on $($params.Firewall)", "Configure HA ($Device)")) {
            return
        }

        $deviceEsc = ConvertTo-SfosXmlEscaped -Text $Device
        $nodeNameEsc = ConvertTo-SfosXmlEscaped -Text $NodeName
        $dedicatedLinkEsc = ConvertTo-SfosXmlEscaped -Text $DedicatedLink
        $dedicatedLinkIPEsc = ConvertTo-SfosXmlEscaped -Text $DedicatedLinkIPAddress
        $hostMacEsc = ConvertTo-SfosXmlEscaped -Text $HostMAC
        $fallbackEsc = ConvertTo-SfosXmlEscaped -Text $FallbackPrimaryDevice

        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passphrase)
        try {
            $passphrasePlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        $passphraseEsc = ConvertTo-SfosXmlEscaped -Text $passphrasePlain

        $optionalFields = ''
        if ($DedicatedLinkIPAddress) {
            $optionalFields += "      <DedicatedLinkIPAddress>$dedicatedLinkIPEsc</DedicatedLinkIPAddress>`n"
        }
        if ($PSBoundParameters.ContainsKey('KeepAliveInterval')) {
            $optionalFields += "      <KeepAlive_Interval>$KeepAliveInterval</KeepAlive_Interval>`n"
        }
        if ($PSBoundParameters.ContainsKey('KeepAliveAttempts')) {
            $optionalFields += "      <KeepAlive_Attempts>$KeepAliveAttempts</KeepAlive_Attempts>`n"
        }
        if ($HostMAC) {
            $optionalFields += "      <HostMAC>$hostMacEsc</HostMAC>`n"
        }
        if ($FallbackPrimaryDevice) {
            $optionalFields += "      <FallbackPrimaryDevice>$fallbackEsc</FallbackPrimaryDevice>`n"
        }
        if ($MonitorPort) {
            $ifaces = ($MonitorPort | ForEach-Object { "        <Interface>$(ConvertTo-SfosXmlEscaped -Text $_)</Interface>" }) -join "`n"
            $optionalFields += "      <MonitorPorts>`n$ifaces`n      </MonitorPorts>`n"
        }
        if ($PeerAdministrationInterface -or $PeerAdministrationIPv4 -or $PeerAdministrationIPv6) {
            $peer = "        <Interface>$(ConvertTo-SfosXmlEscaped -Text $PeerAdministrationInterface)</Interface>`n"
            if ($PeerAdministrationIPv4) { $peer += "        <IPAddressV4>$(ConvertTo-SfosXmlEscaped -Text $PeerAdministrationIPv4)</IPAddressV4>`n" }
            if ($PeerAdministrationIPv6) { $peer += "        <IPAddressV6>$(ConvertTo-SfosXmlEscaped -Text $PeerAdministrationIPv6)</IPAddressV6>`n" }
            $optionalFields += "      <PeerAdministrationList>`n      <PeerConfiguration>`n$peer      </PeerConfiguration>`n      </PeerAdministrationList>`n"
        }

        if ($Quick) {
            # QuickHA is flat for both roles; the firewall auto-assigns HA link IPs and monitored ports.
            $inner = @"
<Set operation="update">
  <HAConfigure>
    <HA_Quick>
      <Device>$deviceEsc</Device>
      <NodeName>$nodeNameEsc</NodeName>
      <DedicatedLink>$dedicatedLinkEsc</DedicatedLink>
      <Passphrase>$passphraseEsc</Passphrase>
    </HA_Quick>
  </HAConfigure>
</Set>
"@
        }
        elseif ($Device -eq 'Auxilliary') {
            # The auxiliary role nests DedicatedLink/Passphrase in an <Auxilliary> wrapper and
            # omits the primary-only fields (measured: the flat shape is rejected here).
            $inner = @"
<Set operation="update">
  <HAConfigure>
    <HA_Interactive>
      <Device>$deviceEsc</Device>
      <NodeName>$nodeNameEsc</NodeName>
      <Auxilliary>
        <DedicatedLink>$dedicatedLinkEsc</DedicatedLink>
        <Passphrase>$passphraseEsc</Passphrase>
      </Auxilliary>
    </HA_Interactive>
  </HAConfigure>
</Set>
"@
        }
        else {
            if (-not $HAConfigurationMode) { throw "-HAConfigurationMode is required for the '$Device' role." }
            if (-not $PSBoundParameters.ContainsKey('ClusterID')) { throw "-ClusterID is required for the '$Device' role." }
            if (-not $DedicatedLinkIPAddress) { throw "-DedicatedLinkIPAddress (the peer HA link IPv4) is required for the '$Device' role." }
            $inner = @"
<Set operation="update">
  <HAConfigure>
    <HA_Interactive>
      <HAConfigurationMode>$HAConfigurationMode</HAConfigurationMode>
      <Device>$deviceEsc</Device>
      <NodeName>$nodeNameEsc</NodeName>
      <ClusterID>$ClusterID</ClusterID>
      <Passphrase>$passphraseEsc</Passphrase>
      <DedicatedLink>$dedicatedLinkEsc</DedicatedLink>
$optionalFields    </HA_Interactive>
  </HAConfigure>
</Set>
"@
        }
        $target = 'HA (Interactive)'
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to update HAConfigure ($target): $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HA_Interactive' -Action 'update' -Target $target
}

<#
.SYNOPSIS
    Resets the interactive High Availability configuration of the Sophos Firewall.

.DESCRIPTION
    Sends the documented <HA_Interactive_Reset/> toggle, clearing a configured (but not yet
    fully formed) HA setup and returning HAConfigure to its unconfigured state. Verified live:
    it cleanly reverts a device that Set-SfosHAConfiguration has put into a primary or
    auxiliary role.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

.PARAMETER Port
    Management/API port number. If omitted, uses the stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, uses the stored connection context.

.PARAMETER Password
    Password for API authentication. If omitted, uses the stored connection context.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for the API call.

.OUTPUTS
    None. Throws an exception if the reset fails.

.EXAMPLE
    Reset-SfosHAConfiguration

.LINK
    Set-SfosHAConfiguration
#>
function Reset-SfosHAConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    if (-not $PSCmdlet.ShouldProcess("HAConfigure on $($params.Firewall)", 'Reset HA')) { return }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
            -Password $params.Password -InnerXml '<Set operation="update"><HAConfigure><HA_Interactive_Reset /></HAConfigure></Set>' `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to reset HAConfigure: $($_.Exception.Message)"
    }

    Assert-SfosApiReturnSuccess -Xml ([xml]$response.Content) -ObjectName 'HA_Interactive' -Action 'update' -Target 'HA (reset)'
}

<#
.SYNOPSIS
    Disables High Availability on the Sophos Firewall.

.DESCRIPTION
    Sends the documented <DisableHA/> toggle, turning off an active HA configuration.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session registered
    with Connect-SfosFirewall -Name.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

.PARAMETER Port
    Management/API port number. If omitted, uses the stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, uses the stored connection context.

.PARAMETER Password
    Password for API authentication. If omitted, uses the stored connection context.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for the API call.

.OUTPUTS
    None. Throws an exception if the operation fails.

.EXAMPLE
    Disable-SfosHAConfiguration

.LINK
    Set-SfosHAConfiguration
#>
function Disable-SfosHAConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    if (-not $PSCmdlet.ShouldProcess("HAConfigure on $($params.Firewall)", 'Disable HA')) { return }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
            -Password $params.Password -InnerXml '<Set operation="update"><HAConfigure><DisableHA /></HAConfigure></Set>' `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to disable HAConfigure: $($_.Exception.Message)"
    }

    Assert-SfosApiReturnSuccess -Xml ([xml]$response.Content) -ObjectName 'HA_Interactive' -Action 'update' -Target 'HA (disable)'
}

#endregion

#region RED

<#
.SYNOPSIS
    Retrieves the RED (Remote Ethernet Device) broker configuration of the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the RED wrapper's REDConfiguration child
    (CONFIGURE > System Services > Red Configuration). All RED-area operations share the same
    <RED> root element with several unrelated children (REDConfiguration, DeauthorizeDevice,
    TLSVersionSettings, BetaFirmware); a single <Get><RED></RED></Get> call returns all four
    together, and this cmdlet reads only the REDConfiguration piece. There is no documented
    server-side filter, and measured live, sending any unexpected child (including a <Filter>)
    inside the RED Get request wipes the whole response to an empty <RED /> instead of an
    error - so this cmdlet sends the bare Get with no children at all.

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
    Returns the raw REDConfiguration XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject. System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosREDConfiguration

.NOTES
    Minimum supported PowerShell version: 5.1
    [HW] Measured live on both lab firewalls (neither has RED hardware): the response is
    <REDConfiguration><Status>Disable</Status></REDConfiguration> with no OrganizationName,
    City, Country, Email or EULA field present at all - the firewall omits unset elements
    rather than sending them empty, so this cmdlet's OrganizationName/City/Country/Email/
    REDEULA properties were never observed populated and their casing/emptiness handling is
    documentation-faithful, not measured.
    The <Status> child here is REDConfiguration's own Enable/Disable data field, not an API
    status - it has no code attribute and no sibling <Name>, which is exactly what Core's
    generic heuristic would otherwise misidentify as an unrecognised status. Only a coded
    Status anywhere under <RED> is treated as a real error here.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/RedConfiguration/operations/RedConfiguration.html

.LINK
    Set-SfosREDConfiguration
#>
function Get-SfosREDConfiguration {
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

    $inner = '<Get><RED></RED></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve RED configuration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See .NOTES: REDConfiguration's own <Status> is a data field, never an API status here.
    $codedStatus = $XmlResponse.SelectSingleNode('/Response/RED//Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'get'
    }

    $node = $XmlResponse.SelectSingleNode('/Response/RED/REDConfiguration')

    if (-not $node) {
        return $null
    }

    if ($AsXml) {
        return $node
    }

    $eulaNode = $node.SelectSingleNode('REDEULA')

    [PSCustomObject]@{
        Status           = [string]$node.Status
        OrganizationName = [string]$node.OrganizationName
        City             = [string]$node.City
        Country          = [string]$node.Country
        Email            = [string]$node.Email
        REDEULA          = if ($eulaNode) { [string]$eulaNode.InnerText } else { '' }
    }
}

<#
.SYNOPSIS
    Configures the RED broker registration of the Sophos Firewall.

.DESCRIPTION
    [HW - NOT EXECUTED LIVE] Builds the RED/REDConfiguration request for the documented "Red
    Configuration" operation. Supports ShouldProcess; use -WhatIf to preview.

    Reads the current REDConfiguration first and preserves any field not explicitly supplied,
    per this project's read-modify-write rule. Not run against a real firewall - neither lab
    appliance has RED hardware, and Status Enable is a device-wide broker registration switch,
    the same class of setting the project avoids probing live for exactly this reason (compare
    Set-SfosSSLTLSInspectionSettings). Verified only by shadowing Invoke-SfosApi in-session and
    inspecting the captured request XML.

.PARAMETER Status
    'Enable' or 'Disable' [doc, table mandatory; Sample field name matches].

.PARAMETER OrganizationName
    Organization name shown to the RED cloud broker [doc, Sample only].

.PARAMETER City
    City [doc, Sample only].

.PARAMETER Country
    Country [doc, Sample only].

.PARAMETER Email
    Contact email address [doc, Sample only].

.PARAMETER REDEULA
    'Enable' or 'Disable' - EULA acceptance flag. Sent as <REDEULA>, the Sample's element
    name; the attribute table instead documents the same concept as 'REDTermsOfUse'. Neither
    name was confirmed against a live populated object (see the Notes section on
    Get-SfosREDConfiguration), so this is a documented guess, not a measured fact.

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
    None. Throws an exception if the request fails.

.EXAMPLE
    Set-SfosREDConfiguration -Status Disable -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    [HW] Not executed against a live firewall - see .DESCRIPTION. Verified only structurally.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/RedConfiguration/operations/RedConfiguration.html

.LINK
    Get-SfosREDConfiguration
#>
function Set-SfosREDConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Status,

        [ValidateLength(0, 100)]
        [string]$OrganizationName,

        [ValidateLength(0, 100)]
        [string]$City,

        [ValidateLength(0, 100)]
        [string]$Country,

        [ValidateLength(0, 100)]
        [string]$Email,

        [ValidateSet('Enable', 'Disable')]
        [string]$REDEULA,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if (-not $PSCmdlet.ShouldProcess("RED configuration on $($params.Firewall)", "Set status $Status")) {
            return
        }

        $existing = Get-SfosREDConfiguration -Firewall $params.Firewall -Port $params.Port `
            -Username $params.Username -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck

        $targetOrg = if ($PSBoundParameters.ContainsKey('OrganizationName')) { $OrganizationName } elseif ($existing) { $existing.OrganizationName } else { '' }
        $targetCity = if ($PSBoundParameters.ContainsKey('City')) { $City } elseif ($existing) { $existing.City } else { '' }
        $targetCountry = if ($PSBoundParameters.ContainsKey('Country')) { $Country } elseif ($existing) { $existing.Country } else { '' }
        $targetEmail = if ($PSBoundParameters.ContainsKey('Email')) { $Email } elseif ($existing) { $existing.Email } else { '' }
        $targetEula = if ($PSBoundParameters.ContainsKey('REDEULA')) { $REDEULA } elseif ($existing -and $existing.REDEULA) { $existing.REDEULA } else { 'Disable' }

        $orgEsc = ConvertTo-SfosXmlEscaped -Text $targetOrg
        $cityEsc = ConvertTo-SfosXmlEscaped -Text $targetCity
        $countryEsc = ConvertTo-SfosXmlEscaped -Text $targetCountry
        $emailEsc = ConvertTo-SfosXmlEscaped -Text $targetEmail

        $inner = @"
<Set operation="update">
  <RED>
    <REDConfiguration>
      <Status>$Status</Status>
      <OrganizationName>$orgEsc</OrganizationName>
      <City>$cityEsc</City>
      <Country>$countryEsc</Country>
      <Email>$emailEsc</Email>
      <REDEULA>$targetEula</REDEULA>
    </REDConfiguration>
  </RED>
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
            throw "Failed to update RED configuration: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'update' -Target 'REDConfiguration'
    }
}

<#
.SYNOPSIS
    Retrieves the TLS version setting used for RED broker connections.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the RED wrapper's TLSVersionSettings child
    (CONFIGURE > System Services > TLS version settings). Like the other RED-area entities,
    this is fetched through the shared <Get><RED></RED></Get> call - see
    Get-SfosREDConfiguration's .DESCRIPTION for the details shared across all four.

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
    Returns the raw TLSVersionSettings XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject. System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosREDTLSVersionSettings

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live on both lab firewalls: <TLSVersionSettings><TLSVersion>TLS v1.0 and
    later</TLSVersion></TLSVersionSettings> - confirming the Sample's plain-text enum values
    are the real wire form. The attribute table instead claims TLSVersion is a numeric SCALAR
    restricted to '0'/'1'/'2' - contradicted by this live response, which is text.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/ForceTLS/operations/TLSVersionSettings.html

.LINK
    Set-SfosREDTLSVersionSettings
#>
function Get-SfosREDTLSVersionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' names the actual configuration
    # object here (TLSVersionSettings), a singleton with no singular sibling, the same
    # reasoning already applied to Get-SfosWebFilterSettings.
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

    $inner = '<Get><RED></RED></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve RED TLS version settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    $codedStatus = $XmlResponse.SelectSingleNode('/Response/RED//Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'get'
    }

    $node = $XmlResponse.SelectSingleNode('/Response/RED/TLSVersionSettings')

    if (-not $node) {
        return $null
    }

    if ($AsXml) {
        return $node
    }

    [PSCustomObject]@{
        TLSVersion = [string]$node.TLSVersion
    }
}

<#
.SYNOPSIS
    Sets the TLS version setting used for RED broker connections.

.DESCRIPTION
    [HW - NOT EXECUTED LIVE] Builds the RED/TLSVersionSettings request for the documented
    "TLSVersionSettings" operation. Supports ShouldProcess; use -WhatIf to preview.

    This is a single-field entity, so no read-modify-write is needed. Not run against a real
    firewall - this setting governs TLS for the whole RED broker channel device-wide, the same
    class of setting this project avoids probing live. Verified only structurally.

.PARAMETER TLSVersion
    'TLS v1.0 and later', 'TLS v1.2 and later' or 'TLS v1.2 (strict) and later' - the plain-
    text form confirmed live by Get-SfosREDTLSVersionSettings, not the table's numeric codes.

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
    None. Throws an exception if the request fails.

.EXAMPLE
    Set-SfosREDTLSVersionSettings -TLSVersion 'TLS v1.2 (strict) and later' -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    [HW] Not executed against a live firewall - see .DESCRIPTION. Verified only structurally.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/ForceTLS/operations/TLSVersionSettings.html

.LINK
    Get-SfosREDTLSVersionSettings
#>
function Set-SfosREDTLSVersionSettings {
    # PSUseSingularNouns is suppressed on purpose - see Get-SfosREDTLSVersionSettings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('TLS v1.0 and later', 'TLS v1.2 and later', 'TLS v1.2 (strict) and later')]
        [string]$TLSVersion,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if (-not $PSCmdlet.ShouldProcess("RED TLS version settings on $($params.Firewall)", "Set TLSVersion '$TLSVersion'")) {
            return
        }

        $tlsVersionEsc = ConvertTo-SfosXmlEscaped -Text $TLSVersion

        $inner = @"
<Set operation="update">
  <RED>
    <TLSVersionSettings>
      <TLSVersion>$tlsVersionEsc</TLSVersion>
    </TLSVersionSettings>
  </RED>
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
            throw "Failed to update RED TLS version settings: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'update' -Target 'TLSVersionSettings'
    }
}

<#
.SYNOPSIS
    Retrieves the automatic RED device deauthorization settings of the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the RED wrapper's DeauthorizeDevice child
    (CONFIGURE > System Services > Automatic Device Deauthorization). This is a device-wide
    policy setting (whether to auto-deauthorize an idle RED device, and after how many
    minutes) - despite the operation name "DeauthorizeDevice", there is no per-device target
    field documented or observed; see Set-SfosREDDeviceDeauthorizationSettings's .DESCRIPTION
    for why this module names the pair '...Settings' rather than
    '...Invoke-...Deauthorization'.

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
    Returns the raw DeauthorizeDevice XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject. System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosREDDeviceDeauthorizationSettings

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live and identical on both lab firewalls: <DeauthorizeDevice>
    <AutoDeauthorization>Disable</AutoDeauthorization><DeauthorizeAfter>60</DeauthorizeAfter>
    </DeauthorizeDevice> - table and Sample element names agree here, the one RED-area entity
    without a naming disagreement between the two.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/AutomaticDeviceDeauthorization/operations/DeauthorizeDevice.html

.LINK
    Set-SfosREDDeviceDeauthorizationSettings
#>
function Get-SfosREDDeviceDeauthorizationSettings {
    # PSUseSingularNouns is suppressed on purpose. This module's own naming choice (see
    # .DESCRIPTION on the Set- counterpart for why '...Settings' was picked over the
    # operation's literal name 'DeauthorizeDevice') has no singular form that keeps the
    # meaning - a single 'Setting' would be ambiguous about which one.
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

    $inner = '<Get><RED></RED></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve RED device deauthorization settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    $codedStatus = $XmlResponse.SelectSingleNode('/Response/RED//Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'get'
    }

    $node = $XmlResponse.SelectSingleNode('/Response/RED/DeauthorizeDevice')

    if (-not $node) {
        return $null
    }

    if ($AsXml) {
        return $node
    }

    [PSCustomObject]@{
        AutoDeauthorization = [string]$node.AutoDeauthorization
        DeauthorizeAfter    = [string]$node.DeauthorizeAfter
    }
}

<#
.SYNOPSIS
    Sets the automatic RED device deauthorization settings of the Sophos Firewall.

.DESCRIPTION
    [HW - NOT EXECUTED LIVE] Builds the RED/DeauthorizeDevice request for the documented
    "DeauthorizeDevice" operation. Supports ShouldProcess; use -WhatIf to preview.

    Named as a Get/Set settings pair rather than following the operation's own name
    ("DeauthorizeDevice") or the task's suggested 'Invoke-...' verb: the documented and
    observed fields (AutoDeauthorization, DeauthorizeAfter) are a device-wide policy toggle
    with no field that identifies an individual RED device to act on. 'Invoke-' would imply a
    one-time action against a specific device, which this operation cannot express - so it is
    treated as the settings object it actually is, consistent with this project's other
    '...Settings' singletons (e.g. WebFilterProtectionSettings).

    Reads the current settings first and preserves DeauthorizeAfter when only
    AutoDeauthorization is supplied (or vice versa), per this project's read-modify-write
    rule. Not run against a real firewall, per the [HW] grouping for the whole RED area in
    this build's scope - verified only structurally.

.PARAMETER AutoDeauthorization
    'Enable' or 'Disable' [doc, table mandatory].

.PARAMETER DeauthorizeAfter
    Minutes of inactivity before deauthorization, 5-1440 [doc].

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
    None. Throws an exception if the request fails.

.EXAMPLE
    Set-SfosREDDeviceDeauthorizationSettings -AutoDeauthorization Enable -DeauthorizeAfter 120 -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    [HW] Not executed against a live firewall - see .DESCRIPTION. Verified only structurally.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/AutomaticDeviceDeauthorization/operations/DeauthorizeDevice.html

.LINK
    Get-SfosREDDeviceDeauthorizationSettings
#>
function Set-SfosREDDeviceDeauthorizationSettings {
    # PSUseSingularNouns is suppressed on purpose - see Get-SfosREDDeviceDeauthorizationSettings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$AutoDeauthorization,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(5, 1440)]
        [int]$DeauthorizeAfter,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    process {
        if (-not $PSBoundParameters.ContainsKey('AutoDeauthorization') -and -not $PSBoundParameters.ContainsKey('DeauthorizeAfter')) {
            throw 'Set-SfosREDDeviceDeauthorizationSettings requires at least one of -AutoDeauthorization or -DeauthorizeAfter.'
        }

        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if (-not $PSCmdlet.ShouldProcess("RED device deauthorization settings on $($params.Firewall)", 'Set device deauthorization settings')) {
            return
        }

        $existing = Get-SfosREDDeviceDeauthorizationSettings -Firewall $params.Firewall -Port $params.Port `
            -Username $params.Username -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck

        $targetAuto = if ($PSBoundParameters.ContainsKey('AutoDeauthorization')) { $AutoDeauthorization } elseif ($existing) { $existing.AutoDeauthorization } else { 'Disable' }
        $targetAfter = if ($PSBoundParameters.ContainsKey('DeauthorizeAfter')) { $DeauthorizeAfter } elseif ($existing -and $existing.DeauthorizeAfter) { $existing.DeauthorizeAfter } else { 60 }

        $inner = @"
<Set operation="update">
  <RED>
    <DeauthorizeDevice>
      <AutoDeauthorization>$targetAuto</AutoDeauthorization>
      <DeauthorizeAfter>$targetAfter</DeauthorizeAfter>
    </DeauthorizeDevice>
  </RED>
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
            throw "Failed to update RED device deauthorization settings: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'update' -Target 'DeauthorizeDevice'
    }
}

<#
.SYNOPSIS
    Enables or disables RED beta firmware on the Sophos Firewall.

.DESCRIPTION
    [HW - NOT EXECUTED LIVE] Builds the RED/BetaFirmware request for the documented "Run RED
    beta firmware" operation. Supports ShouldProcess; use -WhatIf to preview.

    Single-field entity, so no read-modify-write and no paired Get-* cmdlet - use
    Get-SfosREDConfiguration's underlying <Get><RED></RED></Get> call if the current value is
    needed; it is included in the same response. Not run against a real firewall - toggling
    beta firmware is a firmware-track change with no safe rollback from the API alone.
    Verified only structurally.

.PARAMETER RunBetaFirmware
    'Enable' or 'Disable'. The Sample shows this as an Enable/Disable enum, confirmed live by
    Get-SfosREDConfiguration's shared RED response; the attribute table instead documents it
    as a free-form STRING up to 32 characters, with no value list - not followed here, since
    the live response is unambiguous text but was never observed populated by anything other
    than 'Enable'/'Disable'.

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
    None. Throws an exception if the request fails.

.EXAMPLE
    Set-SfosREDBetaFirmware -RunBetaFirmware Disable -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    [HW] Not executed against a live firewall - see .DESCRIPTION. Verified only structurally.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/RunBetaFirmware/operations/RunREDbetafirmware.html

.LINK
    Get-SfosREDConfiguration
#>
function Set-SfosREDBetaFirmware {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$RunBetaFirmware,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if (-not $PSCmdlet.ShouldProcess("RED beta firmware setting on $($params.Firewall)", "Set RunBetaFirmware '$RunBetaFirmware'")) {
            return
        }

        $inner = @"
<Set operation="update">
  <RED>
    <BetaFirmware>
      <RunBetaFirmware>$RunBetaFirmware</RunBetaFirmware>
    </BetaFirmware>
  </RED>
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
            throw "Failed to update RED beta firmware setting: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RED' -Action 'update' -Target 'BetaFirmware'
    }
}

#endregion

