#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.SystemServices

    PowerShell module for the Sophos Firewall (SFOS) System Services area of the
    XML API: QoS (traffic shaping) policies, syslog servers, the system service
    daemon manager, High Availability, and RED configuration.

    Total functions: 25 (21 exported, 4 internal helpers). See README.md for the
    full cmdlet table.

    Requires SophosFirewall.Core for transport, session state and status
    evaluation. This module builds the entity XML and parses the response; Core
    handles all HTTP(S) communication.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>


#region QoSPolicy
# QoSPolicy (CONFIGURE > System Services > QoS Policy) covers traffic-shaping policies.
# The wire element is <QoSPolicy> (the documentation folder name QOSPolicy is not the
# element name).
#
# BandwidthUsageType takes the free-form values 'Individual' or 'Shared'. An invalid
# value is accepted by the API but clears both BandwidthUsageType and PolicyBasedOn on
# the stored policy, so this module validates the value with ValidateSet before sending
# it and never sends the documented 'on'/'off' form.
# PolicyBasedOn takes 'Application', 'User', 'FirewallRule' or 'WebCategory'. The
# documented value 'Firewall' is stored as 'FirewallRule', so this module sends
# 'FirewallRule' directly.
# Exactly one of four bandwidth field groups applies, selected by ImplementationOn and
# PolicyType: Total+Strict uses TotalBandwidth; Total+Committed uses
# GuaranteedBandwidth and BurstableBandwidth; Individual+Strict uses UploadBandwidth and
# DownloadBandwidth; Individual+Committed uses GuaranteedUploadBandwidth,
# BurstableUploadBandwidth, GuaranteedDownloadBandwidth and BurstableDownloadBandwidth.
# SchedulebasedPolicyRuleList/Rule carries its own PolicyType and Schedule (an existing
# Schedule object's name), plus the same bandwidth group as the top level, chosen by the
# policy's own ImplementationOn combined with the Rule's own PolicyType. The documented
# DetailId field is not part of a stored Rule.
# A malformed request answers with the status node directly under <QoSPolicy>, with no
# <Name> sibling.
# Add, update and remove of a name that does not exist all answer code 200. Remove is a
# true no-op when the name does not exist.

# Builds the bandwidth XML fragment for the one field group selected by ImplementationOn +
# PolicyType, and throws naming the QoS policy and the missing field(s) if the resolved
# values (already merged with the existing object by the caller) do not cover that group.
# Internal helper, not exported.
<#
.SYNOPSIS
    Builds the bandwidth XML fragment for a QoSPolicy.

.DESCRIPTION
    Selects the one bandwidth field group that applies for the given ImplementationOn and
    PolicyType combination, and renders it as XML elements. Throws naming the policy and the
    missing field if the required values are not present in Values. Internal helper, not
    exported.

.PARAMETER Name
    Name of the QoSPolicy, used only in the error message if a required value is missing.

.PARAMETER ImplementationOn
    Selects the bandwidth field group together with PolicyType. Value 'Total' or
    'Individual'.

.PARAMETER PolicyType
    Selects the bandwidth field group together with ImplementationOn. Value 'Strict' or
    'Committed'.

.PARAMETER Values
    Hashtable holding the possible bandwidth values, keyed by field name.
#>
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

<#
.SYNOPSIS
    Builds the SchedulebasedPolicyRuleList XML for a QoSPolicy.

.DESCRIPTION
    Renders an array of rule objects (the shape Get-SfosQoSPolicy returns, with
    PolicyType/Schedule/bandwidth fields) as the SchedulebasedPolicyRuleList XML element.
    Returns an empty element if Rules is null or empty. Internal helper, not exported.

.PARAMETER Name
    Name of the QoSPolicy, used only in error messages for a missing bandwidth value.

.PARAMETER ImplementationOn
    ImplementationOn of the parent QoSPolicy, combined with each rule's own PolicyType to
    select its bandwidth field group.

.PARAMETER Rules
    Array of rule objects to render. May be null or empty.
#>
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
    Retrieves QoS policy objects from a Sophos Firewall.

.DESCRIPTION
    Returns the QoS (traffic shaping) policy objects that are defined on the firewall. A QoS
    policy limits or guarantees bandwidth for traffic that matches an application, a user, a
    firewall rule or a web category. Use this cmdlet to review the existing policies or to
    feed them into another cmdlet through the pipeline. The cmdlet only reads; nothing on the
    firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

    The firewall ships with a set of default QoS policies in addition to any you create; this
    cmdlet returns both.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
    characters. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the QoS
    policy objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per QoS policy, with the
    properties Name, PolicyBasedOn, BandwidthUsageType, ImplementationOn, PolicyType,
    Priority, Description, the bandwidth fields for the selected policy type, and
    SchedulebasedPolicyRuleList. Returns System.Xml.XmlElement when -AsXml is used, and an
    empty array when no object matches.

.EXAMPLE
    Get-SfosQoSPolicy

    Lists every QoS policy on the firewall of the current connection.

.EXAMPLE
    Get-SfosQoSPolicy -NameLike 'Streaming Video'

    Lists the QoS policies whose name contains 'Streaming Video'.

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
    Creates a QoS policy on a Sophos Firewall.

.DESCRIPTION
    Creates a QoS (traffic shaping) policy that limits or guarantees bandwidth for traffic
    matching an application, a user, a firewall rule or a web category. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with permission to create QoS policy objects.

    Exactly one bandwidth field group must be supplied, selected by -ImplementationOn and
    -PolicyType: Total and Strict need -TotalBandwidth; Total and Committed need
    -GuaranteedBandwidth and -BurstableBandwidth; Individual and Strict need -UploadBandwidth
    and -DownloadBandwidth; Individual and Committed need -GuaranteedUploadBandwidth,
    -BurstableUploadBandwidth, -GuaranteedDownloadBandwidth and -BurstableDownloadBandwidth.

.PARAMETER Name
    Required. Name of the new QoS policy. Maximum 50 characters, must not contain a comma.

.PARAMETER PolicyBasedOn
    Required. What the policy attaches to. Valid values: Application, User, FirewallRule,
    WebCategory.

.PARAMETER ImplementationOn
    Required. Total for one shared allocation, or Individual for a per-object allocation.

.PARAMETER PolicyType
    Required. Strict for a hard limit, or Committed for a guarantee with burst.

.PARAMETER Priority
    Required. Traffic priority. Valid values: RealTime, BusinessCritical, Normal2, Normal3,
    Normal4, Normal5, BulkyFTP, BestEffort.

.PARAMETER BandwidthUsageType
    Optional. Individual or Shared. Default: Individual.

.PARAMETER Description
    Optional. Free-text description. Default: empty string.

.PARAMETER TotalBandwidth
    Required together with -ImplementationOn Total and -PolicyType Strict. Bandwidth limit in
    kbps.

.PARAMETER GuaranteedBandwidth
    Required together with -ImplementationOn Total and -PolicyType Committed. Guaranteed
    bandwidth in kbps.

.PARAMETER BurstableBandwidth
    Required together with -ImplementationOn Total and -PolicyType Committed. Burstable
    bandwidth in kbps.

.PARAMETER UploadBandwidth
    Required together with -ImplementationOn Individual and -PolicyType Strict. Upload
    bandwidth limit in kbps.

.PARAMETER DownloadBandwidth
    Required together with -ImplementationOn Individual and -PolicyType Strict. Download
    bandwidth limit in kbps.

.PARAMETER GuaranteedUploadBandwidth
    Required together with -ImplementationOn Individual and -PolicyType Committed. Guaranteed
    upload bandwidth in kbps.

.PARAMETER BurstableUploadBandwidth
    Required together with -ImplementationOn Individual and -PolicyType Committed. Burstable
    upload bandwidth in kbps.

.PARAMETER GuaranteedDownloadBandwidth
    Required together with -ImplementationOn Individual and -PolicyType Committed. Guaranteed
    download bandwidth in kbps.

.PARAMETER BurstableDownloadBandwidth
    Required together with -ImplementationOn Individual and -PolicyType Committed. Burstable
    download bandwidth in kbps.

.PARAMETER SchedulebasedPolicyRuleList
    Optional. Zero or more schedule-based override rules. Each entry is a PSCustomObject
    with PolicyType, Schedule (the name of an existing Schedule object) and the bandwidth
    fields matching -ImplementationOn combined with the rule's own PolicyType. If omitted, no
    schedule-based rule is created.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to create QoS policy
    objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosQoSPolicy -Name 'Branch Office Cap' -PolicyBasedOn User -ImplementationOn Total -PolicyType Strict -Priority Normal3 -TotalBandwidth 512 -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosQoSPolicy -Name 'Branch Office Cap' -PolicyBasedOn User -ImplementationOn Total -PolicyType Strict -Priority Normal3 -TotalBandwidth 512

    Creates a hard per-user total bandwidth limit of 512 kbps.

.EXAMPLE
    New-SfosQoSPolicy -Name 'VoIP App Guarantee' -PolicyBasedOn Application -ImplementationOn Individual -PolicyType Committed -Priority RealTime -GuaranteedUploadBandwidth 64 -BurstableUploadBandwidth 128 -GuaranteedDownloadBandwidth 64 -BurstableDownloadBandwidth 128

    Creates a guaranteed-plus-burst bandwidth allocation per application.

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
    Updates a QoS policy on a Sophos Firewall.

.DESCRIPTION
    Reads the current QoS policy object, replaces the values you pass with your new ones, and
    writes the complete object back; every field you do not pass keeps its current value. Use
    this cmdlet to change a bandwidth limit, priority or description of an existing policy. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with permission to update QoS policy objects.

    -ImplementationOn and -PolicyType are mandatory here, unlike on New-SfosQoSPolicy,
    because the cmdlet accepts pipeline input and needs both values on every call to select
    the right bandwidth fields. Pipe the object from Get-SfosQoSPolicy to supply them
    unchanged.

.PARAMETER Name
    Required. Name of the QoS policy to update. Accepts pipeline input by value and by
    property name.

.PARAMETER PolicyBasedOn
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER ImplementationOn
    Required. See New-SfosQoSPolicy. Accepts pipeline input by property name.

.PARAMETER PolicyType
    Required. See New-SfosQoSPolicy. Accepts pipeline input by property name.

.PARAMETER Priority
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER BandwidthUsageType
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER Description
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted. Pass an empty
    string to clear it.

.PARAMETER TotalBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER GuaranteedBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER BurstableBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER UploadBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER DownloadBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER GuaranteedUploadBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER BurstableUploadBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER GuaranteedDownloadBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER BurstableDownloadBandwidth
    Optional. See New-SfosQoSPolicy. Keeps the current value if omitted.

.PARAMETER SchedulebasedPolicyRuleList
    Optional. See New-SfosQoSPolicy. Keeps the current rule list if omitted. When supplied,
    the whole list is replaced; there is no partial update of individual rules.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to update QoS policy
    objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The Name, ImplementationOn and PolicyType of a QoS policy, for example
    piped from Get-SfosQoSPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update
    or the object does not exist.

.EXAMPLE
    Set-SfosQoSPolicy -Name 'Branch Office Cap' -ImplementationOn Total -PolicyType Strict -TotalBandwidth 1024 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosQoSPolicy -Name 'Branch Office Cap' -ImplementationOn Total -PolicyType Strict -TotalBandwidth 1024

    Raises the bandwidth limit on an existing Total/Strict policy to 1024 kbps.

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
    Removes a QoS policy from a Sophos Firewall.

.DESCRIPTION
    Deletes the QoS policy object with the given name. Removing a name that does not exist
    has no effect. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with permission to remove QoS policy
    objects.

.PARAMETER Name
    Required. Name of the QoS policy to remove. Accepts pipeline input by value and by
    property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to remove QoS policy
    objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The Name of a QoS policy, for example piped from Get-SfosQoSPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosQoSPolicy -Name 'Branch Office Cap' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosQoSPolicy -Name 'Branch Office Cap'

    Removes the QoS policy named 'Branch Office Cap'.

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
# SyslogServers (CONFIGURE > System Services > Syslog Servers). The wire root element is
# <SyslogServers> (plural, unlike most entities), but each object still represents a single
# server; the noun stays singular on the cmdlets, matching the naming convention for
# container-shaped API roots.
#
# The server-side filter does not work for this entity: any <Filter> block returns one fixed
# record instead of the matching set or the full list. Get-SfosSyslogServer never sends a
# <Filter>; -NameLike filters client-side only.
# Facility takes the upper-case form (DAEMON, LOCAL0 through LOCAL7, USER). Facility is
# optional; omitting it leaves it empty on the stored object.
# Format takes the value DeviceStandardFormat.
# LogSettings is a large, variable-shaped subtree; its category set differs between log
# targets, and the built-in local target carries only Name and LogSettings. Rather than
# exposing every leaf toggle as a cmdlet parameter, this module reads and writes the whole
# subtree generically (ConvertFrom-SfosLogSettingsNode / ConvertTo-SfosLogSettingsXml, both
# internal helpers) as a single nested PSCustomObject. -LogSettings on
# New-/Set-SfosSyslogServer takes that same shape: typically the object returned by
# Get-SfosSyslogServer is edited on one leaf property and passed back unchanged otherwise.
# Set-SfosSyslogServer treats the whole subtree as one field for read-modify-write purposes:
# omit -LogSettings to keep the current subtree unchanged, or supply a complete replacement.
# Creating without -LogSettings fills in the full category structure with every leaf set to
# Disable.
# Remove deletes the object and has no effect for a name that does not exist.

<#
.SYNOPSIS
    Converts an XML LogSettings subtree into a nested PSCustomObject.

.DESCRIPTION
    Recursively converts an XML element's children into a nested, ordered PSCustomObject: an
    element with only text content becomes a string property, an element with child elements
    becomes a nested PSCustomObject property. Used for the LogSettings subtree, whose
    category and leaf shape is not fixed. Internal helper, not exported.

.PARAMETER Node
    XML element to convert.
#>
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

<#
.SYNOPSIS
    Converts a nested PSCustomObject into a LogSettings XML subtree.

.DESCRIPTION
    Reverses ConvertFrom-SfosLogSettingsNode: walks a nested PSCustomObject's properties and
    emits the matching XML, escaping every leaf value. Internal helper, not exported.

.PARAMETER LogSettings
    Nested PSCustomObject to convert, in the shape returned by
    ConvertFrom-SfosLogSettingsNode.
#>
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
    Retrieves syslog server objects from a Sophos Firewall.

.DESCRIPTION
    Returns the syslog server objects that are defined on the firewall. A syslog server
    object tells the firewall where to send log messages and which categories to send. Use
    this cmdlet to review the existing servers or to feed them into another cmdlet through
    the pipeline. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

    This entity has no working server-side name filter, so the cmdlet always retrieves the
    full list and applies -NameLike on the client.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
    characters. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the syslog
    server objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per syslog server, with the
    properties Name, ServerAddress, Port, EnableSecureConnection, Facility, SeverityLevel,
    Format and LogSettings. Returns System.Xml.XmlElement when -AsXml is used, and an empty
    array when no object matches.

.EXAMPLE
    Get-SfosSyslogServer

    Lists every syslog server on the firewall of the current connection.

.EXAMPLE
    (Get-SfosSyslogServer -NameLike 'Central').LogSettings.AntiVirus

    Shows the AntiVirus log category setting of the syslog server whose name contains
    'Central'.

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
    Creates a syslog server on a Sophos Firewall.

.DESCRIPTION
    Creates a syslog server object that tells the firewall where to send log messages and
    which categories to send. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with permission to create syslog
    server objects.

.PARAMETER Name
    Required. Name of the new syslog server. Maximum 50 characters, must not contain a
    comma.

.PARAMETER ServerAddress
    Required. IP address or domain name of the syslog target.

.PARAMETER SyslogPort
    Required. UDP or TCP port of the syslog target, 1 to 65535. Named -SyslogPort rather than
    -Port because -Port is reserved for the API management port.

.PARAMETER EnableSecureConnection
    Required. Enable or Disable a secure connection to the syslog target.

.PARAMETER Facility
    Optional. Syslog facility. Valid values: DAEMON, KERNEL, USER, LOCAL0 through LOCAL7. If
    omitted, no facility is stored.

.PARAMETER SeverityLevel
    Required. Minimum severity to send. Valid values: Emergency, Alert, Critical, Error,
    Warning, Notification, Information, Debug.

.PARAMETER Format
    Optional. Log format. Default: DeviceStandardFormat.

.PARAMETER LogSettings
    Optional. Per-category log-suppression settings, as a nested PSCustomObject in the shape
    Get-SfosSyslogServer returns. If omitted, the firewall fills in the full category
    structure with every category set to Disable.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to create syslog
    server objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosSyslogServer -Name 'Branch Syslog' -ServerAddress 'syslog.example.internal' -SyslogPort 514 -EnableSecureConnection Disable -SeverityLevel Information -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosSyslogServer -Name 'Branch Syslog' -ServerAddress 'syslog.example.internal' -SyslogPort 514 -EnableSecureConnection Disable -SeverityLevel Information

    Creates a syslog target with default, all-disabled log category settings.

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
    Updates a syslog server on a Sophos Firewall.

.DESCRIPTION
    Reads the current syslog server object, replaces the values you pass with your new ones,
    and writes the complete object back; every field you do not pass keeps its current value.
    -LogSettings is treated as one field: omit it to keep the current subtree exactly as
    read, or supply a complete nested replacement. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    permission to update syslog server objects.

.PARAMETER Name
    Required. Name of the syslog server to update. Accepts pipeline input by value and by
    property name.

.PARAMETER ServerAddress
    Optional. See New-SfosSyslogServer. Keeps the current value if omitted.

.PARAMETER SyslogPort
    Optional. See New-SfosSyslogServer. Keeps the current value if omitted.

.PARAMETER EnableSecureConnection
    Optional. See New-SfosSyslogServer. Keeps the current value if omitted.

.PARAMETER Facility
    Optional. See New-SfosSyslogServer. Keeps the current value if omitted.

.PARAMETER SeverityLevel
    Optional. See New-SfosSyslogServer. Keeps the current value if omitted.

.PARAMETER Format
    Optional. See New-SfosSyslogServer. Keeps the current value if omitted.

.PARAMETER LogSettings
    Optional. See New-SfosSyslogServer. Keeps the current subtree unchanged if omitted.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to update syslog
    server objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The Name of a syslog server, for example piped from Get-SfosSyslogServer.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update
    or the object does not exist.

.EXAMPLE
    Set-SfosSyslogServer -Name 'Branch Syslog' -SeverityLevel Debug -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSyslogServer -Name 'Branch Syslog' -SeverityLevel Debug

    Changes only the severity level; every other field, including LogSettings, keeps its
    current value.

.EXAMPLE
    $srv = Get-SfosSyslogServer -NameLike 'Branch Syslog'
    $srv.LogSettings.AntiVirus.HTTP = 'Enable'
    Set-SfosSyslogServer -Name $srv.Name -LogSettings $srv.LogSettings

    Changes one log category leaf and writes the whole LogSettings subtree back.

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
    Removes a syslog server from a Sophos Firewall.

.DESCRIPTION
    Deletes the syslog server object with the given name. Removing a name that does not
    exist has no effect. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with permission to remove syslog
    server objects.

.PARAMETER Name
    Required. Name of the syslog server to remove. Accepts pipeline input by value and by
    property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to remove syslog
    server objects. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The Name of a syslog server, for example piped from Get-SfosSyslogServer.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosSyslogServer -Name 'Branch Syslog' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosSyslogServer -Name 'Branch Syslog'

    Removes the syslog server named 'Branch Syslog'.

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
    Returns the run state and last-known action for the ten daemon-managed services:
    AntiSpam, AntiVirus, Authentication, DHCPServer, DNSServer, IPS, WebProxy, WAF,
    DHCPv6Server and RouterAdvertisementService. Use this cmdlet to check whether a service
    is running before or after starting, stopping or restarting it with
    Set-SfosSystemService. The cmdlet only reads; nothing on the firewall is changed. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

    Each daemon's Status value (for example RUNNING or STOPPED) is a data field, not a
    request status; the cmdlet only treats a coded status directly under the response root as
    an error.

.PARAMETER NameLike
    Optional. Returns only services whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern; the characters * and ? are treated as ordinary
    characters. Applied on the client. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the system
    services. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per daemon, with the properties
    Name, Action and Status. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosSystemServiceStatus

    Lists the status of all ten daemon-managed services.

.EXAMPLE
    Get-SfosSystemServiceStatus -NameLike 'DHCP'

    Lists the status of the DHCP-related services.

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

    # A coded status directly under SystemServices is a real error; the per-daemon Status
    # children are always data and are never passed through the generic status check.
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
    reported by Get-SfosSystemServiceStatus. There is no Disable action; only Start, Stop and
    Restart are available. A Stop action may answer with the undocumented status code 202,
    which this cmdlet treats as success. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    permission to manage system services.

.PARAMETER Name
    Required. Daemon to act on. Valid values: AntiSpam, AntiVirus, Authentication,
    DHCPServer, DNSServer, IPS, WebProxy, WAF, DHCPv6Server, RouterAdvertisementService.
    Accepts pipeline input by property name; -Action still has to be supplied explicitly.

.PARAMETER Action
    Required. Start, Stop or Restart.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to manage system
    services. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The Name of a daemon, for example piped from Get-SfosSystemServiceStatus.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSystemService -Name AntiVirus -Action Restart -WhatIf

    Shows what the call would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSystemService -Name AntiVirus -Action Restart

    Restarts the AntiVirus service.

.EXAMPLE
    Get-SfosSystemServiceStatus -NameLike 'DHCP' | Set-SfosSystemService -Action Restart

    Restarts every DHCP-related service.

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

        # Not routed through Assert-SfosApiReturnSuccess: a Stop action can answer with the
        # undocumented code 202, which a normal 500-599/204-210 check would wrongly reject.
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
# HAConfigure (CONFIGURE > System Services > HA). The wire root element is <HAConfigure>,
# holding an <HA_Interactive> child. This entity has no documented Get operation; <Get> is
# accepted and follows the shape of the documented Set operation.
#
# On an appliance with no HA peer configured, the response carries only
# <HA_Interactive><Status>Transaction fail</Status></HA_Interactive>, with no code attribute.
# This exact code-less wording, combined with no other HA_Interactive fields present, is read
# as "HA is not configured" and returns nothing rather than an error.
#
# Some field names differ between the attribute table and the sample XML on the Sophos
# documentation page; this module follows the sample XML, since that is also the shape a live
# object returns: <ClusterID> (table: ClusterId), <Passphrase> (table: EncryptionKey),
# <HostMAC> (table: DisableVMAC), <FallbackPrimaryDevice> (table: FailbackPrimaryDevice).

<#
.SYNOPSIS
    Retrieves the High Availability configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the HA configuration and cluster state of the firewall, or nothing if HA is not
    configured. Use this cmdlet to check the current cluster role before calling
    Initialize-SfosHAConfiguration, or to confirm a cluster formed successfully. The cmdlet
    only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the HA
    configuration. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object. $null if HA is not configured.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties Device, NodeName,
    ClusterID, DedicatedLink, DedicatedLinkIPAddress, KeepAliveInterval, KeepAliveAttempts,
    HostMAC, FallbackPrimaryDevice and Status, or $null when HA is not configured. Returns
    System.Xml.XmlElement, or $null, when -AsXml is used.

.EXAMPLE
    Get-SfosHAConfiguration

    Shows the HA configuration of the firewall of the current connection, or nothing if HA is
    not configured.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/HAConfiguration/operations/HAConfiguration-HASettings.html

.LINK
    Initialize-SfosHAConfiguration
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

    # This exact code-less wording, with no configuration fields present, is this entity's
    # own way of saying "not configured", not an error.
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
    Configures and forms a High Availability cluster on a Sophos Firewall.

.DESCRIPTION
    Puts an appliance into an HA cluster role and forms the cluster. This is not a passive
    setting: applying it reboots the appliance and pairs it with its peer immediately. Once
    the cluster has formed, undo it with Disable-SfosHAConfiguration, run from the primary
    appliance. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with administrative permission.

    Two request shapes are available. QuickHA (-Quick) lets the firewall auto-assign the HA
    link IPs and monitored ports; only -Device, -NodeName, -DedicatedLink and -Passphrase
    apply, and the dedicated link may be an unbound physical port. Interactive mode (the
    default) takes the cluster ID, the peer HA link IP, keepalive values and optionally the
    monitored ports and peer administration address; the dedicated link must be a DMZ, LAG or
    VLAN interface that carries a subnet, because the peer HA link IP sits inside it.

    Configure the auxiliary appliance first, with -Device Auxilliary, then the primary. Both
    appliances must run the same firmware version, or the cluster does not form. For
    interactive mode, the zone carrying the dedicated link must allow SSH in Appliance Access
    on both appliances, or the HA link cannot synchronize.

    This cmdlet does not accept pipeline input.

.PARAMETER Device
    Required. Role this appliance takes: Active_Active, Active_Passive (primary) or
    Auxilliary (standby peer). Selects the whole request shape.

.PARAMETER NodeName
    Required. Node name, 1 to 30 characters.

.PARAMETER ClusterID
    Optional. Cluster ID, 0 to 63. Used for the primary role; omit it for the Auxilliary
    role.

.PARAMETER Passphrase
    Required. HA passphrase, as a SecureString, 10 to 20 characters, including a special
    character.

.PARAMETER DedicatedLink
    Required. Name of the dedicated HA link interface.

.PARAMETER Quick
    Optional. Uses the QuickHA request shape instead of interactive. Required when the
    dedicated link is an unbound physical port.

.PARAMETER DedicatedLinkIPAddress
    Optional. IPv4 address of the peer device's dedicated HA link. Used for the primary role.

.PARAMETER KeepAliveInterval
    Optional. Keepalive request interval in seconds, 250 to 500.

.PARAMETER KeepAliveAttempts
    Optional. Keepalive attempts before failover, 16 to 24.

.PARAMETER HostMAC
    Optional. MAC address of the appliance.

.PARAMETER FallbackPrimaryDevice
    Optional. Valid values: No preference, Auxiliary, Primary.

.PARAMETER MonitorPort
    Optional. Physical interfaces whose link loss triggers failover. At least one monitored
    port must reach live network equipment for HA to form.

.PARAMETER PeerAdministrationInterface
    Optional. Interface used for peer administration. Keeps the auxiliary reachable once the
    cluster forms.

.PARAMETER PeerAdministrationIPv4
    Optional. IPv4 address for the peer administration interface.

.PARAMETER PeerAdministrationIPv6
    Optional. IPv6 address for the peer administration interface.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Initialize-SfosHAConfiguration -Device Active_Passive -NodeName node1 -ClusterID 1 -DedicatedLink Port1 -DedicatedLinkIPAddress '169.254.192.2' -Passphrase (Read-Host -AsSecureString) -WhatIf

    Shows what the call would configure without sending it to the firewall.

.EXAMPLE
    $pw = Read-Host -AsSecureString
    Initialize-SfosHAConfiguration -Device Auxilliary -NodeName node2 -DedicatedLink Port1 -Passphrase $pw -Session fw2
    Initialize-SfosHAConfiguration -Device Active_Passive -NodeName node1 -ClusterID 1 -DedicatedLink Port1 -DedicatedLinkIPAddress '169.254.192.2' -Passphrase $pw -PeerAdministrationInterface Port3 -PeerAdministrationIPv4 '10.0.0.60' -Session fw1

    Forms an interactive active-passive cluster: the auxiliary first, then the primary. The
    dedicated link is a DMZ interface whose subnet holds the peer HA link IP.

.EXAMPLE
    Initialize-SfosHAConfiguration -Quick -Device Auxilliary -NodeName node2 -DedicatedLink Port1 -Passphrase (Read-Host -AsSecureString)

    Forms a QuickHA cluster. The firewall auto-assigns the HA link IPs. Run the same command
    for the primary with -Device Active_Passive. The cmdlet asks for confirmation before it
    writes, because the write reboots the appliance.

.EXAMPLE
    Initialize-SfosHAConfiguration -Quick -Device Auxilliary -NodeName node2 -DedicatedLink Port1 -Passphrase $passphrase -Confirm:$false

    Forms the cluster without asking for confirmation, for use in scripts. Only do this when
    the values have been checked, because the appliance reboots as part of the call.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/HAConfiguration/operations/HAConfiguration-HASettings.html

.LINK
    Get-SfosHAConfiguration

.LINK
    Disable-SfosHAConfiguration
#>
function Initialize-SfosHAConfiguration {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Interactive')]
    param(
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
        if (-not $PSCmdlet.ShouldProcess("HAConfigure on $($params.Firewall)", "Initialize HA ($Device)")) {
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
            # omits the primary-only fields; the flat shape is rejected here.
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
            if (-not $PSBoundParameters.ContainsKey('ClusterID')) { throw "-ClusterID is required for the '$Device' role." }
            if (-not $DedicatedLinkIPAddress) { throw "-DedicatedLinkIPAddress (the peer HA link IPv4) is required for the '$Device' role." }
            # The wire carries the mode in <Device>; a live cluster object holds no <HAConfigurationMode>
            # element, so it is not sent. An empty <PeerAdministrationList> matches the shape of a
            # formed cluster when no peer administration is supplied.
            $emptyPeerAdmin = if ($PeerAdministrationInterface -or $PeerAdministrationIPv4 -or $PeerAdministrationIPv6) { '' } else { "      <PeerAdministrationList></PeerAdministrationList>`n" }
            $inner = @"
<Set operation="update">
  <HAConfigure>
    <HA_Interactive>
      <Device>$deviceEsc</Device>
      <NodeName>$nodeNameEsc</NodeName>
$emptyPeerAdmin      <ClusterID>$ClusterID</ClusterID>
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
    Resets the interactive High Availability configuration of a Sophos Firewall.

.DESCRIPTION
    Clears a configured but not yet fully formed HA setup and returns the appliance to its
    unconfigured state. Use this cmdlet to undo Initialize-SfosHAConfiguration before a
    cluster has actually formed. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the reset.

.EXAMPLE
    Reset-SfosHAConfiguration -WhatIf

    Shows what the call would reset without sending it to the firewall.

.EXAMPLE
    Reset-SfosHAConfiguration

    Clears the current HA configuration of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/HAConfiguration/operations/HAConfiguration-HASettings.html

.LINK
    Initialize-SfosHAConfiguration
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
    Disables High Availability on a Sophos Firewall.

.DESCRIPTION
    Turns off an active HA configuration on both members of the cluster. Run this cmdlet
    against the primary appliance, as required by Sophos: running it against the auxiliary
    appliance instead clears only the auxiliary configuration and leaves the primary
    appliance behind without a working peer. If that happens, reconfigure the primary through
    Initialize-SfosHAConfiguration or the web admin console. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Disable-SfosHAConfiguration -WhatIf

    Shows what the call would disable without sending it to the firewall.

.EXAMPLE
    Disable-SfosHAConfiguration

    Disables HA on the primary appliance of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/System%20Services/HAConfiguration/operations/HAConfiguration-HASettings.html

.LINK
    Initialize-SfosHAConfiguration
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

    # The disable status lands at /Response/DisableHA/Status, not under HA_Interactive.
    Assert-SfosApiReturnSuccess -Xml ([xml]$response.Content) -ObjectName 'DisableHA' -Action 'update' -Target 'HA (disable)'
}

#endregion

#region RED
# All RED-area operations share the same <RED> root element with several unrelated children:
# REDConfiguration, DeauthorizeDevice, TLSVersionSettings and BetaFirmware. A single
# <Get><RED></RED></Get> call returns all four together, and each Get-Sfos* cmdlet in this
# region reads only its own piece. There is no server-side filter for this root; sending any
# unexpected child, including a <Filter>, makes the firewall return an empty <RED />, so every
# Get in this region sends the bare request with no children.
# REDConfiguration's own <Status> child (Enable/Disable) is a data field, not an API status:
# it has no code attribute and no sibling <Name>. Only a coded Status anywhere under <RED> is
# treated as an error.

<#
.SYNOPSIS
    Retrieves the RED (Remote Ethernet Device) broker configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the RED broker registration of the firewall: whether RED is enabled and the
    organization details registered with it. The cmdlet only reads; nothing on the firewall
    is changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the RED
    configuration. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties Status, OrganizationName,
    City, Country, Email and REDEULA. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosREDConfiguration

    Shows the RED broker configuration of the firewall of the current connection.

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

    # REDConfiguration's own <Status> is a data field, never an API status here.
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
    Configures the RED broker registration of a Sophos Firewall.

.DESCRIPTION
    Reads the current RED broker configuration, replaces the values you pass with your new
    ones, and writes the complete object back; every field you do not pass keeps its current
    value. Status enables or disables the RED broker registration for the whole appliance. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER Status
    Required. Enable or Disable the RED broker registration.

.PARAMETER OrganizationName
    Optional. Organization name shown to the RED cloud broker. Maximum 100 characters. Keeps
    the current value if omitted.

.PARAMETER City
    Optional. Maximum 100 characters. Keeps the current value if omitted.

.PARAMETER Country
    Optional. Maximum 100 characters. Keeps the current value if omitted.

.PARAMETER Email
    Optional. Contact email address. Maximum 100 characters. Keeps the current value if
    omitted.

.PARAMETER REDEULA
    Optional. Enable or Disable EULA acceptance. Keeps the current value if omitted, or
    Disable if no current value exists.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The Status of the RED broker configuration, for example piped from
    Get-SfosREDConfiguration.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosREDConfiguration -Status Disable -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosREDConfiguration -Status Disable

    Disables the RED broker registration.

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
    Returns the minimum TLS version the firewall accepts for RED broker connections. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the RED
    settings. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the property TLSVersion, for example 'TLS
    v1.0 and later'. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosREDTLSVersionSettings

    Shows the TLS version setting of the firewall of the current connection.

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
    Sets the minimum TLS version the firewall accepts for RED broker connections, for the
    whole appliance. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with administrative permission.

.PARAMETER TLSVersion
    Required. Valid values: 'TLS v1.0 and later', 'TLS v1.2 and later', 'TLS v1.2 (strict)
    and later'.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The TLSVersion, for example piped from Get-SfosREDTLSVersionSettings.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosREDTLSVersionSettings -TLSVersion 'TLS v1.2 (strict) and later' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosREDTLSVersionSettings -TLSVersion 'TLS v1.2 (strict) and later'

    Requires TLS 1.2 in strict mode for RED broker connections.

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
    Retrieves the automatic RED device deauthorization settings of a Sophos Firewall.

.DESCRIPTION
    Returns the device-wide policy for automatically deauthorizing an idle RED device: whether
    it is enabled, and after how many minutes of inactivity. The cmdlet only reads; nothing on
    the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the RED
    settings. If omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties AutoDeauthorization and
    DeauthorizeAfter. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosREDDeviceDeauthorizationSettings

    Shows the automatic deauthorization settings of the firewall of the current connection.

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
    Sets the automatic RED device deauthorization settings of a Sophos Firewall.

.DESCRIPTION
    Sets the device-wide policy for automatically deauthorizing an idle RED device: whether it
    is enabled, and after how many minutes of inactivity. Reads the current settings first and
    keeps the value of a field you do not pass. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER AutoDeauthorization
    Required. Enable or Disable automatic deauthorization.

.PARAMETER DeauthorizeAfter
    Required. Minutes of inactivity before deauthorization, 5 to 1440.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosREDDeviceDeauthorizationSettings -AutoDeauthorization Enable -DeauthorizeAfter 120 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosREDDeviceDeauthorizationSettings -AutoDeauthorization Enable -DeauthorizeAfter 120

    Deauthorizes an idle RED device automatically after 120 minutes.

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
    Enables or disables RED beta firmware on a Sophos Firewall.

.DESCRIPTION
    Enables or disables the beta firmware track for RED devices, for the whole appliance.
    There is no matching Get cmdlet for this setting in this module. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

.PARAMETER RunBetaFirmware
    Required. Enable or Disable.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosREDBetaFirmware -RunBetaFirmware Disable -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosREDBetaFirmware -RunBetaFirmware Disable

    Disables the beta firmware track for RED devices.

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

