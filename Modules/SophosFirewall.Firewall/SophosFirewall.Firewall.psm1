#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.1' }
<#
        .SYNOPSIS
        Manages firewall rules, rule groups, NAT rules and SSL/TLS inspection on a Sophos Firewall.

        .DESCRIPTION
        Provides cmdlets for the PROTECT > Rules and policies area of the Sophos XGS / SFOS 22.0
        API. The module covers firewall rules (including the network policy subtree), firewall
        rule groups with member management, NAT rules, SSL/TLS inspection rules, and the SSL/TLS
        inspection settings, which the API models as a single unnamed object with no create or
        delete operation.

        Every Set-* cmdlet reads the current object first and writes it back complete, so a call
        that changes one field does not clear the others. Use Connect-SfosFirewall once per
        session; the cmdlets in this module then use that connection without repeating the
        connection parameters.

        The API element for a firewall rule is FirewallRule, even though the web admin and the
        documentation call the same object a security policy. Only PolicyType Network is
        supported; PolicyType User and HTTPBased are documented but not implemented. A rule
        placed at Position Bottom is stored as After the last existing rule, so a later read
        shows After, not Bottom.

        Total Functions: 27 (21 exported, 6 internal helpers) - see README.md for the full
        cmdlet table.

        .EXAMPLE
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosFirewallRule | Format-Table Name, Status, Position, PolicyType

        Connects to the firewall and lists the firewall rules in evaluation order.

        .EXAMPLE
        $policy = New-SfosFirewallRuleNetworkPolicy -Action Accept -SourceZone LAN -DestinationZone WAN
        New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $policy

        Builds a network policy and creates a disabled firewall rule at the bottom of the list.

        .EXAMPLE
        New-SfosFirewallRuleGroup -Name "Outbound" -Members "Allow-LAN-to-WAN"
        (Get-SfosFirewallRuleGroup -NameLike "Outbound").SecurityPolicyList

        Creates a firewall rule group and lists its member rules.

        .EXAMPLE
        Get-SfosSSLTLSInspectionSettings

        Reads the SSL/TLS inspection settings of the current connection.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Connect-SfosFirewall

        .LINK
        Get-SfosFirewallRule

        .LINK
        Get-SfosNATRule
#>

# Helper functions are provided by SophosFirewall.Core module
# Module dependency is handled via RequiredModules in .psd1

#region FirewallRule

# --- FirewallRule ---
#
# The web admin and the documentation call this object a security policy; the wire element
# is FirewallRule. A root element of SecurityPolicy is rejected by the firewall.
#
# Position and rule order are the most sensitive property of this entity: the firewall
# replaces the whole object on an update, so a request that omits Position/After/Before moves
# the rule and reorders the rulebase. Every write cmdlet below therefore funnels through
# ConvertTo-SfosFirewallRuleXml with a fully resolved rule object, and every Set-* reads the
# current object first and preserves Position/After/Before unless the caller overrides them.
#
# <Status> here is a data field (whether the rule is active), not an API status. A status
# node is recognised by a code attribute, or by its parent having no <Name>; the six
# <FirewallRule><Status>Enable</Status> siblings have neither, so they are read as data.
#
# PolicyType has three documented values: User, Network, HTTPBased, each with its own subtree
# (UserPolicy, NetworkPolicy, HTTPBasedPolicy). Only the NetworkPolicy subtree is implemented.
# Get-SfosFirewallRule returns the common top-level fields for any PolicyType; New- and
# Set-SfosFirewallRule accept only PolicyType Network and reject the other two.

<#
.SYNOPSIS
    Builds the <NetworkPolicy> XML for a FirewallRule. Internal helper, not exported.

.DESCRIPTION
    Converts a NetworkPolicy object (as produced by New-SfosFirewallRuleNetworkPolicy or
    returned by Get-SfosFirewallRule) into the NetworkPolicy fragment the firewall expects
    inside a FirewallRule entity. Every value is escaped here. The list wrappers (SourceZones,
    SourceNetworks, DestinationZones, DestinationNetworks, Services) are only emitted when the
    list is non-empty; a rule with no source or destination zones omits the wrapper entirely
    rather than sending it empty.

.PARAMETER NetworkPolicy
    NetworkPolicy object with Action, LogTraffic, SkipLocalDestined, SourceZoneList,
    SourceNetworkList, DestinationZoneList, Schedule, ServiceList, DestinationNetworkList,
    DSCPMarking, WebFilter, WebCategoryBaseQoSPolicy, BlockQuickQuic, ScanVirus,
    ZeroDayProtection, ProxyMode, DecryptHTTPS, ApplicationControl, ApplicationBaseQoSPolicy,
    IntrusionPrevention, NDRActiveThreatIntelligence, TrafficShappingPolicy, ScanSMTP,
    ScanSMTPS, ScanIMAP, ScanIMAPS, ScanPOP3, ScanPOP3S, ScanFTP, SourceSecurityHeartbeat,
    MinimumSourceHBPermitted, DestSecurityHeartbeat and MinimumDestinationHBPermitted
    properties.
#>
function ConvertTo-SfosFirewallRuleNetworkPolicyXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$NetworkPolicy
    )

    $actionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.Action)
    $logTrafficEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.LogTraffic)
    $skipLocalEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.SkipLocalDestined)
    $scheduleEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.Schedule)
    $dscpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.DSCPMarking)
    $webFilterEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.WebFilter)
    $webQosEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.WebCategoryBaseQoSPolicy)
    $blockQuicEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.BlockQuickQuic)
    $scanVirusEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanVirus)
    $zeroDayEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ZeroDayProtection)
    $proxyModeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ProxyMode)
    $decryptHttpsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.DecryptHTTPS)
    $appControlEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ApplicationControl)
    $appQosEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ApplicationBaseQoSPolicy)
    $ipsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.IntrusionPrevention)
    $ndrEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.NDRActiveThreatIntelligence)
    # Wire element is misspelled "TrafficShappingPolicy" (extra 'p') on a live firewall,
    # unlike the correctly spelled "TrafficShapingPolicy" in the vendor doc's attribute
    # table; sending the documented name would land on an unknown element and the field
    # would not be set. The wire spelling wins.
    $trafficShapingEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.TrafficShappingPolicy)
    $scanSmtpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanSMTP)
    $scanSmtpsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanSMTPS)
    $scanImapEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanIMAP)
    $scanImapsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanIMAPS)
    $scanPop3Esc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanPOP3)
    $scanPop3sEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanPOP3S)
    $scanFtpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.ScanFTP)
    $srcHbEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.SourceSecurityHeartbeat)
    $minSrcHbEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.MinimumSourceHBPermitted)
    $dstHbEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.DestSecurityHeartbeat)
    $minDstHbEsc = ConvertTo-SfosXmlEscaped -Text ([string]$NetworkPolicy.MinimumDestinationHBPermitted)

    $sourceZonesXml = ''
    $zoneItems = ''
    foreach ($zone in @($NetworkPolicy.SourceZoneList)) {
        if (-not $zone) {
            continue
        }
        $zoneItems += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
    }
    if ($zoneItems) {
        $sourceZonesXml = "<SourceZones>$zoneItems</SourceZones>"
    }

    $sourceNetworksXml = ''
    $netItems = ''
    foreach ($net in @($NetworkPolicy.SourceNetworkList)) {
        if (-not $net) {
            continue
        }
        $netItems += "<Network>$(ConvertTo-SfosXmlEscaped -Text $net)</Network>"
    }
    if ($netItems) {
        $sourceNetworksXml = "<SourceNetworks>$netItems</SourceNetworks>"
    }

    $destZonesXml = ''
    $dstZoneItems = ''
    foreach ($zone in @($NetworkPolicy.DestinationZoneList)) {
        if (-not $zone) {
            continue
        }
        $dstZoneItems += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
    }
    if ($dstZoneItems) {
        $destZonesXml = "<DestinationZones>$dstZoneItems</DestinationZones>"
    }

    $servicesXml = ''
    $svcItems = ''
    foreach ($svc in @($NetworkPolicy.ServiceList)) {
        if (-not $svc) {
            continue
        }
        $svcItems += "<Service>$(ConvertTo-SfosXmlEscaped -Text $svc)</Service>"
    }
    if ($svcItems) {
        $servicesXml = "<Services>$svcItems</Services>"
    }

    $destNetworksXml = ''
    $dstNetItems = ''
    foreach ($net in @($NetworkPolicy.DestinationNetworkList)) {
        if (-not $net) {
            continue
        }
        $dstNetItems += "<Network>$(ConvertTo-SfosXmlEscaped -Text $net)</Network>"
    }
    if ($dstNetItems) {
        $destNetworksXml = "<DestinationNetworks>$dstNetItems</DestinationNetworks>"
    }

    return "<NetworkPolicy><Action>$actionEsc</Action><LogTraffic>$logTrafficEsc</LogTraffic><SkipLocalDestined>$skipLocalEsc</SkipLocalDestined>$sourceZonesXml$sourceNetworksXml$destZonesXml<Schedule>$scheduleEsc</Schedule>$servicesXml$destNetworksXml<DSCPMarking>$dscpEsc</DSCPMarking><WebFilter>$webFilterEsc</WebFilter><WebCategoryBaseQoSPolicy>$webQosEsc</WebCategoryBaseQoSPolicy><BlockQuickQuic>$blockQuicEsc</BlockQuickQuic><ScanVirus>$scanVirusEsc</ScanVirus><ZeroDayProtection>$zeroDayEsc</ZeroDayProtection><ProxyMode>$proxyModeEsc</ProxyMode><DecryptHTTPS>$decryptHttpsEsc</DecryptHTTPS><ApplicationControl>$appControlEsc</ApplicationControl><ApplicationBaseQoSPolicy>$appQosEsc</ApplicationBaseQoSPolicy><IntrusionPrevention>$ipsEsc</IntrusionPrevention><NDRActiveThreatIntelligence>$ndrEsc</NDRActiveThreatIntelligence><TrafficShappingPolicy>$trafficShapingEsc</TrafficShappingPolicy><ScanSMTP>$scanSmtpEsc</ScanSMTP><ScanSMTPS>$scanSmtpsEsc</ScanSMTPS><ScanIMAP>$scanImapEsc</ScanIMAP><ScanIMAPS>$scanImapsEsc</ScanIMAPS><ScanPOP3>$scanPop3Esc</ScanPOP3><ScanPOP3S>$scanPop3sEsc</ScanPOP3S><ScanFTP>$scanFtpEsc</ScanFTP><SourceSecurityHeartbeat>$srcHbEsc</SourceSecurityHeartbeat><MinimumSourceHBPermitted>$minSrcHbEsc</MinimumSourceHBPermitted><DestSecurityHeartbeat>$dstHbEsc</DestSecurityHeartbeat><MinimumDestinationHBPermitted>$minDstHbEsc</MinimumDestinationHBPermitted></NetworkPolicy>"
}

<#
.SYNOPSIS
    Builds the <Set> inner XML for a FirewallRule entity. Internal helper, not exported.

.DESCRIPTION
    Builds the complete Set request body for a FirewallRule entity, so New-SfosFirewallRule
    and Set-SfosFirewallRule send an identical, complete entity body. Takes a fully resolved
    rule object with the same property shape Get-SfosFirewallRule returns, and escapes every
    value.

    The firewall replaces the whole entity on an update: any element this function does not
    emit is cleared, Position and After/Before included. The caller merges in every field it
    wants preserved, in particular Position, After and Before, before calling this function;
    nothing is read back here.

    Only PolicyType Network is supported. Any other PolicyType throws rather than sending an
    incomplete or empty subtree.

.PARAMETER Operation
    add or update, passed straight to the Set operation attribute.

.PARAMETER Rule
    Fully resolved rule object with Name, Description, IPFamily, Status, Position, Section,
    After, Before, PolicyType and NetworkPolicy properties.
#>
function ConvertTo-SfosFirewallRuleXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Rule
    )

    if ($Rule.PolicyType -ne 'Network') {
        throw "PolicyType '$($Rule.PolicyType)' is not supported by this module - only 'Network' rules can be written. UserPolicy and HTTPBasedPolicy are documented by Sophos but not implemented here."
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Name)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Description)
    $ipFamilyEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.IPFamily)
    $statusEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Status)
    $positionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Position)
    $policyTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.PolicyType)

    $sectionXml = ''
    if ($Rule.Section) {
        $sectionXml = "<Section>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Section))</Section>"
    }

    $afterBeforeXml = ''
    if ($Rule.Position -eq 'After' -and $Rule.After) {
        $afterBeforeXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.After))</Name></After>"
    }
    elseif ($Rule.Position -eq 'Before' -and $Rule.Before) {
        $afterBeforeXml = "<Before><Name>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Before))</Name></Before>"
    }

    $policyXml = ConvertTo-SfosFirewallRuleNetworkPolicyXml -NetworkPolicy $Rule.NetworkPolicy

    return @"
<Set operation="$Operation">
  <FirewallRule>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <IPFamily>$ipFamilyEsc</IPFamily>
    <Status>$statusEsc</Status>
    <Position>$positionEsc</Position>
    $sectionXml
    <PolicyType>$policyTypeEsc</PolicyType>
    $afterBeforeXml
    $policyXml
  </FirewallRule>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves FirewallRule objects from the Sophos Firewall.

.DESCRIPTION
    Returns the firewall rules that are defined on the firewall. A firewall rule controls
    which traffic the appliance permits or denies between zones and networks, and in which
    order the rules are evaluated. Use this cmdlet to review the existing rules or to feed
    them into another cmdlet through the pipeline. The cmdlet only reads; nothing on the
    firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

    Only the top-level fields (Name, Description, IPFamily, Status, Position, Section, After,
    Before, PolicyType) are returned for every rule. The NetworkPolicy property, which carries
    the actual match and action fields, is populated only when PolicyType is Network; for
    PolicyType User or HTTPBased, NetworkPolicy is $null and the rule's own fields are only
    visible with -AsXml. The Status property is the rule's own Enable/Disable flag, not an
    indicator of API success or failure.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result always matches all
    filters you gave.

.PARAMETER NameLike
    Optional. Returns only rules whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER PolicyTypeLike
    Optional. Returns only rules whose PolicyType contains the given text anywhere, for
    example 'Network'. Applied on the client. If omitted, the PolicyType is not used to
    filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for firewall
    rules. If omitted, the value from the current connection is used.

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
    objects. Useful to inspect the fields of a User or HTTPBased rule, which are not exposed
    on the standard output.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per firewall rule, with the
    properties Name, Description, IPFamily, Status, Position, Section, After, Before,
    PolicyType and NetworkPolicy. NetworkPolicy is $null unless PolicyType is Network.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no rule
    matches.

.EXAMPLE
    Get-SfosFirewallRule

    Lists every firewall rule on the firewall of the current connection.

.EXAMPLE
    Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN"

    Lists the rules whose name contains 'Allow-LAN-to-WAN'.

.EXAMPLE
    Get-SfosFirewallRule -PolicyTypeLike "Network" -AsXml

    Returns the raw XML of the Network-type rules, for example to check a field the standard
    output does not contain.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosFirewallRule

.LINK
    Set-SfosFirewallRule
#>
function Get-SfosFirewallRule {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$PolicyTypeLike,

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

    # Server-side pre-filter. SFOS evaluates only the first <key> of the first <Filter>;
    # additional keys and blocks are silently dropped, so every requested filter is applied
    # again client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <FirewallRule>
    $filterXml
  </FirewallRule>
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
        throw "Error retrieving FirewallRule objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Without this check a firewall-side error would be read as an empty result instead of
    # being reported. This also affects Set-SfosFirewallRule, which calls back into this
    # function to read the current object before every update.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRule' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FirewallRule[Name]' | ForEach-Object -Process {
        $_.Node
    }

    $ruleObjects = foreach ($node in @($nodes)) {
        $policyType = [string]$node.PolicyType

        $networkPolicy = $null
        if ($policyType -eq 'Network' -and $node.NetworkPolicy) {
            $netNode = $node.NetworkPolicy

            $sourceZones = [string[]]@($netNode.SourceZones | Select-Object -ExpandProperty Zone | Where-Object -FilterScript { $_ })
            $sourceNetworks = [string[]]@($netNode.SourceNetworks | Select-Object -ExpandProperty Network | Where-Object -FilterScript { $_ })
            $destZones = [string[]]@($netNode.DestinationZones | Select-Object -ExpandProperty Zone | Where-Object -FilterScript { $_ })
            $services = [string[]]@($netNode.Services | Select-Object -ExpandProperty Service | Where-Object -FilterScript { $_ })
            $destNetworks = [string[]]@($netNode.DestinationNetworks | Select-Object -ExpandProperty Network | Where-Object -FilterScript { $_ })

            $networkPolicy = [PSCustomObject]@{
                Action                         = [string]$netNode.Action
                LogTraffic                     = [string]$netNode.LogTraffic
                SkipLocalDestined              = [string]$netNode.SkipLocalDestined
                SourceZoneList                 = $sourceZones
                SourceNetworkList              = $sourceNetworks
                DestinationZoneList            = $destZones
                Schedule                       = [string]$netNode.Schedule
                ServiceList                    = $services
                DestinationNetworkList         = $destNetworks
                DSCPMarking                    = [string]$netNode.DSCPMarking
                WebFilter                      = [string]$netNode.WebFilter
                WebCategoryBaseQoSPolicy       = [string]$netNode.WebCategoryBaseQoSPolicy
                BlockQuickQuic                 = [string]$netNode.BlockQuickQuic
                ScanVirus                      = [string]$netNode.ScanVirus
                ZeroDayProtection              = [string]$netNode.ZeroDayProtection
                ProxyMode                      = [string]$netNode.ProxyMode
                DecryptHTTPS                   = [string]$netNode.DecryptHTTPS
                ApplicationControl             = [string]$netNode.ApplicationControl
                ApplicationBaseQoSPolicy       = [string]$netNode.ApplicationBaseQoSPolicy
                IntrusionPrevention            = [string]$netNode.IntrusionPrevention
                NDRActiveThreatIntelligence    = [string]$netNode.NDRActiveThreatIntelligence
                # See ConvertTo-SfosFirewallRuleNetworkPolicyXml: the wire element is
                # genuinely misspelled "TrafficShappingPolicy" on this firewall.
                TrafficShappingPolicy          = [string]$netNode.TrafficShappingPolicy
                ScanSMTP                       = [string]$netNode.ScanSMTP
                ScanSMTPS                      = [string]$netNode.ScanSMTPS
                ScanIMAP                       = [string]$netNode.ScanIMAP
                ScanIMAPS                      = [string]$netNode.ScanIMAPS
                ScanPOP3                       = [string]$netNode.ScanPOP3
                ScanPOP3S                      = [string]$netNode.ScanPOP3S
                ScanFTP                        = [string]$netNode.ScanFTP
                SourceSecurityHeartbeat        = [string]$netNode.SourceSecurityHeartbeat
                MinimumSourceHBPermitted       = [string]$netNode.MinimumSourceHBPermitted
                DestSecurityHeartbeat          = [string]$netNode.DestSecurityHeartbeat
                MinimumDestinationHBPermitted  = [string]$netNode.MinimumDestinationHBPermitted
            }
        }

        [PSCustomObject]@{
            Name        = [string]$node.Name
            Description = [string]$node.Description
            IPFamily    = [string]$node.IPFamily
            Status      = [string]$node.Status
            Position    = [string]$node.Position
            Section     = [string]$node.Section
            After       = [string]$node.After.Name
            Before      = [string]$node.Before.Name
            PolicyType  = $policyType
            NetworkPolicy = $networkPolicy
        }
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first <Filter> is
    # evaluated by SFOS, and unsupported keys are ignored altogether, so every filter is
    # re-applied here on the returned objects.
    $ruleObjects = @($ruleObjects)
    if ($NameLike) {
        $ruleObjects = @($ruleObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($PolicyTypeLike) {
        $ruleObjects = @($ruleObjects | Where-Object -FilterScript { $_.PolicyType -like "*$PolicyTypeLike*" })
    }

    if ($AsXml) {
        $keptNames = @($ruleObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $ruleObjects
}

<#
.SYNOPSIS
    Resolves one NetworkPolicy field value. Internal helper, not exported.

.DESCRIPTION
    Resolves the value of one NetworkPolicy field for New-SfosFirewallRuleNetworkPolicy and
    Set-SfosFirewallRule. An explicitly bound parameter always wins. Otherwise, when a base
    object is available, the base value is kept. Otherwise the parameter's own value is used
    unchanged.

.PARAMETER IsBound
    Whether the caller explicitly passed the parameter, from $PSBoundParameters.ContainsKey.

.PARAMETER Value
    The parameter's own value - the explicit value when IsBound is $true, otherwise its default.

.PARAMETER BaseValue
    The corresponding value from the base object (InputObject, or the NetworkPolicy being
    merged into).

.PARAMETER HasBase
    Whether a base object is available at all.
#>
function Resolve-SfosNetworkPolicyFieldValue {
    [CmdletBinding()]
    param(
        [bool]$IsBound,
        $Value,
        $BaseValue,
        [bool]$HasBase
    )

    if (-not $IsBound -and $HasBase) {
        return $BaseValue
    }
    return $Value
}

<#
.SYNOPSIS
    Builds a NetworkPolicy object for use with New-SfosFirewallRule or Set-SfosFirewallRule.

.DESCRIPTION
    Creates the object that New-SfosFirewallRule -NetworkPolicy and Set-SfosFirewallRule
    -NetworkPolicy expect. The cmdlet performs no API call; it only builds an in-memory
    object from named parameters, one per NetworkPolicy field, each with a documented
    default.

    Pass an existing NetworkPolicy through -InputObject, for example the NetworkPolicy
    property returned by Get-SfosFirewallRule, to use it as a base. Without -InputObject
    every field falls back to its default. With -InputObject, only the parameters you pass
    explicitly override the base; every other field is copied from -InputObject unchanged,
    so you can change one field without resetting the rest of the policy.

.PARAMETER InputObject
    Optional. An existing NetworkPolicy object to use as a base, for example the
    NetworkPolicy property returned by Get-SfosFirewallRule. Only parameters explicitly
    passed alongside -InputObject override the corresponding field; every other field is
    copied from -InputObject unchanged. Accepts pipeline input.

.PARAMETER Action
    Optional. Traffic handling action: Accept, Reject or Drop. Default: Accept.

.PARAMETER LogTraffic
    Optional. Whether to log traffic matching this rule: Enable or Disable. Default: Disable.

.PARAMETER SkipLocalDestined
    Optional. Skip this rule when the firewall itself is the destination: Enable or Disable.
    Default: Disable.

.PARAMETER SourceZone
    Optional. Source zone names, for example LAN, WAN, DMZ, VPN, Any. Zone names are
    firewall-defined, so no fixed list is enforced. If omitted, no source zone is set.

.PARAMETER SourceNetwork
    Optional. Source network or host object names. If omitted, no source network is set.

.PARAMETER DestinationZone
    Optional. Destination zone names, for example LAN, WAN, LOCAL, VPN, Any.

.PARAMETER Schedule
    Optional. Name of the schedule object this rule is active during. Default: All The Time.

.PARAMETER Service
    Optional. Service object names this rule matches, for example PING, SMTP. If omitted,
    the rule matches all services.

.PARAMETER DestinationNetwork
    Optional. Destination network or host object names.

.PARAMETER DSCPMarking
    Optional. QoS packet classification, -1 to 63. -1 means no DSCP marking. Default: -1.

.PARAMETER WebFilter
    Optional. Name of the web filter policy applied by this rule, or None. Default: None.

.PARAMETER WebCategoryBaseQoSPolicy
    Optional. Bandwidth limit toggle for web categories. Default: '' (empty).

.PARAMETER BlockQuickQuic
    Optional. Block the QUIC protocol: Enable or Disable. Default: Disable.

.PARAMETER ScanVirus
    Optional. Scan matching traffic for viruses: Enable or Disable. Default: Disable.

.PARAMETER ZeroDayProtection
    Optional. Enable zero-day threat protection: Enable or Disable. Default: Disable.

.PARAMETER ProxyMode
    Optional. Use the transparent web proxy: Enable or Disable. Default: Disable.

.PARAMETER DecryptHTTPS
    Optional. Decrypt HTTPS traffic for inspection: Enable or Disable. Default: Disable.

.PARAMETER ApplicationControl
    Optional. Name of the application control policy applied by this rule, or None.
    Default: None.

.PARAMETER ApplicationBaseQoSPolicy
    Optional. Bandwidth limit toggle for application categories. Default: '' (empty).

.PARAMETER IntrusionPrevention
    Optional. Name of the IPS policy applied by this rule, or None. Default: None.

.PARAMETER NDRActiveThreatIntelligence
    Optional. Enable active threat intelligence: Enable or Disable. Default: Disable.

.PARAMETER TrafficShappingPolicy
    Optional. Name of the traffic shaping policy applied by this rule, or None. The
    parameter name matches the wire element spelling used by the firewall. Default: None.

.PARAMETER ScanSMTP
    Optional. Scan SMTP traffic: Enable or Disable. Default: Disable.

.PARAMETER ScanSMTPS
    Optional. Scan SMTPS traffic: Enable or Disable. Default: Disable.

.PARAMETER ScanIMAP
    Optional. Scan IMAP traffic: Enable or Disable. Default: Disable.

.PARAMETER ScanIMAPS
    Optional. Scan IMAPS traffic: Enable or Disable. Default: Disable.

.PARAMETER ScanPOP3
    Optional. Scan POP3 traffic: Enable or Disable. Default: Disable.

.PARAMETER ScanPOP3S
    Optional. Scan POP3S traffic: Enable or Disable. Default: Disable.

.PARAMETER ScanFTP
    Optional. Scan FTP traffic: Enable or Disable. Default: Disable.

.PARAMETER SourceSecurityHeartbeat
    Optional. Require a source Security Heartbeat: Enable or Disable. Default: Disable.

.PARAMETER MinimumSourceHBPermitted
    Optional. Minimum source health status permitted: No Restriction, GREEN or YELLOW.
    Default: No Restriction.

.PARAMETER DestSecurityHeartbeat
    Optional. Require a destination Security Heartbeat: Enable or Disable. Default: Disable.

.PARAMETER MinimumDestinationHBPermitted
    Optional. Minimum destination health status permitted: No Restriction, GREEN or YELLOW.
    Default: No Restriction.

.INPUTS
    System.Management.Automation.PSCustomObject. A NetworkPolicy object, for example the
    NetworkPolicy property returned by Get-SfosFirewallRule, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. A NetworkPolicy object with the same
    property shape Get-SfosFirewallRule returns.

.EXAMPLE
    New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "WAN"

    Builds an Accept policy between LAN and WAN, with logging and scanning left at their
    defaults.

.EXAMPLE
    New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "DMZ" -Service "HTTPS" -LogTraffic Enable

    Builds an Accept policy for HTTPS traffic between LAN and DMZ, with traffic logging
    enabled.

.EXAMPLE
    (Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN").NetworkPolicy | New-SfosFirewallRuleNetworkPolicy -ScanVirus Enable

    Reads the policy of an existing rule and changes only ScanVirus, leaving every other
    field as read from the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosFirewallRule

.LINK
    Set-SfosFirewallRule
#>
function New-SfosFirewallRuleNetworkPolicy {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. This function
    # builds an in-memory object and never calls the API, so there is no state change for
    # ShouldProcess to confirm. The verb New is still correct - it creates an object that is
    # then handed to New-/Set-SfosFirewallRule, which do declare ShouldProcess.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Accept', 'Reject', 'Drop')]
        [string]$Action = 'Accept',

        [ValidateSet('Enable', 'Disable')]
        [string]$LogTraffic = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$SkipLocalDestined = 'Disable',

        [string[]]$SourceZone,

        [string[]]$SourceNetwork,

        [string[]]$DestinationZone,

        [string]$Schedule = 'All The Time',

        [string[]]$Service,

        [string[]]$DestinationNetwork,

        [ValidateRange(-1, 63)]
        [int]$DSCPMarking = -1,

        [string]$WebFilter = 'None',

        [string]$WebCategoryBaseQoSPolicy = '',

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockQuickQuic = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanVirus = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ZeroDayProtection = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ProxyMode = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$DecryptHTTPS = 'Disable',

        [string]$ApplicationControl = 'None',

        [string]$ApplicationBaseQoSPolicy = '',

        [string]$IntrusionPrevention = 'None',

        [ValidateSet('Enable', 'Disable')]
        [string]$NDRActiveThreatIntelligence = 'Disable',

        [string]$TrafficShappingPolicy = 'None',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanSMTP = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanSMTPS = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanIMAP = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanIMAPS = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanPOP3 = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanPOP3S = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanFTP = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$SourceSecurityHeartbeat = 'Disable',

        [ValidateSet('No Restriction', 'GREEN', 'YELLOW')]
        [string]$MinimumSourceHBPermitted = 'No Restriction',

        [ValidateSet('Enable', 'Disable')]
        [string]$DestSecurityHeartbeat = 'Disable',

        [ValidateSet('No Restriction', 'GREEN', 'YELLOW')]
        [string]$MinimumDestinationHBPermitted = 'No Restriction'
    )

    process {
        # $hasBase is $true only when -InputObject was actually supplied (and non-null) - a
        # $null InputObject falls through to the plain defaults, same as omitting the parameter.
        $hasBase = $PSBoundParameters.ContainsKey('InputObject') -and ($null -ne $InputObject)

        $resolvedAction = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('Action') -Value $Action -BaseValue $InputObject.Action -HasBase $hasBase
        $resolvedLogTraffic = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('LogTraffic') -Value $LogTraffic -BaseValue $InputObject.LogTraffic -HasBase $hasBase
        $resolvedSkipLocalDestined = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('SkipLocalDestined') -Value $SkipLocalDestined -BaseValue $InputObject.SkipLocalDestined -HasBase $hasBase
        $resolvedSourceZoneList = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('SourceZone') -Value @($SourceZone) -BaseValue @($InputObject.SourceZoneList) -HasBase $hasBase
        $resolvedSourceNetworkList = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('SourceNetwork') -Value @($SourceNetwork) -BaseValue @($InputObject.SourceNetworkList) -HasBase $hasBase
        $resolvedDestinationZoneList = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('DestinationZone') -Value @($DestinationZone) -BaseValue @($InputObject.DestinationZoneList) -HasBase $hasBase
        $resolvedSchedule = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('Schedule') -Value $Schedule -BaseValue $InputObject.Schedule -HasBase $hasBase
        $resolvedServiceList = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('Service') -Value @($Service) -BaseValue @($InputObject.ServiceList) -HasBase $hasBase
        $resolvedDestinationNetworkList = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('DestinationNetwork') -Value @($DestinationNetwork) -BaseValue @($InputObject.DestinationNetworkList) -HasBase $hasBase
        $resolvedDSCPMarking = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('DSCPMarking') -Value ([string]$DSCPMarking) -BaseValue $InputObject.DSCPMarking -HasBase $hasBase
        $resolvedWebFilter = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('WebFilter') -Value $WebFilter -BaseValue $InputObject.WebFilter -HasBase $hasBase
        $resolvedWebCategoryBaseQoSPolicy = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('WebCategoryBaseQoSPolicy') -Value $WebCategoryBaseQoSPolicy -BaseValue $InputObject.WebCategoryBaseQoSPolicy -HasBase $hasBase
        $resolvedBlockQuickQuic = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('BlockQuickQuic') -Value $BlockQuickQuic -BaseValue $InputObject.BlockQuickQuic -HasBase $hasBase
        $resolvedScanVirus = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanVirus') -Value $ScanVirus -BaseValue $InputObject.ScanVirus -HasBase $hasBase
        $resolvedZeroDayProtection = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ZeroDayProtection') -Value $ZeroDayProtection -BaseValue $InputObject.ZeroDayProtection -HasBase $hasBase
        $resolvedProxyMode = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ProxyMode') -Value $ProxyMode -BaseValue $InputObject.ProxyMode -HasBase $hasBase
        $resolvedDecryptHTTPS = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('DecryptHTTPS') -Value $DecryptHTTPS -BaseValue $InputObject.DecryptHTTPS -HasBase $hasBase
        $resolvedApplicationControl = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ApplicationControl') -Value $ApplicationControl -BaseValue $InputObject.ApplicationControl -HasBase $hasBase
        $resolvedApplicationBaseQoSPolicy = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ApplicationBaseQoSPolicy') -Value $ApplicationBaseQoSPolicy -BaseValue $InputObject.ApplicationBaseQoSPolicy -HasBase $hasBase
        $resolvedIntrusionPrevention = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('IntrusionPrevention') -Value $IntrusionPrevention -BaseValue $InputObject.IntrusionPrevention -HasBase $hasBase
        $resolvedNDRActiveThreatIntelligence = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('NDRActiveThreatIntelligence') -Value $NDRActiveThreatIntelligence -BaseValue $InputObject.NDRActiveThreatIntelligence -HasBase $hasBase
        $resolvedTrafficShappingPolicy = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('TrafficShappingPolicy') -Value $TrafficShappingPolicy -BaseValue $InputObject.TrafficShappingPolicy -HasBase $hasBase
        $resolvedScanSMTP = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanSMTP') -Value $ScanSMTP -BaseValue $InputObject.ScanSMTP -HasBase $hasBase
        $resolvedScanSMTPS = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanSMTPS') -Value $ScanSMTPS -BaseValue $InputObject.ScanSMTPS -HasBase $hasBase
        $resolvedScanIMAP = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanIMAP') -Value $ScanIMAP -BaseValue $InputObject.ScanIMAP -HasBase $hasBase
        $resolvedScanIMAPS = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanIMAPS') -Value $ScanIMAPS -BaseValue $InputObject.ScanIMAPS -HasBase $hasBase
        $resolvedScanPOP3 = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanPOP3') -Value $ScanPOP3 -BaseValue $InputObject.ScanPOP3 -HasBase $hasBase
        $resolvedScanPOP3S = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanPOP3S') -Value $ScanPOP3S -BaseValue $InputObject.ScanPOP3S -HasBase $hasBase
        $resolvedScanFTP = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('ScanFTP') -Value $ScanFTP -BaseValue $InputObject.ScanFTP -HasBase $hasBase
        $resolvedSourceSecurityHeartbeat = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('SourceSecurityHeartbeat') -Value $SourceSecurityHeartbeat -BaseValue $InputObject.SourceSecurityHeartbeat -HasBase $hasBase
        $resolvedMinimumSourceHBPermitted = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('MinimumSourceHBPermitted') -Value $MinimumSourceHBPermitted -BaseValue $InputObject.MinimumSourceHBPermitted -HasBase $hasBase
        $resolvedDestSecurityHeartbeat = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('DestSecurityHeartbeat') -Value $DestSecurityHeartbeat -BaseValue $InputObject.DestSecurityHeartbeat -HasBase $hasBase
        $resolvedMinimumDestinationHBPermitted = Resolve-SfosNetworkPolicyFieldValue -IsBound $PSBoundParameters.ContainsKey('MinimumDestinationHBPermitted') -Value $MinimumDestinationHBPermitted -BaseValue $InputObject.MinimumDestinationHBPermitted -HasBase $hasBase

        return [PSCustomObject]@{
            Action                        = $resolvedAction
            LogTraffic                    = $resolvedLogTraffic
            SkipLocalDestined             = $resolvedSkipLocalDestined
            SourceZoneList                = $resolvedSourceZoneList
            SourceNetworkList             = $resolvedSourceNetworkList
            DestinationZoneList           = $resolvedDestinationZoneList
            Schedule                      = $resolvedSchedule
            ServiceList                   = $resolvedServiceList
            DestinationNetworkList        = $resolvedDestinationNetworkList
            DSCPMarking                   = [string]$resolvedDSCPMarking
            WebFilter                     = $resolvedWebFilter
            WebCategoryBaseQoSPolicy      = $resolvedWebCategoryBaseQoSPolicy
            BlockQuickQuic                = $resolvedBlockQuickQuic
            ScanVirus                     = $resolvedScanVirus
            ZeroDayProtection             = $resolvedZeroDayProtection
            ProxyMode                     = $resolvedProxyMode
            DecryptHTTPS                  = $resolvedDecryptHTTPS
            ApplicationControl            = $resolvedApplicationControl
            ApplicationBaseQoSPolicy      = $resolvedApplicationBaseQoSPolicy
            IntrusionPrevention           = $resolvedIntrusionPrevention
            NDRActiveThreatIntelligence   = $resolvedNDRActiveThreatIntelligence
            TrafficShappingPolicy         = $resolvedTrafficShappingPolicy
            ScanSMTP                      = $resolvedScanSMTP
            ScanSMTPS                     = $resolvedScanSMTPS
            ScanIMAP                      = $resolvedScanIMAP
            ScanIMAPS                     = $resolvedScanIMAPS
            ScanPOP3                      = $resolvedScanPOP3
            ScanPOP3S                     = $resolvedScanPOP3S
            ScanFTP                       = $resolvedScanFTP
            SourceSecurityHeartbeat       = $resolvedSourceSecurityHeartbeat
            MinimumSourceHBPermitted      = $resolvedMinimumSourceHBPermitted
            DestSecurityHeartbeat         = $resolvedDestSecurityHeartbeat
            MinimumDestinationHBPermitted = $resolvedMinimumDestinationHBPermitted
        }
    }
}

<#
.SYNOPSIS
    Creates a new firewall rule on a Sophos Firewall.

.DESCRIPTION
    Creates a firewall rule using the Sophos Firewall API. A firewall rule controls which
    traffic the appliance permits or denies between zones and networks, and in which order
    the rules are evaluated. Only PolicyType Network is supported; build the NetworkPolicy
    subtree with New-SfosFirewallRuleNetworkPolicy first. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    permission to change firewall rules.

    -Status and -Position are mandatory, so neither whether the rule is active nor where it
    sits in the evaluation order is left to a default. Inserting a rule at Position Top moves
    every existing rule down by one position and changes the evaluation order of the whole
    rule base.

.PARAMETER Name
    Required. Name of the firewall rule. 1 to 60 characters, no commas.

.PARAMETER Description
    Optional. Free-text description of the rule.

.PARAMETER IPFamily
    Optional. Internet Protocol version: IPv4 or IPv6. Default: IPv4.

.PARAMETER Status
    Required. Whether the rule is active: Enable or Disable.

.PARAMETER Position
    Required. Where to insert the rule: Top, Bottom, After or Before. Top inserts above every
    existing rule and moves all of them down one position, changing the evaluation order of
    the whole rule base.

.PARAMETER After
    Optional. Name of the existing rule this one is inserted after. Required when -Position
    is After.

.PARAMETER Before
    Optional. Name of the existing rule this one is inserted before. Required when -Position
    is Before.

.PARAMETER Section
    Optional. Policy section: Central_TOP, Local or Central_Bottom.

.PARAMETER PolicyType
    Required. Type of policy: User, Network or HTTPBased. Only Network is implemented; the
    other two values are rejected.

.PARAMETER NetworkPolicy
    Optional. NetworkPolicy object, built with New-SfosFirewallRuleNetworkPolicy. Required
    when -PolicyType is Network.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change firewall
    rules. If omitted, the value from the current connection is used.

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
    $np = New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "WAN"
    New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $np -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    $np = New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "WAN"
    New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $np

    Creates a disabled firewall rule at the bottom of the rule base. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosFirewallRule

.LINK
    New-SfosFirewallRuleNetworkPolicy
#>
function New-SfosFirewallRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Status,

        [Parameter(Mandatory)]
        [ValidateSet('Top', 'Bottom', 'After', 'Before')]
        [string]$Position,

        [string]$After,

        [string]$Before,

        [ValidateSet('Central_TOP', 'Local', 'Central_Bottom')]
        [string]$Section,

        [Parameter(Mandatory)]
        [ValidateSet('User', 'Network', 'HTTPBased')]
        [string]$PolicyType,

        [PSCustomObject]$NetworkPolicy,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($Position -eq 'After' -and -not $After) {
        throw "FirewallRule '$Name': -Position After requires -After <existing rule name>."
    }
    if ($Position -eq 'Before' -and -not $Before) {
        throw "FirewallRule '$Name': -Position Before requires -Before <existing rule name>."
    }
    if ($PolicyType -eq 'Network' -and -not $NetworkPolicy) {
        throw "FirewallRule '$Name': -PolicyType Network requires -NetworkPolicy, built with New-SfosFirewallRuleNetworkPolicy."
    }

    $rule = [PSCustomObject]@{
        Name          = $Name
        Description   = $Description
        IPFamily      = $IPFamily
        Status        = $Status
        Position      = $Position
        Section       = $Section
        After         = $After
        Before        = $Before
        PolicyType    = $PolicyType
        NetworkPolicy = $NetworkPolicy
    }

    $inner = ConvertTo-SfosFirewallRuleXml -Operation 'add' -Rule $rule

    if (-not $PSCmdlet.ShouldProcess("FirewallRule '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating FirewallRule object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRule' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing firewall rule on a Sophos Firewall.

.DESCRIPTION
    Updates a firewall rule using the Sophos Firewall API. You can supply the target rule
    name directly or through the pipeline. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    permission to change firewall rules.

    The firewall replaces the whole rule on update; any field not sent in the request is
    cleared. This is especially sensitive for Position, After and Before: an update that does
    not resend them would move the rule and reorder the whole rule base. The cmdlet reads the
    current rule first and, unless you pass -Position explicitly, resends the existing
    Position, After and Before unchanged, together with every other field you did not pass.

    Only rules with PolicyType Network can be updated; any other PolicyType throws before a
    request is sent.

.PARAMETER Name
    Required. Name of the target rule. Accepts pipeline input.

.PARAMETER Description
    Optional. New description text. If omitted, the existing description is kept.

.PARAMETER IPFamily
    Optional. Internet Protocol version: IPv4 or IPv6. If omitted, the existing value is
    kept.

.PARAMETER Status
    Optional. Whether the rule is active: Enable or Disable. If omitted, the existing value
    is kept.

.PARAMETER Position
    Optional. Where to move the rule: Top, Bottom, After or Before. If omitted, the existing
    Position, After and Before are kept unchanged. If supplied, changes the evaluation order
    of the rule base; Top additionally moves every other rule down one position.

.PARAMETER After
    Optional. Name of the existing rule to move this one after. Required when -Position is
    After.

.PARAMETER Before
    Optional. Name of the existing rule to move this one before. Required when -Position is
    Before.

.PARAMETER Section
    Optional. Policy section: Central_TOP, Local or Central_Bottom. If omitted, the existing
    value is kept.

.PARAMETER NetworkPolicy
    Optional. Complete replacement NetworkPolicy object, built with
    New-SfosFirewallRuleNetworkPolicy or taken from Get-SfosFirewallRule. Replaces the
    existing NetworkPolicy as a whole. If omitted, the existing NetworkPolicy is kept, and
    only the per-field NetworkPolicy parameters below, if passed, change individual fields on
    top of it.

.PARAMETER Action
    Optional. NetworkPolicy field: traffic handling action. Changes only this field; every
    other NetworkPolicy field is preserved.

.PARAMETER LogTraffic
    Optional. NetworkPolicy field: whether to log traffic matching this rule.

.PARAMETER SkipLocalDestined
    Optional. NetworkPolicy field: skip this rule when the firewall itself is the
    destination.

.PARAMETER SourceZone
    Optional. NetworkPolicy field: source zone names. Replaces the whole source zone list.

.PARAMETER SourceNetwork
    Optional. NetworkPolicy field: source network or host object names. Replaces the whole
    source network list.

.PARAMETER DestinationZone
    Optional. NetworkPolicy field: destination zone names. Replaces the whole destination
    zone list.

.PARAMETER Schedule
    Optional. NetworkPolicy field: name of the schedule object this rule is active during.

.PARAMETER Service
    Optional. NetworkPolicy field: service object names this rule matches. Replaces the whole
    service list.

.PARAMETER DestinationNetwork
    Optional. NetworkPolicy field: destination network or host object names. Replaces the
    whole destination network list.

.PARAMETER DSCPMarking
    Optional. NetworkPolicy field: QoS packet classification, -1 to 63.

.PARAMETER WebFilter
    Optional. NetworkPolicy field: name of the web filter policy applied by this rule, or
    None.

.PARAMETER WebCategoryBaseQoSPolicy
    Optional. NetworkPolicy field: bandwidth limit toggle for web categories.

.PARAMETER BlockQuickQuic
    Optional. NetworkPolicy field: block the QUIC protocol.

.PARAMETER ScanVirus
    Optional. NetworkPolicy field: scan matching traffic for viruses.

.PARAMETER ZeroDayProtection
    Optional. NetworkPolicy field: enable zero-day threat protection.

.PARAMETER ProxyMode
    Optional. NetworkPolicy field: use the transparent web proxy.

.PARAMETER DecryptHTTPS
    Optional. NetworkPolicy field: decrypt HTTPS traffic for inspection.

.PARAMETER ApplicationControl
    Optional. NetworkPolicy field: name of the application control policy applied by this
    rule, or None.

.PARAMETER ApplicationBaseQoSPolicy
    Optional. NetworkPolicy field: bandwidth limit toggle for application categories.

.PARAMETER IntrusionPrevention
    Optional. NetworkPolicy field: name of the IPS policy applied by this rule, or None.

.PARAMETER NDRActiveThreatIntelligence
    Optional. NetworkPolicy field: enable active threat intelligence.

.PARAMETER TrafficShappingPolicy
    Optional. NetworkPolicy field: name of the traffic shaping policy applied by this rule,
    or None. The parameter name matches the wire element spelling used by the firewall.

.PARAMETER ScanSMTP
    Optional. NetworkPolicy field: scan SMTP traffic.

.PARAMETER ScanSMTPS
    Optional. NetworkPolicy field: scan SMTPS traffic.

.PARAMETER ScanIMAP
    Optional. NetworkPolicy field: scan IMAP traffic.

.PARAMETER ScanIMAPS
    Optional. NetworkPolicy field: scan IMAPS traffic.

.PARAMETER ScanPOP3
    Optional. NetworkPolicy field: scan POP3 traffic.

.PARAMETER ScanPOP3S
    Optional. NetworkPolicy field: scan POP3S traffic.

.PARAMETER ScanFTP
    Optional. NetworkPolicy field: scan FTP traffic.

.PARAMETER SourceSecurityHeartbeat
    Optional. NetworkPolicy field: require a source Security Heartbeat.

.PARAMETER MinimumSourceHBPermitted
    Optional. NetworkPolicy field: minimum source health status permitted: No Restriction,
    GREEN or YELLOW.

.PARAMETER DestSecurityHeartbeat
    Optional. NetworkPolicy field: require a destination Security Heartbeat.

.PARAMETER MinimumDestinationHBPermitted
    Optional. NetworkPolicy field: minimum destination health status permitted: No
    Restriction, GREEN or YELLOW.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change firewall
    rules. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Objects with a Name property, such as the
    output of Get-SfosFirewallRule, can be piped in.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Description "Updated" -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Description "Updated"

    Changes only the description; Position, After, Before and NetworkPolicy are preserved.
    The cmdlet asks for confirmation before it writes.

.EXAMPLE
    Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN" | Set-SfosFirewallRule -Status Enable

    Enables a previously disabled rule; the rule's position is untouched.

.EXAMPLE
    Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -ScanVirus Enable

    Turns on virus scanning without changing any other NetworkPolicy field.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosFirewallRule

.LINK
    New-SfosFirewallRule
#>
function Set-SfosFirewallRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [ValidateSet('Enable', 'Disable')]
        [string]$Status,

        [ValidateSet('Top', 'Bottom', 'After', 'Before')]
        [string]$Position,

        [string]$After,

        [string]$Before,

        [ValidateSet('Central_TOP', 'Local', 'Central_Bottom')]
        [string]$Section,

        [Parameter(ValueFromPipelineByPropertyName)]
        [PSCustomObject]$NetworkPolicy,

        # Per-field NetworkPolicy parameters. None of these carry a default - see .PARAMETER
        # NetworkPolicy and the merge logic in the process block below: only a field the caller
        # actually passed (checked via $PSBoundParameters.ContainsKey, never a truthiness test)
        # overrides the base, everything else is copied from the current rule (or -NetworkPolicy,
        # if given). A default here would make that field look "passed" on every call and
        # silently reset it on every update.
        [ValidateSet('Accept', 'Reject', 'Drop')]
        [string]$Action,

        [ValidateSet('Enable', 'Disable')]
        [string]$LogTraffic,

        [ValidateSet('Enable', 'Disable')]
        [string]$SkipLocalDestined,

        [string[]]$SourceZone,

        [string[]]$SourceNetwork,

        [string[]]$DestinationZone,

        [string]$Schedule,

        [string[]]$Service,

        [string[]]$DestinationNetwork,

        [ValidateRange(-1, 63)]
        [int]$DSCPMarking,

        [string]$WebFilter,

        [string]$WebCategoryBaseQoSPolicy,

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockQuickQuic,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanVirus,

        [ValidateSet('Enable', 'Disable')]
        [string]$ZeroDayProtection,

        [ValidateSet('Enable', 'Disable')]
        [string]$ProxyMode,

        [ValidateSet('Enable', 'Disable')]
        [string]$DecryptHTTPS,

        [string]$ApplicationControl,

        [string]$ApplicationBaseQoSPolicy,

        [string]$IntrusionPrevention,

        [ValidateSet('Enable', 'Disable')]
        [string]$NDRActiveThreatIntelligence,

        [string]$TrafficShappingPolicy,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanSMTP,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanSMTPS,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanIMAP,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanIMAPS,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanPOP3,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanPOP3S,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanFTP,

        [ValidateSet('Enable', 'Disable')]
        [string]$SourceSecurityHeartbeat,

        [ValidateSet('No Restriction', 'GREEN', 'YELLOW')]
        [string]$MinimumSourceHBPermitted,

        [ValidateSet('Enable', 'Disable')]
        [string]$DestSecurityHeartbeat,

        [ValidateSet('No Restriction', 'GREEN', 'YELLOW')]
        [string]$MinimumDestinationHBPermitted,

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

        # Names of New-SfosFirewallRuleNetworkPolicy's per-field parameters, used below to
        # forward only the ones the caller actually bound. Kept in one place so the field list
        # cannot drift between this array and the parameter block above.
        $networkPolicyFieldNames = @(
            'Action', 'LogTraffic', 'SkipLocalDestined', 'SourceZone', 'SourceNetwork',
            'DestinationZone', 'Schedule', 'Service', 'DestinationNetwork', 'DSCPMarking',
            'WebFilter', 'WebCategoryBaseQoSPolicy', 'BlockQuickQuic', 'ScanVirus',
            'ZeroDayProtection', 'ProxyMode', 'DecryptHTTPS', 'ApplicationControl',
            'ApplicationBaseQoSPolicy', 'IntrusionPrevention', 'NDRActiveThreatIntelligence',
            'TrafficShappingPolicy', 'ScanSMTP', 'ScanSMTPS', 'ScanIMAP', 'ScanIMAPS',
            'ScanPOP3', 'ScanPOP3S', 'ScanFTP', 'SourceSecurityHeartbeat',
            'MinimumSourceHBPermitted', 'DestSecurityHeartbeat', 'MinimumDestinationHBPermitted'
        )
    }

    process {
        if ($PSBoundParameters.ContainsKey('Position')) {
            if ($Position -eq 'After' -and -not $PSBoundParameters.ContainsKey('After')) {
                throw "FirewallRule '$Name': -Position After requires -After <existing rule name>."
            }
            if ($Position -eq 'Before' -and -not $PSBoundParameters.ContainsKey('Before')) {
                throw "FirewallRule '$Name': -Position Before requires -Before <existing rule name>."
            }
        }

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall, Position/After/Before included. So read the current rule first and
        # override only what the caller actually passed.
        $existing = @(Get-SfosFirewallRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The FirewallRule object '$Name' was not found."
        }

        if ($existing[0].PolicyType -ne 'Network') {
            throw "FirewallRule '$Name' has PolicyType '$($existing[0].PolicyType)', which Set-SfosFirewallRule does not support - only 'Network' rules can be modified by this module."
        }

        $targetRule = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) {
            $targetRule.Description = $Description
        }
        if ($PSBoundParameters.ContainsKey('IPFamily')) {
            $targetRule.IPFamily = $IPFamily
        }
        if ($PSBoundParameters.ContainsKey('Status')) {
            $targetRule.Status = $Status
        }
        if ($PSBoundParameters.ContainsKey('Section')) {
            $targetRule.Section = $Section
        }
        if ($PSBoundParameters.ContainsKey('Position')) {
            # Position, After and Before travel together - changing one without the other two
            # would either leave a stale After/Before pointing nowhere in particular, or lose
            # it entirely. Only replace all three when the caller actually asked to move the
            # rule.
            $targetRule.Position = $Position
            if ($Position -eq 'After') {
                $targetRule.After = $After
                $targetRule.Before = ''
            }
            elseif ($Position -eq 'Before') {
                $targetRule.Before = $Before
                $targetRule.After = ''
            }
            else {
                $targetRule.After = ''
                $targetRule.Before = ''
            }
        }
        # Per-field NetworkPolicy merge. -NetworkPolicy (if given) or the rule's current
        # NetworkPolicy is the base; each per-field parameter overrides only its own field on
        # top of that base - see .PARAMETER NetworkPolicy. Forwarded through
        # New-SfosFirewallRuleNetworkPolicy's -InputObject so the field-by-field precedence
        # (Resolve-SfosNetworkPolicyFieldValue) lives in one place instead of being duplicated
        # here.
        #
        # Design choice: -NetworkPolicy and the per-field parameters are not mutually exclusive.
        # Combining them lets a caller start from a hand-built policy and still tweak one field
        # in the same call. Rejecting the combination would guard against a typo but forces an
        # extra round trip for that case, and the "$PSBoundParameters wins" rule already makes
        # the outcome for every field unambiguous, so a rebuild is used instead of a rejection.
        $networkPolicyOverrides = @{}
        foreach ($fieldName in $networkPolicyFieldNames) {
            if ($PSBoundParameters.ContainsKey($fieldName)) {
                $networkPolicyOverrides[$fieldName] = $PSBoundParameters[$fieldName]
            }
        }

        if ($PSBoundParameters.ContainsKey('NetworkPolicy') -or $networkPolicyOverrides.Count -gt 0) {
            $networkPolicyBase = $targetRule.NetworkPolicy
            if ($PSBoundParameters.ContainsKey('NetworkPolicy')) {
                $networkPolicyBase = $NetworkPolicy
            }
            $targetRule.NetworkPolicy = New-SfosFirewallRuleNetworkPolicy -InputObject $networkPolicyBase @networkPolicyOverrides
        }

        $inner = ConvertTo-SfosFirewallRuleXml -Operation 'update' -Rule $targetRule

        if (-not $PSCmdlet.ShouldProcess("FirewallRule '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating FirewallRule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRule' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes a firewall rule from a Sophos Firewall.

.DESCRIPTION
    Deletes a firewall rule by name. Works for any PolicyType, since removal only needs the
    rule's name. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with permission to change firewall rules.
    The change removes the rule from the rule base immediately and cannot be undone from
    within this module; recreate the rule with New-SfosFirewallRule if it was removed by
    mistake.

.PARAMETER Name
    Required. Name of the target rule. Accepts pipeline input.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change firewall
    rules. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Objects with a Name property, such as the
    output of Get-SfosFirewallRule, can be piped in.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosFirewallRule -Name "Allow-LAN-to-WAN" -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN" | Remove-SfosFirewallRule

    Removes the rules whose name contains 'Allow-LAN-to-WAN'. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosFirewallRule
#>
function Remove-SfosFirewallRule {
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
        if (-not $PSCmdlet.ShouldProcess("FirewallRule '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FirewallRule>
    <Name>$nameEsc</Name>
  </FirewallRule>
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
            throw "Error removing FirewallRule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRule' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion


#region FirewallRuleGroup

<#
        .SYNOPSIS
        Retrieves firewall rule group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the firewall rule groups that are defined on the firewall. A firewall rule
        group collects several firewall rules under one name, for easier review and
        management. Use this cmdlet to review the existing groups or to feed them into
        another cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result always matches
        all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only groups whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern. If omitted, the name is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only groups whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for firewall
        rule groups. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per firewall rule group, with
        the properties Name, Description, SecurityPolicyList, Policytype, SourceZones and
        DestinationZones. Returns System.Xml.XmlElement when -AsXml is used, and an empty
        array when no group matches.

        .EXAMPLE
        Get-SfosFirewallRuleGroup

        Lists every firewall rule group on the firewall of the current connection.

        .EXAMPLE
        Get-SfosFirewallRuleGroup -NameLike "Internal"

        Lists the groups whose name contains 'Internal'.

        .EXAMPLE
        Get-SfosFirewallRuleGroup -NameLike "Internal" -AsXml

        Returns the raw XML of the matching groups, for example to check a field the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosFirewallRuleGroup

        .LINK
        Set-SfosFirewallRuleGroup
#>
function Get-SfosFirewallRuleGroup {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
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
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <FirewallRuleGroup>
    $filterXml
  </FirewallRuleGroup>
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
        throw "Error retrieving FirewallRuleGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Without this check, a firewall error - missing permission, invalid filter, server
    # error - would be read as an empty result. This also affects the Set and member
    # cmdlets, which call back into this function to read the current state: they would
    # report "object not found" instead of the real error.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRuleGroup' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FirewallRuleGroup[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $firewallRuleGroupObjects = @()
    foreach ($node in $nodes) {
        $firewallRuleGroupObjects += [PSCustomObject]@{
            Name                = $node.Name
            Description         = $node.Description
            # @() plus the emptiness filter, not a bare cast: SFOS omits the wrapper element
            # entirely when the list is empty, and casting the resulting $null to [string[]]
            # yields @('') - a one-element array holding an empty string, which reads as a
            # member that is not there. Section 7 asks for @().
            SecurityPolicyList  = [string[]]@($node.SecurityPolicyList | Select-Object -ExpandProperty SecurityPolicy -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            Policytype          = $node.Policytype
            SourceZones         = [string[]]@($node.SourceZones | Select-Object -ExpandProperty Zone -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            DestinationZones    = [string[]]@($node.DestinationZones | Select-Object -ExpandProperty Zone -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
        }
    }

    return $firewallRuleGroupObjects
}

<#
        .SYNOPSIS
        Creates a new firewall rule group on a Sophos Firewall.

        .DESCRIPTION
        Creates a firewall rule group that collects one or more firewall rules under one
        name, for easier review and management. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to change firewall rule groups. After creation, use
        Add-SfosFirewallRuleGroupMember to add further members.

        .PARAMETER Name
        Required. Name of the firewall rule group. 1 to 150 characters, no commas.

        .PARAMETER Description
        Optional. Free-text description of the group. Up to 255 characters.

        .PARAMETER Members
        Optional. Names of the firewall rules to include in the group.

        .PARAMETER Policytype
        Optional. Policy type classification: User/network rule, Network rule, User rule, WAF
        rule or Any.

        .PARAMETER SourceZones
        Optional. Source zone names allowed for the group.

        .PARAMETER DestinationZones
        Optional. Destination zone names for the group.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        firewall rule groups. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -Description "Rules for branch office traffic" -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -Description "Rules for branch office traffic"

        Creates an empty rule group. The cmdlet asks for confirmation before it writes.

        .EXAMPLE
        New-SfosFirewallRuleGroup -Name "Branch-Office-Rules"
        Add-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-VPN"

        Creates a group and then adds a member rule to it.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallRuleGroup

        .LINK
        Add-SfosFirewallRuleGroupMember
#>
function New-SfosFirewallRuleGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 150)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [string[]]$members,

        [ValidateSet('User/network rule', 'Network rule', 'User rule', 'WAF rule', 'Any')]
        [string]$Policytype,

        [string[]]$SourceZones,

        [string[]]$DestinationZones,

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
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description

    $xmlMember = ''
    foreach ($member in $members) {
        if (-not $member) {
            continue
        }
        if ($member.Length -gt 60) {
            throw "Member '$member' must be 60 characters or fewer."
        }
        if ($member -match ',') {
            throw "Member '$member' cannot contain a comma."
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<SecurityPolicy>$mEsc</SecurityPolicy>"
    }

    $policytypeXml = ''
    if ($Policytype) {
        $policytypeXml = "<Policytype>$(ConvertTo-SfosXmlEscaped -Text $Policytype)</Policytype>"
    }

    $sourceZonesXml = ''
    if ($SourceZones) {
        $zoneXml = ''
        foreach ($zone in $SourceZones) {
            if (-not $zone) {
                continue
            }
            $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
        }
        $sourceZonesXml = "<SourceZones>$zoneXml</SourceZones>"
    }

    $destinationZonesXml = ''
    if ($DestinationZones) {
        $zoneXml = ''
        foreach ($zone in $DestinationZones) {
            if (-not $zone) {
                continue
            }
            $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
        }
        $destinationZonesXml = "<DestinationZones>$zoneXml</DestinationZones>"
    }

    $inner = @"
<Set operation="add">
  <FirewallRuleGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <SecurityPolicyList>
        $xmlMember
    </SecurityPolicyList>
    $sourceZonesXml
    $destinationZonesXml
    $policytypeXml
  </FirewallRuleGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("FirewallRuleGroup '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating FirewallRuleGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRuleGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing firewall rule group on a Sophos Firewall.

        .DESCRIPTION
        Updates a firewall rule group. You can supply the target group name directly or
        through the pipeline. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to change
        firewall rule groups.

        The firewall replaces the whole group on update; any field not sent in the request is
        cleared. The cmdlet reads the current group first and keeps whatever you do not
        explicitly pass. To clear a field, pass it explicitly with an empty value.

        .PARAMETER Name
        Required. Name of the target group. Accepts pipeline input.

        .PARAMETER Description
        Optional. New description text. If omitted, the existing description is kept.

        .PARAMETER Members
        Optional. Firewall rule names to set as the group's members, replacing the whole
        list. If omitted, the existing members are kept.

        .PARAMETER Policytype
        Optional. Policy type classification. If omitted, the existing value is kept.

        .PARAMETER SourceZones
        Optional. Source zone names, replacing the whole list. If omitted, the existing value
        is kept.

        .PARAMETER DestinationZones
        Optional. Destination zone names, replacing the whole list. If omitted, the existing
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        firewall rule groups. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosFirewallRuleGroup, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -Description "Updated description" -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -Description "Updated description"

        Changes only the description; the members are preserved. The cmdlet asks for
        confirmation before it writes.

        .EXAMPLE
        Get-SfosFirewallRuleGroup -NameLike "Branch-Office-Rules" | Set-SfosFirewallRuleGroup -Policytype "Any"

        Changes the policy type classification of the matching groups.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallRuleGroup
#>
function Set-SfosFirewallRuleGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 150)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('SecurityPolicyList')]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('User/network rule', 'Network rule', 'User rule', 'WAF rule', 'Any')]
        [string]$Policytype,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$SourceZones,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$DestinationZones,

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

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall. So read the current group first and override only what the caller
        # actually passed.
        $existing = @(Get-SfosFirewallRuleGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The FirewallRuleGroup object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetMembers = if ($PSBoundParameters.ContainsKey('members')) {
            @($members)
        }
        else {
            @($existing[0].SecurityPolicyList)
        }

        $targetPolicytype = if ($PSBoundParameters.ContainsKey('Policytype')) {
            $Policytype
        }
        else {
            [string]$existing[0].Policytype
        }

        $targetSourceZones = if ($PSBoundParameters.ContainsKey('SourceZones')) {
            @($SourceZones)
        }
        else {
            @($existing[0].SourceZones)
        }

        $targetDestinationZones = if ($PSBoundParameters.ContainsKey('DestinationZones')) {
            @($DestinationZones)
        }
        else {
            @($existing[0].DestinationZones)
        }

        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 60) {
                throw "Member '$member' must be 60 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<SecurityPolicy>$mEsc</SecurityPolicy>"
        }

        $policytypeXml = ''
        if ($targetPolicytype) {
            $policytypeXml = "<Policytype>$(ConvertTo-SfosXmlEscaped -Text $targetPolicytype)</Policytype>"
        }

        $sourceZonesXml = ''
        if (@($targetSourceZones | Where-Object { $_ }).Count -gt 0) {
            $zoneXml = ''
            foreach ($zone in $targetSourceZones) {
                if (-not $zone) {
                    continue
                }
                $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
            }
            $sourceZonesXml = "<SourceZones>$zoneXml</SourceZones>"
        }

        $destinationZonesXml = ''
        if (@($targetDestinationZones | Where-Object { $_ }).Count -gt 0) {
            $zoneXml = ''
            foreach ($zone in $targetDestinationZones) {
                if (-not $zone) {
                    continue
                }
                $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
            }
            $destinationZonesXml = "<DestinationZones>$zoneXml</DestinationZones>"
        }

        $inner = @"
<Set operation="update">
  <FirewallRuleGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <SecurityPolicyList>
        $xmlMember
    </SecurityPolicyList>
    $sourceZonesXml
    $destinationZonesXml
    $policytypeXml
  </FirewallRuleGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FirewallRuleGroup '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating FirewallRuleGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRuleGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a firewall rule group from a Sophos Firewall.

        .DESCRIPTION
        Deletes a firewall rule group by name. The member firewall rules themselves are not
        deleted. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to change firewall rule
        groups.

        .PARAMETER Name
        Required. Name of the target group. Accepts pipeline input.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        firewall rule groups. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosFirewallRuleGroup, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosFirewallRuleGroup -NameLike "Branch-Office-Rules" | Remove-SfosFirewallRuleGroup

        Removes the groups whose name contains 'Branch-Office-Rules'. The cmdlet asks for
        confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallRuleGroup
#>
function Remove-SfosFirewallRuleGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 150)]
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
        if (-not $PSCmdlet.ShouldProcess("FirewallRuleGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FirewallRuleGroup>
    <Name>$nameEsc</Name>
  </FirewallRuleGroup>
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
            throw "Error removing FirewallRuleGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRuleGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds member rules to an existing firewall rule group on a Sophos Firewall.

        .DESCRIPTION
        Adds firewall rules to a firewall rule group. A firewall rule belongs to at most one
        group; adding it to this group removes it from any group it currently belongs to. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with permission to change firewall rule groups.

        .PARAMETER Name
        Required. Name of the target group. Accepts pipeline input.

        .PARAMETER Members
        Required. Firewall rule names to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        firewall rule groups. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosFirewallRuleGroup, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-VPN","Allow-Branch-DNS" -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Add-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-VPN","Allow-Branch-DNS"

        Adds two firewall rules to the group. The cmdlet asks for confirmation before it
        writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallRuleGroup

        .LINK
        Remove-SfosFirewallRuleGroupMember
#>
function Add-SfosFirewallRuleGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 150)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

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

        $firewallRuleGroup = Get-SfosFirewallRuleGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact group
        $firewallRuleGroup = @($firewallRuleGroup | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($firewallRuleGroup.Count -eq 0) {
            throw "The FirewallRuleGroup object '$Name' was not found."
        }

        $firewallRuleGroup = $firewallRuleGroup[0]

        # Prefill existing members. SFOS applies the member list as a whole - a
        # <Set operation="update"> replaces it instead of appending - so the current
        # members must be written back together with the new ones.
        $groupMembers = @()
        $groupMembers += $firewallRuleGroup.SecurityPolicyList
        $groupMembers += $members
        $groupMembers = $groupMembers | Where-Object -FilterScript { $_ } | Select-Object -Unique

        $xmlMember = ''
        foreach ($member in $groupMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 60) {
                throw "Member '$member' must be 60 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<SecurityPolicy>$memberEsc</SecurityPolicy>"
        }

        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying these over, changing the member
        # list would silently wipe Description, Policytype and the zone lists.
        $descriptionXml = ''
        if ($firewallRuleGroup.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $firewallRuleGroup.Description)</Description>"
        }

        $policytypeXml = ''
        if ($firewallRuleGroup.Policytype) {
            $policytypeXml = "<Policytype>$(ConvertTo-SfosXmlEscaped -Text $firewallRuleGroup.Policytype)</Policytype>"
        }

        $sourceZonesXml = ''
        if (@($firewallRuleGroup.SourceZones | Where-Object { $_ }).Count -gt 0) {
            $zoneXml = ''
            foreach ($zone in $firewallRuleGroup.SourceZones) {
                if (-not $zone) {
                    continue
                }
                $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
            }
            $sourceZonesXml = "<SourceZones>$zoneXml</SourceZones>"
        }

        $destinationZonesXml = ''
        if (@($firewallRuleGroup.DestinationZones | Where-Object { $_ }).Count -gt 0) {
            $zoneXml = ''
            foreach ($zone in $firewallRuleGroup.DestinationZones) {
                if (-not $zone) {
                    continue
                }
                $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
            }
            $destinationZonesXml = "<DestinationZones>$zoneXml</DestinationZones>"
        }

        $inner = @"
<Set operation="update">
    <FirewallRuleGroup>
        <Name>$nameEsc</Name>
        $descriptionXml
        <SecurityPolicyList>
            $xmlMember
        </SecurityPolicyList>
        $sourceZonesXml
        $destinationZonesXml
        $policytypeXml
    </FirewallRuleGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FirewallRuleGroup '$($Name)' on $($params.Firewall)", 'Add members')) {
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
            throw "Error adding members to FirewallRuleGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRuleGroup' -Action 'add members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes member rules from an existing firewall rule group on a Sophos Firewall.

        .DESCRIPTION
        Removes firewall rules from the member list of a firewall rule group. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with permission to change firewall rule groups.

        The member list update on the firewall only adds members; sending a shorter list does
        not remove anything, it only reorders the list. This cmdlet reads the group back
        after the update and raises an error if the members it was asked to remove are still
        present, instead of reporting a success that did not happen. A rule leaves its group
        automatically when the rule itself is deleted, and a group cannot be deleted while it
        still has members.

        .PARAMETER Name
        Required. Name of the target group. Accepts pipeline input.

        .PARAMETER Members
        Required. Firewall rule names to remove from the group.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        firewall rule groups. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosFirewallRuleGroup, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the members are not actually
        removed.

        .EXAMPLE
        Remove-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-DNS" -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Remove-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-DNS"

        Removes one firewall rule from the group. The cmdlet asks for confirmation before it
        writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFirewallRuleGroup

        .LINK
        Add-SfosFirewallRuleGroupMember
#>
function Remove-SfosFirewallRuleGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 150)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

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

        $firewallRuleGroup = Get-SfosFirewallRuleGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        $firewallRuleGroup = @($firewallRuleGroup | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($firewallRuleGroup.Count -eq 0) {
            throw "The FirewallRuleGroup object '$Name' was not found."
        }

        $firewallRuleGroup = $firewallRuleGroup[0]

        if (@($firewallRuleGroup.SecurityPolicyList).Count -eq 0) {
            # Nothing to remove
            return
        }

        $groupMembers = [Collections.ArrayList]@()
        $groupMembers.AddRange([string[]]@($firewallRuleGroup.SecurityPolicyList))

        foreach ($member in $members) {
            [int]$indexMember = $groupMembers.IndexOf($member)

            if ($indexMember -ne -1) {
                $groupMembers.RemoveAt($indexMember)
            }
        }

        $xmlMember = ''
        foreach ($member in $groupMembers) {
            if (-not $member) {
                continue
            }
            if ($member.Length -gt 60) {
                throw "Member '$member' must be 60 characters or fewer."
            }
            if ($member -match ',') {
                throw "Member '$member' cannot contain a comma."
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<SecurityPolicy>$memberEsc</SecurityPolicy>"
        }

        # 'update' with the complete remaining list, not 'remove': SFOS replaces the
        # member list with whatever is sent.
        $descriptionXml = ''
        if ($firewallRuleGroup.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $firewallRuleGroup.Description)</Description>"
        }

        $policytypeXml = ''
        if ($firewallRuleGroup.Policytype) {
            $policytypeXml = "<Policytype>$(ConvertTo-SfosXmlEscaped -Text $firewallRuleGroup.Policytype)</Policytype>"
        }

        $sourceZonesXml = ''
        if (@($firewallRuleGroup.SourceZones | Where-Object { $_ }).Count -gt 0) {
            $zoneXml = ''
            foreach ($zone in $firewallRuleGroup.SourceZones) {
                if (-not $zone) {
                    continue
                }
                $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
            }
            $sourceZonesXml = "<SourceZones>$zoneXml</SourceZones>"
        }

        $destinationZonesXml = ''
        if (@($firewallRuleGroup.DestinationZones | Where-Object { $_ }).Count -gt 0) {
            $zoneXml = ''
            foreach ($zone in $firewallRuleGroup.DestinationZones) {
                if (-not $zone) {
                    continue
                }
                $zoneXml += "<Zone>$(ConvertTo-SfosXmlEscaped -Text $zone)</Zone>"
            }
            $destinationZonesXml = "<DestinationZones>$zoneXml</DestinationZones>"
        }

        $inner = @"
<Set operation="update">
    <FirewallRuleGroup>
        <Name>$nameEsc</Name>
        $descriptionXml
        <SecurityPolicyList>
            $xmlMember
        </SecurityPolicyList>
        $sourceZonesXml
        $destinationZonesXml
        $policytypeXml
    </FirewallRuleGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FirewallRuleGroup '$($Name)' on $($params.Firewall)", 'Remove members')) {
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
            throw "Error removing members from FirewallRuleGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FirewallRuleGroup' -Action 'remove members' -Target $Name

        # Read back and check, because a 200 does not mean the members are gone. On SFOS 22.0
        # the SecurityPolicyList is append-only: sending a shorter list, an empty
        # <SecurityPolicyList/> or no wrapper at all all answer 200 and leave every member in
        # place - only their order changes. Without this check the cmdlet would report
        # success while the group is unchanged, which is worse than failing outright.
        $after = @(Get-SfosFirewallRuleGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })
        if ($after.Count -gt 0) {
            $stillThere = @($members | Where-Object -FilterScript { $_ -and (@($after[0].SecurityPolicyList) -contains $_) })
            if ($stillThere.Count -gt 0) {
                throw ("Removing members from FirewallRuleGroup '$Name' did not take effect: " +
                    "$($stillThere -join ', ') is still a member. The firewall accepted the request " +
                    'with status 200, but on this firmware the member list of a rule group only ever ' +
                    'grows - a shorter list is ignored. Remove the rule itself, or delete and recreate ' +
                    'the group with the members you want.')
            }
        }
    }
}

#endregion

#region NATRule

<#
        .SYNOPSIS
        Retrieves NAT rules from a Sophos Firewall.

        .DESCRIPTION
        Returns the NAT rules that are defined on the firewall. A NAT rule translates the
        source or destination address of matching traffic. Use this cmdlet to review the
        existing rules or to feed them into another cmdlet through the pipeline. The cmdlet
        only reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly. The Status
        property is the rule's own Enable/Disable flag, not an indicator of API success or
        failure.

        You can combine several filters. The firewall itself evaluates at most one of them, so
        every filter you supply is applied again on the client. The result always matches all
        filters you gave.

        .PARAMETER NameLike
        Optional. Returns only rules whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern. If omitted, the name is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only rules whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for NAT
        rules. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per NAT rule, with the
        properties Name, Description, IPFamily, Status, Position, After, Before,
        LinkedFirewallrule, TranslatedSource, TranslatedDestination, TranslatedService,
        OverrideInterfaceNATPolicy, InboundInterfaces and OutboundInterfaces. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no rule matches.

        .EXAMPLE
        Get-SfosNATRule

        Lists every NAT rule on the firewall of the current connection.

        .EXAMPLE
        Get-SfosNATRule -NameLike "SNAT"

        Lists the rules whose name contains 'SNAT'.

        .EXAMPLE
        Get-SfosNATRule -NameLike "SNAT" -AsXml

        Returns the raw XML of the matching rules, for example to check a field the standard
        output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosNATRule

        .LINK
        Set-SfosNATRule
#>
function Get-SfosNATRule {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
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
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <NATRule>
    $filterXml
  </NATRule>
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
        throw "Error retrieving NATRule objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NATRule' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/NATRule[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $natRuleObjects = @()
    foreach ($node in $nodes) {
        $afterName = $null
        if ($node.After) {
            $afterName = $node.After.Name
        }
        $beforeName = $null
        if ($node.Before) {
            $beforeName = $node.Before.Name
        }

        $natRuleObjects += [PSCustomObject]@{
            Name                        = $node.Name
            Description                 = $node.Description
            IPFamily                    = $node.IPFamily
            Status                      = $node.Status
            Position                    = $node.Position
            After                       = $afterName
            Before                      = $beforeName
            LinkedFirewallrule          = $node.LinkedFirewallrule
            TranslatedSource            = $node.TranslatedSource
            TranslatedDestination       = $node.TranslatedDestination
            TranslatedService           = $node.TranslatedService
            OverrideInterfaceNATPolicy  = $node.OverrideInterfaceNATPolicy
            # See Get-SfosFirewallRuleGroup: a bare cast of the missing wrapper turns into
            # @(''), not @().
            InboundInterfaces           = [string[]]@($node.InboundInterfaces | Select-Object -ExpandProperty Interface -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            OutboundInterfaces          = [string[]]@($node.OutboundInterfaces | Select-Object -ExpandProperty Interface -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
        }
    }

    return $natRuleObjects
}

<#
        .SYNOPSIS
        Creates a new NAT rule on a Sophos Firewall.

        .DESCRIPTION
        Creates a NAT rule that translates the source or destination address of matching
        traffic. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to change NAT rules.

        .PARAMETER Name
        Required. Name of the NAT rule. 1 to 60 characters, no commas.

        .PARAMETER Description
        Optional. Free-text description of the rule. Up to 255 characters.

        .PARAMETER IPFamily
        Optional. IP address family: IPv4 or IPv6. Default: IPv4.

        .PARAMETER Status
        Optional. Whether the rule is enabled: Enable or Disable. Default: Enable.

        .PARAMETER Position
        Optional. Where to insert the rule relative to the existing rule list: Top, Bottom,
        After or Before. Default: Bottom. After and Before require -After or -Before to name
        the reference rule.

        .PARAMETER After
        Optional. Name of the existing NAT rule after which this rule is inserted. Required
        when -Position is After.

        .PARAMETER Before
        Optional. Name of the existing NAT rule before which this rule is inserted. Required
        when -Position is Before.

        .PARAMETER LinkedFirewallrule
        Optional. Name of the firewall rule this NAT rule is linked to.

        .PARAMETER TranslatedSource
        Optional. Translated source: Original, MASQ, IPAddress or IPRange. Default: Original.

        .PARAMETER TranslatedDestination
        Optional. Translated destination: Original, IPAddress, IPRange, IPList or FQDN.
        Default: Original.

        .PARAMETER TranslatedService
        Optional. Translated service: Original or the name of a service object.
        Default: Original.

        .PARAMETER OverrideInterfaceNATPolicy
        Optional. Whether to override the interface-level NAT policy: Enable or Disable.
        Default: Disable.

        .PARAMETER InboundInterfaces
        Optional. Inbound interface names.

        .PARAMETER OutboundInterfaces
        Optional. Outbound interface names.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change NAT
        rules. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        New-SfosNATRule -Name "SNAT-LAN-to-WAN" -TranslatedSource "MASQ" -Status Disable -Position Bottom -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosNATRule -Name "SNAT-LAN-to-WAN" -TranslatedSource "MASQ" -Status Disable -Position Bottom

        Creates a disabled masquerade rule at the bottom of the rule list. The cmdlet asks
        for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosNATRule
#>
function New-SfosNATRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [ValidateSet('Enable', 'Disable')]
        [string]$Status = 'Enable',

        [ValidateSet('Top', 'Bottom', 'After', 'Before')]
        [string]$Position = 'Bottom',

        [string]$After,

        [string]$Before,

        [string]$LinkedFirewallrule,

        [ValidateSet('Original', 'MASQ', 'IPAddress', 'IPRange')]
        [string]$TranslatedSource = 'Original',

        [ValidateSet('Original', 'IPAddress', 'IPRange', 'IPList', 'FQDN')]
        [string]$TranslatedDestination = 'Original',

        [string]$TranslatedService = 'Original',

        [ValidateSet('Enable', 'Disable')]
        [string]$OverrideInterfaceNATPolicy = 'Disable',

        [string[]]$InboundInterfaces,

        [string[]]$OutboundInterfaces,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    if ($Position -eq 'After' -and -not $After) {
        throw "NATRule '$Name': -Position 'After' requires -After to name the reference rule."
    }
    if ($Position -eq 'Before' -and -not $Before) {
        throw "NATRule '$Name': -Position 'Before' requires -Before to name the reference rule."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $linkedEsc = ConvertTo-SfosXmlEscaped -Text $LinkedFirewallrule
    $translatedSourceEsc = ConvertTo-SfosXmlEscaped -Text $TranslatedSource
    $translatedDestinationEsc = ConvertTo-SfosXmlEscaped -Text $TranslatedDestination
    $translatedServiceEsc = ConvertTo-SfosXmlEscaped -Text $TranslatedService

    $afterXml = ''
    if ($Position -eq 'After') {
        $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text $After)</Name></After>"
    }
    $beforeXml = ''
    if ($Position -eq 'Before') {
        $beforeXml = "<Before><Name>$(ConvertTo-SfosXmlEscaped -Text $Before)</Name></Before>"
    }

    $linkedXml = ''
    if ($LinkedFirewallrule) {
        $linkedXml = "<LinkedFirewallrule>$linkedEsc</LinkedFirewallrule>"
    }

    $inboundXml = ''
    if ($InboundInterfaces) {
        $interfaceXml = ''
        foreach ($interfaceName in $InboundInterfaces) {
            if (-not $interfaceName) {
                continue
            }
            $interfaceXml += "<Interface>$(ConvertTo-SfosXmlEscaped -Text $interfaceName)</Interface>"
        }
        $inboundXml = "<InboundInterfaces>$interfaceXml</InboundInterfaces>"
    }

    $outboundXml = ''
    if ($OutboundInterfaces) {
        $interfaceXml = ''
        foreach ($interfaceName in $OutboundInterfaces) {
            if (-not $interfaceName) {
                continue
            }
            $interfaceXml += "<Interface>$(ConvertTo-SfosXmlEscaped -Text $interfaceName)</Interface>"
        }
        $outboundXml = "<OutboundInterfaces>$interfaceXml</OutboundInterfaces>"
    }

    $inner = @"
<Set operation="add">
  <NATRule>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <IPFamily>$IPFamily</IPFamily>
    <Status>$Status</Status>
    <Position>$Position</Position>
    $afterXml
    $beforeXml
    $linkedXml
    <TranslatedSource>$translatedSourceEsc</TranslatedSource>
    <TranslatedDestination>$translatedDestinationEsc</TranslatedDestination>
    <TranslatedService>$translatedServiceEsc</TranslatedService>
    $inboundXml
    $outboundXml
    <OverrideInterfaceNATPolicy>$OverrideInterfaceNATPolicy</OverrideInterfaceNATPolicy>
  </NATRule>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("NATRule '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating NATRule object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NATRule' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing NAT rule on a Sophos Firewall.

        .DESCRIPTION
        Updates a NAT rule. You can supply the target rule name directly or through the
        pipeline. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with permission to change NAT rules.

        The firewall replaces the whole rule on update; any field not sent in the request is
        cleared. The cmdlet reads the current rule first and keeps whatever you do not
        explicitly pass, Position, After and Before included, so a one-field change never
        moves the rule in the evaluation order. To clear a field, pass it explicitly with an
        empty value.

        .PARAMETER Name
        Required. Name of the target rule. Accepts pipeline input.

        .PARAMETER Description
        Optional. New description text. If omitted, the existing description is kept.

        .PARAMETER IPFamily
        Optional. IP address family: IPv4 or IPv6. If omitted, the existing value is kept.

        .PARAMETER Status
        Optional. Whether the rule is enabled: Enable or Disable. If omitted, the existing
        value is kept.

        .PARAMETER Position
        Optional. Where the rule sits relative to the rule list: Top, Bottom, After or
        Before. If omitted, the existing position is kept.

        .PARAMETER After
        Optional. Name of the existing NAT rule after which this rule is inserted. Required
        when the effective -Position is After. If omitted, the existing value is kept.

        .PARAMETER Before
        Optional. Name of the existing NAT rule before which this rule is inserted. Required
        when the effective -Position is Before. If omitted, the existing value is kept.

        .PARAMETER LinkedFirewallrule
        Optional. Name of the firewall rule this NAT rule is linked to. If omitted, the
        existing value is kept.

        .PARAMETER TranslatedSource
        Optional. Translated source: Original, MASQ, IPAddress or IPRange. If omitted, the
        existing value is kept.

        .PARAMETER TranslatedDestination
        Optional. Translated destination: Original, IPAddress, IPRange, IPList or FQDN. If
        omitted, the existing value is kept.

        .PARAMETER TranslatedService
        Optional. Translated service: Original or the name of a service object. If omitted,
        the existing value is kept.

        .PARAMETER OverrideInterfaceNATPolicy
        Optional. Whether to override the interface-level NAT policy: Enable or Disable. If
        omitted, the existing value is kept.

        .PARAMETER InboundInterfaces
        Optional. Inbound interface names, replacing the whole list. If omitted, the existing
        value is kept.

        .PARAMETER OutboundInterfaces
        Optional. Outbound interface names, replacing the whole list. If omitted, the
        existing value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change NAT
        rules. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosNATRule, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosNATRule -Name "SNAT-LAN-to-WAN" -Description "Updated description" -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosNATRule -Name "SNAT-LAN-to-WAN" -Description "Updated description"

        Changes only the description; the position and every other field are preserved. The
        cmdlet asks for confirmation before it writes.

        .EXAMPLE
        Get-SfosNATRule -NameLike "SNAT-LAN-to-WAN" | Set-SfosNATRule -Status Disable

        Disables the matching rules.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosNATRule
#>
function Set-SfosNATRule {
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
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Status,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Top', 'Bottom', 'After', 'Before')]
        [string]$Position,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$After,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Before,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$LinkedFirewallrule,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Original', 'MASQ', 'IPAddress', 'IPRange')]
        [string]$TranslatedSource,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Original', 'IPAddress', 'IPRange', 'IPList', 'FQDN')]
        [string]$TranslatedDestination,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$TranslatedService,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$OverrideInterfaceNATPolicy,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$InboundInterfaces,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$OutboundInterfaces,

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

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall, and that includes Position: a Set that only touches Description would
        # otherwise reset Position to whatever the firewall defaults an omitted field to,
        # silently reordering the rule.
        $existing = @(Get-SfosNATRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The NATRule object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetIPFamily = if ($PSBoundParameters.ContainsKey('IPFamily')) { $IPFamily } else { [string]$existing[0].IPFamily }
        $targetStatus = if ($PSBoundParameters.ContainsKey('Status')) { $Status } else { [string]$existing[0].Status }
        $targetPosition = if ($PSBoundParameters.ContainsKey('Position')) { $Position } else { [string]$existing[0].Position }
        $targetAfter = if ($PSBoundParameters.ContainsKey('After')) { $After } else { [string]$existing[0].After }
        $targetBefore = if ($PSBoundParameters.ContainsKey('Before')) { $Before } else { [string]$existing[0].Before }
        $targetLinked = if ($PSBoundParameters.ContainsKey('LinkedFirewallrule')) { $LinkedFirewallrule } else { [string]$existing[0].LinkedFirewallrule }
        $targetTranslatedSource = if ($PSBoundParameters.ContainsKey('TranslatedSource')) { $TranslatedSource } else { [string]$existing[0].TranslatedSource }
        $targetTranslatedDestination = if ($PSBoundParameters.ContainsKey('TranslatedDestination')) { $TranslatedDestination } else { [string]$existing[0].TranslatedDestination }
        $targetTranslatedService = if ($PSBoundParameters.ContainsKey('TranslatedService')) { $TranslatedService } else { [string]$existing[0].TranslatedService }
        $targetOverride = if ($PSBoundParameters.ContainsKey('OverrideInterfaceNATPolicy')) { $OverrideInterfaceNATPolicy } else { [string]$existing[0].OverrideInterfaceNATPolicy }
        # @() must wrap the whole if/else: a one-element array from a branch unrolls to a
        # scalar on assignment under PS 5.1.
        $targetInbound = @(if ($PSBoundParameters.ContainsKey('InboundInterfaces')) { $InboundInterfaces } else { $existing[0].InboundInterfaces })
        $targetOutbound = @(if ($PSBoundParameters.ContainsKey('OutboundInterfaces')) { $OutboundInterfaces } else { $existing[0].OutboundInterfaces })

        if ($targetPosition -eq 'After' -and -not $targetAfter) {
            throw "NATRule '$Name': Position 'After' requires -After to name the reference rule."
        }
        if ($targetPosition -eq 'Before' -and -not $targetBefore) {
            throw "NATRule '$Name': Position 'Before' requires -Before to name the reference rule."
        }

        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
        $linkedEsc = ConvertTo-SfosXmlEscaped -Text $targetLinked
        $translatedSourceEsc = ConvertTo-SfosXmlEscaped -Text $targetTranslatedSource
        $translatedDestinationEsc = ConvertTo-SfosXmlEscaped -Text $targetTranslatedDestination
        $translatedServiceEsc = ConvertTo-SfosXmlEscaped -Text $targetTranslatedService

        $afterXml = ''
        if ($targetPosition -eq 'After') {
            $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text $targetAfter)</Name></After>"
        }
        $beforeXml = ''
        if ($targetPosition -eq 'Before') {
            $beforeXml = "<Before><Name>$(ConvertTo-SfosXmlEscaped -Text $targetBefore)</Name></Before>"
        }

        $linkedXml = ''
        if ($targetLinked) {
            $linkedXml = "<LinkedFirewallrule>$linkedEsc</LinkedFirewallrule>"
        }

        $inboundXml = ''
        if (@($targetInbound | Where-Object { $_ }).Count -gt 0) {
            $interfaceXml = ''
            foreach ($interfaceName in $targetInbound) {
                if (-not $interfaceName) {
                    continue
                }
                $interfaceXml += "<Interface>$(ConvertTo-SfosXmlEscaped -Text $interfaceName)</Interface>"
            }
            $inboundXml = "<InboundInterfaces>$interfaceXml</InboundInterfaces>"
        }

        $outboundXml = ''
        if (@($targetOutbound | Where-Object { $_ }).Count -gt 0) {
            $interfaceXml = ''
            foreach ($interfaceName in $targetOutbound) {
                if (-not $interfaceName) {
                    continue
                }
                $interfaceXml += "<Interface>$(ConvertTo-SfosXmlEscaped -Text $interfaceName)</Interface>"
            }
            $outboundXml = "<OutboundInterfaces>$interfaceXml</OutboundInterfaces>"
        }

        $inner = @"
<Set operation="update">
  <NATRule>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <IPFamily>$targetIPFamily</IPFamily>
    <Status>$targetStatus</Status>
    <Position>$targetPosition</Position>
    $afterXml
    $beforeXml
    $linkedXml
    <TranslatedSource>$translatedSourceEsc</TranslatedSource>
    <TranslatedDestination>$translatedDestinationEsc</TranslatedDestination>
    <TranslatedService>$translatedServiceEsc</TranslatedService>
    $inboundXml
    $outboundXml
    <OverrideInterfaceNATPolicy>$targetOverride</OverrideInterfaceNATPolicy>
  </NATRule>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("NATRule '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating NATRule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NATRule' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a NAT rule from a Sophos Firewall.

        .DESCRIPTION
        Deletes a NAT rule by name. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with permission to change
        NAT rules.

        .PARAMETER Name
        Required. Name of the target rule. Accepts pipeline input.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change NAT
        rules. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosNATRule, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosNATRule -Name "SNAT-LAN-to-WAN" -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosNATRule -NameLike "SNAT-LAN-to-WAN" | Remove-SfosNATRule

        Removes the rules whose name contains 'SNAT-LAN-to-WAN'. The cmdlet asks for
        confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosNATRule
#>
function Remove-SfosNATRule {
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
        if (-not $PSCmdlet.ShouldProcess("NATRule '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <NATRule>
    <Name>$nameEsc</Name>
  </NATRule>
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
            throw "Error removing NATRule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NATRule' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion


#region SSLTLSInspectionRule

<#
.SYNOPSIS
    Builds the wrapper/item XML for a repeatable simple-value list inside a
    SSLTLSInspectionRule entity. Internal helper, not exported.

.DESCRIPTION
    Builds one repeatable list field of a SSLTLSInspectionRule entity: SourceZones/Zone,
    SourceNetworks/Network, Identity/Members, DestinationZones/Zone,
    DestinationNetworks/Network and Services/Service all share this wrapper-and-item shape.
    Every value is escaped here. An empty or absent -Value still returns the empty wrapper
    element, because the firewall replaces the whole entity on update, and an absent wrapper
    is how a field gets cleared, not how it is left unchanged.

.PARAMETER WrapperTag
    Name of the outer element, e.g. 'SourceZones'.

.PARAMETER ItemTag
    Name of the repeated inner element, e.g. 'Zone'.

.PARAMETER Value
    Zero or more string values to place inside the wrapper.
#>
function ConvertTo-SfosSSLTLSInspectionRuleXmlList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$WrapperTag,

        [Parameter(Mandatory)]
        [string]$ItemTag,

        [string[]]$Value
    )

    $itemsXml = ''
    foreach ($item in @($Value)) {
        if (-not $item) {
            continue
        }
        $itemEsc = ConvertTo-SfosXmlEscaped -Text $item
        $itemsXml += "<$ItemTag>$itemEsc</$ItemTag>"
    }

    return "<$WrapperTag>$itemsXml</$WrapperTag>"
}

<#
.SYNOPSIS
    Builds the <Websites> XML for a SSLTLSInspectionRule entity. Internal helper, not exported.

.DESCRIPTION
    Builds the Websites field of a SSLTLSInspectionRule entity. Websites wraps zero or more
    Activity elements, each an object reference with Name and Type, where Type is Web
    Category or URL Group. Every value is escaped here.

.PARAMETER Website
    Zero or more objects with Name and Type properties, as returned by
    Get-SfosSSLTLSInspectionRule in its Website property.
#>
function ConvertTo-SfosSSLTLSInspectionRuleWebsitesXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [PSCustomObject[]]$Website
    )

    $activityXml = ''
    foreach ($site in @($Website)) {
        if (-not $site) {
            continue
        }
        $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$site.Name)
        $typeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$site.Type)
        $activityXml += "<Activity><Name>$nameEsc</Name><Type>$typeEsc</Type></Activity>"
    }

    return "<Websites>$activityXml</Websites>"
}

<#
.SYNOPSIS
    Builds the <Set> inner XML for a SSLTLSInspectionRule entity. Internal helper, not exported.

.DESCRIPTION
    Builds the complete Set request body for a SSLTLSInspectionRule entity, so New- and
    Set-SfosSSLTLSInspectionRule send an identical, complete entity body. Takes a fully
    resolved rule object with the same property shape Get-SfosSSLTLSInspectionRule returns,
    and escapes every value.

    The firewall replaces the whole entity on an update: any element this function does not
    emit is cleared. The caller merges in every field it wants preserved before calling this
    function; nothing is read back here.

    IsDefault is never emitted. It is read-only, and the firewall's built-in default rule
    must never be reconstructed or altered through this path; New-SfosSSLTLSInspectionRule
    and Set-SfosSSLTLSInspectionRule guard against touching it separately.

.PARAMETER Operation
    add or update, passed straight to the Set operation attribute.

.PARAMETER Rule
    Fully resolved rule object with Name, Description, Enable, LogConnections, SourceZones,
    SourceNetworks, Identity, DestinationZones, DestinationNetworks, Services, Website,
    DecryptAction and DecryptionProfile properties.

.PARAMETER Position
    Top or Bottom. Only meaningful on add; Set-SfosSSLTLSInspectionRule never supplies it.
    Omitted entirely when not given, so the firewall's own default position applies.
#>
function ConvertTo-SfosSSLTLSInspectionRuleEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Rule,

        [ValidateSet('Top', 'Bottom')]
        [string]$Position
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Name)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Description)
    $enableEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Enable)
    $logEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.LogConnections)
    $decryptActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.DecryptAction)
    $decryptProfileEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.DecryptionProfile)

    $positionXml = ''
    if ($Position) {
        $positionXml = "<Position>$(ConvertTo-SfosXmlEscaped -Text $Position)</Position>"
    }

    $sourceZonesXml = ConvertTo-SfosSSLTLSInspectionRuleXmlList -WrapperTag 'SourceZones' -ItemTag 'Zone' -Value $Rule.SourceZones
    $sourceNetworksXml = ConvertTo-SfosSSLTLSInspectionRuleXmlList -WrapperTag 'SourceNetworks' -ItemTag 'Network' -Value $Rule.SourceNetworks
    $identityXml = ConvertTo-SfosSSLTLSInspectionRuleXmlList -WrapperTag 'Identity' -ItemTag 'Members' -Value $Rule.Identity
    $destZonesXml = ConvertTo-SfosSSLTLSInspectionRuleXmlList -WrapperTag 'DestinationZones' -ItemTag 'Zone' -Value $Rule.DestinationZones
    $destNetworksXml = ConvertTo-SfosSSLTLSInspectionRuleXmlList -WrapperTag 'DestinationNetworks' -ItemTag 'Network' -Value $Rule.DestinationNetworks
    $servicesXml = ConvertTo-SfosSSLTLSInspectionRuleXmlList -WrapperTag 'Services' -ItemTag 'Service' -Value $Rule.Services
    $websitesXml = ConvertTo-SfosSSLTLSInspectionRuleWebsitesXml -Website $Rule.Website

    return @"
<Set operation="$Operation">
  <SSLTLSInspectionRule>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <Enable>$enableEsc</Enable>
    <LogConnections>$logEsc</LogConnections>
    $positionXml
    $sourceZonesXml
    $sourceNetworksXml
    $identityXml
    $destZonesXml
    $destNetworksXml
    $servicesXml
    $websitesXml
    <DecryptAction>$decryptActionEsc</DecryptAction>
    <DecryptionProfile>$decryptProfileEsc</DecryptionProfile>
  </SSLTLSInspectionRule>
</Set>
"@
}

<#
        .SYNOPSIS
        Retrieves SSL/TLS inspection rules from a Sophos Firewall.

        .DESCRIPTION
        Returns the SSL/TLS inspection rules that are defined on the firewall. Use this
        cmdlet to review the existing rules or to feed them into another cmdlet through the
        pipeline. The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        The firewall's built-in rule ('Exclusions by website or category') is returned like
        any other rule, with IsDefault set to Yes. Check IsDefault before scripting bulk
        changes; New-, Set- and Remove-SfosSSLTLSInspectionRule refuse to modify or remove it.

        Every returned rule carries the shape Set-SfosSSLTLSInspectionRule expects for its
        list parameters, so a rule read back from this cmdlet can be piped straight into
        Set-SfosSSLTLSInspectionRule.

        .PARAMETER NameLike
        Optional. Returns only rules whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern. If omitted, the name is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for SSL/TLS
        inspection rules. If omitted, the value from the current connection is used.

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
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per rule, with the properties
        Name, IsDefault, Description, Enable, LogConnections, SourceZones, SourceNetworks,
        Identity, DestinationZones, DestinationNetworks, Services, Website (an array of
        objects with Name and Type), DecryptAction and DecryptionProfile. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no rule matches.

        .EXAMPLE
        Get-SfosSSLTLSInspectionRule

        Lists every SSL/TLS inspection rule on the firewall of the current connection.

        .EXAMPLE
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass"

        Lists the rules whose name contains 'Bypass'.

        .EXAMPLE
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass-Banking" -AsXml

        Returns the raw XML of the matching rules, for example to check a field the standard
        output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosSSLTLSInspectionRule

        .LINK
        Set-SfosSSLTLSInspectionRule
#>
function Get-SfosSSLTLSInspectionRule {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,

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

    # Server-side pre-filter. SFOS evaluates only the first <key> of the first <Filter>;
    # additional keys and blocks are silently dropped, so the filter is applied again
    # client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <SSLTLSInspectionRule>
    $filterXml
  </SSLTLSInspectionRule>
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
        throw "Error retrieving SSLTLSInspectionRule objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Without this check a firewall-side error - missing permission, invalid filter, server
    # error - would be read as an empty result instead of being reported. This also affects
    # Set-/Remove-SfosSSLTLSInspectionRule, which call back into this function to read the
    # current object before writing.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTLSInspectionRule' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SSLTLSInspectionRule[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering. Only the first <key> of the first <Filter> is evaluated by
    # SFOS, and unsupported keys are ignored altogether, so the filter is re-applied here.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $ruleObjects = foreach ($node in @($nodes)) {
        # A rule with no website references has no <Websites> element at all, so
        # $node.Websites is $null. Without the -FilterScript below, @($null.Activity) is a
        # one-element array containing $null, not an empty array.
        $websites = foreach ($activityNode in @($node.Websites.Activity | Where-Object -FilterScript { $_ })) {
            [PSCustomObject]@{
                Name = [string]$activityNode.Name
                Type = [string]$activityNode.Type
            }
        }

        [PSCustomObject]@{
            Name                = [string]$node.Name
            IsDefault           = [string]$node.IsDefault
            Description         = [string]$node.Description
            Enable              = [string]$node.Enable
            LogConnections      = [string]$node.LogConnections
            SourceZones         = [string[]]@($node.SourceZones | Select-Object -ExpandProperty Zone -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            SourceNetworks      = [string[]]@($node.SourceNetworks | Select-Object -ExpandProperty Network -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            Identity            = [string[]]@($node.Identity | Select-Object -ExpandProperty Members -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            DestinationZones    = [string[]]@($node.DestinationZones | Select-Object -ExpandProperty Zone -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            DestinationNetworks = [string[]]@($node.DestinationNetworks | Select-Object -ExpandProperty Network -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            Services            = [string[]]@($node.Services | Select-Object -ExpandProperty Service -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            # Same $null-when-empty foreach quirk as above, guarded the same way.
            Website             = @($websites | Where-Object -FilterScript { $_ })
            DecryptAction       = [string]$node.DecryptAction
            DecryptionProfile   = [string]$node.DecryptionProfile
        }
    }

    return @($ruleObjects)
}

<#
        .SYNOPSIS
        Creates a new SSL/TLS inspection rule on a Sophos Firewall.

        .DESCRIPTION
        Creates a rule that controls whether matching HTTPS traffic is decrypted, exempted or
        denied by the SSL/TLS inspection engine. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to change SSL/TLS inspection rules.

        -Enable has no default and must be supplied explicitly on every call, because it
        controls whether the rule is live on the firewall.

        Creating a rule through this cmdlet is currently rejected by the firewall for every
        combination of fields tried. Use the web admin console to create SSL/TLS inspection
        rules; once a rule exists, Get-, Set- and Remove-SfosSSLTLSInspectionRule work against
        it normally.

        .PARAMETER Name
        Required. Name of the rule. 1 to 60 characters, no commas.

        .PARAMETER Enable
        Required. Whether the rule is active: Yes, No, t or f.

        .PARAMETER Description
        Optional. Free-text description of the rule. Up to 255 characters.

        .PARAMETER LogConnections
        Optional. Whether to log matching connections to the SSL log: Enable, Disable, t or
        f. If omitted, the firewall applies its own default.

        .PARAMETER Position
        Optional. Where to place the new rule in the rule list: Top or Bottom. If omitted,
        the firewall defaults to Bottom.

        .PARAMETER DecryptAction
        Optional. Action for traffic matching the rule: Decrypt, Do not decrypt or Deny. If
        omitted, the firewall applies its own default.

        .PARAMETER DecryptionProfile
        Optional. Name of the associated decryption profile. If omitted, the firewall applies
        its own default, or none for a Do not decrypt or Deny rule.

        .PARAMETER SourceZones
        Optional. Source zone names. If omitted, the firewall applies its own default.

        .PARAMETER SourceNetworks
        Optional. Source network, host or group names. If omitted, the firewall applies its
        own default.

        .PARAMETER Identity
        Optional. Source users or groups the rule applies to. If omitted, the firewall
        applies its own default.

        .PARAMETER DestinationZones
        Optional. Destination zone names. If omitted, the firewall applies its own default.

        .PARAMETER DestinationNetworks
        Optional. Destination network, host or group names. If omitted, the firewall applies
        its own default.

        .PARAMETER Services
        Optional. Service names. If omitted, the firewall applies its own default.

        .PARAMETER Website
        Optional. Website or category references the rule applies to, each an object with
        Name and Type properties, Type being Web Category or URL Group. If omitted, the
        firewall applies its own default.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        SSL/TLS inspection rules. If omitted, the value from the current connection is used.

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
        create.

        .EXAMPLE
        $website = [PSCustomObject]@{ Name = 'Banking'; Type = 'Web Category' }
        New-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -Enable No -DecryptAction "Do not decrypt" -Website $website -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        $website = [PSCustomObject]@{ Name = 'Banking'; Type = 'Web Category' }
        New-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -Enable No -DecryptAction "Do not decrypt" -Website $website

        Creates a disabled rule that exempts a web category from decryption. The cmdlet asks
        for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLTLSInspectionRule
#>
function New-SfosSSLTLSInspectionRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Yes', 'No', 't', 'f')]
        [string]$Enable,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('Enable', 'Disable', 't', 'f')]
        [string]$LogConnections,

        [ValidateSet('Top', 'Bottom')]
        [string]$Position,

        [ValidateSet('Decrypt', 'Do not decrypt', 'Deny')]
        [string]$DecryptAction,

        [string]$DecryptionProfile,

        [string[]]$SourceZones,
        [string[]]$SourceNetworks,
        [string[]]$Identity,
        [string[]]$DestinationZones,
        [string[]]$DestinationNetworks,
        [string[]]$Services,
        [PSCustomObject[]]$Website,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    foreach ($site in @($Website)) {
        if ($site -and ([string]$site.Type) -notin @('Web Category', 'URL Group')) {
            throw "SSLTLSInspectionRule '$Name': -Website entry Type must be 'Web Category' or 'URL Group', got '$($site.Type)'."
        }
    }

    $ruleObject = [PSCustomObject]@{
        Name                = $Name
        Description         = $Description
        Enable              = $Enable
        LogConnections      = $LogConnections
        SourceZones         = $SourceZones
        SourceNetworks      = $SourceNetworks
        Identity            = $Identity
        DestinationZones    = $DestinationZones
        DestinationNetworks = $DestinationNetworks
        Services            = $Services
        Website             = $Website
        DecryptAction       = $DecryptAction
        DecryptionProfile   = $DecryptionProfile
    }

    # -Position only when the caller bound it: passing an unbound $Position forwards "",
    # which violates the helper's ValidateSet('Top','Bottom') and crashes client-side
    # before any API call.
    $builderArgs = @{ Operation = 'add'; Rule = $ruleObject }
    if ($PSBoundParameters.ContainsKey('Position')) { $builderArgs['Position'] = $Position }
    $inner = ConvertTo-SfosSSLTLSInspectionRuleEntityXml @builderArgs

    if (-not $PSCmdlet.ShouldProcess("SSLTLSInspectionRule '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating SSLTLSInspectionRule object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTLSInspectionRule' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing SSL/TLS inspection rule on a Sophos Firewall.

        .DESCRIPTION
        Updates a SSL/TLS inspection rule. You can supply the target rule name directly or
        through the pipeline. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with permission to change
        SSL/TLS inspection rules. This cmdlet does not reposition rules.

        The firewall replaces the whole rule on update; any field not sent in the request is
        cleared. The cmdlet reads the current rule first and keeps whatever you do not
        explicitly pass. The list parameters (SourceZones, SourceNetworks, Identity,
        DestinationZones, DestinationNetworks, Services, Website) are wholesale replacements
        when supplied, not merges; to add one zone to an existing list, pass the full desired
        list.

        The firewall's built-in rule ('Exclusions by website or category', IsDefault Yes) is
        refused by this cmdlet, because it is the only built-in TLS bypass rule and an
        accidental change to it is not recoverable through this module.

        .PARAMETER Name
        Required. Name of the target rule. Accepts pipeline input.

        .PARAMETER Description
        Optional. New description text. Up to 255 characters. If omitted, the current value
        is kept.

        .PARAMETER Enable
        Optional. Whether the rule is active: Yes, No, t or f. If omitted, the current value
        is kept.

        .PARAMETER LogConnections
        Optional. Whether to log matching connections: Enable, Disable, t or f. If omitted,
        the current value is kept.

        .PARAMETER DecryptAction
        Optional. Action for matching traffic: Decrypt, Do not decrypt or Deny. If omitted,
        the current value is kept.

        .PARAMETER DecryptionProfile
        Optional. Name of the associated decryption profile. If omitted, the current value is
        kept.

        .PARAMETER SourceZones
        Optional. Source zone names, replacing the whole list. If omitted, the current list
        is kept.

        .PARAMETER SourceNetworks
        Optional. Source network, host or group names, replacing the whole list. If omitted,
        the current list is kept.

        .PARAMETER Identity
        Optional. Source users or groups, replacing the whole list. If omitted, the current
        list is kept.

        .PARAMETER DestinationZones
        Optional. Destination zone names, replacing the whole list. If omitted, the current
        list is kept.

        .PARAMETER DestinationNetworks
        Optional. Destination network, host or group names, replacing the whole list. If
        omitted, the current list is kept.

        .PARAMETER Services
        Optional. Service names, replacing the whole list. If omitted, the current list is
        kept.

        .PARAMETER Website
        Optional. Website or category references, replacing the whole list, each an object
        with Name and Type properties, Type being Web Category or URL Group. If omitted, the
        current list is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        SSL/TLS inspection rules. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosSSLTLSInspectionRule, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -DecryptionProfile "Maximum compatibility" -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -DecryptionProfile "Maximum compatibility"

        Changes only the decryption profile, leaving every other field untouched. The cmdlet
        asks for confirmation before it writes.

        .EXAMPLE
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass-Banking" | Set-SfosSSLTLSInspectionRule -Enable No

        Disables the matching rules.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLTLSInspectionRule
#>
function Set-SfosSSLTLSInspectionRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('Yes', 'No', 't', 'f')]
        [string]$Enable,

        [ValidateSet('Enable', 'Disable', 't', 'f')]
        [string]$LogConnections,

        [ValidateSet('Decrypt', 'Do not decrypt', 'Deny')]
        [string]$DecryptAction,

        [string]$DecryptionProfile,

        [string[]]$SourceZones,
        [string[]]$SourceNetworks,
        [string[]]$Identity,
        [string[]]$DestinationZones,
        [string[]]$DestinationNetworks,
        [string[]]$Services,
        [PSCustomObject[]]$Website,

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
        $existing = @(Get-SfosSSLTLSInspectionRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLTLSInspectionRule object '$Name' was not found."
        }

        if ($existing[0].IsDefault -match '^yes$') {
            throw "SSLTLSInspectionRule '$Name' is a default rule (IsDefault=$($existing[0].IsDefault)) and is protected from modification by this cmdlet."
        }

        if ($PSBoundParameters.ContainsKey('Website')) {
            foreach ($site in @($Website)) {
                if ($site -and ([string]$site.Type) -notin @('Web Category', 'URL Group')) {
                    throw "SSLTLSInspectionRule '$Name': -Website entry Type must be 'Web Category' or 'URL Group', got '$($site.Type)'."
                }
            }
        }

        $targetRule = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) {
            $targetRule.Description = $Description
        }
        if ($PSBoundParameters.ContainsKey('Enable')) {
            $targetRule.Enable = $Enable
        }
        if ($PSBoundParameters.ContainsKey('LogConnections')) {
            $targetRule.LogConnections = $LogConnections
        }
        if ($PSBoundParameters.ContainsKey('DecryptAction')) {
            $targetRule.DecryptAction = $DecryptAction
        }
        if ($PSBoundParameters.ContainsKey('DecryptionProfile')) {
            $targetRule.DecryptionProfile = $DecryptionProfile
        }
        if ($PSBoundParameters.ContainsKey('SourceZones')) {
            $targetRule.SourceZones = @($SourceZones)
        }
        if ($PSBoundParameters.ContainsKey('SourceNetworks')) {
            $targetRule.SourceNetworks = @($SourceNetworks)
        }
        if ($PSBoundParameters.ContainsKey('Identity')) {
            $targetRule.Identity = @($Identity)
        }
        if ($PSBoundParameters.ContainsKey('DestinationZones')) {
            $targetRule.DestinationZones = @($DestinationZones)
        }
        if ($PSBoundParameters.ContainsKey('DestinationNetworks')) {
            $targetRule.DestinationNetworks = @($DestinationNetworks)
        }
        if ($PSBoundParameters.ContainsKey('Services')) {
            $targetRule.Services = @($Services)
        }
        if ($PSBoundParameters.ContainsKey('Website')) {
            $targetRule.Website = @($Website)
        }

        $inner = ConvertTo-SfosSSLTLSInspectionRuleEntityXml -Operation 'update' -Rule $targetRule

        if (-not $PSCmdlet.ShouldProcess("SSLTLSInspectionRule '$Name' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating SSLTLSInspectionRule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTLSInspectionRule' -Action 'update' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes an SSL/TLS inspection rule from a Sophos Firewall.

        .DESCRIPTION
        Deletes an SSL/TLS inspection rule by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to change SSL/TLS inspection rules.

        The cmdlet reads the rule before deleting it and refuses to remove the firewall's
        built-in rule ('Exclusions by website or category', IsDefault Yes), because it is the
        only built-in TLS bypass rule and cannot be restored if removed by mistake. The read
        also turns an attempt to remove a rule that does not exist into a clear "was not
        found" instead of a firewall error code.

        .PARAMETER Name
        Required. Name of the target rule. Accepts pipeline input.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change
        SSL/TLS inspection rules. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. Objects with a Name property, such as
        the output of Get-SfosSSLTLSInspectionRule, can be piped in.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass-Banking" | Remove-SfosSSLTLSInspectionRule

        Removes the rules whose name contains 'Bypass-Banking'. The cmdlet asks for
        confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLTLSInspectionRule
#>
function Remove-SfosSSLTLSInspectionRule {
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
        $existing = @(Get-SfosSSLTLSInspectionRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLTLSInspectionRule object '$Name' was not found."
        }

        if ($existing[0].IsDefault -match '^yes$') {
            throw "SSLTLSInspectionRule '$Name' is a default rule (IsDefault=$($existing[0].IsDefault)) and is protected from removal by this cmdlet."
        }

        if (-not $PSCmdlet.ShouldProcess("SSLTLSInspectionRule '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <SSLTLSInspectionRule>
    <Name>$nameEsc</Name>
  </SSLTLSInspectionRule>
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
            throw "Error removing SSLTLSInspectionRule object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTLSInspectionRule' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion

#region SSLTLSInspectionSettings

<#
        .SYNOPSIS
        Retrieves the SSL/TLS inspection settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide SSL/TLS inspection settings: the CA certificates used for
        re-signing during decryption, the fallback actions for SSL 2.0/3.0, SSL compression
        and exceeded-connection cases, TLS 1.3 handling, and the on/off switches for the TLS
        engine and TLS inspection itself. There is exactly one instance of this object per
        firewall. The cmdlet only reads; nothing on the firewall is changed. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        SSL/TLS inspection settings. If omitted, the value from the current connection is
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
        System.Management.Automation.PSCustomObject. One object with the properties RSACA,
        ECCA, SSLv2SSLv3, SSLCompression, SSLConnectionsExceeded, TLS13Decryption,
        SSLTLSEngine and SSLTLSInspection. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosSSLTLSInspectionSettings

        Returns the current SSL/TLS inspection settings of the firewall of the current
        connection.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosSSLTLSInspectionSettings
#>
function Get-SfosSSLTLSInspectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <SSLTLSInspectionSettings>, a
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

    $inner = '<Get><SSLTLSInspectionSettings></SSLTLSInspectionSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SSLTLSInspectionSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTLSInspectionSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SSLTLSInspectionSettings')
    if (-not $node) {
        throw 'SSLTLSInspectionSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        RSACA                   = [string]$node.RSACA
        ECCA                    = [string]$node.ECCA
        SSLv2SSLv3               = [string]$node.SSLv2SSLv3
        SSLCompression           = [string]$node.SSLCompression
        SSLConnectionsExceeded   = [string]$node.SSLConnectionsExceeded
        TLS13Decryption          = [string]$node.TLS13Decryption
        SSLTLSEngine             = [string]$node.SSLTLSEngine
        SSLTLSInspection         = [string]$node.SSLTLSInspection
    }
}

<#
        .SYNOPSIS
        Updates the SSL/TLS inspection settings on a Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide SSL/TLS inspection settings. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with permission to change the SSL/TLS inspection settings. The cmdlet reads the
        current settings first and resends every field, overriding only what you explicitly
        pass, so fields you do not pass keep their current value.

        Every field of this entity applies device-wide and takes effect immediately for every
        HTTPS connection through the firewall; there is no per-rule scope. Disabling
        SSLTLSEngine or SSLTLSInspection turns SSL/TLS inspection off for the whole appliance.
        Review the current settings with Get-SfosSSLTLSInspectionSettings and use -WhatIf
        before applying a change.

        .PARAMETER RSACA
        Optional. Name of the RSA CA certificate used for re-signing during decryption. If
        omitted, the current value is kept.

        .PARAMETER ECCA
        Optional. Name of the EC CA certificate used for re-signing during decryption. If
        omitted, the current value is kept.

        .PARAMETER SSLv2SSLv3
        Optional. Action for SSL 2.0/3.0 connections: Allow without decryption, Drop or
        Reject. If omitted, the current value is kept.

        .PARAMETER SSLCompression
        Optional. Action for connections using SSL compression: Allow without decryption,
        Drop or Reject. If omitted, the current value is kept.

        .PARAMETER SSLConnectionsExceeded
        Optional. Action applied once the maximum number of concurrent SSL connections is
        exceeded: Allow without decryption, Drop or Reject. If omitted, the current value is
        kept.

        .PARAMETER TLS13Decryption
        Optional. Action for TLS 1.3 connections: Decrypt as 1.3 or Downgrade to TLS 1.2 and
        decrypt. If omitted, the current value is kept.

        .PARAMETER SSLTLSEngine
        Optional. Whether the SSL/TLS inspection engine itself is on: Enabled or Disabled. If
        omitted, the current value is kept.

        .PARAMETER SSLTLSInspection
        Optional. Whether SSL/TLS traffic is inspected: Enabled or Disabled. If omitted, the
        current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs permission to change the
        SSL/TLS inspection settings. If omitted, the value from the current connection is
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
        Set-SfosSSLTLSInspectionSettings -RSACA "MyIssuingCA" -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSSLTLSInspectionSettings -RSACA "MyIssuingCA" -Confirm:$false

        Changes only the RSA re-signing CA, leaving every other field untouched, without
        asking for confirmation. Use this form only in scripts where the value has already
        been reviewed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSSLTLSInspectionSettings
#>
function Set-SfosSSLTLSInspectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <SSLTLSInspectionSettings>, a
    # singleton holding one configuration, not a plural container.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$RSACA,
        [string]$ECCA,

        [ValidateSet('Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLv2SSLv3,

        [ValidateSet('Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLCompression,

        [ValidateSet('Allow without decryption', 'Drop', 'Reject')]
        [string]$SSLConnectionsExceeded,

        [ValidateSet('Decrypt as 1.3', 'Downgrade to TLS 1.2 and decrypt')]
        [string]$TLS13Decryption,

        [ValidateSet('Enabled', 'Disabled')]
        [string]$SSLTLSEngine,

        [ValidateSet('Enabled', 'Disabled')]
        [string]$SSLTLSInspection,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSSLTLSInspectionSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetRsaCa = if ($bp.ContainsKey('RSACA')) { $RSACA } else { $existing.RSACA }
    $targetEcCa = if ($bp.ContainsKey('ECCA')) { $ECCA } else { $existing.ECCA }
    $targetSslv2Sslv3 = if ($bp.ContainsKey('SSLv2SSLv3')) { $SSLv2SSLv3 } else { $existing.SSLv2SSLv3 }
    $targetCompression = if ($bp.ContainsKey('SSLCompression')) { $SSLCompression } else { $existing.SSLCompression }
    $targetExceeded = if ($bp.ContainsKey('SSLConnectionsExceeded')) { $SSLConnectionsExceeded } else { $existing.SSLConnectionsExceeded }
    $targetTls13 = if ($bp.ContainsKey('TLS13Decryption')) { $TLS13Decryption } else { $existing.TLS13Decryption }
    $targetEngine = if ($bp.ContainsKey('SSLTLSEngine')) { $SSLTLSEngine } else { $existing.SSLTLSEngine }
    $targetInspection = if ($bp.ContainsKey('SSLTLSInspection')) { $SSLTLSInspection } else { $existing.SSLTLSInspection }

    if (-not $PSCmdlet.ShouldProcess("SSLTLSInspectionSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <SSLTLSInspectionSettings>
    <RSACA>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetRsaCa))</RSACA>
    <ECCA>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetEcCa))</ECCA>
    <SSLv2SSLv3>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetSslv2Sslv3))</SSLv2SSLv3>
    <SSLCompression>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetCompression))</SSLCompression>
    <SSLConnectionsExceeded>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetExceeded))</SSLConnectionsExceeded>
    <TLS13Decryption>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetTls13))</TLS13Decryption>
    <SSLTLSEngine>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetEngine))</SSLTLSEngine>
    <SSLTLSInspection>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetInspection))</SSLTLSInspection>
  </SSLTLSInspectionSettings>
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
        throw "Error updating SSLTLSInspectionSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTLSInspectionSettings' -Action 'update'
}

#endregion

