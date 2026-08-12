#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }
<#
        .SYNOPSIS
        Manages firewall rules, rule groups, NAT rules and SSL/TLS inspection on Sophos Firewall.

        .DESCRIPTION
        PowerShell module for the PROTECT > Firewall area of the Sophos XGS / SFOS 22.0 XML API.
        The SFOS web admin presents the same area as "Rules and policies".

        This module provides functions to create, read, update, and delete:
        - Firewall Rules (network policies, with a builder for the policy subtree)
        - Firewall Rule Groups (with member management)
        - NAT Rules
        - SSL/TLS Inspection Rules

        It also exposes the SSL/TLS inspection settings, which the API models as a singleton
        without a name and with no create or delete operation.

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect to the firewall and list the rules in evaluation order
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosFirewallRule | Format-Table Name, Status, Position, PolicyType

        .EXAMPLE
        # Create a disabled rule at the bottom of the list
        $policy = New-SfosFirewallRuleNetworkPolicy -Action Accept -SourceZone LAN -DestinationZone WAN
        New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $policy

        .EXAMPLE
        # Group rules and inspect the members
        New-SfosFirewallRuleGroup -Name "Outbound" -Members "Allow-LAN-to-WAN"
        (Get-SfosFirewallRuleGroup -NameLike "Outbound").SecurityPolicyList

        .EXAMPLE
        # Read the SSL/TLS inspection settings
        Get-SfosSSLTLSInspectionSettings

        .NOTES
        Module Name: SophosFirewall.Firewall
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+

        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)

        API Compatibility:
        - Sophos SFOS 22.0
        - Sophos XGS Firewall Series

        Total Functions: 21
        - 5 Firewall Rule functions (including the network policy builder)
        - 6 Firewall Rule Group functions (including Add/Remove members)
        - 4 NAT Rule functions
        - 4 SSL/TLS Inspection Rule functions
        - 2 SSL/TLS Inspection Settings functions (Get/Set)

        These cmdlets change the rule base of a live firewall. A rule in the wrong place, or
        an update that drops a rule's position, changes which traffic the appliance permits.
        Every Set-* therefore reads the current object first and writes it back complete.

        Behaviour that differs from the vendor documentation was measured against a live
        appliance and is recorded in the .NOTES of the affected function. The most important
        ones:
        - The documentation folder is called SecurityPolicy, but the XML element is
          FirewallRule. Several other elements in this area differ from their folder name
          in the same way.
        - Position 'Bottom' is normalised by the firewall to 'After' anchored on the last
          rule, so what a Get returns is not what was sent.
        - The wire element is spelled TrafficShappingPolicy, with a doubled p. The
          documentation spells it correctly; the appliance does not.
        - Only PolicyType 'Network' is supported. 'User' and 'HTTPBased' exist in the
          documentation but could not be verified, so the cmdlets refuse them rather than
          guessing at their subtree.

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
# The doc folder is called SecurityPolicy, but the wire element is <FirewallRule> - a
# <SecurityPolicy> root answers 529 'Input request module is Invalid' [live]. Position and
# rule order are the single most dangerous property of this entity: SFOS replaces the whole
# object on <Set operation="update">, so an update that omits Position/After/Before moves the
# rule and silently reorders the entire rulebase. Every write cmdlet below therefore funnels
# through ConvertTo-SfosFirewallRuleXml with a fully resolved rule object, and Set-* always
# reads the current object first and preserves Position/After/Before unless the caller
# explicitly overrides them.
#
# <Status> here is a data field ("is this rule active"), not an API status - Core's
# Get-SfosApiStatus already tells the two apart (a real status node either carries a 'code'
# attribute or its parent has no <Name>; six <FirewallRule><Status>Enable</Status> siblings
# have neither), so no extra handling is needed in this module.
#
# PolicyType [doc] has three documented values: User, Network, HTTPBased - each with its own
# subtree (UserPolicy, NetworkPolicy, HTTPBasedPolicy). All six rules on the lab firewall are
# PolicyType=Network, and only NetworkPolicy's ~30 fields have been read and written against a
# live firewall. UserPolicy and HTTPBasedPolicy are documented but NOT implemented here - see
# the .NOTES on Get-/New-/Set-SfosFirewallRule. Get-SfosFirewallRule still returns the common
# top-level fields for any PolicyType; New-/Set-SfosFirewallRule refuse to write anything but
# PolicyType=Network, which also means they can never touch the five other-typed... (in this
# lab, all six existing rules happen to be Network, so this restriction does not block them,
# it only blocks types nobody has verified).

<#
.SYNOPSIS
    Builds the <NetworkPolicy> XML for a FirewallRule. Internal helper, not exported.

.DESCRIPTION
    Converts a NetworkPolicy object (as produced by New-SfosFirewallRuleNetworkPolicy or
    returned by Get-SfosFirewallRule) into the <NetworkPolicy>...</NetworkPolicy> fragment
    SFOS expects inside a FirewallRule. Every value is escaped here. List wrappers
    (SourceZones, SourceNetworks, DestinationZones, DestinationNetworks, Services) are only
    emitted when the list is non-empty - a live rule with no SourceZones/DestinationZones
    (the MTA auto rule) omits the wrapper entirely rather than sending it empty [live], and an
    empty <SourceZones/> was not tested, so this helper mirrors what was actually observed.

    Element order follows the live GET response where a field was observed
    (fw-live-FirewallRule.xml), and the vendor sample XML where it was not (SourceNetworks).
    SFOS is expected to parse child elements by name, not by position, so this is a
    readability choice, not a correctness requirement.

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
    # Wire element is misspelled "TrafficShappingPolicy" (extra 'p') on a live firewall -
    # confirmed in fw-live-FirewallRule.xml on all six existing rules. The vendor doc's
    # attribute table uses the correctly spelled "TrafficShapingPolicy"; sending that name
    # instead would land on an unknown element and the field would not be set. Same class of
    # trap as the invented <CountryHostGroup> element documented in the project build rules - the wire
    # spelling wins.
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
    Centralizes the FirewallRule XML shape so New- and Set-SfosFirewallRule send an
    identical, complete entity body. Takes a fully resolved rule object - same property
    shape Get-SfosFirewallRule returns - and escapes every value.

    SFOS replaces the whole entity on <Set operation="update">: any element this function
    does not emit is cleared on the firewall, Position and After/Before included. The caller
    is responsible for merging in every field it wants preserved (in particular Position,
    After, Before) before calling this function; nothing is read back here.

    Only PolicyType=Network is supported - see the module-level comment at the top of this
    region. Any other PolicyType throws rather than silently sending an incomplete or empty
    subtree.

.PARAMETER Operation
    'add' or 'update', passed straight to <Set operation="...">.

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
        throw "PolicyType '$($Rule.PolicyType)' is not supported by this module - only 'Network' rules can be written. UserPolicy and HTTPBasedPolicy are documented by Sophos but have not been implemented or verified against a live firewall."
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
    Queries the Sophos Firewall XML API for FirewallRule (security policy) objects. By
    default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML
    nodes.

    Only the top-level fields (Name, Description, IPFamily, Status, Position, Section, After,
    Before, PolicyType) are guaranteed for every rule. The NetworkPolicy property is populated
    only when PolicyType is 'Network' - the only subtree this module has read and written
    against a live firewall. For any other PolicyType (User, HTTPBased), NetworkPolicy is
    $null and the rule's type-specific fields are not exposed; use -AsXml to inspect them.

    Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is
    designed to return an empty result when no records are found. <Status> inside a
    FirewallRule node is the rule's own Enable/Disable flag, not an API status - Core tells
    the two apart before this cmdlet ever sees a status.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER Port
    Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the
    stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER Password
    Password for API authentication. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER NameLike
    Optional name filter. In Sophos SFOS, 'like' behaves as a substring match. Sent to the
    firewall as the server-side filter, then re-applied client-side (section 6: only the first key of
    the first filter is evaluated server-side, and this module never relies on that alone).

.PARAMETER PolicyTypeLike
    Optional PolicyType filter, matched as a substring (for example 'Network'). The firewall
    does not support filtering on PolicyType, so this filter is always applied client-side.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for the API call.

.PARAMETER AsXml
    Returns raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject with properties: Name, Description, IPFamily, Status, Position, Section,
    After, Before, PolicyType, NetworkPolicy (object with Action, LogTraffic,
    SkipLocalDestined, SourceZoneList, SourceNetworkList, DestinationZoneList, Schedule,
    ServiceList, DestinationNetworkList, DSCPMarking, WebFilter, WebCategoryBaseQoSPolicy,
    BlockQuickQuic, ScanVirus, ZeroDayProtection, ProxyMode, DecryptHTTPS, ApplicationControl,
    ApplicationBaseQoSPolicy, IntrusionPrevention, NDRActiveThreatIntelligence,
    TrafficShappingPolicy, ScanSMTP, ScanSMTPS, ScanIMAP, ScanIMAPS, ScanPOP3, ScanPOP3S,
    ScanFTP, SourceSecurityHeartbeat, MinimumSourceHBPermitted, DestSecurityHeartbeat,
    MinimumDestinationHBPermitted properties, or $null when PolicyType is not 'Network').
    System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    # Retrieve all firewall rules
    Get-SfosFirewallRule

.EXAMPLE
    # Filter by name (substring match)
    Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN"

.EXAMPLE
    # Only Network-type rules, raw XML for troubleshooting
    Get-SfosFirewallRule -PolicyTypeLike "Network" -AsXml

.NOTES
    Minimum supported PowerShell version: 5.1
    This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
    UserPolicy and HTTPBasedPolicy rules are returned with NetworkPolicy = $null; their
    type-specific fields are not parsed by this cmdlet.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/SecurityPolicy/SecurityPolicy.html
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
    Shared precedence rule for New-SfosFirewallRuleNetworkPolicy's -InputObject and for
    Set-SfosFirewallRule's per-field NetworkPolicy parameters (which forward through
    New-SfosFirewallRuleNetworkPolicy - see Set-SfosFirewallRule): an explicitly bound
    parameter always wins; otherwise, when a base object is available (an -InputObject, or the
    NetworkPolicy Set-SfosFirewallRule is merging into), that base's value is kept; otherwise
    the parameter's own value is used unchanged - for New-SfosFirewallRuleNetworkPolicy without
    -InputObject that is already the parameter's documented default, because PowerShell assigns
    parameter defaults before the function body runs regardless of whether the caller supplied
    the parameter. Centralised here so the precedence cannot drift between the ~30 NetworkPolicy
    fields (the project build rules, section 5's "$PSBoundParameters.ContainsKey, not a truthiness test").

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
    Builds a NetworkPolicy sub-object for use with New-/Set-SfosFirewallRule.

.DESCRIPTION
    Creates the object New-SfosFirewallRule -NetworkPolicy and Set-SfosFirewallRule
    -NetworkPolicy expect. Performs no API call. A raw hashtable would need every one of the
    ~30 NetworkPolicy fields spelled and ordered correctly, including the misspelled wire
    element TrafficShappingPolicy - this builder exists so callers work from named parameters
    with defaults instead, the same reasoning as New-SfosWebFilterPolicyRule in
    SophosFirewall.Web.

    Accepts an existing NetworkPolicy via -InputObject (for example the NetworkPolicy property
    Get-SfosFirewallRule returns) as a base. Without -InputObject every field falls back to its
    documented default, exactly as before this parameter was added. With -InputObject, only the
    parameters the caller actually passed override the base - every other field is copied from
    -InputObject unchanged, so a single field can be changed without resetting the other ~29.

.PARAMETER InputObject
    Existing NetworkPolicy object to use as a base, for example the NetworkPolicy property
    returned by Get-SfosFirewallRule. Only parameters explicitly passed alongside -InputObject
    override the corresponding field; every other field is copied from -InputObject unchanged.
    Accepts pipeline input, so
    (Get-SfosFirewallRule -NameLike 'Allow-LAN-to-WAN').NetworkPolicy | New-SfosFirewallRuleNetworkPolicy -ScanVirus Enable
    changes only ScanVirus and leaves every other field as read from the firewall.

.PARAMETER Action
    Traffic handling action: 'Accept', 'Reject' or 'Drop'. Default: 'Accept'.

.PARAMETER LogTraffic
    Whether to log traffic matching this rule: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER SkipLocalDestined
    Skip this rule when the firewall itself is the destination: 'Enable' or 'Disable'.
    Default: 'Disable'.

.PARAMETER SourceZone
    Source zone names, for example 'LAN', 'WAN', 'DMZ', 'VPN', 'Any'. Zone names are
    firewall-defined, not a fixed set, so no validation is applied beyond non-empty strings.
    Omit to leave SourceZones unset, as the live 'Auto added firewall policy for MTA' rule
    does.

.PARAMETER SourceNetwork
    Source network/host object names. Not observed populated on the lab firewall; documented
    by Sophos only.

.PARAMETER DestinationZone
    Destination zone names, for example 'LAN', 'WAN', 'LOCAL', 'VPN', 'Any'.

.PARAMETER Schedule
    Name of the Schedule object this rule is active during. Default: 'All The Time' (a Sophos
    factory-default schedule).

.PARAMETER Service
    Service object names this rule matches, for example 'PING', 'SMTP'. Omit to match all
    services, as most of the six lab rules do.

.PARAMETER DestinationNetwork
    Destination network/host object names.

.PARAMETER DSCPMarking
    QoS packet classification, -1 to 63. Sophos documents 0-63 with named classes; -1 was
    observed live on rules that do not use DSCP marking. Default: -1.

.PARAMETER WebFilter
    Name of the web filter policy applied by this rule, or 'None'. Default: 'None'.

.PARAMETER WebCategoryBaseQoSPolicy
    Bandwidth limit toggle for web categories. The vendor doc lists 'Apply'/'Revoke'; the six
    live rules instead show '0' or an empty string, so this parameter is not constrained by a
    ValidateSet - the discrepancy is unresolved. Default: '' (empty, matching most live rules).

.PARAMETER BlockQuickQuic
    Block the QUIC protocol: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanVirus
    Scan matching traffic for viruses: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ZeroDayProtection
    Enable zero-day threat protection: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ProxyMode
    Use the transparent web proxy: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER DecryptHTTPS
    Decrypt HTTPS traffic for inspection: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ApplicationControl
    Name of the application control policy applied by this rule, or 'None'. Default: 'None'.

.PARAMETER ApplicationBaseQoSPolicy
    Bandwidth limit toggle for application categories. Same doc/live discrepancy as
    -WebCategoryBaseQoSPolicy; not constrained by a ValidateSet. Default: ''.

.PARAMETER IntrusionPrevention
    Name of the IPS policy applied by this rule, or 'None'. Default: 'None'.

.PARAMETER NDRActiveThreatIntelligence
    Enable active threat intelligence: 'Enable' or 'Disable'. The vendor's shared attribute
    table lists this as a top-level true/false field, but it is observed live inside
    NetworkPolicy with Enable/Disable values - the live shape is what this builder uses.
    Default: 'Disable'.

.PARAMETER TrafficShappingPolicy
    Name of the traffic shaping policy applied by this rule, or 'None'. Spelled exactly as
    the live wire element - see the module-level comment on ConvertTo-SfosFirewallRuleNetworkPolicyXml.
    Default: 'None'.

.PARAMETER ScanSMTP
    Scan SMTP traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanSMTPS
    Scan SMTPS traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanIMAP
    Scan IMAP traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanIMAPS
    Scan IMAPS traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanPOP3
    Scan POP3 traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanPOP3S
    Scan POP3S traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER ScanFTP
    Scan FTP traffic: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER SourceSecurityHeartbeat
    Require a source Security Heartbeat: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER MinimumSourceHBPermitted
    Minimum source health status permitted: 'No Restriction', 'GREEN' or 'YELLOW'.
    Default: 'No Restriction'.

.PARAMETER DestSecurityHeartbeat
    Require a destination Security Heartbeat: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER MinimumDestinationHBPermitted
    Minimum destination health status permitted: 'No Restriction', 'GREEN' or 'YELLOW'.
    Default: 'No Restriction'.

.OUTPUTS
    PSCustomObject with the same property shape Get-SfosFirewallRule returns for
    NetworkPolicy.

.EXAMPLE
    # Accept LAN-to-WAN traffic, disabled by default, no scanning
    New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "WAN"

.EXAMPLE
    # Accept and log a specific service between two zones
    New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "DMZ" -Service "HTTPS" -LogTraffic Enable

.EXAMPLE
    # Change one field on an existing rule's policy, everything else copied unchanged
    (Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN").NetworkPolicy | New-SfosFirewallRuleNetworkPolicy -ScanVirus Enable

.NOTES
    Minimum supported PowerShell version: 5.1
    This cmdlet performs no API call; it only builds an in-memory object.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/SecurityPolicy/operations/Addfirewallrule%26Editfirewallrule.html

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
    Creates a new firewall rule (security policy) on the Sophos Firewall.

.DESCRIPTION
    Creates a FirewallRule object using the Sophos Firewall XML API. Only PolicyType=Network
    is supported - see the module-level comment at the top of this region for why. Build the
    NetworkPolicy subtree with New-SfosFirewallRuleNetworkPolicy.

    -Status and -Position are mandatory on purpose: this is the most security-critical entity
    in the whole project, and neither "is this rule active" nor "where does it sit in the
    evaluation order" should default silently.

.PARAMETER Name
    Name of the firewall rule (1-60 characters, no commas - the vendor doc gives a 60
    character limit for this entity specifically, unlike the 50-character limit used
    elsewhere in this project).

.PARAMETER Description
    Optional description. No length limit is documented for this field; 255 characters is
    used here to match the convention of every other entity in this project, not a measured
    or documented limit.

.PARAMETER IPFamily
    Internet Protocol version: 'IPv4' or 'IPv6'. Default: 'IPv4'.

.PARAMETER Status
    Whether the rule is active: 'Enable' or 'Disable'. Mandatory - see .DESCRIPTION.

.PARAMETER Position
    Where to insert the rule: 'Top', 'Bottom', 'After' or 'Before'. Mandatory - see
    .DESCRIPTION. 'Top' inserts above every existing rule and moves all of them down one
    position, changing the evaluation order of the whole rulebase; use with care.

.PARAMETER After
    Name of the existing rule this one is inserted after. Required when -Position is 'After'.

.PARAMETER Before
    Name of the existing rule this one is inserted before. Required when -Position is
    'Before'.

.PARAMETER Section
    Policy section: 'Central_TOP', 'Local' or 'Central_Bottom'. Documented by Sophos; not
    observed on any of the six live rules used to verify this module, which all omit it.

.PARAMETER PolicyType
    Type of policy: 'User', 'Network' or 'HTTPBased'. Only 'Network' is implemented - any
    other value throws. Kept as a parameter (rather than hard-coding 'Network') so the
    limitation is explicit at the call site instead of silently assumed.

.PARAMETER NetworkPolicy
    NetworkPolicy subtree, built with New-SfosFirewallRuleNetworkPolicy. Mandatory when
    -PolicyType is 'Network'.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

.PARAMETER Port
    Management/API port number. If omitted, uses stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, uses stored connection context.

.PARAMETER Password
    Password for API authentication. If omitted, uses stored connection context.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation.

.OUTPUTS
    None. Throws an exception if creation fails.

.EXAMPLE
    # Create a disabled rule at the bottom of the rulebase
    $np = New-SfosFirewallRuleNetworkPolicy -SourceZone "LAN" -DestinationZone "WAN"
    New-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Status Disable -Position Bottom -PolicyType Network -NetworkPolicy $np

.NOTES
    Minimum supported PowerShell version: 5.1
    This cmdlet changes the rule base of a production firewall. -Position Top reorders every
    existing rule; verify -Position/-After/-Before before running this against a
    shared/production firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/SecurityPolicy/operations/Addfirewallrule%26Editfirewallrule.html

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
        [switch]$SkipCertificateCheck
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
    Updates an existing FirewallRule object on the Sophos Firewall.

.DESCRIPTION
    Updates a FirewallRule object using the Sophos Firewall XML API. You can supply the
    target rule name directly or via the pipeline.

    SFOS replaces the whole entity on update - any element not sent in the request is cleared
    on the firewall. This is especially dangerous for Position/After/Before: an update that
    forgot to resend them would move the rule and reorder the whole rulebase. This cmdlet
    always reads the current rule first and, unless the caller explicitly passes -Position (in
    which case -After/-Before must match it as required by -Position's value), resends the
    existing Position/After/Before completely unchanged, together with every other field the
    caller did not pass.

    Only rules with PolicyType='Network' can be updated - see the module-level comment at the
    top of this region. Any other PolicyType throws before any request is sent.

.PARAMETER Name
    Name of the target rule.

.PARAMETER Description
    Optional description text. If omitted, the existing description is kept.

.PARAMETER IPFamily
    Internet Protocol version: 'IPv4' or 'IPv6'. If omitted, the existing value is kept.

.PARAMETER Status
    Whether the rule is active: 'Enable' or 'Disable'. If omitted, the existing value is
    kept.

.PARAMETER Position
    Where to move the rule: 'Top', 'Bottom', 'After' or 'Before'. If omitted, the existing
    Position (and After/Before) is kept untouched - this is the default and the safe choice.
    If supplied, changes the evaluation order of the rulebase; 'Top' additionally moves every
    other rule down one position.

.PARAMETER After
    Name of the existing rule to move this one after. Required when -Position is 'After'.
    Ignored (and not resent) when -Position is omitted.

.PARAMETER Before
    Name of the existing rule to move this one before. Required when -Position is 'Before'.
    Ignored (and not resent) when -Position is omitted.

.PARAMETER Section
    Policy section: 'Central_TOP', 'Local' or 'Central_Bottom'. If omitted, the existing value
    is kept.

.PARAMETER NetworkPolicy
    Complete replacement NetworkPolicy subtree, built with New-SfosFirewallRuleNetworkPolicy
    or taken from Get-SfosFirewallRule. This REPLACES the existing subtree wholesale, exactly
    as the API does - it does not merge individual fields on its own. Omit this parameter to
    keep the existing NetworkPolicy unchanged.

    Combine it with the per-field NetworkPolicy parameters below (-ScanVirus, -SourceZone, ...)
    to change only some fields: when -NetworkPolicy is also supplied, it - not the rule's current
    state - becomes the base the per-field parameters are applied on top of. This lets a caller
    start from a hand-built policy and still tweak one field without a second round trip.

.PARAMETER Action
    NetworkPolicy field: traffic handling action. Changes only this field; every other
    NetworkPolicy field is preserved from the rule's current state (or from -NetworkPolicy, if
    also supplied). See -NetworkPolicy. Values and default: see
    New-SfosFirewallRuleNetworkPolicy's -Action.

.PARAMETER LogTraffic
    NetworkPolicy field: whether to log traffic matching this rule. See -Action for how single
    NetworkPolicy fields are changed without touching the rest.

.PARAMETER SkipLocalDestined
    NetworkPolicy field: skip this rule when the firewall itself is the destination. See
    -Action.

.PARAMETER SourceZone
    NetworkPolicy field: source zone names. Replaces the whole SourceZoneList with the values
    given here; every other NetworkPolicy field is preserved. See -Action.

.PARAMETER SourceNetwork
    NetworkPolicy field: source network/host object names. Replaces the whole
    SourceNetworkList. See -Action.

.PARAMETER DestinationZone
    NetworkPolicy field: destination zone names. Replaces the whole DestinationZoneList. See
    -Action.

.PARAMETER Schedule
    NetworkPolicy field: name of the Schedule object this rule is active during. See -Action.

.PARAMETER Service
    NetworkPolicy field: service object names this rule matches. Replaces the whole
    ServiceList. See -Action.

.PARAMETER DestinationNetwork
    NetworkPolicy field: destination network/host object names. Replaces the whole
    DestinationNetworkList. See -Action.

.PARAMETER DSCPMarking
    NetworkPolicy field: QoS packet classification, -1 to 63. See -Action.

.PARAMETER WebFilter
    NetworkPolicy field: name of the web filter policy applied by this rule, or 'None'. See
    -Action.

.PARAMETER WebCategoryBaseQoSPolicy
    NetworkPolicy field: bandwidth limit toggle for web categories. See -Action and
    New-SfosFirewallRuleNetworkPolicy's -WebCategoryBaseQoSPolicy for the doc/live discrepancy.

.PARAMETER BlockQuickQuic
    NetworkPolicy field: block the QUIC protocol. See -Action.

.PARAMETER ScanVirus
    NetworkPolicy field: scan matching traffic for viruses. See -Action.

.PARAMETER ZeroDayProtection
    NetworkPolicy field: enable zero-day threat protection. See -Action.

.PARAMETER ProxyMode
    NetworkPolicy field: use the transparent web proxy. See -Action.

.PARAMETER DecryptHTTPS
    NetworkPolicy field: decrypt HTTPS traffic for inspection. See -Action.

.PARAMETER ApplicationControl
    NetworkPolicy field: name of the application control policy applied by this rule, or
    'None'. See -Action.

.PARAMETER ApplicationBaseQoSPolicy
    NetworkPolicy field: bandwidth limit toggle for application categories. See -Action and
    New-SfosFirewallRuleNetworkPolicy's -ApplicationBaseQoSPolicy for the doc/live discrepancy.

.PARAMETER IntrusionPrevention
    NetworkPolicy field: name of the IPS policy applied by this rule, or 'None'. See -Action.

.PARAMETER NDRActiveThreatIntelligence
    NetworkPolicy field: enable active threat intelligence. See -Action.

.PARAMETER TrafficShappingPolicy
    NetworkPolicy field: name of the traffic shaping policy applied by this rule, or 'None'.
    Spelled exactly as the live wire element - see the module-level comment on
    ConvertTo-SfosFirewallRuleNetworkPolicyXml. See -Action.

.PARAMETER ScanSMTP
    NetworkPolicy field: scan SMTP traffic. See -Action.

.PARAMETER ScanSMTPS
    NetworkPolicy field: scan SMTPS traffic. See -Action.

.PARAMETER ScanIMAP
    NetworkPolicy field: scan IMAP traffic. See -Action.

.PARAMETER ScanIMAPS
    NetworkPolicy field: scan IMAPS traffic. See -Action.

.PARAMETER ScanPOP3
    NetworkPolicy field: scan POP3 traffic. See -Action.

.PARAMETER ScanPOP3S
    NetworkPolicy field: scan POP3S traffic. See -Action.

.PARAMETER ScanFTP
    NetworkPolicy field: scan FTP traffic. See -Action.

.PARAMETER SourceSecurityHeartbeat
    NetworkPolicy field: require a source Security Heartbeat. See -Action.

.PARAMETER MinimumSourceHBPermitted
    NetworkPolicy field: minimum source health status permitted ('No Restriction', 'GREEN' or
    'YELLOW'). See -Action.

.PARAMETER DestSecurityHeartbeat
    NetworkPolicy field: require a destination Security Heartbeat. See -Action.

.PARAMETER MinimumDestinationHBPermitted
    NetworkPolicy field: minimum destination health status permitted ('No Restriction',
    'GREEN' or 'YELLOW'). See -Action.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER Port
    Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the
    stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER Password
    Password for API authentication. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for the API call.

.OUTPUTS
    None. Throws an exception if the update fails.

.EXAMPLE
    # Change only the description; Position, After/Before and NetworkPolicy are preserved
    Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -Description "Updated"

.EXAMPLE
    # Enable a previously disabled rule via pipeline input, position untouched
    Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN" | Set-SfosFirewallRule -Status Enable

.EXAMPLE
    # Turn on virus scanning without touching any other NetworkPolicy field (IntrusionPrevention,
    # ApplicationControl, Schedule, source zones, ... are all preserved from the current rule)
    Set-SfosFirewallRule -Name "Allow-LAN-to-WAN" -ScanVirus Enable

.NOTES
    Minimum supported PowerShell version: 5.1
    This cmdlet changes the rule base of a production firewall. Passing -Position reorders the
    rulebase; verify -Name and -Position/-After/-Before before running this against a
    shared/production firewall.
    This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/SecurityPolicy/operations/Addfirewallrule%26Editfirewallrule.html
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
        # silently reset it - the same trap the project build rules, section 5 documents for -IPFamily.
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
        [switch]$SkipCertificateCheck
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
    Removes a FirewallRule object from the Sophos Firewall.

.DESCRIPTION
    Removes a FirewallRule object using the Sophos Firewall XML API. This cmdlet supports
    ShouldProcess; use -WhatIf to preview the change. Works for any PolicyType - removal only
    needs the rule's Name, so the Network-only restriction on Set-SfosFirewallRule does not
    apply here.

.PARAMETER Name
    Name of the target rule.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER Port
    Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the
    stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER Password
    Password for API authentication. If omitted, the cmdlet attempts to use the stored
    connection context.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for the API call.

.OUTPUTS
    None. Throws an exception if removal fails.

.EXAMPLE
    # Preview removal
    Remove-SfosFirewallRule -Name "Allow-LAN-to-WAN" -WhatIf

.EXAMPLE
    # Pipeline removal
    Get-SfosFirewallRule -NameLike "Allow-LAN-to-WAN" | Remove-SfosFirewallRule

.NOTES
    Minimum supported PowerShell version: 5.1
    This cmdlet changes the rule base of a production firewall and removes a rule outright.
    There is no confirmation beyond ShouldProcess/-WhatIf and no dependency check - verify
    -Name before running this against a shared/production firewall.
    This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/SecurityPolicy/operations/Delete%20firewall%20rule.html
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
        [switch]$SkipCertificateCheck
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
        Retrieves FirewallRuleGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for FirewallRuleGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all firewall rule groups
        Get-SfosFirewallRuleGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosFirewallRuleGroup -NameLike "Internal"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosFirewallRuleGroup -NameLike "Internal" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/FirewallGroup/FirewallGroup.html
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

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
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
        Creates a new firewall rule group on the Sophos Firewall.

        .DESCRIPTION
        Creates a firewall rule group that can contain multiple firewall rule names.
        Use this to logically group related firewall rules for easier management.
        After creation, use Add-SfosFirewallRuleGroupMember to add additional members.

        .PARAMETER Name
        Name of the firewall rule group (1-150 characters, no commas).

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER Members
        Array of firewall rule names to include in the group as SecurityPolicy entries.

        .PARAMETER Policytype
        Optional policy type classification: 'User/network rule', 'Network rule', 'User rule', 'WAF rule' or 'Any'.

        .PARAMETER SourceZones
        Optional array of source zone names allowed for the group.

        .PARAMETER DestinationZones
        Optional array of destination zone names for the group.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create an empty rule group
        New-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -Description "Rules for branch office traffic"

        .EXAMPLE
        # Create group and add members separately
        New-SfosFirewallRuleGroup -Name "Branch-Office-Rules"
        Add-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-VPN"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/FirewallGroup/FirewallGroup.html

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
        [switch]$SkipCertificateCheck
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
        Updates an existing FirewallRuleGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a FirewallRuleGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current group first and keeps whatever
        the caller does not explicitly pass (Description, Members, Policytype, SourceZones,
        DestinationZones). To clear a field, pass it explicitly with an empty value.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER Members
        One or more firewall rule names to set as SecurityPolicy entries. If omitted, the existing members are kept.

        .PARAMETER Policytype
        Optional policy type classification. If omitted, the existing value is kept.

        .PARAMETER SourceZones
        Optional array of source zone names. If omitted, the existing value is kept.

        .PARAMETER DestinationZones
        Optional array of destination zone names. If omitted, the existing value is kept.

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
        # Update the description only, members are preserved
        Set-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -Description "Updated description"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosFirewallRuleGroup -NameLike "Branch-Office-Rules" | Set-SfosFirewallRuleGroup -Policytype "Any"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/FirewallGroup/FirewallGroup.html
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
        [switch]$SkipCertificateCheck
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
        Removes a FirewallRuleGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a FirewallRuleGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Name
        Name of the target object.

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
        # Preview removal
        Remove-SfosFirewallRuleGroup -Name "Branch-Office-Rules" -WhatIf

        .EXAMPLE
        # Pipeline removal
        Get-SfosFirewallRuleGroup -NameLike "Branch-Office-Rules" | Remove-SfosFirewallRuleGroup

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/FirewallGroup/FirewallGroup.html
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
        [switch]$SkipCertificateCheck
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
        Adds members to an existing FirewallRuleGroup object on the Sophos Firewall.

        .DESCRIPTION
        Adds firewall rule names as SecurityPolicy entries to a FirewallRuleGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety. Adding a firewall rule to a group removes it from any group it currently belongs to.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more firewall rule names to add.

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
        None. Throws an exception if the operation fails.

        .EXAMPLE
        # Add members to an existing group
        Add-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-VPN","Allow-Branch-DNS"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/FirewallGroup/FirewallGroup.html
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
        [switch]$SkipCertificateCheck
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
        Removes members from an existing FirewallRuleGroup object on the Sophos Firewall.

        .DESCRIPTION
        Removes firewall rule names from the SecurityPolicy list of a FirewallRuleGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        Known firmware limitation (SFOS 22.0, measured): the member list of a rule group is
        append-only on update. Sending a shorter list, an empty <SecurityPolicyList/> or no
        wrapper at all is answered with status 200, but every member stays in place - only
        their order changes. This cmdlet therefore reads the group back afterwards and throws
        if the members it was asked to remove are still there, rather than reporting a success
        the firewall did not perform.

        A rule does leave its group when the rule itself is deleted, and a group cannot be
        deleted while it still has members.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more firewall rule names to remove. See DESCRIPTION: on this firmware the
        firewall ignores the removal, so this cmdlet reports an error instead of a false
        success.

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
        None. Throws an exception if the operation fails.

        .EXAMPLE
        # Remove members from an existing group
        Remove-SfosFirewallRuleGroupMember -Name "Branch-Office-Rules" -Members "Allow-Branch-DNS"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/FirewallGroup/FirewallGroup.html
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
        [switch]$SkipCertificateCheck
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
        Retrieves NATRule objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for NATRule objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: the <Status> element on a NATRule is a data field (Enable/Disable), not an API
        status - Core distinguishes the two and this cmdlet does not build any status
        evaluation of its own. Sophos GET responses can also be inconsistent regarding actual
        API status elements; this cmdlet returns an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all NAT rules
        Get-SfosNATRule

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosNATRule -NameLike "SNAT"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosNATRule -NameLike "SNAT" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/NATRule/NATRule.html
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
        Creates a new NAT rule on the Sophos Firewall.

        .DESCRIPTION
        Creates a NAT rule (source or destination NAT policy) on the Sophos Firewall.

        .PARAMETER Name
        Name of the NAT rule (1-60 characters, no commas).

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. Default: 'IPv4'.

        .PARAMETER Status
        Whether the rule is enabled: 'Enable' or 'Disable'. Default: 'Enable'.

        .PARAMETER Position
        Where to insert the rule relative to the existing rule list: 'Top', 'Bottom', 'After' or 'Before'. Default: 'Bottom'. 'After' and 'Before' require the -After or -Before parameter to name the reference rule.

        .PARAMETER After
        Name of the existing NAT rule after which this rule is inserted. Required when -Position is 'After'.

        .PARAMETER Before
        Name of the existing NAT rule before which this rule is inserted. Required when -Position is 'Before'.

        .PARAMETER LinkedFirewallrule
        Optional name of the firewall rule this NAT rule is linked to.

        .PARAMETER TranslatedSource
        Translated source: 'Original', 'MASQ', 'IPAddress' or 'IPRange'. Default: 'Original'.

        .PARAMETER TranslatedDestination
        Translated destination: 'Original', 'IPAddress', 'IPRange', 'IPList' or 'FQDN'. Default: 'Original'.

        .PARAMETER TranslatedService
        Translated service: 'Original' or the name of a service object. Default: 'Original'.

        .PARAMETER OverrideInterfaceNATPolicy
        Whether to override the interface-level NAT policy: 'Enable' or 'Disable'. Default: 'Disable'.

        .PARAMETER InboundInterfaces
        Optional array of inbound interface names.

        .PARAMETER OutboundInterfaces
        Optional array of outbound interface names.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a disabled masquerade rule at the bottom of the rule list
        New-SfosNATRule -Name "SNAT-LAN-to-WAN" -TranslatedSource "MASQ" -Status Disable -Position Bottom

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/NATRule/NATRule.html

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
        [switch]$SkipCertificateCheck
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
        Updates an existing NATRule object on the Sophos Firewall.

        .DESCRIPTION
        Updates a NATRule object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current rule first and keeps whatever
        the caller does not explicitly pass, including Position (and After/Before), so a
        one-field change never moves the rule in the evaluation order. To clear a field,
        pass it explicitly with an empty value.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER IPFamily
        IP address family: 'IPv4' or 'IPv6'. If omitted, the existing value is kept.

        .PARAMETER Status
        Whether the rule is enabled: 'Enable' or 'Disable'. If omitted, the existing value is kept.

        .PARAMETER Position
        Where the rule sits relative to the rule list: 'Top', 'Bottom', 'After' or 'Before'. If omitted, the existing position is kept.

        .PARAMETER After
        Name of the existing NAT rule after which this rule is inserted. Required when the effective -Position is 'After'. If omitted, the existing value is kept.

        .PARAMETER Before
        Name of the existing NAT rule before which this rule is inserted. Required when the effective -Position is 'Before'. If omitted, the existing value is kept.

        .PARAMETER LinkedFirewallrule
        Optional name of the firewall rule this NAT rule is linked to. If omitted, the existing value is kept.

        .PARAMETER TranslatedSource
        Translated source: 'Original', 'MASQ', 'IPAddress' or 'IPRange'. If omitted, the existing value is kept.

        .PARAMETER TranslatedDestination
        Translated destination: 'Original', 'IPAddress', 'IPRange', 'IPList' or 'FQDN'. If omitted, the existing value is kept.

        .PARAMETER TranslatedService
        Translated service: 'Original' or the name of a service object. If omitted, the existing value is kept.

        .PARAMETER OverrideInterfaceNATPolicy
        Whether to override the interface-level NAT policy: 'Enable' or 'Disable'. If omitted, the existing value is kept.

        .PARAMETER InboundInterfaces
        Optional array of inbound interface names. If omitted, the existing value is kept.

        .PARAMETER OutboundInterfaces
        Optional array of outbound interface names. If omitted, the existing value is kept.

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
        # Update only the description; position and every other field are preserved
        Set-SfosNATRule -Name "SNAT-LAN-to-WAN" -Description "Updated description"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosNATRule -NameLike "SNAT-LAN-to-WAN" | Set-SfosNATRule -Status Disable

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/NATRule/NATRule.html
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
        [switch]$SkipCertificateCheck
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
        # @() wraps the whole if/else: a one-element array from a branch unrolls to a scalar
        # on assignment (measured on PS 5.1; two real data-loss bugs of this class were fixed 2026-08-12).
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
        Removes a NATRule object from the Sophos Firewall.

        .DESCRIPTION
        Removes a NATRule object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Name
        Name of the target object.

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
        # Preview removal
        Remove-SfosNATRule -Name "SNAT-LAN-to-WAN" -WhatIf

        .EXAMPLE
        # Pipeline removal
        Get-SfosNATRule -NameLike "SNAT-LAN-to-WAN" | Remove-SfosNATRule

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/NATRule/NATRule.html
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
        [switch]$SkipCertificateCheck
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
    Centralizes the shape shared by SourceZones/Zone, SourceNetworks/Network,
    Identity/Members, DestinationZones/Zone, DestinationNetworks/Network and
    Services/Service - all repeatable single-value lists wrapped in one outer
    element [doc, sample XML on the Add/Update operations page]. Every value is
    escaped here. An empty or absent -Value still returns the (empty) wrapper
    element, because SFOS replaces the whole entity on update - see the project build rules
    SS5 - and an absent wrapper is how a field gets cleared, not how it is left
    unchanged.

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
    <Websites> wraps zero or more <Activity> elements, each an object reference with
    <Name> and <Type> (Type is 'Web Category' or 'URL Group') [doc, live]. Every value
    is escaped here.

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
    Centralizes the SSLTLSInspectionRule XML shape so New- and Set-SfosSSLTLSInspectionRule
    send an identical, complete entity body. Takes a fully resolved rule object - same
    property shape Get-SfosSSLTLSInspectionRule returns - and escapes every value.

    SFOS replaces the whole entity on <Set operation="update">: any element this function
    does not emit is cleared on the firewall [doc, the project build rules SS5]. The caller is responsible
    for merging in every field it wants preserved before calling this function; nothing is
    read back here.

    IsDefault is deliberately never emitted: the vendor doc marks it read-only, and the
    firewall's default rule ('Exclusions by website or category') must never be
    reconstructed or altered through this path - New-/Set-SfosSSLTLSInspectionRule guard
    against touching it separately.

.PARAMETER Operation
    'add' or 'update', passed straight to <Set operation="...">.

.PARAMETER Rule
    Fully resolved rule object with Name, Description, Enable, LogConnections, SourceZones,
    SourceNetworks, Identity, DestinationZones, DestinationNetworks, Services, Website,
    DecryptAction and DecryptionProfile properties.

.PARAMETER Position
    'Top' or 'Bottom'. Only meaningful on 'add' - the operations page notes it is "not
    required in UPDATE" [doc] - so Set-SfosSSLTLSInspectionRule never supplies it. Omitted
    entirely (no <Position> element sent) when not given, so the firewall's own default
    (Bottom) [doc] applies.
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
        Retrieves SSLTLSInspectionRule objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for SSLTLSInspectionRule objects. By default the
        cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        The firewall's built-in rule 'Exclusions by website or category' is returned like any
        other object, flagged IsDefault='Yes' [live]. Check IsDefault before scripting bulk
        changes; New-/Set-/Remove-SfosSSLTLSInspectionRule refuse to modify or remove it.

        Every returned rule also carries the shape Set-SfosSSLTLSInspectionRule expects for
        its list parameters (Website is an array of objects with Name/Type), so a rule read
        back from this cmdlet can be fed straight into Set-SfosSSLTLSInspectionRule -Website.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter and re-applied client-side, since SFOS only evaluates the first <key> of the first <Filter> and silently ignores unsupported keys.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject with properties: Name, IsDefault, Description, Enable, LogConnections, SourceZones, SourceNetworks, Identity, DestinationZones, DestinationNetworks, Services, Website (array of objects with Name/Type), DecryptAction, DecryptionProfile. System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all SSL/TLS inspection rules
        Get-SfosSSLTLSInspectionRule

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass-Banking" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        The raw XML also contains a <MoveTo> element (empty <Name/>, <OrderBy>After</OrderBy> observed on the default rule) [live] - a write-only positioning directive the sample Add/Update XML documents, apparently echoed back on Get with no meaning of its own. This cmdlet does not expose it; Set-SfosSSLTLSInspectionRule never repositions a rule.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/TLSRule/TLSRule.html
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
        Creates a new SSLTLSInspectionRule on the Sophos Firewall.

        .DESCRIPTION
        Creates a rule that controls whether matching HTTPS traffic is decrypted, exempted or
        denied by the SSL/TLS inspection engine.

        -Enable has no default and must be supplied explicitly on every call: this field
        controls whether the rule is live on the firewall, so this cmdlet refuses to guess at
        it the way an optional parameter with a fixed default would.

        .PARAMETER Name
        Name of the rule (1-60 characters, no commas, UTF-8 allowed) [doc].

        .PARAMETER Enable
        Whether the rule is active: 'Yes', 'No', 't' or 'f' [doc]. Mandatory - no default is applied by this cmdlet.

        .PARAMETER Description
        Optional rule description (max 255 characters) [doc].

        .PARAMETER LogConnections
        Whether to log matching connections to the SSL log: 'Enable', 'Disable', 't' or 'f' [doc]. If omitted, the firewall applies its own default.

        .PARAMETER Position
        'Top' or 'Bottom' - where to place the new rule in the rule list [doc]. If omitted, the firewall defaults to 'Bottom' [doc]. There is no way to request placement above an existing rule through this parameter; use -Position 'Bottom' (or omit it) to avoid ever inserting a new rule above the existing rule set.

        .PARAMETER DecryptAction
        Action for traffic matching the rule: 'Decrypt', 'Do not decrypt' or 'Deny' [doc]. If omitted, the firewall applies its own default.

        .PARAMETER DecryptionProfile
        Name of the associated decryption profile [doc]. If omitted, the firewall applies its own default (or none, for a 'Do not decrypt'/'Deny' rule).

        .PARAMETER SourceZones
        One or more source zone names [doc]. If omitted, the firewall applies its own default.

        .PARAMETER SourceNetworks
        One or more source network/host/group names [doc]. If omitted, the firewall applies its own default.

        .PARAMETER Identity
        One or more source users/groups the rule applies to [doc]. If omitted, the firewall applies its own default.

        .PARAMETER DestinationZones
        One or more destination zone names [doc]. If omitted, the firewall applies its own default.

        .PARAMETER DestinationNetworks
        One or more destination network/host/group names [doc]. If omitted, the firewall applies its own default.

        .PARAMETER Services
        One or more service names [doc]. If omitted, the firewall applies its own default.

        .PARAMETER Website
        Zero or more website/category references the rule applies to, each an object with Name and Type properties, Type being 'Web Category' or 'URL Group' [doc, live] - e.g. [PSCustomObject]@{ Name = 'Banking'; Type = 'Web Category' }. If omitted, the firewall applies its own default.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a disabled rule that exempts a web category from decryption
        $website = [PSCustomObject]@{ Name = 'Banking'; Type = 'Web Category' }
        New-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -Enable No -DecryptAction "Do not decrypt" -Website $website

        .NOTES
        Minimum supported PowerShell version: 5.1
        IsDefault is not a parameter - it is a read-only field per the vendor doc, never sent by this cmdlet.

        Known firmware limitation (SFOS 22.0, measured): creating an SSL/TLS inspection rule
        does not work on this firmware. Every attempt is answered with status 501. More than
        30 variants were tried, including a byte-for-byte copy of the rule the appliance
        itself returns from a Get, and both the field order of the documented sample and that
        of the live object.

        The blocker is IsDefault. Omit it and the firewall names it in <InvalidParams>; send
        it and it is rejected for every value tried - no, No, NO, false, f, 0, yes, and even
        Yes, which is the value the live rule carries. The documentation marks the field
        read-only, so there is no documented way to satisfy the validator. Adding any other
        field changes nothing, except that DecryptAction suppresses the diagnosis and leaves
        <InvalidParams/> empty.

        This cmdlet is therefore implemented faithfully to the documentation but is
        unconfirmed against a real appliance. Get, Set and Remove on existing rules do work.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/TLSRule/operations/AddSSLTLSinspectionrule%26UpdateSSLTLSinspectionrule.html

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
        [switch]$SkipCertificateCheck
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
    # before any API call (found by the per-function acceptance run 2026-08-12).
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
        Updates an existing SSLTLSInspectionRule on the Sophos Firewall.

        .DESCRIPTION
        Updates a SSLTLSInspectionRule object using the Sophos Firewall XML API. You can
        supply the target rule name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall [doc, the project build rules SS5]. This cmdlet reads the current rule first
        and keeps whatever the caller does not explicitly pass. List parameters
        (SourceZones/SourceNetworks/Identity/DestinationZones/DestinationNetworks/Services/
        Website) are wholesale replacements when supplied, not merges - to add one zone to an
        existing list, pass the full desired list.

        The firewall's built-in rule 'Exclusions by website or category' (IsDefault='Yes')
        is refused by this cmdlet: it is the firewall's only built-in TLS bypass rule, and an
        accidental edit here is not recoverable through this module. Unlike the softer,
        documentation-only IsDefault warning used elsewhere in this codebase (e.g.
        WebFilterException), this is an enforced block, because breaking the sole default rule
        here can change what HTTPS traffic gets decrypted or blocked device-wide.

        .PARAMETER Name
        Name of the target rule.

        .PARAMETER Description
        New description (max 255 characters). If omitted, the current value is kept.

        .PARAMETER Enable
        Whether the rule is active: 'Yes', 'No', 't' or 'f' [doc]. Security-relevant: never defaulted by this cmdlet - only sent when explicitly bound, otherwise the value read from the firewall is resent unchanged.

        .PARAMETER LogConnections
        Whether to log matching connections: 'Enable', 'Disable', 't' or 'f' [doc]. If omitted, the current value is kept.

        .PARAMETER DecryptAction
        Action for matching traffic: 'Decrypt', 'Do not decrypt' or 'Deny' [doc]. Security-relevant: never defaulted by this cmdlet. If omitted, the current value is kept.

        .PARAMETER DecryptionProfile
        Name of the associated decryption profile [doc]. If omitted, the current value is kept.

        .PARAMETER SourceZones
        Full replacement list of source zone names. If omitted, the current list is kept.

        .PARAMETER SourceNetworks
        Full replacement list of source network/host/group names. If omitted, the current list is kept.

        .PARAMETER Identity
        Full replacement list of source users/groups. If omitted, the current list is kept.

        .PARAMETER DestinationZones
        Full replacement list of destination zone names. If omitted, the current list is kept.

        .PARAMETER DestinationNetworks
        Full replacement list of destination network/host/group names. If omitted, the current list is kept.

        .PARAMETER Services
        Full replacement list of service names. If omitted, the current list is kept.

        .PARAMETER Website
        Full replacement list of website/category references, each an object with Name and Type properties, Type being 'Web Category' or 'URL Group' [doc, live]. If omitted, the current list is kept.

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
        # Change only the decryption profile, leaving every other field untouched
        Set-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -DecryptionProfile "Maximum compatibility"

        .EXAMPLE
        # Pipeline update
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass-Banking" | Set-SfosSSLTLSInspectionRule -Enable No

        .NOTES
        Minimum supported PowerShell version: 5.1
        This cmdlet does not reposition rules: it never sends <Position> or <MoveTo>, matching the operations page note that Position is "not required in UPDATE".

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/TLSRule/operations/AddSSLTLSinspectionrule%26UpdateSSLTLSinspectionrule.html

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
        [switch]$SkipCertificateCheck
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
        Removes a SSLTLSInspectionRule from the Sophos Firewall.

        .DESCRIPTION
        Removes a SSLTLSInspectionRule using the Sophos Firewall XML API. This cmdlet
        supports ShouldProcess; use -WhatIf to preview the change.

        Unlike the general Remove-Sfos* pattern in this codebase (see the project build rules "Still open",
        which passes the raw firewall error through for a non-existent object rather than
        reading first), this cmdlet reads the object before deleting it, at the cost of one
        extra round trip per call. The reason is specific to this entity: the firewall's only
        built-in TLS bypass rule ('Exclusions by website or category', IsDefault='Yes') has no
        undo if removed, so the extra read buys a hard stop - a named, unambiguous refusal -
        before that can happen, and also turns a delete of a non-existent rule into a clear
        "was not found" instead of a misleading firewall error code.

        .PARAMETER Name
        Name of the target rule.

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
        # Preview removal
        Remove-SfosSSLTLSInspectionRule -Name "Bypass-Banking" -WhatIf

        .EXAMPLE
        # Pipeline removal
        Get-SfosSSLTLSInspectionRule -NameLike "Bypass-Banking" | Remove-SfosSSLTLSInspectionRule

        .NOTES
        Minimum supported PowerShell version: 5.1
        Refuses to remove any rule with IsDefault='Yes' - see .DESCRIPTION.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/TLSRule/operations/Delete%20SSL%20TLS%20inspection%20rule.html

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
        [switch]$SkipCertificateCheck
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
        Retrieves the SSLTLSInspectionSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the SSLTLSInspectionSettings singleton. There
        is exactly one instance of this element per firewall - it holds the device-wide
        SSL/TLS inspection engine configuration (CA certificates for re-signing, the fallback
        actions for SSL 2.0/3.0, SSL compression and exceeded-connection cases, TLS 1.3
        handling, and the on/off switches for the TLS engine and TLS inspection itself). By
        default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw
        XML node.

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
        # Retrieve the current SSL/TLS inspection settings
        Get-SfosSSLTLSInspectionSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>) and XML escaping for user input.
        This entity has no <Name>; Get returns exactly one record [live].

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/TLSSettings/TLSSettings.html
#>
function Get-SfosSSLTLSInspectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <SSLTLSInspectionSettings>, a
    # singleton holding one configuration. the project build rules, section 3 puts the Sophos spelling above
    # PowerShell habit.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

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
        Updates the SSLTLSInspectionSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the SSLTLSInspectionSettings singleton using the Sophos Firewall XML API.
        This cmdlet reads the current settings first and resends every field, overriding only
        what the caller explicitly passes (read-modify-write - see the fragment/module header
        for why this is required even though the entity is a singleton: an update replaces the
        whole entity, and every field this cmdlet does not send would be reset to whatever the
        firewall treats as its default). This cmdlet supports ShouldProcess; use -WhatIf to
        preview the change.

        .PARAMETER RSACA
        Name of the RSA CA certificate used for re-signing during decryption [doc]. If omitted, the current value is kept.

        .PARAMETER ECCA
        Name of the EC CA certificate used for re-signing during decryption [doc]. If omitted, the current value is kept.

        .PARAMETER SSLv2SSLv3
        Action for SSL 2.0/3.0 connections: 'Allow without decryption', 'Drop' or 'Reject' [doc]. If omitted, the current value is kept.

        .PARAMETER SSLCompression
        Action for connections using SSL compression: 'Allow without decryption', 'Drop' or 'Reject' [doc]. If omitted, the current value is kept.

        .PARAMETER SSLConnectionsExceeded
        Action applied once the maximum number of concurrent SSL connections is exceeded: 'Allow without decryption', 'Drop' or 'Reject' [doc]. If omitted, the current value is kept.

        .PARAMETER TLS13Decryption
        Action for TLS 1.3 connections: 'Decrypt as 1.3' or 'Downgrade to TLS 1.2 and decrypt' [doc]. If omitted, the current value is kept.

        .PARAMETER SSLTLSEngine
        Whether the SSL/TLS inspection engine itself is on: 'Enabled' or 'Disabled' [doc]. If omitted, the current value is kept.

        .PARAMETER SSLTLSInspection
        Whether SSL/TLS traffic is inspected: 'Enabled' or 'Disabled' [doc]. If omitted, the current value is kept.

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
        # Change only the RSA re-signing CA, leaving every other device-wide field untouched
        Set-SfosSSLTLSInspectionSettings -RSACA "MyIssuingCA" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        Every field of this entity acts device-wide, immediately, for every HTTPS connection through the firewall - there is no per-object or per-rule scope to fall back on. SSLTLSEngine='Disabled' or SSLTLSInspection='Disabled' turns SSL/TLS inspection off firewall-wide; a wrong SSLv2SSLv3/SSLCompression/SSLConnectionsExceeded/TLS13Decryption value can drop or reject HTTPS connections that were previously allowed. No parameter carries a default value in this cmdlet on purpose - only what the caller explicitly passes (or what read-modify-write carries forward unchanged from the current state) is ever sent. Verified against the live firewall via its Get path only; the write path was verified by inspecting the generated XML (e.g. with -WhatIf), never executed, because every field here is on this task's do-not-touch list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Firewall/TLSSettings/operations/UpdateSSLTLSinspectionsettings.html

        .LINK
        Get-SfosSSLTLSInspectionSettings
#>
function Set-SfosSSLTLSInspectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <SSLTLSInspectionSettings>, a
    # singleton holding one configuration. the project build rules, section 3 puts the Sophos spelling above
    # PowerShell habit.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
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
        [switch]$SkipCertificateCheck
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

