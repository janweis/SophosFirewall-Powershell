#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }

<#
        .SYNOPSIS
        Manages routing on Sophos Firewall: gateways, health checks, SD-WAN, unicast and multicast routes.

        .DESCRIPTION
        PowerShell module for the CONFIGURE > Routing area of the Sophos XGS / SFOS 22.0
        XML API.

        This module provides functions to create, read, update, and delete:
        - Gateway objects and health check profiles (including the status toggle)
        - SD-WAN profiles and SD-WAN policy routes (including the status toggle)
        - Unicast routes
        - Multicast routes, the multicast forwarding setting and PIM dynamic routing

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect and list the configured gateways with their health state
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosGatewayHost | Format-Table Name, GatewayIP, Interface
        Get-SfosHealthCheckProfileStatus

        .EXAMPLE
        # Create a disabled static route and enable it later
        New-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0" -Interface "Port1" -Status OFF
        Set-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0" -Status ON

        .EXAMPLE
        # Read the SD-WAN routes and their state
        Get-SfosSDWANPolicyRoute | Format-Table Name, IPFamily
        Get-SfosSDWANPolicyRouteStatus

        .NOTES
        Module Name: SophosFirewall.Routing
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+

        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)

        API Compatibility:
        - Sophos SFOS 22.0
        - Sophos XGS Firewall Series

        Total Functions: 32 (31 exported, 1 internal helper)
        - 10 Gateway and health check functions
        - 10 SD-WAN profile and policy route functions
        - 11 Unicast, multicast and PIM functions

        These cmdlets change how a live firewall forwards traffic. A wrong route or a removed
        gateway decides whether packets reach their destination at all, and a change that cuts
        off the management path also cuts off the API used to repair it. Every Set-* therefore
        reads the current object first and writes it back complete.

        Behaviour that differs from the vendor documentation was measured against a live
        appliance and is recorded in the .NOTES of the affected function. The most important
        ones:
        - The documentation folder names are not the wire element names for seven of the ten
          entities (PolicyRoute is SDWANPolicyRoute, MonitorObject is HealthCheckProfile,
          GatewayObject is GatewayHost, and so on). Four read paths exist without being
          documented at all, and the Multicast topic page is entirely empty.
        - UnicastRoute has no working update: operation="update" answers 500 whatever is sent,
          so Set-SfosUnicastRoute removes and recreates the route, with a brief window where
          it is absent. The firewall also accepts duplicate routes for the same destination
          and mask with code 200; New-SfosUnicastRoute refuses that client-side.
        - Removing an SD-WAN profile that a policy route still references answers 200 and
          silently deletes the referencing route as well - see Remove-SfosSDWANProfile.
        - The status toggles answer 200 for names that do not exist without changing anything;
          both Set-*Status cmdlets read back afterwards and throw when nothing happened.
        - Enabled state is represented inconsistently across entities (integer 1/0 on the
          health check profile, text ON/OFF on routes and status entities); values are passed
          through exactly as the firewall delivers them.

        Functions that could not be confirmed against the lab appliance are marked as such in
        their own .NOTES (multicast route writes answer 500 for every documented variant, and
        PIM's write path applies device-wide and was verified structurally only). They are
        implemented faithful to the documentation rather than omitted, but nothing about them
        should be assumed to work.
#>

#requires -Version 5.1
#requires -Modules SophosFirewall.Core

# SophosFirewall.Routing - Group A: Gateways & Health Checks
# Entities: GatewayHost (doc folder GatewayObject), HealthCheckProfile (doc folder
# MonitorObject), HealthCheckProfileStatus (doc folder MonitorObjectStatus).
#
# Measured live against the SFOS lab (22.0, APIVersion 2200.1) - see .NOTES on each
# function for the specific finding. Two cross-cutting findings that apply to every
# GatewayHost function in this fragment:
#
# 1. The enable-flag element is spelled <Healthcheck> (lowercase 'c') on the wire, not
#    <HealthCheck> as the sample XML on the GatewayObject Add/Update page shows. Sending
#    the sample's casing is silently ignored (unknown element) and the create fails with a
#    generic, field-less 501 - the API validates Name/GatewayIP/Interface/IPFamily
#    individually (each produces a precise <InvalidParams><Params>/GatewayHost/Field</...>
#    on a bad value) but does not name Healthcheck/MailNotification/Interval/Timeout in
#    <InvalidParams> even when they are the reason a request is rejected.
# 2. GatewayIP values from 203.0.113.0/24 (TEST-NET-3, RFC 5737) are rejected by SFOS with
#    the same generic, field-less 501 - consistent with the documented exclusion of
#    "RESERVED" address classes from GatewayIP, just not enumerated by name. This directly
#    conflicts with this task's mandated test range. Flagged for the orchestrator; the live
#    round-trip in this file's verification therefore used a private RFC 1918 address
#    instead (an unused address on the test-approved carrier interface's subnet) and removed it
#    immediately after each test. No such object is left behind - see the task report.

#region GatewayHost

<#
.SYNOPSIS
    Retrieves GatewayHost objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for GatewayHost objects (Routing > Gateways). By
    default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML
    nodes.

    The server only evaluates the first <key> of the first <Filter> reliably [doc/measured
    pattern shared by every entity in this module]; -NameLike is sent as that one server-side
    key (exact-match tested live and confirmed working for this entity), and every filter -
    including -NameLike again - is re-applied client-side with AND semantics so -AsXml returns
    the same set as the default output.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side.

.PARAMETER GatewayIPLike
    Filters by GatewayIP, substring match. Client-side only.

.PARAMETER InterfaceLike
    Filters by Interface, substring match. Client-side only.

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
    # List every gateway
    Get-SfosGatewayHost

.EXAMPLE
    # Find a gateway by name
    Get-SfosGatewayHost -NameLike 'ISP1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: an empty firewall answers HTTP 200 with
    '<GatewayHost><Status>No. of records Zero.</Status></GatewayHost>' - this is a normal
    empty result, not an error, and this cmdlet returns @() for it. The lab's de-facto default
    route (an interface-derived DHCP gateway) is managed outside this entity entirely and does
    not appear here even when a working default gateway exists on the firewall - see the task
    report.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/GatewayObject/GatewayObject.html

.LINK
    New-SfosGatewayHost
#>
function Get-SfosGatewayHost {
    [CmdletBinding()]
    param(
        [string]$NameLike,
        [string]$GatewayIPLike,
        [string]$InterfaceLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

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
  <GatewayHost>
    $filterXml
  </GatewayHost>
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
        throw "Error retrieving GatewayHost objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GatewayHost' -Action 'get'

    # Only nodes that carry a <Name> are data objects - a status-only response has none.
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/GatewayHost[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $ruleNodes = @($node.SelectNodes('MonitoringCondition/Rule'))
        $ruleList = foreach ($ruleNode in $ruleNodes) {
            [PSCustomObject]@{
                Protocol  = [string]$ruleNode.Protocol
                Port      = [string]$ruleNode.Port
                IPAddress = [string]$ruleNode.IPAddress
                Condition = [string]$ruleNode.Condition
            }
        }

        [PSCustomObject]@{
            Name                    = [string]$node.Name
            IPFamily                = [string]$node.IPFamily
            GatewayIP               = [string]$node.GatewayIP
            Interface               = [string]$node.Interface
            NetworkZone             = [string]$node.NetworkZone
            Healthcheck             = [string]$node.Healthcheck
            MailNotification        = [string]$node.MailNotification
            Interval                = [string]$node.Interval
            Timeout                 = [string]$node.Timeout
            FailureRetries          = [string]$node.FailureRetries
            MonitoringConditionList = @($ruleList)
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($GatewayIPLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.GatewayIP -like "*$GatewayIPLike*" })
    }
    if ($InterfaceLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Interface -like "*$InterfaceLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a new GatewayHost object on the Sophos Firewall.

.DESCRIPTION
    Creates a GatewayHost (Routing > Gateways) using the Sophos Firewall XML API. Supports
    ShouldProcess; use -WhatIf to preview.

    When -Healthcheck is 'ON', -Interval, -Timeout, -FailureRetries and at least one
    -MonitoringCondition entry are required and sent; when -Healthcheck is 'OFF' (the
    default), none of those elements are sent at all - matching the shape SFOS itself
    produces for a health-check-disabled gateway [measured].

.PARAMETER Name
    Name of the gateway [doc]. Mandatory. Max 50 characters, no commas.

.PARAMETER IPFamily
    'IPv4' or 'IPv6' [doc]. Mandatory.

.PARAMETER GatewayIP
    IP address of the gateway [doc]. Mandatory. SFOS rejects reserved/documentation address
    classes with a generic, field-less 501 - see the region header comment for the measured
    conflict with this task's mandated 203.0.113.0/24 test range.

.PARAMETER Interface
    Outgoing interface for the gateway, for example 'Port1' [doc]. Mandatory.

.PARAMETER NetworkZone
    Zone assigned to the gateway [doc]. Optional; omitted or empty is accepted.

.PARAMETER Healthcheck
    Enables health-check monitoring for this gateway: 'ON' or 'OFF' [doc, but note the wire
    element is spelled with a lowercase 'c' - see the region header comment]. Default: 'OFF'.

.PARAMETER MailNotification
    Sends an email notification on gateway status change: 'ON' or 'OFF' [doc]. Default: 'OFF'.

.PARAMETER Interval
    Health-check probe interval in seconds, 5-65535 [doc]. Required when -Healthcheck is 'ON'.

.PARAMETER Timeout
    Health-check response timeout in seconds, 1-10 [doc]. Required when -Healthcheck is 'ON'.

.PARAMETER FailureRetries
    Number of failed health-check retries before the gateway is marked down, 1-10 [doc]. Wire
    element is <FailureRetries> - the sample XML on the doc page shows a bare <Retries/>
    instead, which is not a field the API validates or accepts [measured: an omitted
    FailureRetries is named directly in <InvalidParams>, a present-but-misnamed <Retries> is
    not]. Required when -Healthcheck is 'ON'.

.PARAMETER MonitoringCondition
    One or more health-check rules, each a PSCustomObject with Protocol ('PING' or 'TCP'),
    IPAddress, and optionally Port and Condition ('AND'/'OR' - applies to the next rule in
    the list) [doc]. Required when -Healthcheck is 'ON'.

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
    # Gateway with health-check disabled (default)
    New-SfosGatewayHost -Name 'ISP1' -IPFamily IPv4 -GatewayIP '203.0.113.1' -Interface 'Port1'

.EXAMPLE
    # Gateway with health-check enabled
    $rule = [PSCustomObject]@{ Protocol = 'PING'; IPAddress = '203.0.113.1'; Port = '*' }
    New-SfosGatewayHost -Name 'ISP1' -IPFamily IPv4 -GatewayIP '203.0.113.1' -Interface 'Port1' `
        -Healthcheck ON -Interval 60 -Timeout 5 -FailureRetries 3 -MonitoringCondition $rule

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: create with -Healthcheck OFF (no Interval/Timeout/FailureRetries/
    MonitoringCondition sent) and create with -Healthcheck ON plus a single PING rule both
    answered code 200 and the object was confirmed present and correctly shaped on a
    subsequent Get. See the region header comment for the two measured pitfalls
    (Healthcheck casing, GatewayIP address-class rejection) that block a naive implementation
    of this cmdlet.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/GatewayObject/operations/AddGatewayObject%26UpdateGatewayObject.html

.LINK
    Get-SfosGatewayHost
#>
function New-SfosGatewayHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [Parameter(Mandatory)]
        [string]$GatewayIP,

        [Parameter(Mandatory)]
        [string]$Interface,

        [string]$NetworkZone = '',

        [ValidateSet('ON', 'OFF')]
        [string]$Healthcheck = 'OFF',

        [ValidateSet('ON', 'OFF')]
        [string]$MailNotification = 'OFF',

        [ValidateRange(5, 65535)]
        [int]$Interval,

        [ValidateRange(1, 10)]
        [int]$Timeout,

        [ValidateRange(1, 10)]
        [int]$FailureRetries,

        [PSCustomObject[]]$MonitoringCondition,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($Healthcheck -eq 'ON') {
        if (-not $PSBoundParameters.ContainsKey('Interval') -or -not $PSBoundParameters.ContainsKey('Timeout') -or -not $PSBoundParameters.ContainsKey('FailureRetries') -or -not $MonitoringCondition) {
            throw "GatewayHost '$Name': -Healthcheck ON requires -Interval, -Timeout, -FailureRetries and at least one -MonitoringCondition entry."
        }
    }

    if (-not $PSCmdlet.ShouldProcess("GatewayHost '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $gatewayIPEsc = ConvertTo-SfosXmlEscaped -Text $GatewayIP
    $interfaceEsc = ConvertTo-SfosXmlEscaped -Text $Interface
    $zoneEsc = ConvertTo-SfosXmlEscaped -Text $NetworkZone

    $healthXml = ''
    if ($Healthcheck -eq 'ON') {
        $ruleXml = ''
        foreach ($rule in $MonitoringCondition) {
            $protocolEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Protocol)
            $ipEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.IPAddress)
            $portEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Port)
            $conditionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Condition)
            $ruleXml += "<Rule><Protocol>$protocolEsc</Protocol><Port>$portEsc</Port><IPAddress>$ipEsc</IPAddress><Condition>$conditionEsc</Condition></Rule>"
        }

        $healthXml = @"
<Interval>$Interval</Interval>
    <Timeout>$Timeout</Timeout>
    <FailureRetries>$FailureRetries</FailureRetries>
    <MonitoringCondition>$ruleXml</MonitoringCondition>
"@
    }

    $inner = @"
<Set operation="add">
  <GatewayHost>
    <Name>$nameEsc</Name>
    <IPFamily>$IPFamily</IPFamily>
    <GatewayIP>$gatewayIPEsc</GatewayIP>
    <Interface>$interfaceEsc</Interface>
    <NetworkZone>$zoneEsc</NetworkZone>
    <Healthcheck>$Healthcheck</Healthcheck>
    <MailNotification>$MailNotification</MailNotification>
    $healthXml
  </GatewayHost>
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
        throw "Error creating GatewayHost object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GatewayHost' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing GatewayHost object on the Sophos Firewall.

.DESCRIPTION
    Updates a GatewayHost using the Sophos Firewall XML API. Reads the current object first
    and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
    use -WhatIf to preview.

    This cmdlet uses a single parameter set, per the project rule that pipeline input and
    parameter sets do not mix: -Healthcheck is the discriminator for whether
    Interval/Timeout/FailureRetries/MonitoringCondition are sent, and it is always resolved
    from either the caller's value or the object's current value - never left to a
    parameter-set default.

.PARAMETER Name
    Name of the target gateway. Mandatory; accepts pipeline input by property name.

.PARAMETER IPFamily
    'IPv4' or 'IPv6'. If omitted, the existing value is kept.

.PARAMETER GatewayIP
    IP address of the gateway. If omitted, the existing value is kept.

.PARAMETER Interface
    Outgoing interface for the gateway. If omitted, the existing value is kept.

.PARAMETER NetworkZone
    Zone assigned to the gateway. If omitted, the existing value is kept.

.PARAMETER Healthcheck
    'ON' or 'OFF'. If omitted, the existing value is kept. Determines whether
    Interval/Timeout/FailureRetries/MonitoringCondition are required and sent - see
    -MonitoringCondition.

.PARAMETER MailNotification
    'ON' or 'OFF'. If omitted, the existing value is kept.

.PARAMETER Interval
    Health-check probe interval in seconds, 5-65535. If omitted, the existing value is kept
    (when the resolved -Healthcheck is 'ON'; ignored when 'OFF').

.PARAMETER Timeout
    Health-check response timeout in seconds, 1-10. If omitted, the existing value is kept
    (when the resolved -Healthcheck is 'ON'; ignored when 'OFF').

.PARAMETER FailureRetries
    Number of failed health-check retries before the gateway is marked down, 1-10. If
    omitted, the existing value is kept (when the resolved -Healthcheck is 'ON'; ignored when
    'OFF').

.PARAMETER MonitoringCondition
    Complete replacement list of health-check rules (PSCustomObject with Protocol, IPAddress,
    optionally Port and Condition). If omitted, the existing list is kept (when the resolved
    -Healthcheck is 'ON'; ignored when 'OFF'). Required when switching -Healthcheck from
    'OFF' to 'ON' in the same call, together with -Interval/-Timeout/-FailureRetries, since
    there is no existing value to fall back to.

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
    # Turn on mail notification, everything else is preserved
    Set-SfosGatewayHost -Name 'ISP1' -MailNotification ON

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: created a test gateway with -Healthcheck OFF, updated -MailNotification
    from OFF to ON only, re-read it and confirmed every other field (IPFamily, GatewayIP,
    Interface) was unchanged, then removed it. See the task report for the full round trip.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/GatewayObject/operations/AddGatewayObject%26UpdateGatewayObject.html

.LINK
    Get-SfosGatewayHost
#>
function Set-SfosGatewayHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string]$GatewayIP,

        [string]$Interface,

        [string]$NetworkZone,

        [ValidateSet('ON', 'OFF')]
        [string]$Healthcheck,

        [ValidateSet('ON', 'OFF')]
        [string]$MailNotification,

        [ValidateRange(5, 65535)]
        [int]$Interval,

        [ValidateRange(1, 10)]
        [int]$Timeout,

        [ValidateRange(1, 10)]
        [int]$FailureRetries,

        [PSCustomObject[]]$MonitoringCondition,

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
        $bp = $PSBoundParameters

        $existing = @(Get-SfosGatewayHost -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The GatewayHost object '$Name' was not found."
        }
        $current = $existing[0]

        $targetIPFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { $current.IPFamily }
        $targetGatewayIP = if ($bp.ContainsKey('GatewayIP')) { $GatewayIP } else { $current.GatewayIP }
        $targetInterface = if ($bp.ContainsKey('Interface')) { $Interface } else { $current.Interface }
        $targetZone = if ($bp.ContainsKey('NetworkZone')) { $NetworkZone } else { $current.NetworkZone }
        $targetHealthcheck = if ($bp.ContainsKey('Healthcheck')) { $Healthcheck } else { $current.Healthcheck }
        $targetMailNotification = if ($bp.ContainsKey('MailNotification')) { $MailNotification } else { $current.MailNotification }

        if ($targetHealthcheck -eq 'ON') {
            $targetInterval = if ($bp.ContainsKey('Interval')) { $Interval } else { $current.Interval }
            $targetTimeout = if ($bp.ContainsKey('Timeout')) { $Timeout } else { $current.Timeout }
            $targetRetries = if ($bp.ContainsKey('FailureRetries')) { $FailureRetries } else { $current.FailureRetries }
            $targetRules = if ($bp.ContainsKey('MonitoringCondition')) { $MonitoringCondition } else { $current.MonitoringConditionList }

            if (-not $targetInterval -or -not $targetTimeout -or -not $targetRetries -or -not $targetRules -or @($targetRules).Count -eq 0) {
                throw "GatewayHost '$Name': -Healthcheck ON requires Interval, Timeout, FailureRetries and at least one MonitoringCondition entry, either from the current object or from the call."
            }
        }

        if (-not $PSCmdlet.ShouldProcess("GatewayHost '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $gatewayIPEsc = ConvertTo-SfosXmlEscaped -Text $targetGatewayIP
        $interfaceEsc = ConvertTo-SfosXmlEscaped -Text $targetInterface
        $zoneEsc = ConvertTo-SfosXmlEscaped -Text $targetZone

        $healthXml = ''
        if ($targetHealthcheck -eq 'ON') {
            $ruleXml = ''
            foreach ($rule in $targetRules) {
                $protocolEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Protocol)
                $ipEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.IPAddress)
                $portEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Port)
                $conditionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Condition)
                $ruleXml += "<Rule><Protocol>$protocolEsc</Protocol><Port>$portEsc</Port><IPAddress>$ipEsc</IPAddress><Condition>$conditionEsc</Condition></Rule>"
            }

            $healthXml = @"
<Interval>$targetInterval</Interval>
    <Timeout>$targetTimeout</Timeout>
    <FailureRetries>$targetRetries</FailureRetries>
    <MonitoringCondition>$ruleXml</MonitoringCondition>
"@
        }

        $inner = @"
<Set operation="update">
  <GatewayHost>
    <Name>$nameEsc</Name>
    <IPFamily>$targetIPFamily</IPFamily>
    <GatewayIP>$gatewayIPEsc</GatewayIP>
    <Interface>$interfaceEsc</Interface>
    <NetworkZone>$zoneEsc</NetworkZone>
    <Healthcheck>$targetHealthcheck</Healthcheck>
    <MailNotification>$targetMailNotification</MailNotification>
    $healthXml
  </GatewayHost>
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
            throw "Error updating GatewayHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GatewayHost' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a GatewayHost object from the Sophos Firewall.

.DESCRIPTION
    Removes a GatewayHost using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist, rather than passing through the
    firewall's own answer for that case [measured: Remove on a nonexistent GatewayHost
    answers code 504 "Deleting entity referred by another entity" - actively misleading, the
    object never existed and nothing referred to it]. Supports ShouldProcess; use -WhatIf to
    preview.

.PARAMETER Name
    Name of the gateway to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosGatewayHost -Name 'ISP1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removed a test gateway created for this purpose, confirmed gone with a
    follow-up Get, then confirmed the "not found" error path against a name that never
    existed. See the task report.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/GatewayObject/operations/Delete%20Gateway%20Object.html

.LINK
    Get-SfosGatewayHost
#>
function Remove-SfosGatewayHost {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

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
        $existing = @(Get-SfosGatewayHost -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The GatewayHost object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("GatewayHost '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <GatewayHost>
    <Name>$nameEsc</Name>
  </GatewayHost>
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
            throw "Error removing GatewayHost object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GatewayHost' -Action 'remove' -Target $Name
    }
}

#endregion

#region HealthCheckProfile

<#
.SYNOPSIS
    Retrieves HealthCheckProfile objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for HealthCheckProfile objects (Routing > Health
    Check Profiles). By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to
    return the raw XML nodes.

    -NameLike is sent as the single server-side filter key and re-applied client-side
    together with every other filter, AND semantics, per the project's server-side filtering
    rule.

.PARAMETER NameLike
    Filters by Name, substring match.

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
    Get-SfosHealthCheckProfile

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: the Status field is an integer ('1'), a different representation of
    "enabled" than the ON/OFF text used by HealthCheckProfileStatus.Status for the same
    concept - returned exactly as the firewall sends it, not normalized. The 'conditionid'
    field inside each ProbeTarget is present live but documented nowhere; it is returned
    as-is and is not accepted back by New-/Set-SfosHealthCheckProfile.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/MonitorObject/MonitorObject.html

.LINK
    New-SfosHealthCheckProfile
#>
function Get-SfosHealthCheckProfile {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

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
  <HealthCheckProfile>
    $filterXml
  </HealthCheckProfile>
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
        throw "Error retrieving HealthCheckProfile objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HealthCheckProfile' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/HealthCheckProfile[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $targetNodes = @($node.SelectNodes('ProbeTargets/ProbeTarget'))
        $targetList = foreach ($targetNode in $targetNodes) {
            [PSCustomObject]@{
                conditionid  = [string]$targetNode.conditionid
                monitorip    = [string]$targetNode.monitorip
                monitormethod = [string]$targetNode.monitormethod
                operator     = [string]$targetNode.operator
                port         = [string]$targetNode.port
            }
        }

        [PSCustomObject]@{
            Name                  = [string]$node.Name
            IPFamily              = [string]$node.IPFamily
            ProbeInterval         = [string]$node.ProbeInterval
            ResponseTimeout       = [string]$node.ResponseTimeout
            ProbesResponseFailure = [string]$node.ProbesResponseFailure
            ProbeResponseSuccess  = [string]$node.ProbeResponseSuccess
            Status                = [string]$node.Status
            ProbeTargets          = @($targetList)
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
    Creates a new HealthCheckProfile object on the Sophos Firewall.

.DESCRIPTION
    Creates a HealthCheckProfile (Routing > Health Check Profiles) using the Sophos Firewall
    XML API. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the health check profile [doc]. Mandatory. Max 125 characters, no commas.

.PARAMETER IPFamily
    'IPv4' or 'IPv6' [doc]. Default: 'IPv4'.

.PARAMETER ProbeInterval
    Interval between health check probes in seconds, 1-65535 [doc]. If omitted, the firewall
    applies its own default (60, per the doc).

.PARAMETER ResponseTimeout
    Time in which the target must respond, 1-10 [doc]. If omitted, the firewall applies its
    own default (2, per the doc).

.PARAMETER ProbesResponseFailure
    Consecutive failed probes before the object is deactivated, 1-10 [doc]. If omitted, the
    firewall applies its own default (1, per the doc).

.PARAMETER ProbeResponseSuccess
    Consecutive successful probes before the object is activated, 1-10 [doc]. If omitted, the
    firewall applies its own default (3, per the doc).

.PARAMETER ProbeTarget
    One or more probe targets, each a PSCustomObject with monitormethod ('PING' or 'TCP'),
    and optionally monitorip, port and operator ('&' or '|', default '|') [doc]. Mandatory -
    a profile with no targets has nothing to probe.

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
    $t = [PSCustomObject]@{ monitormethod = 'PING'; monitorip = '203.0.113.10'; port = '0'; operator = '|' }
    New-SfosHealthCheckProfile -Name 'WAN-Probe' -IPFamily IPv4 -ProbeTarget $t

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: 'Set operation="add"' for this entity answers code 200 and does create the
    object, but Get-SfosHealthCheckProfile - this entity's own listing - never shows a
    standalone profile that is not attached to a gateway or SD-WAN profile; only the one
    production profile that is attached (to the lab's SD-WAN profile) appears there. The
    created object was confirmed to genuinely exist by two independent, non-Get signals:
    Get-SfosHealthCheckProfileStatus lists a matching record under the profile's own raw
    Name (see that cmdlet's .NOTES), and Remove-SfosHealthCheckProfile on the same name
    removed that record (confirmed by it disappearing from
    Get-SfosHealthCheckProfileStatus). Whether such a standalone-and-invisible profile is
    actually usable when later referenced by a GatewayHost or SD-WAN profile was not tested
    (out of scope for this group). Because Get-SfosHealthCheckProfile cannot see these
    objects, Set-SfosHealthCheckProfile's read-modify-write cannot operate on them either -
    see that cmdlet's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/MonitorObject/operations/Addhealthcheckprofile%26Updatethehealthcheckprofile.html

.LINK
    Get-SfosHealthCheckProfile
#>
function New-SfosHealthCheckProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 125)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [ValidateRange(1, 65535)]
        [int]$ProbeInterval,

        [ValidateRange(1, 10)]
        [int]$ResponseTimeout,

        [ValidateRange(1, 10)]
        [int]$ProbesResponseFailure,

        [ValidateRange(1, 10)]
        [int]$ProbeResponseSuccess,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$ProbeTarget,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("HealthCheckProfile '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $bp = $PSBoundParameters
    $intervalXml = if ($bp.ContainsKey('ProbeInterval')) { "<ProbeInterval>$ProbeInterval</ProbeInterval>" } else { '' }
    $timeoutXml = if ($bp.ContainsKey('ResponseTimeout')) { "<ResponseTimeout>$ResponseTimeout</ResponseTimeout>" } else { '' }
    $failureXml = if ($bp.ContainsKey('ProbesResponseFailure')) { "<ProbesResponseFailure>$ProbesResponseFailure</ProbesResponseFailure>" } else { '' }
    $successXml = if ($bp.ContainsKey('ProbeResponseSuccess')) { "<ProbeResponseSuccess>$ProbeResponseSuccess</ProbeResponseSuccess>" } else { '' }

    $targetsXml = ''
    foreach ($target in $ProbeTarget) {
        $methodEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.monitormethod)
        $ipEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.monitorip)
        $portEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.port)
        $operatorEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.operator)
        $targetsXml += "<ProbeTarget><monitormethod>$methodEsc</monitormethod><monitorip>$ipEsc</monitorip><port>$portEsc</port><operator>$operatorEsc</operator></ProbeTarget>"
    }

    $inner = @"
<Set operation="add">
  <HealthCheckProfile>
    <Name>$nameEsc</Name>
    <IPFamily>$IPFamily</IPFamily>
    $intervalXml
    $timeoutXml
    $failureXml
    $successXml
    <ProbeTargets>$targetsXml</ProbeTargets>
  </HealthCheckProfile>
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
        throw "Error creating HealthCheckProfile object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HealthCheckProfile' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing HealthCheckProfile object on the Sophos Firewall.

.DESCRIPTION
    Updates a HealthCheckProfile using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER Name
    Name of the target profile. Mandatory; accepts pipeline input by property name.

.PARAMETER IPFamily
    'IPv4' or 'IPv6'. If omitted, the existing value is kept.

.PARAMETER ProbeInterval
    Interval between health check probes in seconds, 1-65535. If omitted, the existing value
    is kept.

.PARAMETER ResponseTimeout
    Time in which the target must respond, 1-10. If omitted, the existing value is kept.

.PARAMETER ProbesResponseFailure
    Consecutive failed probes before the object is deactivated, 1-10. If omitted, the
    existing value is kept.

.PARAMETER ProbeResponseSuccess
    Consecutive successful probes before the object is activated, 1-10. If omitted, the
    existing value is kept.

.PARAMETER ProbeTarget
    Complete replacement list of probe targets (PSCustomObject with monitormethod, and
    optionally monitorip, port, operator). If omitted, the existing list is kept - the
    'conditionid' field the firewall returns on Get is dropped on resend, since the Add/Update
    sample never accepts it as input.

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
    Set-SfosHealthCheckProfile -Name 'WAN-Probe' -ProbeInterval 30

.NOTES
    Minimum supported PowerShell version: 5.1
    Not verified against the live firewall as a write. This cmdlet reads the current object
    through Get-SfosHealthCheckProfile before writing, and that Get does not show a
    standalone profile not attached to a gateway or SD-WAN profile - see
    New-SfosHealthCheckProfile's .NOTES - so a freshly created test profile cannot be updated
    through this cmdlet either; it throws "was not found" for it. The only profile
    Get-SfosHealthCheckProfile does show is production (attached to the live SD-WAN profile),
    and was not used for a write test. Implemented per the documented Add/Update contract and
    the read-modify-write rule shared by every Set-* in this project; verifying it needs
    either a firmware where standalone profiles are listed, or a profile actually attached to
    a test gateway/SD-WAN profile, neither available within this task's safety scope.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/MonitorObject/operations/Addhealthcheckprofile%26Updatethehealthcheckprofile.html

.LINK
    Get-SfosHealthCheckProfile
#>
function Set-SfosHealthCheckProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [ValidateRange(1, 65535)]
        [int]$ProbeInterval,

        [ValidateRange(1, 10)]
        [int]$ResponseTimeout,

        [ValidateRange(1, 10)]
        [int]$ProbesResponseFailure,

        [ValidateRange(1, 10)]
        [int]$ProbeResponseSuccess,

        [PSCustomObject[]]$ProbeTarget,

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
        $bp = $PSBoundParameters

        $existing = @(Get-SfosHealthCheckProfile -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The HealthCheckProfile object '$Name' was not found."
        }
        $current = $existing[0]

        $targetIPFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { $current.IPFamily }
        $targetInterval = if ($bp.ContainsKey('ProbeInterval')) { $ProbeInterval } else { $current.ProbeInterval }
        $targetTimeout = if ($bp.ContainsKey('ResponseTimeout')) { $ResponseTimeout } else { $current.ResponseTimeout }
        $targetFailure = if ($bp.ContainsKey('ProbesResponseFailure')) { $ProbesResponseFailure } else { $current.ProbesResponseFailure }
        $targetSuccess = if ($bp.ContainsKey('ProbeResponseSuccess')) { $ProbeResponseSuccess } else { $current.ProbeResponseSuccess }
        $targetTargets = if ($bp.ContainsKey('ProbeTarget')) { $ProbeTarget } else { $current.ProbeTargets }

        if (-not $PSCmdlet.ShouldProcess("HealthCheckProfile '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $targetsXml = ''
        foreach ($target in @($targetTargets)) {
            $methodEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.monitormethod)
            $ipEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.monitorip)
            $portEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.port)
            $operatorEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.operator)
            $targetsXml += "<ProbeTarget><monitormethod>$methodEsc</monitormethod><monitorip>$ipEsc</monitorip><port>$portEsc</port><operator>$operatorEsc</operator></ProbeTarget>"
        }

        $inner = @"
<Set operation="update">
  <HealthCheckProfile>
    <Name>$nameEsc</Name>
    <IPFamily>$targetIPFamily</IPFamily>
    <ProbeInterval>$targetInterval</ProbeInterval>
    <ResponseTimeout>$targetTimeout</ResponseTimeout>
    <ProbesResponseFailure>$targetFailure</ProbesResponseFailure>
    <ProbeResponseSuccess>$targetSuccess</ProbeResponseSuccess>
    <ProbeTargets>$targetsXml</ProbeTargets>
  </HealthCheckProfile>
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
            throw "Error updating HealthCheckProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HealthCheckProfile' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a HealthCheckProfile object from the Sophos Firewall.

.DESCRIPTION
    Removes a HealthCheckProfile using the Sophos Firewall XML API.

    Unlike every other Remove-* in this project, this cmdlet does not read the object first
    to produce a clean "not found" error: Get-SfosHealthCheckProfile does not list a
    standalone profile that is not attached to a gateway or SD-WAN profile [measured - see
    New-SfosHealthCheckProfile's .NOTES], so a pre-check against it would reject removing an
    object that genuinely exists. Instead this cmdlet calls Remove directly and relies on
    Assert-SfosApiReturnSuccess to surface a real failure; a name that was never created
    answers a status with an empty code attribute and the message "Operation could not be
    performed on Entity.", which Assert-SfosApiReturnSuccess correctly treats as a failure
    (an empty code is not "no code at all", and the message is not the "No. of records Zero."
    wording that means empty) [measured]. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the profile to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosHealthCheckProfile -Name 'WAN-Probe'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live end-to-end: created 'WAN-Probe' with New-SfosHealthCheckProfile,
    confirmed it existed via Get-SfosHealthCheckProfileStatus (see that cmdlet's .NOTES),
    removed it with this cmdlet (code 200), and confirmed it was gone from
    Get-SfosHealthCheckProfileStatus afterwards - no test object left behind. Also
    verified the error path: Remove on a name that was never created answers a status with
    an empty code attribute and "Operation could not be performed on Entity.", which this
    cmdlet surfaces as a thrown error rather than silent success - see the .DESCRIPTION.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/MonitorObject/operations/Delete%20health%20check%20profile.html

.LINK
    Get-SfosHealthCheckProfile
#>
function Remove-SfosHealthCheckProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

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
        # No pre-check via Get-SfosHealthCheckProfile here - see the .DESCRIPTION for why
        # that Get cannot be trusted to confirm existence for this entity. The Remove call
        # itself, checked by Assert-SfosApiReturnSuccess below, is the only reliable signal.
        if (-not $PSCmdlet.ShouldProcess("HealthCheckProfile '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <HealthCheckProfile>
    <Name>$nameEsc</Name>
  </HealthCheckProfile>
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
            throw "Error removing HealthCheckProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HealthCheckProfile' -Action 'remove' -Target $Name
    }
}

#endregion

#region HealthCheckProfileStatus

<#
.SYNOPSIS
    Retrieves HealthCheckProfileStatus records from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for HealthCheckProfileStatus records - the on/off
    state of the health check attached to a gateway or SD-WAN profile, or standing alone for
    a profile that is not yet attached to either. This Get is undocumented [measured,
    consistent with the same finding for HealthCheckProfileStatus's sibling status entities
    and for FirewallAuthentication elsewhere in this project: SFOS exposes a working Get for
    entities whose docs only describe a write operation]. By default the cmdlet returns
    PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

    This entity does not get a server-side filter [measured: unlike GatewayHost and
    HealthCheckProfile, sending '<Filter><key name="Name" criteria="like">...' for
    HealthCheckProfileStatus answers '<Status>Transaction fail</Status>' - no code, and not
    the "No. of records Zero." wording that means an empty result - so it would either look
    like every record failed or, if that message were misread as empty, hide real records.
    Same defect class already known for ContentConditionList in this project]. Every filter
    is therefore applied client-side only, against a full, unfiltered Get.

.PARAMETER NameLike
    Filters by Name, substring match. Client-side only - see the .DESCRIPTION.

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
    Get-SfosHealthCheckProfileStatus

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: records tied to a gateway or SD-WAN profile are named
    'HealthCheckObject_SDWAN_<SDWANProfileName>' / 'HealthCheckObject_GW_<GatewayHostName>'.
    A standalone HealthCheckProfile - created but not attached to either - gets a status
    record too, under its own raw Name with no prefix; this was the only way this project
    could confirm New-SfosHealthCheckProfile actually creates something on this firmware,
    since Get-SfosHealthCheckProfile itself never lists a standalone profile - see
    New-SfosHealthCheckProfile's .NOTES. Status is returned exactly as the firewall sends it
    (text 'ON'/'OFF'), not normalized - it is a different representation of "enabled" than
    HealthCheckProfile.Status (integer).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/MonitorObjectStatus/MonitorObjectStatus.html

.LINK
    Set-SfosHealthCheckProfileStatus
#>
function Get-SfosHealthCheckProfileStatus {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # No server-side filter for this entity - see the .DESCRIPTION for the measured
    # "Transaction fail" behaviour. Always a full, unfiltered Get; -NameLike is applied
    # client-side below.
    $inner = '<Get><HealthCheckProfileStatus></HealthCheckProfileStatus></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving HealthCheckProfileStatus records: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HealthCheckProfileStatus' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/HealthCheckProfileStatus[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name   = [string]$node.Name
            Status = [string]$node.Status
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
    Turns a HealthCheckProfileStatus record on or off.

.DESCRIPTION
    Toggles the on/off state of a health check attached to a gateway or SD-WAN profile,
    using the single dedicated operation SFOS documents for this entity - there is no
    New/Remove, only this toggle. This is a two-field entity (Name, Status) with nothing
    else to preserve, so unlike every other Set-* in this project it does not read the
    current object first - there is no other field a read-modify-write could lose. Supports
    ShouldProcess; use -WhatIf to preview.

    WARNING: the Name of a HealthCheckProfileStatus record identifies the gateway or SD-WAN
    profile it monitors (see Get-SfosHealthCheckProfileStatus's .NOTES). Disabling the status
    record for a production gateway or SD-WAN profile silently stops health monitoring for
    that live route - the route itself is unaffected, only its failover detection is. Verify
    -Name against Get-SfosHealthCheckProfileStatus before calling this on anything other than
    a test object.

.PARAMETER Name
    Name of the health check status record to change. Mandatory; accepts pipeline input by
    property name.

.PARAMETER Status
    'ON' or 'OFF' [sample XML - the parameter table on the same doc page instead calls this
    field mandatory INTEGER, which contradicts the sample; ON/OFF is what this cmdlet sends,
    matching what Get-SfosHealthCheckProfileStatus reads back live]. Mandatory.

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
    Set-SfosHealthCheckProfileStatus -Name 'HealthCheckObject_GW_ISP1' -Status OFF

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live end-to-end, without touching either production record: created
    'WAN-Probe' with New-SfosHealthCheckProfile, which registers its own
    HealthCheckProfileStatus record under that raw Name (see Get-SfosHealthCheckProfileStatus
    .NOTES); toggled it OFF with this cmdlet, confirmed via Get; toggled it back ON and
    confirmed again; then removed the whole test profile with Remove-SfosHealthCheckProfile.
    Neither 'HealthCheckObject_SDWAN_sdwan_MainOffice' nor the tabu
    'HealthCheckObject_GW_DHCP_Port2_GW' was ever targeted. The error path (a nonexistent
    Name) was also verified: it answers code 500 "Operation could not be performed on
    Entity"; an invalid -Status value sent around this cmdlet's client-side ValidateSet was
    separately verified with a raw request and rejected with code 501 and
    '/HealthCheckProfileStatus/Status' named in InvalidParams.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/MonitorObjectStatus/operations/Changehealthcheckobjectstatus.html

.LINK
    Get-SfosHealthCheckProfileStatus
#>
function Set-SfosHealthCheckProfileStatus {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$Status,

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
        if (-not $PSCmdlet.ShouldProcess("HealthCheckProfileStatus '$Name' on $($params.Firewall)", "Set Status=$Status")) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Set operation="update">
  <HealthCheckProfileStatus>
    <Name>$nameEsc</Name>
    <Status>$Status</Status>
  </HealthCheckProfileStatus>
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
            throw "Error updating HealthCheckProfileStatus record '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HealthCheckProfileStatus' -Action 'update' -Target $Name
    }
}

#endregion

#requires -Version 5.1
#requires -Modules SophosFirewall.Core
<#
    SophosFirewall.Routing - Group B: SD-WAN Routing
    Entities: SDWANProfile (Get/New/Set/Remove), SDWANPolicyRoute (Get/New/Set/Remove),
    SDWANPolicyRouteStatus (Get/Set - toggle only, no New/Remove documented or accepted).

    Doc folder names differ from the wire element in every case here (folder SDWANProfile
    matches, folders PolicyRoute and PolicyRouteStatus do not) - confirmed live for all three,
    see the entity map. Root elements used below are the measured/sample wire names:
    <SDWANProfile>, <SDWANPolicyRoute>, <SDWANPolicyRouteStatus>.
#>

#region SDWANPolicyRoute-internal helpers (not exported)

<#
.SYNOPSIS
    Normalises a DSCPMarking value for the wire. Internal helper, not exported.

.DESCRIPTION
    Measured live against SDWANPolicyRoute: every DSCPMarking value round-trips as the bare
    number Get returns it as (e.g. '1', '9', '8'), and named codepoints round-trip fine too
    once written with their full text ('8-Class 1(CS1)') - Get then echoes back whatever was
    last written verbatim. The single exception is the value '0': sending the bare string '0'
    back - exactly what a fresh object or a prior write of '0-Best Effort' reads back as - is
    rejected with 'code="501" Configuration parameters validation failed', naming
    /SDWANPolicyRoute/DSCPMarking. Only '0-Best Effort' is accepted for that codepoint. This
    normalises just that one value; every other value (explicit or read back from an existing
    object during Set's read-modify-write) passes through unchanged.
#>
function ConvertTo-SfosDSCPMarkingWireValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Value
    )

    if ($Value -eq '0') {
        return '0-Best Effort'
    }

    return $Value
}

#endregion

#region SDWANProfile

<#
        .SYNOPSIS
        Retrieves SD-WAN profiles from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for SDWANProfile objects. Server-side filtering
        only evaluates a single 'Name' key reliably (measured); -NameLike is sent as that one
        key and reapplied client-side afterwards, so -AsXml returns the same set as the
        default output. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml
        to return the raw XML nodes.

        .PARAMETER NameLike
        Filters by profile name, substring match (SFOS 'like' semantics, not a wildcard).

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
        # Retrieve every SD-WAN profile
        Get-SfosSDWANProfile

        .EXAMPLE
        # Retrieve a single profile by name
        Get-SfosSDWANProfile -NameLike "MainOffice"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: SLAStrategy came back as 'BestQualityv' on every object observed on this
        firmware, including a brand-new profile that never had SLAStrategy set explicitly - the
        documented values are 'BestQuality' and 'CustomSLA'. This is returned verbatim, not
        normalised, because Set-SfosSDWANProfile's read-modify-write must be able to write the
        exact same string back (see Set-SfosSDWANProfile's .NOTES).
        GatewayPreferences, EnableSLA, IsLatency, IsJitter and IsPacketloss are returned exactly
        as delivered (e.g. 'ON'/'OFF') - nothing is normalised.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/SDWANProfile/SDWANProfile.html
#>
function Get-SfosSDWANProfile {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 60)]
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
  <SDWANProfile>
    $xmlFilterAdvanced
  </SDWANProfile>
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
        throw "Failed to retrieve SDWANProfile objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANProfile' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SDWANProfile[Name]' | ForEach-Object -Process { $_.Node }

    # Client-side re-application, same substring semantics as the server.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $result = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $gatewayPreferences = @()
        if ($node.GatewayPreferences -and $node.GatewayPreferences.Gateway) {
            foreach ($gw in @($node.GatewayPreferences.Gateway)) {
                $gatewayPreferences += [PSCustomObject]@{
                    GatewayName    = [string]$gw.gatewayname
                    OrderId        = [string]$gw.orderid
                    GatewayWeights = [string]$gw.gatewayweights
                }
            }
        }

        $result += [PSCustomObject]@{
            Name                   = [string]$node.Name
            Description            = [string]$node.Description
            IPFamily               = [string]$node.IPFamily
            GatewayPreferences     = $gatewayPreferences
            EnableSLA              = [string]$node.EnableSLA
            RoutingStrategy        = [string]$node.RoutingStrategy
            LBMethod                = [string]$node.LBMethod
            SLAStrategy            = [string]$node.SLAStrategy
            IsLatency              = [string]$node.IsLatency
            IsJitter               = [string]$node.IsJitter
            IsPacketloss           = [string]$node.IsPacketloss
            LatencyValue           = [string]$node.LatencyValue
            JitterValue            = [string]$node.JitterValue
            PacketlossValue        = [string]$node.PacketlossValue
            ProbeCount             = [string]$node.ProbeCount
            HealthCheckProfileName = [string]$node.HealthCheckProfileName
        }
    }

    return $result
}

<#
        .SYNOPSIS
        Creates a new SD-WAN profile on the Sophos Firewall.

        .DESCRIPTION
        Creates an SDWANProfile object using the Sophos Firewall XML API. Supports ShouldProcess;
        use -WhatIf to preview the request.

        .PARAMETER Name
        Name of the SD-WAN profile (1-60 characters, no commas).

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER IPFamily
        IP address family. Only 'IPv4' is documented as an allowed value for this entity.

        .PARAMETER GatewayName
        One or more gateway object names (GatewayHost) to add to the profile's gateway
        preference list, in priority order. At least one is required.

        .PARAMETER GatewayWeights
        Optional load-balancing weight per gateway, matching -GatewayName by position. Supply
        either none or exactly one value per -GatewayName entry.

        .PARAMETER EnableSLA
        Turns SLA-based gateway selection on or off.

        .PARAMETER SLAStrategy
        Quality-matching approach. Documented values are 'BestQuality' and 'CustomSLA'; see
        Get-SfosSDWANProfile's .NOTES for what this firmware actually returns.

        .PARAMETER IsLatency
        Enables latency as an SLA criterion.

        .PARAMETER IsJitter
        Enables jitter as an SLA criterion.

        .PARAMETER IsPacketloss
        Enables packet loss as an SLA criterion.

        .PARAMETER LatencyValue
        Maximum latency threshold in ms (1-60000).

        .PARAMETER JitterValue
        Maximum jitter threshold in ms (1-60000).

        .PARAMETER PacketlossValue
        Maximum packet loss threshold in percent (0-100).

        .PARAMETER ProbeCount
        Active link probe count (5-100).

        .PARAMETER RoutingStrategy
        Gateway traffic routing method.

        .PARAMETER LBMethod
        Load balancing algorithm, used when -RoutingStrategy is 'Loadbalancing'.

        .PARAMETER HealthCheckProfileName
        Name of an existing HealthCheckProfile object to associate with this profile.

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
        # Create a minimal profile with a single gateway, SLA off
        New-SfosSDWANProfile -Name "Branch-Profile" -GatewayName "Branch-Gateway" -EnableSLA OFF -HealthCheckProfileName "HealthCheckObject_Branch"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live against the lab firewall with a disposable test profile referencing a
        disposable test gateway; both were removed afterwards. Remove-SfosSDWANProfile's help
        documents a measured side effect of deleting a profile that a route still references.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/SDWANProfile/operations/AddSD-WANprofile&UpdateSD-WANprofile.html
#>
function New-SfosSDWANProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4')]
        [string]$IPFamily,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$GatewayName,

        [int[]]$GatewayWeights,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$EnableSLA,

        [ValidateSet('BestQuality', 'CustomSLA')]
        [string]$SLAStrategy,

        [ValidateSet('ON', 'OFF')]
        [string]$IsLatency,

        [ValidateSet('ON', 'OFF')]
        [string]$IsJitter,

        [ValidateSet('ON', 'OFF')]
        [string]$IsPacketloss,

        [ValidateRange(1, 60000)]
        [int]$LatencyValue,

        [ValidateRange(1, 60000)]
        [int]$JitterValue,

        [ValidateRange(0, 100)]
        [int]$PacketlossValue,

        [ValidateRange(5, 100)]
        [int]$ProbeCount,

        [ValidateSet('FirstAvailable', 'Loadbalancing')]
        [string]$RoutingStrategy,

        [ValidateSet('WRR', 'SrcSticky', 'DestSticky', 'SrcDestSticky', 'ConnectionSticky')]
        [string]$LBMethod,

        [Parameter(Mandatory)]
        [ValidateLength(1, 85)]
        [string]$HealthCheckProfileName,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($GatewayWeights -and $GatewayWeights.Count -ne $GatewayName.Count) {
        throw "SDWANProfile '$Name': -GatewayWeights must supply exactly one value per -GatewayName entry, or none at all."
    }

    if (-not $PSCmdlet.ShouldProcess("SDWANProfile '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $descXml = ''
    if ($PSBoundParameters.ContainsKey('Description')) {
        $descXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $ipFamilyXml = ''
    if ($PSBoundParameters.ContainsKey('IPFamily')) {
        $ipFamilyXml = "<IPFamily>$IPFamily</IPFamily>"
    }

    $gwXml = ''
    for ($i = 0; $i -lt $GatewayName.Count; $i++) {
        $gwNameEsc = ConvertTo-SfosXmlEscaped -Text $GatewayName[$i]
        $orderId = $i + 1
        $weightXml = ''
        if ($GatewayWeights) {
            $weightXml = "<gatewayweights>$($GatewayWeights[$i])</gatewayweights>"
        }
        $gwXml += "<Gateway><gatewayname>$gwNameEsc</gatewayname><orderid>$orderId</orderid>$weightXml</Gateway>"
    }

    $slaStrategyXml = ''
    if ($PSBoundParameters.ContainsKey('SLAStrategy')) {
        $slaStrategyXml = "<SLAStrategy>$SLAStrategy</SLAStrategy>"
    }

    $isLatencyXml = ''
    if ($PSBoundParameters.ContainsKey('IsLatency')) {
        $isLatencyXml = "<IsLatency>$IsLatency</IsLatency>"
    }

    $isJitterXml = ''
    if ($PSBoundParameters.ContainsKey('IsJitter')) {
        $isJitterXml = "<IsJitter>$IsJitter</IsJitter>"
    }

    $isPacketlossXml = ''
    if ($PSBoundParameters.ContainsKey('IsPacketloss')) {
        $isPacketlossXml = "<IsPacketloss>$IsPacketloss</IsPacketloss>"
    }

    $latencyValueXml = ''
    if ($PSBoundParameters.ContainsKey('LatencyValue')) {
        $latencyValueXml = "<LatencyValue>$LatencyValue</LatencyValue>"
    }

    $jitterValueXml = ''
    if ($PSBoundParameters.ContainsKey('JitterValue')) {
        $jitterValueXml = "<JitterValue>$JitterValue</JitterValue>"
    }

    $packetlossValueXml = ''
    if ($PSBoundParameters.ContainsKey('PacketlossValue')) {
        $packetlossValueXml = "<PacketlossValue>$PacketlossValue</PacketlossValue>"
    }

    $probeCountXml = ''
    if ($PSBoundParameters.ContainsKey('ProbeCount')) {
        $probeCountXml = "<ProbeCount>$ProbeCount</ProbeCount>"
    }

    $routingStrategyXml = ''
    if ($PSBoundParameters.ContainsKey('RoutingStrategy')) {
        $routingStrategyXml = "<RoutingStrategy>$RoutingStrategy</RoutingStrategy>"
    }

    $lbMethodXml = ''
    if ($PSBoundParameters.ContainsKey('LBMethod')) {
        $lbMethodXml = "<LBMethod>$LBMethod</LBMethod>"
    }

    $hcpNameEsc = ConvertTo-SfosXmlEscaped -Text $HealthCheckProfileName

    $inner = @"
<Set operation="add">
  <SDWANProfile>
    <Name>$nameEsc</Name>
    $descXml
    $ipFamilyXml
    <GatewayPreferences>
      $gwXml
    </GatewayPreferences>
    <EnableSLA>$EnableSLA</EnableSLA>
    $routingStrategyXml
    $slaStrategyXml
    $isLatencyXml
    $isJitterXml
    $isPacketlossXml
    $latencyValueXml
    $jitterValueXml
    $packetlossValueXml
    $probeCountXml
    $lbMethodXml
    <HealthCheckProfileName>$hcpNameEsc</HealthCheckProfileName>
  </SDWANProfile>
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
        throw "Failed to create SDWANProfile object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANProfile' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an SD-WAN profile on the Sophos Firewall.

        .DESCRIPTION
        Updates an SDWANProfile object. This cmdlet reads the current profile first and resends
        every field, overriding only what the caller explicitly passes - SFOS replaces the
        whole entity on update. Supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Name
        Name of the SD-WAN profile to update. Accepted from the pipeline by property name, so
        Get-SfosSDWANProfile | Set-SfosSDWANProfile works.

        .PARAMETER Description
        New description. If omitted, the value currently on the firewall is kept.

        .PARAMETER IPFamily
        New IP family. If omitted, the value currently on the firewall is kept.

        .PARAMETER GatewayName
        Replaces the entire gateway preference list, in the order given (orderid is
        renumbered 1..N). If omitted, the existing gateway preferences are kept exactly as read
        back, including their original orderid and gatewayweights.

        .PARAMETER GatewayWeights
        Load-balancing weight per gateway, matching -GatewayName by position. Only meaningful
        together with -GatewayName; supplying it alone throws.

        .PARAMETER EnableSLA
        New SLA activation state. If omitted, the value currently on the firewall is kept.

        .PARAMETER SLAStrategy
        New quality-matching approach. If omitted, the raw value currently on the firewall is
        kept and resent unchanged - including a non-enumerated value such as this firmware's
        'BestQualityv' (see .NOTES). Validation against the documented set only applies when
        this parameter is explicitly supplied.

        .PARAMETER IsLatency
        New latency-monitoring toggle. If omitted, the value currently on the firewall is kept.

        .PARAMETER IsJitter
        New jitter-monitoring toggle. If omitted, the value currently on the firewall is kept.

        .PARAMETER IsPacketloss
        New packet-loss-monitoring toggle. If omitted, the value currently on the firewall is kept.

        .PARAMETER LatencyValue
        New latency threshold in ms. If omitted, the value currently on the firewall is kept.

        .PARAMETER JitterValue
        New jitter threshold in ms. If omitted, the value currently on the firewall is kept.

        .PARAMETER PacketlossValue
        New packet loss threshold in percent. If omitted, the value currently on the firewall is kept.

        .PARAMETER ProbeCount
        New active link probe count. If omitted, the value currently on the firewall is kept.

        .PARAMETER RoutingStrategy
        New routing strategy. If omitted, the value currently on the firewall is kept.

        .PARAMETER LBMethod
        New load balancing algorithm. If omitted, the value currently on the firewall is kept.

        .PARAMETER HealthCheckProfileName
        New associated health check profile. If omitted, the value currently on the firewall is kept.

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
        # Turn SLA off, keep everything else
        Set-SfosSDWANProfile -Name "Branch-Profile" -EnableSLA OFF

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: SLAStrategy reads back as 'BestQualityv' on this firmware, not the
        documented 'BestQuality'. Writing that raw string back verbatim (unchanged, i.e. the
        caller did not pass -SLAStrategy) succeeds with code 200 - it is only the parameter's
        ValidateSet that would reject it, and that check is bypassed on the preserve-as-read
        path by design: the existing value is carried in a plain local variable, never
        re-bound through the -SLAStrategy parameter, so ValidateSet only fires when a caller
        explicitly passes an out-of-set value.
        Verified live with a disposable test profile: create, read-modify-write round trip
        (unchanged), and delete, each checked against the actual firewall response.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/SDWANProfile/operations/AddSD-WANprofile&UpdateSD-WANprofile.html
#>
function Set-SfosSDWANProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4')]
        [string]$IPFamily,

        [string[]]$GatewayName,
        [int[]]$GatewayWeights,

        [ValidateSet('ON', 'OFF')]
        [string]$EnableSLA,

        [ValidateSet('BestQuality', 'CustomSLA')]
        [string]$SLAStrategy,

        [ValidateSet('ON', 'OFF')]
        [string]$IsLatency,

        [ValidateSet('ON', 'OFF')]
        [string]$IsJitter,

        [ValidateSet('ON', 'OFF')]
        [string]$IsPacketloss,

        [ValidateRange(1, 60000)]
        [int]$LatencyValue,

        [ValidateRange(1, 60000)]
        [int]$JitterValue,

        [ValidateRange(0, 100)]
        [int]$PacketlossValue,

        [ValidateRange(5, 100)]
        [int]$ProbeCount,

        [ValidateSet('FirstAvailable', 'Loadbalancing')]
        [string]$RoutingStrategy,

        [ValidateSet('WRR', 'SrcSticky', 'DestSticky', 'SrcDestSticky', 'ConnectionSticky')]
        [string]$LBMethod,

        [ValidateLength(1, 85)]
        [string]$HealthCheckProfileName,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if ($GatewayWeights -and -not $PSBoundParameters.ContainsKey('GatewayName')) {
            throw "SDWANProfile '$Name': -GatewayWeights requires -GatewayName; weights are positional against the supplied gateway list."
        }
        if ($GatewayWeights -and $GatewayWeights.Count -ne $GatewayName.Count) {
            throw "SDWANProfile '$Name': -GatewayWeights must supply exactly one value per -GatewayName entry, or none at all."
        }

        $existing = @(Get-SfosSDWANProfile -NameLike $Name -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object { $_.Name -eq $Name })
        if ($existing.Count -eq 0) {
            throw "The SDWANProfile object '$Name' was not found."
        }
        $current = $existing[0]

        if (-not $PSCmdlet.ShouldProcess("SDWANProfile '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { $current.Description }
        $descXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>"

        $targetIPFamily = if ($PSBoundParameters.ContainsKey('IPFamily')) { $IPFamily } else { $current.IPFamily }
        $ipFamilyXml = if ($targetIPFamily) { "<IPFamily>$targetIPFamily</IPFamily>" } else { '' }

        $gwXml = ''
        if ($PSBoundParameters.ContainsKey('GatewayName')) {
            for ($i = 0; $i -lt $GatewayName.Count; $i++) {
                $gwNameEsc = ConvertTo-SfosXmlEscaped -Text $GatewayName[$i]
                $orderId = $i + 1
                $weightXml = ''
                if ($GatewayWeights) {
                    $weightXml = "<gatewayweights>$($GatewayWeights[$i])</gatewayweights>"
                }
                $gwXml += "<Gateway><gatewayname>$gwNameEsc</gatewayname><orderid>$orderId</orderid>$weightXml</Gateway>"
            }
        }
        else {
            foreach ($gw in @($current.GatewayPreferences)) {
                $gwNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.GatewayName)
                $orderIdEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.OrderId)
                $weightXml = ''
                if ($gw.GatewayWeights) {
                    $weightXml = "<gatewayweights>$(ConvertTo-SfosXmlEscaped -Text ([string]$gw.GatewayWeights))</gatewayweights>"
                }
                $gwXml += "<Gateway><gatewayname>$gwNameEsc</gatewayname><orderid>$orderIdEsc</orderid>$weightXml</Gateway>"
            }
        }

        $targetEnableSLA = if ($PSBoundParameters.ContainsKey('EnableSLA')) { $EnableSLA } else { $current.EnableSLA }

        # Preserve-as-read on purpose (see .NOTES): $targetSLAStrategy is a plain local
        # variable, never re-bound through the -SLAStrategy parameter, so this firmware's
        # non-enumerated 'BestQualityv' can be resent without tripping ValidateSet.
        $targetSLAStrategy = if ($PSBoundParameters.ContainsKey('SLAStrategy')) { $SLAStrategy } else { $current.SLAStrategy }
        $slaStrategyXml = if ($targetSLAStrategy) { "<SLAStrategy>$(ConvertTo-SfosXmlEscaped -Text $targetSLAStrategy)</SLAStrategy>" } else { '' }

        $targetIsLatency = if ($PSBoundParameters.ContainsKey('IsLatency')) { $IsLatency } else { $current.IsLatency }
        $isLatencyXml = if ($targetIsLatency) { "<IsLatency>$targetIsLatency</IsLatency>" } else { '' }

        $targetIsJitter = if ($PSBoundParameters.ContainsKey('IsJitter')) { $IsJitter } else { $current.IsJitter }
        $isJitterXml = if ($targetIsJitter) { "<IsJitter>$targetIsJitter</IsJitter>" } else { '' }

        $targetIsPacketloss = if ($PSBoundParameters.ContainsKey('IsPacketloss')) { $IsPacketloss } else { $current.IsPacketloss }
        $isPacketlossXml = if ($targetIsPacketloss) { "<IsPacketloss>$targetIsPacketloss</IsPacketloss>" } else { '' }

        $targetLatencyValue = if ($PSBoundParameters.ContainsKey('LatencyValue')) { [string]$LatencyValue } else { $current.LatencyValue }
        $latencyValueXml = if ($null -ne $targetLatencyValue -and $targetLatencyValue -ne '') { "<LatencyValue>$targetLatencyValue</LatencyValue>" } else { '' }

        $targetJitterValue = if ($PSBoundParameters.ContainsKey('JitterValue')) { [string]$JitterValue } else { $current.JitterValue }
        $jitterValueXml = if ($null -ne $targetJitterValue -and $targetJitterValue -ne '') { "<JitterValue>$targetJitterValue</JitterValue>" } else { '' }

        $targetPacketlossValue = if ($PSBoundParameters.ContainsKey('PacketlossValue')) { [string]$PacketlossValue } else { $current.PacketlossValue }
        $packetlossValueXml = if ($null -ne $targetPacketlossValue -and $targetPacketlossValue -ne '') { "<PacketlossValue>$targetPacketlossValue</PacketlossValue>" } else { '' }

        $targetProbeCount = if ($PSBoundParameters.ContainsKey('ProbeCount')) { [string]$ProbeCount } else { $current.ProbeCount }
        $probeCountXml = if ($null -ne $targetProbeCount -and $targetProbeCount -ne '') { "<ProbeCount>$targetProbeCount</ProbeCount>" } else { '' }

        $targetRoutingStrategy = if ($PSBoundParameters.ContainsKey('RoutingStrategy')) { $RoutingStrategy } else { $current.RoutingStrategy }
        $routingStrategyXml = if ($targetRoutingStrategy) { "<RoutingStrategy>$targetRoutingStrategy</RoutingStrategy>" } else { '' }

        $targetLBMethod = if ($PSBoundParameters.ContainsKey('LBMethod')) { $LBMethod } else { $current.LBMethod }
        $lbMethodXml = if ($targetLBMethod) { "<LBMethod>$targetLBMethod</LBMethod>" } else { '' }

        $targetHealthCheckProfileName = if ($PSBoundParameters.ContainsKey('HealthCheckProfileName')) { $HealthCheckProfileName } else { $current.HealthCheckProfileName }
        $hcpNameEsc = ConvertTo-SfosXmlEscaped -Text $targetHealthCheckProfileName

        $inner = @"
<Set operation="update">
  <SDWANProfile>
    <Name>$nameEsc</Name>
    $descXml
    $ipFamilyXml
    <GatewayPreferences>
      $gwXml
    </GatewayPreferences>
    <EnableSLA>$targetEnableSLA</EnableSLA>
    $routingStrategyXml
    $slaStrategyXml
    $isLatencyXml
    $isJitterXml
    $isPacketlossXml
    $latencyValueXml
    $jitterValueXml
    $packetlossValueXml
    $probeCountXml
    $lbMethodXml
    <HealthCheckProfileName>$hcpNameEsc</HealthCheckProfileName>
  </SDWANProfile>
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
            throw "Failed to update SDWANProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANProfile' -Action 'update' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an SD-WAN profile from the Sophos Firewall.

        .DESCRIPTION
        Removes an SDWANProfile object by name. Supports ShouldProcess; use -WhatIf to preview
        the change.

        WARNING - measured live: deleting a profile that an existing SDWANPolicyRoute still
        references (via SDWANProfileName) answers code 200 'Configuration applied successfully'
        and silently cascades - the referencing route is deleted along with the profile, with
        no warning of any kind. Check for dependent routes with
        Get-SfosSDWANPolicyRoute | Where-Object { $_.SDWANProfileName -eq $Name } before removing
        a profile that may be in use.

        .PARAMETER Name
        Name of the SD-WAN profile to remove. Accepted from the pipeline, so
        Get-SfosSDWANProfile | Remove-SfosSDWANProfile works.

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
        # Remove a profile that is not referenced by any route
        Remove-SfosSDWANProfile -Name "Branch-Profile"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Removing a non-existent profile answers code="" (the attribute is present but empty)
        with the message 'Operation could not be performed on Entity.' - measured live.
        Assert-SfosApiReturnSuccess treats an empty code the same as a missing one and throws,
        which is the correct outcome here, just via the generic "status without a code" wording
        rather than a name-specific message (matches the project-wide open item for Remove-*
        cmdlets in general - see the project build rules).
        Verified live: create, remove, and the cascade-delete side effect documented above (all
        against disposable ZZTest-prefixed objects, cleaned up afterwards).

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/SDWANProfile/operations/Delete%20SD-WAN%20profile.html
#>
function Remove-SfosSDWANProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        if (-not $PSCmdlet.ShouldProcess("SDWANProfile '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SDWANProfile><Name>$nameEsc</Name></SDWANProfile></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove SDWANProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANProfile' -Action 'remove' -Target $Name
    }
}

#endregion

#region SDWANPolicyRoute

<#
        .SYNOPSIS
        Retrieves SD-WAN policy routes from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for SDWANPolicyRoute objects. Server-side filtering
        only evaluates a single 'Name' key reliably (measured); -NameLike is sent as that one
        key and reapplied client-side afterwards. By default the cmdlet returns a
        PowerShell-friendly object. Use -AsXml to return the raw XML nodes.

        .PARAMETER NameLike
        Filters by route name, substring match (SFOS 'like' semantics, not a wildcard).

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
        # Retrieve every SD-WAN policy route
        Get-SfosSDWANPolicyRoute

        .NOTES
        Minimum supported PowerShell version: 5.1
        The 'Status' element on this entity is a data field (the route's own enabled flag,
        '1'/'0' as text) - not an API status. It has a <Name> sibling, so the shared
        Get-SfosApiStatus/Assert-SfosApiReturnSuccess heuristic correctly leaves it alone
        (verified live). It is unrelated to, and uses a different representation than, the
        SDWANPolicyRouteStatus entity's own ON/OFF text - see Get-SfosSDWANPolicyRouteStatus.
        Returned here as 'Status' (the wire name), exactly as delivered.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/PolicyRoute/PolicyRoute.html
#>
function Get-SfosSDWANPolicyRoute {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 60)]
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
  <SDWANPolicyRoute>
    $xmlFilterAdvanced
  </SDWANPolicyRoute>
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
        throw "Failed to retrieve SDWANPolicyRoute objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANPolicyRoute' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SDWANPolicyRoute[Name]' | ForEach-Object -Process { $_.Node }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $result = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $sourceNetworks = if ($node.SourceNetworks -and $node.SourceNetworks.Network) { [string[]]@($node.SourceNetworks.Network) } else { @() }
        $destinationNetworks = if ($node.DestinationNetworks -and $node.DestinationNetworks.Network) { [string[]]@($node.DestinationNetworks.Network) } else { @() }
        $services = if ($node.Services -and $node.Services.Service) { [string[]]@($node.Services.Service) } else { @() }
        $users = if ($node.Users -and $node.Users.User) { [string[]]@($node.Users.User) } else { @() }
        $applicationObjects = if ($node.ApplicationObjects -and $node.ApplicationObjects.ApplicationObject) { [string[]]@($node.ApplicationObjects.ApplicationObject) } else { @() }

        $result += [PSCustomObject]@{
            Name                = [string]$node.Name
            Description         = [string]$node.Description
            IPFamily            = [string]$node.IPFamily
            SourceNetworks      = $sourceNetworks
            DestinationNetworks = $destinationNetworks
            Services            = $services
            Users               = $users
            ApplicationObjects  = $applicationObjects
            LinkSelection       = [string]$node.LinkSelection
            SDWANProfileName    = [string]$node.SDWANProfileName
            Gateway             = [string]$node.Gateway
            BackupGateway       = [string]$node.BackupGateway
            Healthcheck         = [string]$node.Healthcheck
            Interface           = [string]$node.Interface
            DSCPMarking         = [string]$node.DSCPMarking
            Status              = [string]$node.Status
        }
    }

    return $result
}

<#
        .SYNOPSIS
        Creates a new SD-WAN policy route on the Sophos Firewall.

        .DESCRIPTION
        Creates an SDWANPolicyRoute object using the Sophos Firewall XML API. Supports
        ShouldProcess; use -WhatIf to preview the request.

        .PARAMETER Name
        Name of the SD-WAN route (1-60 characters, no commas).

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER IPFamily
        IP protocol version. Defaults to 'IPv4' when omitted - unlike SDWANProfile's IPFamily,
        this element cannot be left out of the request entirely; see .NOTES.

        .PARAMETER SourceNetwork
        Names of existing network/host objects to match as traffic sources.

        .PARAMETER DestinationNetwork
        Names of existing network/host objects to match as traffic destinations.

        .PARAMETER Service
        Names of existing service objects to match.

        .PARAMETER User
        Names of users or groups whose traffic this route applies to.

        .PARAMETER ApplicationObject
        Names of existing application objects to match.

        .PARAMETER LinkSelection
        Method of link selection: pick gateways directly, or defer to an SD-WAN profile.

        .PARAMETER SDWANProfileName
        Name of an existing SDWANProfile to assign to the route. Mandatory per the Sophos API
        documentation regardless of -LinkSelection.

        .PARAMETER Gateway
        Primary gateway for the route (used with -LinkSelection SelectGateways).

        .PARAMETER BackupGateway
        Backup gateway used when the primary gateway fails.

        .PARAMETER Healthcheck
        Route behaviour when all gateways are down.

        .PARAMETER Interface
        Incoming interface that receives the packets this route matches.

        .PARAMETER DSCPMarking
        DSCP codepoint to match, as a bare number (0-63) optionally followed by '-ClassName'
        (e.g. '8-Class 1(CS1)'), matching what Get-SfosSDWANPolicyRoute returns. The value '0'
        is normalised to '0-Best Effort' automatically - see the module's internal
        ConvertTo-SfosDSCPMarkingWireValue helper and this cmdlet's .NOTES.

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
        # Create a route that defers gateway selection to an SD-WAN profile
        New-SfosSDWANPolicyRoute -Name "Branch-Route" -DestinationNetwork "Branch-Net" -LinkSelection SelectSDWANProfile -SDWANProfileName "Branch-Profile"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: although the documentation table marks IPFamily 'Default IPv4' (implying
        it can be left out), omitting the element entirely on create is rejected with code 501
        'Configuration parameters validation failed' naming /SDWANPolicyRoute/IPFamily. This
        cmdlet always sends the element, defaulting to 'IPv4' when -IPFamily is not supplied.
        Measured live: this entity has no enable/disable field of its own - a newly created
        route is enabled immediately (its own 'Status' data field reads '1'). To create a route
        disabled, follow up with Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName $Name
        -Status OFF right after creation.
        Verified live end to end with a disposable test route against a disposable test profile
        and a disposable destination network object, all removed afterwards.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/PolicyRoute/operations/AddSD-WANroute&UpdateSD-WANroute.html
#>
function New-SfosSDWANPolicyRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string[]]$SourceNetwork,
        [string[]]$DestinationNetwork,
        [string[]]$Service,
        [string[]]$User,
        [string[]]$ApplicationObject,

        [ValidateSet('SelectGateways', 'SelectSDWANProfile')]
        [string]$LinkSelection,

        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [string]$SDWANProfileName,

        [string]$Gateway,
        [string]$BackupGateway,

        [ValidateSet('ON', 'OFF')]
        [string]$Healthcheck,

        [string]$Interface,

        [ValidatePattern('^[0-9]{1,2}(-.+)?$')]
        [string]$DSCPMarking,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("SDWANPolicyRoute '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $descXml = ''
    if ($PSBoundParameters.ContainsKey('Description')) {
        $descXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    # Measured live: despite the documentation table marking IPFamily 'Default IPv4' (implying
    # it can be omitted), the firewall answers code 501 'Configuration parameters validation
    # failed' naming /SDWANPolicyRoute/IPFamily when the element is left out entirely. Unlike
    # SDWANProfile's IPFamily (genuinely optional, confirmed live), this one is always sent.
    $effectiveIPFamily = if ($PSBoundParameters.ContainsKey('IPFamily')) { $IPFamily } else { 'IPv4' }
    $ipFamilyXml = "<IPFamily>$effectiveIPFamily</IPFamily>"

    $sourceXml = ''
    if ($SourceNetwork) {
        $items = ($SourceNetwork | Where-Object { $_ } | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
        if ($items) { $sourceXml = "<SourceNetworks>$items</SourceNetworks>" }
    }

    $destXml = ''
    if ($DestinationNetwork) {
        $items = ($DestinationNetwork | Where-Object { $_ } | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
        if ($items) { $destXml = "<DestinationNetworks>$items</DestinationNetworks>" }
    }

    $serviceXml = ''
    if ($Service) {
        $items = ($Service | Where-Object { $_ } | ForEach-Object { "<Service>$(ConvertTo-SfosXmlEscaped -Text $_)</Service>" }) -join ''
        if ($items) { $serviceXml = "<Services>$items</Services>" }
    }

    $userXml = ''
    if ($User) {
        $items = ($User | Where-Object { $_ } | ForEach-Object { "<User>$(ConvertTo-SfosXmlEscaped -Text $_)</User>" }) -join ''
        if ($items) { $userXml = "<Users>$items</Users>" }
    }

    $appObjXml = ''
    if ($ApplicationObject) {
        $items = ($ApplicationObject | Where-Object { $_ } | ForEach-Object { "<ApplicationObject>$(ConvertTo-SfosXmlEscaped -Text $_)</ApplicationObject>" }) -join ''
        if ($items) { $appObjXml = "<ApplicationObjects>$items</ApplicationObjects>" }
    }

    $linkSelectionXml = ''
    if ($PSBoundParameters.ContainsKey('LinkSelection')) {
        $linkSelectionXml = "<LinkSelection>$LinkSelection</LinkSelection>"
    }

    $sdwanProfileNameEsc = ConvertTo-SfosXmlEscaped -Text $SDWANProfileName

    $gatewayXml = ''
    if ($PSBoundParameters.ContainsKey('Gateway')) {
        $gatewayXml = "<Gateway>$(ConvertTo-SfosXmlEscaped -Text $Gateway)</Gateway>"
    }

    $backupGatewayXml = ''
    if ($PSBoundParameters.ContainsKey('BackupGateway')) {
        $backupGatewayXml = "<BackupGateway>$(ConvertTo-SfosXmlEscaped -Text $BackupGateway)</BackupGateway>"
    }

    $healthcheckXml = ''
    if ($PSBoundParameters.ContainsKey('Healthcheck')) {
        $healthcheckXml = "<Healthcheck>$Healthcheck</Healthcheck>"
    }

    $interfaceXml = ''
    if ($PSBoundParameters.ContainsKey('Interface')) {
        $interfaceXml = "<Interface>$(ConvertTo-SfosXmlEscaped -Text $Interface)</Interface>"
    }

    $dscpMarkingXml = ''
    if ($PSBoundParameters.ContainsKey('DSCPMarking')) {
        $dscpWire = ConvertTo-SfosDSCPMarkingWireValue -Value $DSCPMarking
        $dscpMarkingXml = "<DSCPMarking>$(ConvertTo-SfosXmlEscaped -Text $dscpWire)</DSCPMarking>"
    }

    $inner = @"
<Set operation="add">
  <SDWANPolicyRoute>
    <Name>$nameEsc</Name>
    $descXml
    $ipFamilyXml
    $sourceXml
    $serviceXml
    $destXml
    $appObjXml
    $userXml
    $linkSelectionXml
    <SDWANProfileName>$sdwanProfileNameEsc</SDWANProfileName>
    $gatewayXml
    $backupGatewayXml
    $healthcheckXml
    $interfaceXml
    $dscpMarkingXml
  </SDWANPolicyRoute>
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
        throw "Failed to create SDWANPolicyRoute object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANPolicyRoute' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an SD-WAN policy route on the Sophos Firewall.

        .DESCRIPTION
        Updates an SDWANPolicyRoute object. This cmdlet reads the current route first and
        resends every field, overriding only what the caller explicitly passes - SFOS replaces
        the whole entity on update. Supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Name
        Name of the SD-WAN route to update. Accepted from the pipeline by property name, so
        Get-SfosSDWANPolicyRoute | Set-SfosSDWANPolicyRoute works.

        .PARAMETER Description
        New description. If omitted, the value currently on the firewall is kept.

        .PARAMETER IPFamily
        New IP family. If omitted, the value currently on the firewall is kept.

        .PARAMETER SourceNetwork
        Replaces the entire source network list. If omitted, the existing list is kept.

        .PARAMETER DestinationNetwork
        Replaces the entire destination network list. If omitted, the existing list is kept.

        .PARAMETER Service
        Replaces the entire service list. If omitted, the existing list is kept.

        .PARAMETER User
        Replaces the entire user/group list. If omitted, the existing list is kept.

        .PARAMETER ApplicationObject
        Replaces the entire application object list. If omitted, the existing list is kept.

        .PARAMETER LinkSelection
        New link selection method. If omitted, the value currently on the firewall is kept.

        .PARAMETER SDWANProfileName
        New SD-WAN profile assignment. If omitted, the value currently on the firewall is kept.

        .PARAMETER Gateway
        New primary gateway. If omitted, the value currently on the firewall is kept.

        .PARAMETER BackupGateway
        New backup gateway. If omitted, the value currently on the firewall is kept.

        .PARAMETER Healthcheck
        New health check behaviour. If omitted, the value currently on the firewall is kept.

        .PARAMETER Interface
        New incoming interface. If omitted, the value currently on the firewall is kept.

        .PARAMETER DSCPMarking
        New DSCP codepoint. If omitted, the raw value read back from the firewall is resent
        unchanged, through the same '0' -> '0-Best Effort' normalisation New-SfosSDWANPolicyRoute
        applies (see that cmdlet's .PARAMETER DSCPMarking and .NOTES) - the read-modify-write
        preserve path would otherwise resend a value the firewall demonstrably rejects.

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
        # Change only the interface, everything else is preserved
        Set-SfosSDWANPolicyRoute -Name "Branch-Route" -Interface "Port2"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: DSCPMarking read back as the bare number '0' (the default) cannot be
        resent as '0' - the firewall answers code 501 'Configuration parameters validation
        failed' naming /SDWANPolicyRoute/DSCPMarking. Every other value round-trips as-is. See
        ConvertTo-SfosDSCPMarkingWireValue.
        Verified live: full read-modify-write round trip against a disposable test route
        (unchanged fields byte-identical on re-read, including DestinationNetworks and
        Interface, which a minimal update omitting them would otherwise have cleared).

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/PolicyRoute/operations/AddSD-WANroute&UpdateSD-WANroute.html
#>
function Set-SfosSDWANPolicyRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string[]]$SourceNetwork,
        [string[]]$DestinationNetwork,
        [string[]]$Service,
        [string[]]$User,
        [string[]]$ApplicationObject,

        [ValidateSet('SelectGateways', 'SelectSDWANProfile')]
        [string]$LinkSelection,

        [ValidateLength(1, 60)]
        [string]$SDWANProfileName,

        [string]$Gateway,
        [string]$BackupGateway,

        [ValidateSet('ON', 'OFF')]
        [string]$Healthcheck,

        [string]$Interface,

        [ValidatePattern('^[0-9]{1,2}(-.+)?$')]
        [string]$DSCPMarking,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        $existing = @(Get-SfosSDWANPolicyRoute -NameLike $Name -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object { $_.Name -eq $Name })
        if ($existing.Count -eq 0) {
            throw "The SDWANPolicyRoute object '$Name' was not found."
        }
        $current = $existing[0]

        if (-not $PSCmdlet.ShouldProcess("SDWANPolicyRoute '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { $current.Description }
        $descXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>"

        $targetIPFamily = if ($PSBoundParameters.ContainsKey('IPFamily')) { $IPFamily } else { $current.IPFamily }
        $ipFamilyXml = if ($targetIPFamily) { "<IPFamily>$targetIPFamily</IPFamily>" } else { '' }

        $targetSource = if ($PSBoundParameters.ContainsKey('SourceNetwork')) { $SourceNetwork } else { $current.SourceNetworks }
        $sourceXml = ''
        if ($targetSource) {
            $items = ($targetSource | Where-Object { $_ } | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
            if ($items) { $sourceXml = "<SourceNetworks>$items</SourceNetworks>" }
        }

        $targetDest = if ($PSBoundParameters.ContainsKey('DestinationNetwork')) { $DestinationNetwork } else { $current.DestinationNetworks }
        $destXml = ''
        if ($targetDest) {
            $items = ($targetDest | Where-Object { $_ } | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
            if ($items) { $destXml = "<DestinationNetworks>$items</DestinationNetworks>" }
        }

        $targetService = if ($PSBoundParameters.ContainsKey('Service')) { $Service } else { $current.Services }
        $serviceXml = ''
        if ($targetService) {
            $items = ($targetService | Where-Object { $_ } | ForEach-Object { "<Service>$(ConvertTo-SfosXmlEscaped -Text $_)</Service>" }) -join ''
            if ($items) { $serviceXml = "<Services>$items</Services>" }
        }

        $targetUser = if ($PSBoundParameters.ContainsKey('User')) { $User } else { $current.Users }
        $userXml = ''
        if ($targetUser) {
            $items = ($targetUser | Where-Object { $_ } | ForEach-Object { "<User>$(ConvertTo-SfosXmlEscaped -Text $_)</User>" }) -join ''
            if ($items) { $userXml = "<Users>$items</Users>" }
        }

        $targetAppObj = if ($PSBoundParameters.ContainsKey('ApplicationObject')) { $ApplicationObject } else { $current.ApplicationObjects }
        $appObjXml = ''
        if ($targetAppObj) {
            $items = ($targetAppObj | Where-Object { $_ } | ForEach-Object { "<ApplicationObject>$(ConvertTo-SfosXmlEscaped -Text $_)</ApplicationObject>" }) -join ''
            if ($items) { $appObjXml = "<ApplicationObjects>$items</ApplicationObjects>" }
        }

        $targetLinkSelection = if ($PSBoundParameters.ContainsKey('LinkSelection')) { $LinkSelection } else { $current.LinkSelection }
        $linkSelectionXml = if ($targetLinkSelection) { "<LinkSelection>$targetLinkSelection</LinkSelection>" } else { '' }

        $targetSDWANProfileName = if ($PSBoundParameters.ContainsKey('SDWANProfileName')) { $SDWANProfileName } else { $current.SDWANProfileName }
        $sdwanProfileNameEsc = ConvertTo-SfosXmlEscaped -Text $targetSDWANProfileName

        $targetGateway = if ($PSBoundParameters.ContainsKey('Gateway')) { $Gateway } else { $current.Gateway }
        $gatewayXml = if ($targetGateway) { "<Gateway>$(ConvertTo-SfosXmlEscaped -Text $targetGateway)</Gateway>" } else { '' }

        $targetBackupGateway = if ($PSBoundParameters.ContainsKey('BackupGateway')) { $BackupGateway } else { $current.BackupGateway }
        $backupGatewayXml = if ($targetBackupGateway) { "<BackupGateway>$(ConvertTo-SfosXmlEscaped -Text $targetBackupGateway)</BackupGateway>" } else { '' }

        $targetHealthcheck = if ($PSBoundParameters.ContainsKey('Healthcheck')) { $Healthcheck } else { $current.Healthcheck }
        $healthcheckXml = if ($targetHealthcheck) { "<Healthcheck>$targetHealthcheck</Healthcheck>" } else { '' }

        $targetInterface = if ($PSBoundParameters.ContainsKey('Interface')) { $Interface } else { $current.Interface }
        $interfaceXml = if ($targetInterface) { "<Interface>$(ConvertTo-SfosXmlEscaped -Text $targetInterface)</Interface>" } else { '' }

        $targetDSCPMarking = if ($PSBoundParameters.ContainsKey('DSCPMarking')) { $DSCPMarking } else { $current.DSCPMarking }
        $dscpMarkingXml = ''
        if ($targetDSCPMarking) {
            $dscpWire = ConvertTo-SfosDSCPMarkingWireValue -Value $targetDSCPMarking
            $dscpMarkingXml = "<DSCPMarking>$(ConvertTo-SfosXmlEscaped -Text $dscpWire)</DSCPMarking>"
        }

        $inner = @"
<Set operation="update">
  <SDWANPolicyRoute>
    <Name>$nameEsc</Name>
    $descXml
    $ipFamilyXml
    $sourceXml
    $serviceXml
    $destXml
    $appObjXml
    $userXml
    $linkSelectionXml
    <SDWANProfileName>$sdwanProfileNameEsc</SDWANProfileName>
    $gatewayXml
    $backupGatewayXml
    $healthcheckXml
    $interfaceXml
    $dscpMarkingXml
  </SDWANPolicyRoute>
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
            throw "Failed to update SDWANPolicyRoute object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANPolicyRoute' -Action 'update' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an SD-WAN policy route from the Sophos Firewall.

        .DESCRIPTION
        Removes an SDWANPolicyRoute object by name. Supports ShouldProcess; use -WhatIf to
        preview the change.

        .PARAMETER Name
        Name of the SD-WAN route to remove. Accepted from the pipeline, so
        Get-SfosSDWANPolicyRoute | Remove-SfosSDWANPolicyRoute works.

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
        # Remove a route by name
        Remove-SfosSDWANPolicyRoute -Name "Branch-Route"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Removing a non-existent route answers code="" (present but empty) with the message
        'Operation could not be performed on Entity.' - measured live. Same generic-throw
        behaviour as Remove-SfosSDWANProfile; see that cmdlet's .NOTES.
        Verified live against a disposable test route.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/PolicyRoute/operations/Delete%20SD-WAN%20route.html
#>
function Remove-SfosSDWANPolicyRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        if (-not $PSCmdlet.ShouldProcess("SDWANPolicyRoute '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SDWANPolicyRoute><Name>$nameEsc</Name></SDWANPolicyRoute></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove SDWANPolicyRoute object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANPolicyRoute' -Action 'remove' -Target $Name
    }
}

#endregion

#region SDWANPolicyRouteStatus

<#
        .SYNOPSIS
        Retrieves SD-WAN policy route enable/disable status from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for SDWANPolicyRouteStatus records (undocumented as
        a Get operation - the Sophos documentation only describes the status-change write - but
        measured to work the same way Get works for every other status-toggle entity in this
        API area). -NameLike is applied client-side only; see .NOTES for why no server-side
        filter is ever sent for this entity. By default the cmdlet returns a
        PowerShell-friendly object. Use -AsXml to return the raw XML nodes.

        .PARAMETER NameLike
        Filters by route name, substring match, applied client-side.

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
        # Retrieve the enable/disable status of every SD-WAN policy route
        Get-SfosSDWANPolicyRouteStatus

        .NOTES
        Minimum supported PowerShell version: 5.1
        Two measured defects specific to this entity, both confirmed live and both worked
        around in this cmdlet rather than in Core (Core stays generic across every module):

        1. Server-side filtering is completely broken here, not just "unsupported and
           ignored" like most other entities in this API area - sending ANY <Filter>, even one
           that exactly matches an existing record, makes the firewall answer
           <Status>Transaction fail</Status> instead of the matching record. This cmdlet never
           sends a Filter; it always fetches the full list and filters client-side.

        2. This entity's identifying element is <SDWANPolicyRouteName>, not <Name> - unlike
           every other status-toggle entity in this API area (HealthCheckProfileStatus uses
           <Name>). The shared Get-SfosApiStatus/Assert-SfosApiReturnSuccess heuristic treats a
           code-less <Status> as an API status when its parent has no <Name> sibling, which is
           meant to catch entities like HealthCheckProfileStatus that legitimately use <Name>.
           Here it backfires: every data row's own <Status>ON</Status>/<Status>OFF</Status>
           value gets misread as an unrecognised API status and the generic assertion throws on
           the very first non-empty result (reproduced live: 'OFF' raised "Sophos API returned
           a status without a code"). This cmdlet does its own status handling instead of
           calling Assert-SfosApiReturnSuccess unconditionally: a <Status> that carries a @code
           attribute is still handed to the generic assertion (real API errors, e.g. a
           malformed request, do carry a code here); a code-less <Status> is only accepted when
           its text is 'ON', 'OFF', or matches 'No. of records Zero.' - anything else code-less
           (such as the 'Transaction fail' from point 1) still throws.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/PolicyRouteStatus/operations/PolicyRoutestatuschange.html
#>
function Get-SfosSDWANPolicyRouteStatus {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 60)]
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

    # No Filter block, ever - see .NOTES point 1: any Filter on this entity answers
    # 'Transaction fail' instead of the matching record, even for an exact match.
    $inner = '<Get><SDWANPolicyRouteStatus></SDWANPolicyRouteStatus></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve SDWANPolicyRouteStatus objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See .NOTES point 2. A coded status is a real API error/warning and goes through the
    # generic table-driven check; a code-less status is only ever data (ON/OFF) or the
    # empty-result wording here - anything else code-less throws explicitly.
    $codedStatus = $XmlResponse.SelectSingleNode('/Response/SDWANPolicyRouteStatus/Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANPolicyRouteStatus' -Action 'get'
    }
    else {
        foreach ($statusNode in @($XmlResponse.SelectNodes('/Response/SDWANPolicyRouteStatus/Status'))) {
            $statusMessage = [string]$statusNode.InnerText
            if ($statusMessage -eq 'ON' -or $statusMessage -eq 'OFF' -or $statusMessage -match 'records\s+Zero') {
                continue
            }
            throw "Sophos API returned an unrecognised status while retrieving SDWANPolicyRouteStatus objects: '$statusMessage'"
        }
    }

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SDWANPolicyRouteStatus[SDWANPolicyRouteName]' | ForEach-Object -Process { $_.Node }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.SDWANPolicyRouteName -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $result = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $result += [PSCustomObject]@{
            SDWANPolicyRouteName = [string]$node.SDWANPolicyRouteName
            Status               = [string]$node.Status
        }
    }

    return $result
}

<#
        .SYNOPSIS
        Enables or disables an SD-WAN policy route on the Sophos Firewall.

        .DESCRIPTION
        Toggles the enabled/disabled status of an existing SDWANPolicyRoute using the dedicated
        status-change operation - there is no New/Remove for this entity, only Get and this Set.
        Supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER SDWANPolicyRouteName
        Name of the SD-WAN route to toggle. Aliased as 'Name' so both
        Get-SfosSDWANPolicyRoute | Set-SfosSDWANPolicyRouteStatus and
        Get-SfosSDWANPolicyRouteStatus | Set-SfosSDWANPolicyRouteStatus bind by property name.

        .PARAMETER Status
        New status: 'ON' or 'OFF'.

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
        None. Throws an exception if the update fails or cannot be confirmed.

        .EXAMPLE
        # Disable a route right after creating it
        Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName "Branch-Route" -Status OFF

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: toggling the status of a route name that does not exist on the firewall
        answers code 200 'Configuration applied successfully' and changes nothing - a
        false-positive success, the same defect class as the project's known open item for
        Remove-Sfos* cmdlets in general (see the project build rules), just on a Set here instead of a Remove.
        Because this cmdlet's whole purpose is the toggle, it reads the status back after a
        successful-looking write and throws if the route was not found or the status does not
        match what was requested, rather than reporting a silent no-op as success.
        Verified live: toggle to OFF and back to ON against a disposable test route, and the
        false-positive-on-nonexistent-name behaviour reproduced against a route name that did
        not exist.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/Routing/PolicyRouteStatus/operations/PolicyRoutestatuschange.html
#>
function Set-SfosSDWANPolicyRouteStatus {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [Alias('Name')]
        [ValidateLength(1, 60)]
        [string]$SDWANPolicyRouteName,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$Status,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        if (-not $PSCmdlet.ShouldProcess("SDWANPolicyRouteStatus '$SDWANPolicyRouteName' on $($params.Firewall)", "Set status $Status")) {
            return
        }

        $routeNameEsc = ConvertTo-SfosXmlEscaped -Text $SDWANPolicyRouteName

        $inner = @"
<Set operation="update">
  <SDWANPolicyRouteStatus>
    <SDWANPolicyRouteName>$routeNameEsc</SDWANPolicyRouteName>
    <Status>$Status</Status>
  </SDWANPolicyRouteStatus>
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
            throw "Failed to update SDWANPolicyRouteStatus for '$SDWANPolicyRouteName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SDWANPolicyRouteStatus' -Action 'update' -Target $SDWANPolicyRouteName

        # See .NOTES: a coded 200 here does not guarantee the named route exists - confirm by
        # reading the status back, so a caller cannot mistake a silent no-op for success.
        $confirmed = @(Get-SfosSDWANPolicyRouteStatus -NameLike $SDWANPolicyRouteName -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
            Where-Object { $_.SDWANPolicyRouteName -eq $SDWANPolicyRouteName })

        if ($confirmed.Count -eq 0 -or $confirmed[0].Status -ne $Status) {
            throw "SDWANPolicyRouteStatus update for '$SDWANPolicyRouteName' reported success but could not be confirmed on the firewall (expected Status '$Status'). The route name may not exist."
        }
    }
}

#endregion

# SophosFirewall.Routing - Group C: Static & Multicast Routing
#
# Entities: UnicastRoute, MulticastRoute, MulticastConfiguration (read-only),
# PIMDynamicRouting. Style follows scratchpad/fragments/group-e-firewallauth.ps1.
#
# Cross-cutting findings from this group's live verification (see task report for the
# full table):
#   - UnicastRoute.Netmask is dotted-decimal ("255.255.255.0") on the wire, not the
#     INTEGER 0-128 the parameter table claims - the sample XML wins here [measured].
#   - UnicastRoute has its own <Status>ON/OFF</Status> data field (the route's enabled
#     flag) and, unlike FirewallRule/NATRule, no <Name> element to protect it under the
#     Name-based heuristic in Core's Get-SfosApiStatus. Get-SfosUnicastRoute therefore
#     scopes Assert-SfosApiReturnSuccess to responses that carry no <DestinationIP> -
#     i.e. status-only responses - instead of calling it unconditionally with
#     -ObjectName 'UnicastRoute', which would misread every stored route's own Status
#     field as a broken, code-less API status [measured].
#   - <Set operation="update"> answers code 500 for UnicastRoute on every field
#     combination tried, including a true no-op and variants with/without the
#     <OldConfiguration> subtree - matching the existing Set-SfosStaticARP precedent.
#     Set-SfosUnicastRoute is therefore remove-then-recreate, like Set-SfosGreRoute and
#     Set-SfosStaticARP [measured].
#   - Remove-SfosUnicastRoute answering 200 was not reproducible with just the
#     documented composite key (DestinationIP+Netmask); the full object body (matching
#     what Get-SfosUnicastRoute returns) is what worked reliably across repeated
#     attempts, so Remove-SfosUnicastRoute reads the object back first and always sends
#     every field [measured].
#   - The firewall does NOT enforce DestinationIP+Netmask as a unique key: creating a
#     second UnicastRoute with identical DestinationIP, Netmask and every other field
#     answered code 200 and produced two indistinguishable records, confirmed live. This
#     likely explains the non-reproducible 500s noted above - an ambiguous match across
#     duplicate "key" values is a plausible cause. New-SfosUnicastRoute therefore checks
#     for an existing DestinationIP+Netmask match first and throws rather than silently
#     creating an ambiguous duplicate; Set-/Remove-SfosUnicastRoute still only operate on
#     the first match if a duplicate exists elsewhere on the firewall (for example one
#     created outside this module) [measured].
#   - MulticastRoute Add answered code 500 "Operation could not be performed on Entity"
#     on every documented-shape variant tried (with/without SourceInterface, with/
#     without TunnelType, with/without the DestinationInterfaceList wrapper, exact
#     sample field order) - about a dozen attempts total. The lab firewall's
#     MulticastConfiguration singleton reads MulticastForwardingSetting = Disable, which
#     is the most likely gate, but that could not be confirmed: MulticastConfiguration
#     has no documented write operation at all (see below), so flipping it to test the
#     hypothesis would be an undocumented write to a device-wide setting, out of scope
#     for this task. New-/Set-/Remove-SfosMulticastRoute are implemented documentation-
#     faithful and verified at the XML-generation level only, per the existing
#     New-SfosSSLTLSInspectionRule precedent. Get-SfosMulticastRoute is confirmed live
#     (zero records, matches the documented root element and table).
#   - MulticastConfiguration's own doc page (Multicast/Multicast.html) has an empty
#     Description and Operations section - no operation is documented for this entity at
#     all, not even Get. No Set-SfosMulticastConfiguration was built, per the existing
#     Set-SfosGuestUser precedent (no cmdlet for an undocumented write path).
#   - PIMDynamicRouting is a device-wide dynamic-routing singleton; Get is confirmed
#     live, Set was implemented and checked structurally only, never sent to the lab
#     firewall, per the existing Set-SfosAdminAuthentication precedent and this task's
#     explicit instruction.

#region UnicastRoute

<#
        .SYNOPSIS
        Retrieves UnicastRoute (static route) objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for UnicastRoute objects. UnicastRoute has no
        Name element; it is identified by the composite key DestinationIP + Netmask. By
        default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw
        XML nodes.

        Only the DestinationIP server-side filter key was verified to work (measured); the
        result is always filtered again client-side, so -AsXml returns the same set as the
        default output.

        .PARAMETER DestinationIPLike
        Filters routes whose DestinationIP contains the given substring. Sent to the firewall
        as a server-side filter and re-applied client-side.

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
        # List every static route
        Get-SfosUnicastRoute

        .EXAMPLE
        # Find routes toward a given destination range
        Get-SfosUnicastRoute -DestinationIPLike "203.0.113"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: Netmask is returned dotted-decimal ("255.255.255.0"), not the prefix-
        length INTEGER the parameter table describes. Status is the route's ON/OFF enabled
        flag, not an API status - see the module-level comment at the top of this fragment for
        why Assert-SfosApiReturnSuccess is only invoked for status-only (non-record)
        responses here.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/UnicastRoute/UnicastRoute.html

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/UnicastRoute/operations/AddUnicastRoute&UpdateUnicastRoute.html
#>
function Get-SfosUnicastRoute {
    [CmdletBinding()]
    param(
        # Functional parameters
        [ValidateLength(1, 45)]
        [string]$DestinationIPLike,

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
    if ($DestinationIPLike) {
        $destLikeEsc = ConvertTo-SfosXmlEscaped -Text $DestinationIPLike
        $filterXml = ('<Filter><key name="DestinationIP" criteria="like">{0}</key></Filter>' -f $destLikeEsc)
    }

    $inner = @"
<Get>
  <UnicastRoute>
    $filterXml
  </UnicastRoute>
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
        throw "Error retrieving UnicastRoute objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See the module-level comment at the top of this fragment: UnicastRoute's own
    # <Status>ON/OFF</Status> data field is code-less and has no <Name> sibling, so it is
    # indistinguishable from a broken API status under Core's generic heuristic. Every
    # measured real status here (200, 501, 529, "No. of records Zero.") appeared on a
    # <UnicastRoute> node that carried no <DestinationIP> - i.e. a status-only response,
    # never alongside actual route data - so scoping the check to that shape catches
    # genuine problems without misreading a stored route's enabled flag.
    if (@($XmlResponse.SelectNodes('/Response/UnicastRoute[not(DestinationIP)]')).Count -gt 0) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UnicastRoute' -Action 'get'
    }

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/UnicastRoute[DestinationIP]' | ForEach-Object -Process {
        $_.Node
    }

    if ($DestinationIPLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.DestinationIP -like "*$DestinationIPLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $routeObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            IPFamily               = [string]$node.IPFamily
            DestinationIP          = [string]$node.DestinationIP
            Netmask                = [string]$node.Netmask
            Gateway                = [string]$node.Gateway
            Interface               = [string]$node.Interface
            Distance                = [string]$node.Distance
            AdministrativeDistance = [string]$node.AdministrativeDistance
            Blackhole              = [string]$node.Blackhole
            Status                 = [string]$node.Status
            Description            = [string]$node.Description
        }
    }

    return @($routeObjects)
}

<#
        .SYNOPSIS
        Creates a new UnicastRoute (static route) object on the Sophos Firewall.

        .DESCRIPTION
        Creates a UnicastRoute object on the Sophos Firewall XML API. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER DestinationIP
        Destination IPv4/IPv6 address of the route (max 45 chars). Cannot be a multicast or
        loopback address.

        .PARAMETER Netmask
        Netmask of the destination, dotted-decimal (for example "255.255.255.0") - measured
        live; the parameter table's claim of an INTEGER prefix length (0-128) was rejected
        with code 501.

        .PARAMETER IPFamily
        Address family of the route. Defaults to IPv4.

        .PARAMETER Gateway
        Gateway IPv4/IPv6 address for the route. Optional.

        .PARAMETER Interface
        Egress interface for the route. Optional.

        .PARAMETER Distance
        Routing metric (0-255). Defaults to 0.

        .PARAMETER AdministrativeDistance
        Administrative distance (1-255). Defaults to 1.

        .PARAMETER Blackhole
        Creates (Enable) or does not create (Disable/omitted) a blackhole route.

        .PARAMETER Status
        Turns the static route on or off. Defaults to ON.

        .PARAMETER Description
        Free-text description of the route (max 255 chars).

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
        # Create a disabled static route toward a documentation/test range via Port1
        New-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0" -Interface "Port1" -Status OFF -Description "Lab segment via Port1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live against the lab firewall: creation succeeds (code 200) with a dotted-
        decimal Netmask; the INTEGER form from the parameter table was rejected (code 501,
        InvalidParams /UnicastRoute/Netmask). Also measured: the firewall does not enforce
        DestinationIP+Netmask as unique - creating a second, identical route answered 200 and
        produced two indistinguishable records - so this cmdlet checks for an existing match
        first and throws rather than silently creating an ambiguous duplicate.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/UnicastRoute/UnicastRoute.html

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/UnicastRoute/operations/AddUnicastRoute&UpdateUnicastRoute.html

        .LINK
        Get-SfosUnicastRoute
#>
function New-SfosUnicastRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 45)]
        [string]$DestinationIP,

        [Parameter(Mandatory)]
        [ValidateLength(1, 45)]
        [string]$Netmask,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [string]$Gateway,
        [string]$Interface,

        [ValidateRange(0, 255)]
        [int]$Distance = 0,

        [ValidateRange(1, 255)]
        [int]$AdministrativeDistance = 1,

        [ValidateSet('Enable', 'Disable')]
        [string]$Blackhole,

        [ValidateSet('ON', 'OFF')]
        [string]$Status = 'ON',

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Measured: the firewall does not enforce DestinationIP+Netmask as a unique key - see
    # the module-level comment at the top of this fragment. Checked here so this cmdlet
    # cannot itself create an ambiguous duplicate that a later Set-/Remove-SfosUnicastRoute
    # would have to guess between.
    $duplicate = @(Get-SfosUnicastRoute -DestinationIPLike $DestinationIP -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.DestinationIP -eq $DestinationIP -and $_.Netmask -eq $Netmask })
    if ($duplicate.Count -gt 0) {
        throw "A UnicastRoute object for '$DestinationIP/$Netmask' already exists."
    }

    $gatewayXml = if ($Gateway) { "<Gateway>$(ConvertTo-SfosXmlEscaped -Text $Gateway)</Gateway>" } else { '' }
    $interfaceXml = if ($Interface) { "<Interface>$(ConvertTo-SfosXmlEscaped -Text $Interface)</Interface>" } else { '' }
    $blackholeXml = if ($Blackhole) { "<Blackhole>$(ConvertTo-SfosXmlEscaped -Text $Blackhole)</Blackhole>" } else { '' }
    $descriptionXml = if ($PSBoundParameters.ContainsKey('Description')) { "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>" } else { '' }

    $inner = @"
<Set operation="add">
  <UnicastRoute>
    <IPFamily>$IPFamily</IPFamily>
    <DestinationIP>$(ConvertTo-SfosXmlEscaped -Text $DestinationIP)</DestinationIP>
    <Netmask>$(ConvertTo-SfosXmlEscaped -Text $Netmask)</Netmask>
    $gatewayXml
    $interfaceXml
    <Distance>$Distance</Distance>
    <AdministrativeDistance>$AdministrativeDistance</AdministrativeDistance>
    $blackholeXml
    <Status>$Status</Status>
    $descriptionXml
  </UnicastRoute>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("UnicastRoute '$DestinationIP/$Netmask' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating UnicastRoute object '$DestinationIP/$Netmask': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UnicastRoute' -Action 'create' -Target "$DestinationIP/$Netmask"
}

<#
        .SYNOPSIS
        Replaces an existing UnicastRoute object on the Sophos Firewall.

        .DESCRIPTION
        "Updates" a UnicastRoute object by removing the existing route for the given
        DestinationIP/Netmask and recreating it with the merged field values (read-modify-
        write; caller-supplied values win, everything else is kept from the current object).
        This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        Measured live: <Set operation="update"> answers code 500 "Operation could not be
        performed on Entity" for this entity regardless of content - a true no-op, full field
        sets, and variants with/without <OldConfiguration> all failed identically. This
        matches the existing Set-SfosStaticARP precedent, so this cmdlet removes and
        recreates the route instead, with a brief window where the route is absent. If the
        recreate step fails, the route is left removed rather than silently reverted.

        .PARAMETER DestinationIP
        Destination IP address of the target route (identifying key, together with Netmask).

        .PARAMETER Netmask
        Netmask of the target route, dotted-decimal (identifying key, together with
        DestinationIP).

        .PARAMETER Gateway
        Gateway IPv4/IPv6 address for the route. If omitted, the existing value is kept.

        .PARAMETER Interface
        Egress interface for the route. If omitted, the existing value is kept.

        .PARAMETER Distance
        Routing metric (0-255). If omitted, the existing value is kept.

        .PARAMETER AdministrativeDistance
        Administrative distance (1-255). If omitted, the existing value is kept.

        .PARAMETER Blackhole
        Creates or removes a blackhole route. If omitted, the existing value is kept.

        .PARAMETER Status
        Turns the static route on or off. If omitted, the existing value is kept.

        .PARAMETER Description
        Free-text description of the route. If omitted, the existing value is kept.

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
        None. Throws an exception if the delete-and-recreate fails.

        .EXAMPLE
        # Change only the description, everything else is preserved
        Set-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0" -Description "Backup path via Port1"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live end to end: create, remove-and-recreate with a changed field, and a
        follow-up Get confirmed both the changed and the preserved fields.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/UnicastRoute/operations/AddUnicastRoute&UpdateUnicastRoute.html

        .LINK
        Get-SfosUnicastRoute

        .LINK
        Remove-SfosUnicastRoute
#>
function Set-SfosUnicastRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$DestinationIP,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Netmask,

        [string]$Gateway,
        [string]$Interface,

        [ValidateRange(0, 255)]
        [int]$Distance,

        [ValidateRange(1, 255)]
        [int]$AdministrativeDistance,

        [ValidateSet('Enable', 'Disable')]
        [string]$Blackhole,

        [ValidateSet('ON', 'OFF')]
        [string]$Status,

        [ValidateLength(0, 255)]
        [string]$Description,

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
        $existing = @(Get-SfosUnicastRoute -DestinationIPLike $DestinationIP -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.DestinationIP -eq $DestinationIP -and $_.Netmask -eq $Netmask })

        if ($existing.Count -eq 0) {
            throw "The UnicastRoute object '$DestinationIP/$Netmask' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetGateway = if ($bp.ContainsKey('Gateway')) { $Gateway } else { [string]$current.Gateway }
        $targetInterface = if ($bp.ContainsKey('Interface')) { $Interface } else { [string]$current.Interface }
        $targetDistance = if ($bp.ContainsKey('Distance')) { $Distance } else { [int][string]$current.Distance }
        $targetAdminDistance = if ($bp.ContainsKey('AdministrativeDistance')) { $AdministrativeDistance } else { [int][string]$current.AdministrativeDistance }
        $targetBlackhole = if ($bp.ContainsKey('Blackhole')) { $Blackhole } else { [string]$current.Blackhole }
        $targetStatus = if ($bp.ContainsKey('Status')) { $Status } else { [string]$current.Status }
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$current.Description }
        $targetIPFamily = [string]$current.IPFamily

        if (-not $PSCmdlet.ShouldProcess("UnicastRoute '$DestinationIP/$Netmask' on $($params.Firewall)", 'Replace (remove and recreate)')) {
            return
        }

        Remove-SfosUnicastRoute -DestinationIP $DestinationIP -Netmask $Netmask -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false

        $newArgs = @{
            DestinationIP          = $DestinationIP
            Netmask                = $Netmask
            IPFamily               = $targetIPFamily
            Gateway                = $targetGateway
            Interface              = $targetInterface
            Distance               = $targetDistance
            AdministrativeDistance = $targetAdminDistance
            Status                 = $targetStatus
            Description            = $targetDescription
            Firewall               = $params.Firewall
            Port                   = $params.Port
            Username               = $params.Username
            Password               = $params.Password
            SkipCertificateCheck   = $params.SkipCertificateCheck
            Confirm                = $false
        }
        # A route that was never configured as a blackhole route comes back from Get with an
        # empty Blackhole. Passing that '' on would fail New-SfosUnicastRoute's
        # ValidateSet('Enable','Disable') during parameter binding, making every such route
        # impossible to update - found by the test suite. Only pass the value when it exists.
        if ($targetBlackhole) { $newArgs['Blackhole'] = $targetBlackhole }

        New-SfosUnicastRoute @newArgs
    }
}

<#
        .SYNOPSIS
        Removes a UnicastRoute object from the Sophos Firewall.

        .DESCRIPTION
        Removes a UnicastRoute object using the Sophos Firewall XML API. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        Measured live: sending only the documented composite key (DestinationIP + Netmask),
        or that plus Interface, answered code 200 on one attempt but code 500 "Operation could
        not be performed on Entity" on a later, structurally identical attempt against a
        differently-valued object - not reproducible on demand. Sending the full object body
        (every field Get-SfosUnicastRoute returns) succeeded reliably on every attempt, so
        this cmdlet reads the object back first and always sends the complete body.

        .PARAMETER DestinationIP
        Destination IP address of the target route (identifying key, together with Netmask).

        .PARAMETER Netmask
        Netmask of the target route, dotted-decimal (identifying key, together with
        DestinationIP).

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
        # Remove a test route
        Remove-SfosUnicastRoute -DestinationIP "203.0.113.0" -Netmask "255.255.255.0"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Verified live: removal followed by Get-SfosUnicastRoute confirmed the record no
        longer exists.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/UnicastRoute/operations/Delete%20Unicast%20Route.html

        .LINK
        Get-SfosUnicastRoute
#>
function Remove-SfosUnicastRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$DestinationIP,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Netmask,

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
        $existing = @(Get-SfosUnicastRoute -DestinationIPLike $DestinationIP -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.DestinationIP -eq $DestinationIP -and $_.Netmask -eq $Netmask })

        if ($existing.Count -eq 0) {
            throw "The UnicastRoute object '$DestinationIP/$Netmask' was not found."
        }
        $current = $existing[0]

        if (-not $PSCmdlet.ShouldProcess("UnicastRoute '$DestinationIP/$Netmask' on $($params.Firewall)", 'Remove')) {
            return
        }

        $gatewayXml = if ($current.Gateway) { "<Gateway>$(ConvertTo-SfosXmlEscaped -Text ([string]$current.Gateway))</Gateway>" } else { '' }
        $interfaceXml = if ($current.Interface) { "<Interface>$(ConvertTo-SfosXmlEscaped -Text ([string]$current.Interface))</Interface>" } else { '' }
        $blackholeXml = if ($current.Blackhole) { "<Blackhole>$(ConvertTo-SfosXmlEscaped -Text ([string]$current.Blackhole))</Blackhole>" } else { '' }
        $descriptionXml = if ($current.Description) { "<Description>$(ConvertTo-SfosXmlEscaped -Text ([string]$current.Description))</Description>" } else { '' }

        $inner = @"
<Remove>
  <UnicastRoute>
    <IPFamily>$([string]$current.IPFamily)</IPFamily>
    <DestinationIP>$(ConvertTo-SfosXmlEscaped -Text ([string]$current.DestinationIP))</DestinationIP>
    <Netmask>$(ConvertTo-SfosXmlEscaped -Text ([string]$current.Netmask))</Netmask>
    $gatewayXml
    $interfaceXml
    <Distance>$([string]$current.Distance)</Distance>
    <AdministrativeDistance>$([string]$current.AdministrativeDistance)</AdministrativeDistance>
    $blackholeXml
    <Status>$([string]$current.Status)</Status>
    $descriptionXml
  </UnicastRoute>
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
            throw "Error removing UnicastRoute object '$DestinationIP/$Netmask': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UnicastRoute' -Action 'remove' -Target "$DestinationIP/$Netmask"
    }
}

#endregion

#region MulticastRoute

<#
        .SYNOPSIS
        Retrieves MulticastRoute objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for MulticastRoute objects. MulticastRoute has no
        Name element; it is identified by the composite key SourceIPAddress +
        MulticastAddress. By default the cmdlet returns PowerShell-friendly objects. Use
        -AsXml to return the raw XML nodes.

        Only one server-side filter key is ever sent, per the documented single-key
        limitation; the result is always filtered again client-side for every requested
        field, combined with AND.

        .PARAMETER SourceIPAddressLike
        Filters routes whose SourceIPAddress contains the given substring. Sent to the
        firewall as the server-side filter (SourceIPAddress is the entity's mandatory field)
        and re-applied client-side.

        .PARAMETER MulticastAddressLike
        Filters routes whose MulticastAddress contains the given substring. Applied client-
        side only.

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
        # List every multicast route
        Get-SfosMulticastRoute

        .NOTES
        Minimum supported PowerShell version: 5.1
        Confirmed live: the root element matches the documented entity name and folder name
        (MulticastRoute), unlike most other entities in this API area. The lab firewall has no
        multicast routes configured, so this Get was only verified on the empty-result path
        ("No. of records Zero."); server-side filter honouring for SourceIPAddress could not be
        confirmed against a real record.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/MulticastRoute/MulticastRoute.html

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/MulticastRoute/operations/AddMulticastRoute&EditMulticastRoute.html
#>
function Get-SfosMulticastRoute {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$SourceIPAddressLike,
        [string]$MulticastAddressLike,

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
    if ($SourceIPAddressLike) {
        $srcLikeEsc = ConvertTo-SfosXmlEscaped -Text $SourceIPAddressLike
        $filterXml = ('<Filter><key name="SourceIPAddress" criteria="like">{0}</key></Filter>' -f $srcLikeEsc)
    }

    $inner = @"
<Get>
  <MulticastRoute>
    $filterXml
  </MulticastRoute>
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
        throw "Error retrieving MulticastRoute objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # MulticastRoute carries no Status data field, so the generic ObjectName-scoped check
    # is safe here (unlike UnicastRoute above).
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MulticastRoute' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/MulticastRoute[SourceIPAddress]' | ForEach-Object -Process {
        $_.Node
    }

    if ($SourceIPAddressLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.SourceIPAddress -like "*$SourceIPAddressLike*" })
    }
    if ($MulticastAddressLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.MulticastAddress -like "*$MulticastAddressLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $routeObjects = foreach ($node in @($nodes)) {
        $destinations = foreach ($destNode in @($node.SelectNodes('DestinationInterfaceList/DestinationInterface'))) {
            [PSCustomObject]@{
                Interface  = [string]$destNode.Interface
                TunnelType = [string]$destNode.TunnelType
            }
        }

        [PSCustomObject]@{
            SourceIPAddress          = [string]$node.SourceIPAddress
            SourceTunnel             = [string]$node.SourceTunnel
            SourceInterface          = [string]$node.SourceInterface
            MulticastAddress         = [string]$node.MulticastAddress
            DestinationInterfaceList = @($destinations)
        }
    }

    return @($routeObjects)
}

<#
        .SYNOPSIS
        Creates a new MulticastRoute object on the Sophos Firewall.

        .DESCRIPTION
        Creates a MulticastRoute object on the Sophos Firewall XML API. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        NOT confirmed against the live firewall: every documented-shape variant tried (with
        and without SourceInterface, with and without TunnelType, with and without the
        DestinationInterfaceList wrapper, the exact sample field order) answered code 500
        "Operation could not be performed on Entity". The lab firewall's MulticastConfiguration
        singleton reads MulticastForwardingSetting = Disable, which is the most likely gate,
        but MulticastConfiguration has no documented write operation to test that hypothesis,
        so it was not attempted. This cmdlet is implemented documentation-faithful and
        verified at the XML-generation level only, per the existing New-SfosSSLTLSInspectionRule
        precedent.

        .PARAMETER SourceIPAddress
        Source IPv4 address of the multicast traffic. Cannot be a multicast, reserved,
        loopback, unspecified, broadcast or link-local address.

        .PARAMETER MulticastAddress
        Destination multicast IPv4 address (the multicast group).

        .PARAMETER SourceInterface
        Source interface to accept the multicast traffic on. Optional; mutually exclusive
        with -SourceTunnel in practice, not enforced here since neither could be verified
        live.

        .PARAMETER SourceTunnel
        Source tunnel type (SystemInterface, IPSec or GRE) instead of a plain interface.
        Optional.

        .PARAMETER DestinationInterface
        One or more destination interface names to forward the multicast traffic to. Must be
        the same length as -DestinationTunnelType when both are supplied.

        .PARAMETER DestinationTunnelType
        Tunnel type (SystemInterface, IPSec or GRE) for each entry in -DestinationInterface,
        matched by position. Must be the same length as -DestinationInterface when both are
        supplied.

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
        # Build the request for a multicast test route (not confirmed to succeed - see .NOTES)
        New-SfosMulticastRoute -SourceIPAddress "203.0.113.10" -MulticastAddress "239.255.255.10" -DestinationInterface "Port1" -DestinationTunnelType "SystemInterface" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT live-verified - see .DESCRIPTION. Every attempt against the lab firewall answered
        code 500 regardless of field combination.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/MulticastRoute/operations/AddMulticastRoute&EditMulticastRoute.html

        .LINK
        Get-SfosMulticastRoute
#>
function New-SfosMulticastRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SourceIPAddress,

        [Parameter(Mandatory)]
        [string]$MulticastAddress,

        [string]$SourceInterface,

        [ValidateSet('SystemInterface', 'IPSec', 'GRE')]
        [string]$SourceTunnel,

        [string[]]$DestinationInterface,

        [ValidateSet('SystemInterface', 'IPSec', 'GRE')]
        [string[]]$DestinationTunnelType,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    if ($DestinationInterface -and $DestinationTunnelType -and $DestinationInterface.Count -ne $DestinationTunnelType.Count) {
        throw "MulticastRoute '$SourceIPAddress -> $MulticastAddress': -DestinationInterface and -DestinationTunnelType must supply the same number of entries."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $destXml = ''
    for ($i = 0; $i -lt @($DestinationInterface).Count; $i++) {
        $ifaceEsc = ConvertTo-SfosXmlEscaped -Text $DestinationInterface[$i]
        $tunnelType = if ($DestinationTunnelType -and $i -lt $DestinationTunnelType.Count) { $DestinationTunnelType[$i] } else { '' }
        $tunnelTypeXml = if ($tunnelType) { "<TunnelType>$tunnelType</TunnelType>" } else { '' }
        $destXml += "<DestinationInterface><Interface>$ifaceEsc</Interface>$tunnelTypeXml</DestinationInterface>"
    }

    $sourceInterfaceXml = if ($SourceInterface) { "<SourceInterface>$(ConvertTo-SfosXmlEscaped -Text $SourceInterface)</SourceInterface>" } else { '' }
    $sourceTunnelXml = if ($SourceTunnel) { "<SourceTunnel>$SourceTunnel</SourceTunnel>" } else { '' }

    $inner = @"
<Set operation="add">
  <MulticastRoute>
    <SourceIPAddress>$(ConvertTo-SfosXmlEscaped -Text $SourceIPAddress)</SourceIPAddress>
    $sourceInterfaceXml
    $sourceTunnelXml
    <MulticastAddress>$(ConvertTo-SfosXmlEscaped -Text $MulticastAddress)</MulticastAddress>
    <DestinationInterfaceList>
      $destXml
    </DestinationInterfaceList>
  </MulticastRoute>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("MulticastRoute '$SourceIPAddress -> $MulticastAddress' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating MulticastRoute object '$SourceIPAddress -> $MulticastAddress': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MulticastRoute' -Action 'create' -Target "$SourceIPAddress -> $MulticastAddress"
}

<#
        .SYNOPSIS
        Updates an existing MulticastRoute object on the Sophos Firewall.

        .DESCRIPTION
        Updates a MulticastRoute object using <Set operation="update">, reading the current
        object first and resending every field, overriding only what the caller explicitly
        passes (read-modify-write). Includes the <OldConfiguration> subtree the documented
        sample shows, carrying the unchanged identifying key. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        NOT confirmed against the live firewall: no MulticastRoute object could be created to
        update (see New-SfosMulticastRoute). Implemented documentation-faithful and verified
        at the XML-generation level only.

        .PARAMETER SourceIPAddress
        Source IPv4 address of the target route (identifying key, together with
        MulticastAddress).

        .PARAMETER MulticastAddress
        Multicast group address of the target route (identifying key, together with
        SourceIPAddress).

        .PARAMETER SourceInterface
        Source interface to accept the multicast traffic on. If omitted, the existing value
        is kept.

        .PARAMETER SourceTunnel
        Source tunnel type (SystemInterface, IPSec or GRE). If omitted, the existing value is
        kept.

        .PARAMETER DestinationInterface
        One or more destination interface names. If omitted, the existing list is kept. Must
        be the same length as -DestinationTunnelType when both are supplied.

        .PARAMETER DestinationTunnelType
        Tunnel type for each entry in -DestinationInterface, matched by position. If omitted,
        the existing list is kept.

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
        # Change the destination interface list only
        Set-SfosMulticastRoute -SourceIPAddress "203.0.113.10" -MulticastAddress "239.255.255.10" -DestinationInterface "Port1" -DestinationTunnelType "SystemInterface"

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT live-verified - see .DESCRIPTION.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/MulticastRoute/operations/AddMulticastRoute&EditMulticastRoute.html

        .LINK
        Get-SfosMulticastRoute
#>
function Set-SfosMulticastRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$SourceIPAddress,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$MulticastAddress,

        [string]$SourceInterface,

        [ValidateSet('SystemInterface', 'IPSec', 'GRE')]
        [string]$SourceTunnel,

        [string[]]$DestinationInterface,

        [ValidateSet('SystemInterface', 'IPSec', 'GRE')]
        [string[]]$DestinationTunnelType,

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
        if ($DestinationInterface -and $DestinationTunnelType -and $DestinationInterface.Count -ne $DestinationTunnelType.Count) {
            throw "MulticastRoute '$SourceIPAddress -> $MulticastAddress': -DestinationInterface and -DestinationTunnelType must supply the same number of entries."
        }

        $existing = @(Get-SfosMulticastRoute -SourceIPAddressLike $SourceIPAddress -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.SourceIPAddress -eq $SourceIPAddress -and $_.MulticastAddress -eq $MulticastAddress })

        if ($existing.Count -eq 0) {
            throw "The MulticastRoute object '$SourceIPAddress -> $MulticastAddress' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetSourceInterface = if ($bp.ContainsKey('SourceInterface')) { $SourceInterface } else { [string]$current.SourceInterface }
        $targetSourceTunnel = if ($bp.ContainsKey('SourceTunnel')) { $SourceTunnel } else { [string]$current.SourceTunnel }
        $targetDestInterfaces = if ($bp.ContainsKey('DestinationInterface')) { @($DestinationInterface) } else { @($current.DestinationInterfaceList | ForEach-Object { $_.Interface }) }
        $targetDestTunnelTypes = if ($bp.ContainsKey('DestinationTunnelType')) { @($DestinationTunnelType) } else { @($current.DestinationInterfaceList | ForEach-Object { $_.TunnelType }) }

        if (-not $PSCmdlet.ShouldProcess("MulticastRoute '$SourceIPAddress -> $MulticastAddress' on $($params.Firewall)", 'Update')) {
            return
        }

        $destXml = ''
        for ($i = 0; $i -lt $targetDestInterfaces.Count; $i++) {
            $ifaceEsc = ConvertTo-SfosXmlEscaped -Text $targetDestInterfaces[$i]
            $tunnelType = if ($i -lt $targetDestTunnelTypes.Count) { $targetDestTunnelTypes[$i] } else { '' }
            $tunnelTypeXml = if ($tunnelType) { "<TunnelType>$tunnelType</TunnelType>" } else { '' }
            $destXml += "<DestinationInterface><Interface>$ifaceEsc</Interface>$tunnelTypeXml</DestinationInterface>"
        }

        $sourceInterfaceXml = if ($targetSourceInterface) { "<SourceInterface>$(ConvertTo-SfosXmlEscaped -Text $targetSourceInterface)</SourceInterface>" } else { '' }
        $sourceTunnelXml = if ($targetSourceTunnel) { "<SourceTunnel>$targetSourceTunnel</SourceTunnel>" } else { '' }

        $inner = @"
<Set operation="update">
  <MulticastRoute>
    <SourceIPAddress>$(ConvertTo-SfosXmlEscaped -Text $SourceIPAddress)</SourceIPAddress>
    $sourceInterfaceXml
    $sourceTunnelXml
    <MulticastAddress>$(ConvertTo-SfosXmlEscaped -Text $MulticastAddress)</MulticastAddress>
    <DestinationInterfaceList>
      $destXml
    </DestinationInterfaceList>
    <OldConfiguration>
      <SourceIPAddress>$(ConvertTo-SfosXmlEscaped -Text $SourceIPAddress)</SourceIPAddress>
      <MulticastAddress>$(ConvertTo-SfosXmlEscaped -Text $MulticastAddress)</MulticastAddress>
    </OldConfiguration>
  </MulticastRoute>
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
            throw "Error updating MulticastRoute object '$SourceIPAddress -> $MulticastAddress': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MulticastRoute' -Action 'update' -Target "$SourceIPAddress -> $MulticastAddress"
    }
}

<#
        .SYNOPSIS
        Removes a MulticastRoute object from the Sophos Firewall.

        .DESCRIPTION
        Removes a MulticastRoute object using the Sophos Firewall XML API and the documented
        composite key (SourceIPAddress + MulticastAddress). This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        NOT confirmed against the live firewall: no MulticastRoute object could be created to
        remove (see New-SfosMulticastRoute). A delete against a non-existent key answered code
        500, consistent with the documented status table (200/500/527) and with the same
        non-specific 500 measured for Remove-SfosUnicastRoute against a non-existent object.

        .PARAMETER SourceIPAddress
        Source IPv4 address of the target route (identifying key, together with
        MulticastAddress).

        .PARAMETER MulticastAddress
        Multicast group address of the target route (identifying key, together with
        SourceIPAddress).

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
        # Remove a multicast route
        Remove-SfosMulticastRoute -SourceIPAddress "203.0.113.10" -MulticastAddress "239.255.255.10"

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT live-verified end to end - see .DESCRIPTION. The error path (delete of a
        non-existent key, code 500) was confirmed live.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/MulticastRoute/operations/Delete%20Multicast%20Route.html

        .LINK
        Get-SfosMulticastRoute
#>
function Remove-SfosMulticastRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$SourceIPAddress,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$MulticastAddress,

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
        if (-not $PSCmdlet.ShouldProcess("MulticastRoute '$SourceIPAddress -> $MulticastAddress' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Remove>
  <MulticastRoute>
    <SourceIPAddress>$(ConvertTo-SfosXmlEscaped -Text $SourceIPAddress)</SourceIPAddress>
    <MulticastAddress>$(ConvertTo-SfosXmlEscaped -Text $MulticastAddress)</MulticastAddress>
  </MulticastRoute>
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
            throw "Error removing MulticastRoute object '$SourceIPAddress -> $MulticastAddress': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MulticastRoute' -Action 'remove' -Target "$SourceIPAddress -> $MulticastAddress"
    }
}

#endregion

#region MulticastConfiguration

<#
        .SYNOPSIS
        Retrieves the MulticastConfiguration settings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the MulticastConfiguration singleton (global
        multicast forwarding setting). There is exactly one instance of this element per
        firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to
        return the raw XML node.

        No Set-SfosMulticastConfiguration cmdlet exists: the vendor documentation page for
        this entity (Multicast/Multicast.html) has an empty Description and an empty
        Operations section - no operation, not even Get, is documented for it at all. This Get
        is undocumented but works (measured), consistent with the existing finding that Get is
        generally available even when the docs only show write operations, or no operations at
        all. Without a documented write path this cmdlet stays read-only, per the existing
        Set-SfosGuestUser precedent.

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
        # Check whether multicast forwarding is enabled device-wide
        Get-SfosMulticastConfiguration

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: MulticastForwardingSetting = Disable on the lab firewall. This value
        also explains why MulticastRoute objects could not be created during this task's
        verification (see New-SfosMulticastRoute) - unconfirmed, since there is no documented
        write path to test that hypothesis.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/Multicast/Multicast.html
#>
function Get-SfosMulticastConfiguration {
    # PSUseSingularNouns is suppressed on purpose: <MulticastConfiguration> is the entity's
    # own singleton name, not a plural container - it has no singular child element.
    # the project build rules, section 3 gives the Sophos wire spelling precedence here.
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

    $inner = '<Get><MulticastConfiguration></MulticastConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MulticastConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MulticastConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/MulticastConfiguration')
    if (-not $node) {
        throw 'MulticastConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        MulticastForwardingSetting = [string]$node.MulticastForwardingSetting
    }
}

#endregion

#region PIMDynamicRouting

<#
        .SYNOPSIS
        Retrieves the PIMDynamicRouting settings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the PIMDynamicRouting singleton (device-wide
        PIM-SM dynamic multicast routing configuration). There is exactly one instance of this
        element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use
        -AsXml to return the raw XML node.

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
        # Check whether dynamic PIM routing is enabled device-wide
        Get-SfosPIMDynamicRouting

        .NOTES
        Minimum supported PowerShell version: 5.1
        Measured live: ManagePIM = Disable and CandidateRP is an empty self-closing tag on the
        lab firewall - not the text "Disable" the parameter table's value list (Disable/
        Static/Dynamic) implies for an unconfigured RP. Because no RP is configured, the
        nested StaticRPIP/DynamicRIP subtrees never appeared in the live response and their
        shape could not be confirmed.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/PIM/PIM.html

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/PIM/operations/PIM-SMConfiguration.html
#>
function Get-SfosPIMDynamicRouting {
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

    $inner = '<Get><PIMDynamicRouting></PIMDynamicRouting></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving PIMDynamicRouting: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PIMDynamicRouting' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/PIMDynamicRouting')
    if (-not $node) {
        throw 'PIMDynamicRouting could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $interfaces = [string[]]@($node.SelectNodes('InterfaceList/Interface') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })
    $staticRPGroups = [string[]]@($node.SelectNodes('StaticRPIP/GroupIP/IPAddress') | ForEach-Object -Process { $_.InnerText } | Where-Object { $_ })
    $staticRPIPNode = $node.SelectSingleNode('StaticRPIP/IPAddress')

    return [PSCustomObject]@{
        ManagePIM       = [string]$node.ManagePIM
        InterfaceList   = $interfaces
        CandidateRP     = [string]$node.CandidateRP
        StaticRPIP      = if ($staticRPIPNode) { [string]$staticRPIPNode.InnerText } else { '' }
        StaticRPGroupIP = $staticRPGroups
    }
}

<#
        .SYNOPSIS
        Updates the PIMDynamicRouting settings on the Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide PIMDynamicRouting singleton. This cmdlet reads the current
        settings first and resends every field, overriding only what the caller explicitly
        passes (read-modify-write). This cmdlet supports ShouldProcess; use -WhatIf to preview
        the change.

        WARNING: ManagePIM switches dynamic multicast routing on or off for the entire device.
        Per this task's explicit instruction this cmdlet was implemented and checked
        structurally only - it was never executed against the lab firewall, matching the
        existing Set-SfosAdminAuthentication precedent for security-critical, device-wide
        settings.

        .PARAMETER ManagePIM
        Enables or disables PIM to provide dynamic multicast support on the device. If
        omitted, the value currently on the firewall is kept.

        .PARAMETER InterfaceList
        Interfaces on which PIM is enabled. If omitted, the existing list is kept.

        .PARAMETER CandidateRP
        Selects how the rendezvous point is determined (Disable, Static or Dynamic). If
        omitted, the value currently on the firewall is kept.

        .PARAMETER StaticRPIP
        Unicast IP address used as the static RP, when -CandidateRP is Static. If omitted, the
        value currently on the firewall is kept.

        .PARAMETER StaticRPGroupIP
        Multicast group IP addresses or networks served by the static RP. If omitted, the
        existing list is kept.

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
        # Preview enabling PIM on Port1 without sending the request
        Set-SfosPIMDynamicRouting -ManagePIM Enable -InterfaceList "Port1" -WhatIf

        .NOTES
        Minimum supported PowerShell version: 5.1
        NOT verified against the live firewall as a write - deliberately not exercised because
        this is a device-wide dynamic routing toggle. The nesting and field names are inferred
        from the documented sample XML on the PIM-SM Configuration operation page.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Routing/PIM/operations/PIM-SMConfiguration.html

        .LINK
        Get-SfosPIMDynamicRouting
#>
function Set-SfosPIMDynamicRouting {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$ManagePIM,

        [string[]]$InterfaceList,

        [ValidateSet('Disable', 'Static', 'Dynamic')]
        [string]$CandidateRP,

        [string]$StaticRPIP,

        [string[]]$StaticRPGroupIP,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosPIMDynamicRouting -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetManagePIM = if ($PSBoundParameters.ContainsKey('ManagePIM')) { $ManagePIM } else { [string]$existing.ManagePIM }
    $targetInterfaces = if ($PSBoundParameters.ContainsKey('InterfaceList')) { @($InterfaceList) } else { @($existing.InterfaceList) }
    $targetCandidateRP = if ($PSBoundParameters.ContainsKey('CandidateRP')) { $CandidateRP } else { [string]$existing.CandidateRP }
    $targetStaticRPIP = if ($PSBoundParameters.ContainsKey('StaticRPIP')) { $StaticRPIP } else { [string]$existing.StaticRPIP }
    $targetStaticRPGroupIP = if ($PSBoundParameters.ContainsKey('StaticRPGroupIP')) { @($StaticRPGroupIP) } else { @($existing.StaticRPGroupIP) }

    if (-not $PSCmdlet.ShouldProcess("PIMDynamicRouting on $($params.Firewall)", 'Update')) {
        return
    }

    $interfaceXml = ''
    foreach ($iface in $targetInterfaces) {
        if (-not $iface) { continue }
        $interfaceXml += "<Interface>$(ConvertTo-SfosXmlEscaped -Text $iface)</Interface>"
    }

    $staticRPXml = ''
    if ($targetStaticRPIP) {
        $groupXml = ''
        foreach ($groupIp in $targetStaticRPGroupIP) {
            if (-not $groupIp) { continue }
            $groupXml += "<IPAddress>$(ConvertTo-SfosXmlEscaped -Text $groupIp)</IPAddress>"
        }
        $staticRPXml = @"
    <StaticRPIP>
      <IPAddress>$(ConvertTo-SfosXmlEscaped -Text $targetStaticRPIP)</IPAddress>
      <GroupIP>
        $groupXml
      </GroupIP>
    </StaticRPIP>
"@
    }

    $candidateRPXml = if ($targetCandidateRP) { "<CandidateRP>$(ConvertTo-SfosXmlEscaped -Text $targetCandidateRP)</CandidateRP>" } else { '' }

    $inner = @"
<Set operation="update">
  <PIMDynamicRouting>
    <ManagePIM>$(ConvertTo-SfosXmlEscaped -Text $targetManagePIM)</ManagePIM>
    <InterfaceList>
      $interfaceXml
    </InterfaceList>
    $candidateRPXml
    $staticRPXml
  </PIMDynamicRouting>
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
        throw "Error updating PIMDynamicRouting: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PIMDynamicRouting' -Action 'update'
}

#endregion

