#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.1' }

<#
        .SYNOPSIS
        Manages routing on a Sophos Firewall: gateways, health checks, SD-WAN, unicast and multicast routes.

        .DESCRIPTION
        PowerShell module for the CONFIGURE > Routing area of the Sophos XGS / SFOS 22.0 XML
        API. Provides functions to create, read, update and delete gateway objects and health
        check profiles, SD-WAN profiles and policy routes, unicast routes, multicast routes,
        the multicast forwarding setting and PIM dynamic routing.

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        These cmdlets change how a live firewall forwards traffic. A wrong route or a removed
        gateway decides whether packets still reach their destination, and a change to the
        management path can also cut off the API session used to correct it. Every Set-*
        cmdlet reads the current object first and writes it back complete.

        Total Functions: 32 (31 exported, 1 internal helper) - see README.md for the full
        cmdlet table.

        .EXAMPLE
        Connect-SfosFirewall -Firewall '192.168.1.1' -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosGatewayHost | Format-Table Name, GatewayIP, Interface
        Get-SfosHealthCheckProfileStatus

        Connects to the firewall and lists the configured gateways with their health state.

        .EXAMPLE
        New-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Interface 'Port1' -Status OFF
        Set-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Status ON

        Creates a disabled static route and enables it afterwards.

        .EXAMPLE
        Get-SfosSDWANPolicyRoute | Format-Table Name, IPFamily
        Get-SfosSDWANPolicyRouteStatus

        Lists the SD-WAN policy routes together with their enabled state.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>


# Group: Gateways and health checks.
# Entities: GatewayHost (API documentation folder GatewayObject), HealthCheckProfile
# (documentation folder MonitorObject), HealthCheckProfileStatus (documentation folder
# MonitorObjectStatus).
#
# The enable flag of a gateway is spelled <Healthcheck> (lowercase c) on the wire, not
# <HealthCheck> as the sample XML in the documentation shows. The API validates Name,
# GatewayIP, Interface and IPFamily individually and names the offending field on a bad
# value, but not Healthcheck, MailNotification, Interval or Timeout.
#
# GatewayIP must lie in the subnet of the chosen Interface. An address outside that
# subnet is rejected, whether it is a public or a private address.

#region GatewayHost

<#
.SYNOPSIS
    Retrieves gateway objects from a Sophos Firewall.

.DESCRIPTION
    Returns the gateway objects defined under Routing > Gateways. A gateway object names
    the next hop and the interface used to reach it, and is used as a target in unicast
    routes, SD-WAN policy routes and health check profiles. Use this cmdlet to review the
    existing gateways or to feed them into another cmdlet through the pipeline. The cmdlet
    only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

    A default gateway that the firewall derives from an interface, for example a DHCP
    lease, is not a gateway object and is not returned here.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only gateways whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER GatewayIPLike
    Optional. Returns only gateways whose IP address contains the given text anywhere.
    Applied on the client. If omitted, the address is not used to filter.

.PARAMETER InterfaceLike
    Optional. Returns only gateways whose interface name contains the given text anywhere.
    Applied on the client. If omitted, the interface is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.Management.Automation.PSCustomObject. One object per gateway, with the
    properties Name, IPFamily, GatewayIP, Interface, NetworkZone, Healthcheck,
    MailNotification, Interval, Timeout, FailureRetries and MonitoringConditionList.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no object
    matches.

.EXAMPLE
    Get-SfosGatewayHost

    Lists every gateway object on the firewall of the current connection.

.EXAMPLE
    Get-SfosGatewayHost -NameLike 'ISP1'

    Lists the gateways whose name contains 'ISP1'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Creates a gateway object on a Sophos Firewall.

.DESCRIPTION
    Creates a gateway object under Routing > Gateways. A gateway names the next hop and
    the outgoing interface, and is used as a target in unicast routes, SD-WAN policy
    routes and health check profiles. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with write permission for routing objects.

    When -Healthcheck is 'ON', -Interval, -Timeout, -FailureRetries and at least one
    -MonitoringCondition entry are required. When -Healthcheck is 'OFF', those values are
    not needed.

.PARAMETER Name
    Required. Name of the gateway. Maximum 50 characters, must not contain a comma.

.PARAMETER IPFamily
    Required. Address family of the gateway. Valid values: IPv4, IPv6.

.PARAMETER GatewayIP
    Required. IP address of the gateway. The address must lie in the subnet of the chosen
    -Interface; an address outside that subnet is rejected.

.PARAMETER Interface
    Required. Outgoing interface for the gateway, for example 'Port1'.

.PARAMETER NetworkZone
    Optional. Zone assigned to the gateway. If omitted, no zone is set.

.PARAMETER Healthcheck
    Optional. Enables health-check monitoring for the gateway. Valid values: ON, OFF.
    Default: OFF.

.PARAMETER MailNotification
    Optional. Sends an email notification when the gateway status changes. Valid values:
    ON, OFF. Default: OFF.

.PARAMETER Interval
    Required when -Healthcheck is ON. Probe interval in seconds, 5-65535.

.PARAMETER Timeout
    Required when -Healthcheck is ON. Response timeout in seconds, 1-10.

.PARAMETER FailureRetries
    Required when -Healthcheck is ON. Number of failed probes before the gateway is
    marked down, 1-10.

.PARAMETER MonitoringCondition
    Required when -Healthcheck is ON. One or more health-check rules, each a
    PSCustomObject with the properties Protocol (PING or TCP), IPAddress, and optionally
    Port and Condition (AND or OR, applies to the next rule in the list).

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    creation.

.EXAMPLE
    New-SfosGatewayHost -Name 'ISP1' -IPFamily IPv4 -GatewayIP '192.168.1.254' -Interface 'Port1' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosGatewayHost -Name 'ISP1' -IPFamily IPv4 -GatewayIP '192.168.1.254' -Interface 'Port1'

    Creates a gateway with health-check monitoring disabled.

.EXAMPLE
    $rule = [PSCustomObject]@{ Protocol = 'PING'; IPAddress = '192.168.1.254'; Port = '*' }
    New-SfosGatewayHost -Name 'ISP1' -IPFamily IPv4 -GatewayIP '192.168.1.254' -Interface 'Port1' -Healthcheck ON -Interval 60 -Timeout 5 -FailureRetries 3 -MonitoringCondition $rule

    Creates a gateway with health-check monitoring enabled, using a single PING rule.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    Updates a gateway object on a Sophos Firewall.

.DESCRIPTION
    Changes one or more fields of an existing gateway. The cmdlet reads the current object
    first and sends the complete entity back, so fields you do not pass keep their current
    value. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with write permission for routing objects.

    -Healthcheck controls whether Interval, Timeout, FailureRetries and
    MonitoringCondition are sent. When you switch it from OFF to ON in the same call, pass
    -Interval, -Timeout, -FailureRetries and -MonitoringCondition too, because there is no
    previous value to fall back to.

.PARAMETER Name
    Required. Name of the gateway to update. Accepts pipeline input by property name.

.PARAMETER IPFamily
    Optional. Address family of the gateway. Valid values: IPv4, IPv6. If omitted, the
    current value is kept.

.PARAMETER GatewayIP
    Optional. IP address of the gateway. If omitted, the current value is kept.

.PARAMETER Interface
    Optional. Outgoing interface for the gateway. If omitted, the current value is kept.

.PARAMETER NetworkZone
    Optional. Zone assigned to the gateway. If omitted, the current value is kept.

.PARAMETER Healthcheck
    Optional. Enables health-check monitoring for the gateway. Valid values: ON, OFF. If
    omitted, the current value is kept.

.PARAMETER MailNotification
    Optional. Sends an email notification when the gateway status changes. Valid values:
    ON, OFF. If omitted, the current value is kept.

.PARAMETER Interval
    Optional. Probe interval in seconds, 5-65535. If omitted, the current value is kept.

.PARAMETER Timeout
    Optional. Response timeout in seconds, 1-10. If omitted, the current value is kept.

.PARAMETER FailureRetries
    Optional. Number of failed probes before the gateway is marked down, 1-10. If omitted,
    the current value is kept.

.PARAMETER MonitoringCondition
    Optional. Complete replacement list of health-check rules, each a PSCustomObject with
    the properties Protocol (PING or TCP), IPAddress, and optionally Port and Condition
    (AND or OR). If omitted, the current list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.String. Accepts a gateway name by property name, so Get-SfosGatewayHost |
    Set-SfosGatewayHost works.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosGatewayHost -Name 'ISP1' -MailNotification ON -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosGatewayHost -Name 'ISP1' -MailNotification ON

    Turns on mail notification for the gateway. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    Removes a gateway object from a Sophos Firewall.

.DESCRIPTION
    Deletes a gateway object under Routing > Gateways. The cmdlet reads the object first
    and reports a clear error if the name does not exist. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with write permission for routing objects.

.PARAMETER Name
    Required. Name of the gateway to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.String. Accepts a gateway name by property name, so Get-SfosGatewayHost |
    Remove-SfosGatewayHost works.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the gateway does not exist or
    the firewall rejects the removal.

.EXAMPLE
    Remove-SfosGatewayHost -Name 'ISP1' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosGatewayHost -Name 'ISP1'

    Removes the gateway named ISP1.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    Retrieves health check profiles from a Sophos Firewall.

.DESCRIPTION
    Returns the health check profiles defined under Routing > Health Check Profiles. A
    health check profile groups one or more probe targets used to decide whether a
    gateway or SD-WAN link is up. Use this cmdlet to review the existing profiles or to
    feed them into another cmdlet through the pipeline. The cmdlet only reads; nothing on
    the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only profiles whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.Management.Automation.PSCustomObject. One object per profile, with the
    properties Name, IPFamily, ProbeInterval, ResponseTimeout, ProbesResponseFailure,
    ProbeResponseSuccess, Status and ProbeTargets. Status is the enabled state as an
    integer, as delivered by the firewall. ProbeTargets is a list of objects with
    conditionid, monitorip, monitormethod, operator and port. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosHealthCheckProfile

    Lists every health check profile on the firewall of the current connection.

.EXAMPLE
    Get-SfosHealthCheckProfile -NameLike 'ISP'

    Lists the profiles whose name contains 'ISP'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Creates a health check profile on a Sophos Firewall.

.DESCRIPTION
    Creates a health check profile under Routing > Health Check Profiles. A profile groups
    one or more probe targets and is attached to a gateway or an SD-WAN profile to decide
    whether that link is up. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with write permission for
    routing objects.

.PARAMETER Name
    Required. Name of the profile. Maximum 125 characters, must not contain a comma.

.PARAMETER IPFamily
    Optional. Address family of the profile. Valid values: IPv4, IPv6. Default: IPv4.

.PARAMETER ProbeInterval
    Optional. Interval between probes in seconds, 1-65535. If omitted, the firewall applies
    its own default.

.PARAMETER ResponseTimeout
    Optional. Time in seconds within which a target must respond, 1-10. If omitted, the
    firewall applies its own default.

.PARAMETER ProbesResponseFailure
    Optional. Number of consecutive failed probes before the profile is marked down, 1-10.
    If omitted, the firewall applies its own default.

.PARAMETER ProbeResponseSuccess
    Optional. Number of consecutive successful probes before the profile is marked up,
    1-10. If omitted, the firewall applies its own default.

.PARAMETER ProbeTarget
    Required. One or more probe targets, each a PSCustomObject with the property
    monitormethod (PING or TCP), and optionally monitorip, port and operator (& or |,
    default |).

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    creation.

.EXAMPLE
    $t = [PSCustomObject]@{ monitormethod = 'PING'; monitorip = '203.0.113.10'; port = '0'; operator = '|' }
    New-SfosHealthCheckProfile -Name 'WAN-Probe' -IPFamily IPv4 -ProbeTarget $t -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    $t = [PSCustomObject]@{ monitormethod = 'PING'; monitorip = '203.0.113.10'; port = '0'; operator = '|' }
    New-SfosHealthCheckProfile -Name 'WAN-Probe' -IPFamily IPv4 -ProbeTarget $t

    Creates a health check profile with a single PING probe target.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    Updates a health check profile on a Sophos Firewall.

.DESCRIPTION
    Changes one or more fields of an existing health check profile. The cmdlet reads the
    current object first and sends the complete entity back, so fields you do not pass keep
    their current value. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with write permission for
    routing objects.

.PARAMETER Name
    Required. Name of the profile to update. Accepts pipeline input by property name.

.PARAMETER IPFamily
    Optional. Address family of the profile. Valid values: IPv4, IPv6. If omitted, the
    current value is kept.

.PARAMETER ProbeInterval
    Optional. Interval between probes in seconds, 1-65535. If omitted, the current value is
    kept.

.PARAMETER ResponseTimeout
    Optional. Time in seconds within which a target must respond, 1-10. If omitted, the
    current value is kept.

.PARAMETER ProbesResponseFailure
    Optional. Number of consecutive failed probes before the profile is marked down, 1-10.
    If omitted, the current value is kept.

.PARAMETER ProbeResponseSuccess
    Optional. Number of consecutive successful probes before the profile is marked up,
    1-10. If omitted, the current value is kept.

.PARAMETER ProbeTarget
    Optional. Complete replacement list of probe targets, each a PSCustomObject with the
    property monitormethod, and optionally monitorip, port and operator. If omitted, the
    current list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.String. Accepts a profile name by property name, so Get-SfosHealthCheckProfile |
    Set-SfosHealthCheckProfile works.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosHealthCheckProfile -Name 'WAN-Probe' -ProbeInterval 30 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosHealthCheckProfile -Name 'WAN-Probe' -ProbeInterval 30

    Changes the probe interval of the profile. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    Removes a health check profile from a Sophos Firewall.

.DESCRIPTION
    Deletes a health check profile under Routing > Health Check Profiles. Unlike most
    Remove-* cmdlets in this module, this cmdlet does not read the object first; it sends
    the removal directly and reports an error if the firewall rejects it. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with write permission for routing objects.

.PARAMETER Name
    Required. Name of the profile to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.String. Accepts a profile name by property name, so Get-SfosHealthCheckProfile |
    Remove-SfosHealthCheckProfile works.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosHealthCheckProfile -Name 'WAN-Probe' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosHealthCheckProfile -Name 'WAN-Probe'

    Removes the health check profile named WAN-Probe.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    Retrieves health check status records from a Sophos Firewall.

.DESCRIPTION
    Returns the enabled state of the health check attached to a gateway or SD-WAN profile,
    or standing alone for a profile that is not attached to either. A record tied to a
    gateway or SD-WAN profile is named HealthCheckObject_GW_<GatewayName> or
    HealthCheckObject_SDWAN_<ProfileName>; a standalone profile keeps its own name. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

    Filters are applied on the client, against the full list of records.

.PARAMETER NameLike
    Optional. Returns only records whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.Management.Automation.PSCustomObject. One object per record, with the properties
    Name and Status (ON or OFF). Returns System.Xml.XmlElement when -AsXml is used, and an
    empty array when no record matches.

.EXAMPLE
    Get-SfosHealthCheckProfileStatus

    Lists every health check status record on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # No server-side filter for this entity: a full, unfiltered Get; -NameLike is applied
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
    Turns a health check status record on or off on a Sophos Firewall.

.DESCRIPTION
    Changes the enabled state of the health check attached to a gateway or SD-WAN profile,
    or of a standalone profile. This is the only write operation for this entity; there is
    no separate create or delete. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with write permission for
    routing objects.

.PARAMETER Name
    Required. Name of the health check status record to change. Accepts pipeline input by
    property name.

.PARAMETER Status
    Required. New state of the record. Valid values: ON, OFF.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for routing
    objects. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

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
    System.String. Accepts a record name by property name, so
    Get-SfosHealthCheckProfileStatus | Set-SfosHealthCheckProfileStatus works.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosHealthCheckProfileStatus -Name 'HealthCheckObject_GW_ISP1' -Status OFF -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosHealthCheckProfileStatus -Name 'HealthCheckObject_GW_ISP1' -Status OFF

    Turns off the health check status record for the gateway ISP1.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

<#
    Group: SD-WAN routing.
    Entities: SDWANProfile, SDWANPolicyRoute, SDWANPolicyRouteStatus. SDWANPolicyRouteStatus
    has only a read and a toggle operation; there is no create or delete for it. The wire
    root elements are <SDWANProfile>, <SDWANPolicyRoute> and <SDWANPolicyRouteStatus>, which
    do not always match the corresponding API documentation folder name.
#>

#region SDWANPolicyRoute-internal helpers (not exported)

<#
.SYNOPSIS
    Normalises a DSCPMarking value for the wire. Internal helper, not exported.

.DESCRIPTION
    A DSCPMarking value round-trips through the API as the same string it was written
    with, with one exception: the codepoint that Get returns as the bare number '0' is
    rejected on write unless sent as '0-Best Effort'. This helper applies that one
    substitution; every other value passes through unchanged.

.PARAMETER Value
    DSCPMarking value to normalise, as read back from the firewall or supplied by the
    caller.
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
        Retrieves SD-WAN profiles from a Sophos Firewall.

        .DESCRIPTION
        Returns the SD-WAN profiles defined under Routing > SD-WAN Routes. An SD-WAN profile
        groups gateways with a selection strategy and is used as a target in SD-WAN policy
        routes. Use this cmdlet to review the existing profiles or to feed them into another
        cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        .PARAMETER NameLike
        Optional. Returns only profiles whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for routing
        objects. If omitted, the value from the current connection is used.

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
        System.Management.Automation.PSCustomObject. One object per profile, with the
        properties Name, SLAStrategy, GatewayPreferences, EnableSLA, IsLatency, IsJitter and
        IsPacketloss. Returns System.Xml.XmlElement when -AsXml is used, and an empty array
        when no object matches.

        .EXAMPLE
        Get-SfosSDWANProfile

        Lists every SD-WAN profile on the firewall of the current connection.

        .EXAMPLE
        Get-SfosSDWANProfile -NameLike 'MainOffice'

        Lists the profiles whose name contains 'MainOffice'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosSDWANProfile
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
        Creates an SD-WAN profile on a Sophos Firewall.

        .DESCRIPTION
        Creates an SD-WAN profile under Routing > SD-WAN Routes. A profile groups one or
        more gateways with a selection strategy and is used as a target in SD-WAN policy
        routes. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission for routing
        objects.

        .PARAMETER Name
        Required. Name of the profile. 1-60 characters, must not contain a comma.

        .PARAMETER Description
        Optional. Free-text description, maximum 255 characters. If omitted, no
        description is set.

        .PARAMETER IPFamily
        Optional. Address family of the profile. Valid value: IPv4.

        .PARAMETER GatewayName
        Required. One or more names of existing gateway objects, in priority order, to add
        to the profile's gateway preference list.

        .PARAMETER GatewayWeights
        Optional. Load-balancing weight per gateway, matching -GatewayName by position.
        Supply either none or exactly one value per -GatewayName entry.

        .PARAMETER EnableSLA
        Required. Turns SLA-based gateway selection on or off. Valid values: ON, OFF.

        .PARAMETER SLAStrategy
        Optional. Quality-matching approach. Valid values: BestQuality, CustomSLA.

        .PARAMETER IsLatency
        Optional. Enables latency as an SLA criterion. Valid values: ON, OFF.

        .PARAMETER IsJitter
        Optional. Enables jitter as an SLA criterion. Valid values: ON, OFF.

        .PARAMETER IsPacketloss
        Optional. Enables packet loss as an SLA criterion. Valid values: ON, OFF.

        .PARAMETER LatencyValue
        Optional. Maximum latency threshold in milliseconds, 1-60000.

        .PARAMETER JitterValue
        Optional. Maximum jitter threshold in milliseconds, 1-60000.

        .PARAMETER PacketlossValue
        Optional. Maximum packet loss threshold in percent, 0-100.

        .PARAMETER ProbeCount
        Optional. Number of active link probes, 5-100.

        .PARAMETER RoutingStrategy
        Optional. Traffic routing method across the gateways. Valid values:
        FirstAvailable, Loadbalancing.

        .PARAMETER LBMethod
        Optional. Load-balancing algorithm, used when -RoutingStrategy is Loadbalancing.
        Valid values: WRR, SrcSticky, DestSticky, SrcDestSticky, ConnectionSticky.

        .PARAMETER HealthCheckProfileName
        Required. Name of an existing health check profile to associate with this profile.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosSDWANProfile -Name 'Branch-Profile' -GatewayName 'Branch-Gateway' -EnableSLA OFF -HealthCheckProfileName 'HealthCheckObject_Branch' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosSDWANProfile -Name 'Branch-Profile' -GatewayName 'Branch-Gateway' -EnableSLA OFF -HealthCheckProfileName 'HealthCheckObject_Branch'

        Creates a profile with a single gateway and SLA-based selection turned off.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANProfile
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an SD-WAN profile on a Sophos Firewall.

        .DESCRIPTION
        Changes one or more fields of an existing SD-WAN profile. The cmdlet reads the
        current profile first and sends the complete entity back, so fields you do not pass
        keep their current value. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with write permission
        for routing objects.

        .PARAMETER Name
        Required. Name of the profile to update. Accepts pipeline input by property name.

        .PARAMETER Description
        Optional. Free-text description, maximum 255 characters. If omitted, the current
        value is kept.

        .PARAMETER IPFamily
        Optional. Address family of the profile. Valid value: IPv4. If omitted, the current
        value is kept.

        .PARAMETER GatewayName
        Optional. Complete replacement list of gateway names, in priority order. If omitted,
        the current gateway preference list is kept, including each gateway's weight.

        .PARAMETER GatewayWeights
        Optional. Load-balancing weight per gateway, matching -GatewayName by position. Only
        meaningful together with -GatewayName.

        .PARAMETER EnableSLA
        Optional. Turns SLA-based gateway selection on or off. Valid values: ON, OFF. If
        omitted, the current value is kept.

        .PARAMETER SLAStrategy
        Optional. Quality-matching approach. Valid values: BestQuality, CustomSLA. If
        omitted, the current value is kept.

        .PARAMETER IsLatency
        Optional. Enables latency as an SLA criterion. Valid values: ON, OFF. If omitted,
        the current value is kept.

        .PARAMETER IsJitter
        Optional. Enables jitter as an SLA criterion. Valid values: ON, OFF. If omitted, the
        current value is kept.

        .PARAMETER IsPacketloss
        Optional. Enables packet loss as an SLA criterion. Valid values: ON, OFF. If
        omitted, the current value is kept.

        .PARAMETER LatencyValue
        Optional. Maximum latency threshold in milliseconds, 1-60000. If omitted, the
        current value is kept.

        .PARAMETER JitterValue
        Optional. Maximum jitter threshold in milliseconds, 1-60000. If omitted, the current
        value is kept.

        .PARAMETER PacketlossValue
        Optional. Maximum packet loss threshold in percent, 0-100. If omitted, the current
        value is kept.

        .PARAMETER ProbeCount
        Optional. Number of active link probes, 5-100. If omitted, the current value is
        kept.

        .PARAMETER RoutingStrategy
        Optional. Traffic routing method across the gateways. Valid values: FirstAvailable,
        Loadbalancing. If omitted, the current value is kept.

        .PARAMETER LBMethod
        Optional. Load-balancing algorithm, used when -RoutingStrategy is Loadbalancing.
        Valid values: WRR, SrcSticky, DestSticky, SrcDestSticky, ConnectionSticky. If
        omitted, the current value is kept.

        .PARAMETER HealthCheckProfileName
        Optional. Name of the associated health check profile. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts a profile name by property name, so Get-SfosSDWANProfile |
        Set-SfosSDWANProfile works.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSDWANProfile -Name 'Branch-Profile' -EnableSLA OFF -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSDWANProfile -Name 'Branch-Profile' -EnableSLA OFF

        Turns off SLA-based gateway selection. All other fields keep their current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANProfile
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

        # $targetSLAStrategy is a plain local variable, never re-bound through the
        # -SLAStrategy parameter, so a value outside the documented set can still be
        # preserved as read without tripping ValidateSet.
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
        Removes an SD-WAN profile from a Sophos Firewall.

        .DESCRIPTION
        Deletes an SD-WAN profile under Routing > SD-WAN Routes. If an SD-WAN policy route
        still references the profile, the firewall deletes that route along with the
        profile, without a separate warning. Check for dependent routes with
        Get-SfosSDWANPolicyRoute before removing a profile that may still be in use. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission for routing objects.

        .PARAMETER Name
        Required. Name of the profile to remove. Accepts pipeline input.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts a profile name, so Get-SfosSDWANProfile |
        Remove-SfosSDWANProfile works.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosSDWANProfile -Name 'Branch-Profile' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosSDWANPolicyRoute | Where-Object { $_.SDWANProfileName -eq 'Branch-Profile' }
        Remove-SfosSDWANProfile -Name 'Branch-Profile'

        Checks for policy routes that still reference the profile, then removes it.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANProfile
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves SD-WAN policy routes from a Sophos Firewall.

        .DESCRIPTION
        Returns the SD-WAN policy routes defined under Routing > SD-WAN Routes. A policy
        route matches traffic by source, destination, service, user or application and
        sends it over a chosen gateway or SD-WAN profile. Use this cmdlet to review the
        existing routes or to feed them into another cmdlet through the pipeline. The
        cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        The Status property returned here is the route's own enabled flag, separate from
        the record returned by Get-SfosSDWANPolicyRouteStatus for the same route.

        .PARAMETER NameLike
        Optional. Returns only routes whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

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
        System.Management.Automation.PSCustomObject. One object per route, with the
        properties Name, Description, IPFamily, SourceNetworks, DestinationNetworks,
        Services, Users, ApplicationObjects, LinkSelection, SDWANProfileName, Gateway,
        BackupGateway, Healthcheck, Interface, DSCPMarking and Status. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosSDWANPolicyRoute

        Lists every SD-WAN policy route on the firewall of the current connection.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosSDWANPolicyRoute
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
        Creates an SD-WAN policy route on a Sophos Firewall.

        .DESCRIPTION
        Creates an SD-WAN policy route under Routing > SD-WAN Routes. A policy route
        matches traffic by source, destination, service, user or application and sends it
        over a chosen gateway or SD-WAN profile. A newly created route is enabled
        immediately; use Set-SfosSDWANPolicyRouteStatus to disable it afterwards. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission for routing objects.

        .PARAMETER Name
        Required. Name of the route. 1-60 characters, must not contain a comma.

        .PARAMETER Description
        Optional. Free-text description, maximum 255 characters. If omitted, no
        description is set.

        .PARAMETER IPFamily
        Optional. Address family of the route. Valid values: IPv4, IPv6. Default: IPv4.

        .PARAMETER SourceNetwork
        Optional. Names of existing network or host objects to match as traffic sources. If
        omitted, the route matches any source.

        .PARAMETER DestinationNetwork
        Optional. Names of existing network or host objects to match as traffic
        destinations. If omitted, the route matches any destination.

        .PARAMETER Service
        Optional. Names of existing service objects to match. If omitted, the route matches
        any service.

        .PARAMETER User
        Optional. Names of users or groups whose traffic the route applies to. If omitted,
        the route applies to all users.

        .PARAMETER ApplicationObject
        Optional. Names of existing application objects to match. If omitted, the route
        matches any application.

        .PARAMETER LinkSelection
        Optional. Method of link selection. Valid values: SelectGateways,
        SelectSDWANProfile.

        .PARAMETER SDWANProfileName
        Required. Name of an existing SD-WAN profile to assign to the route.

        .PARAMETER Gateway
        Optional. Primary gateway for the route, used with -LinkSelection
        SelectGateways.

        .PARAMETER BackupGateway
        Optional. Backup gateway used when the primary gateway fails.

        .PARAMETER Healthcheck
        Optional. Route behavior when all gateways are down. Valid values: ON, OFF.

        .PARAMETER Interface
        Optional. Incoming interface that receives the packets this route matches.

        .PARAMETER DSCPMarking
        Optional. DSCP codepoint to match, as a bare number (0-63) optionally followed by
        -ClassName, for example '8-Class 1(CS1)'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosSDWANPolicyRoute -Name 'Branch-Route' -DestinationNetwork 'Branch-Net' -LinkSelection SelectSDWANProfile -SDWANProfileName 'Branch-Profile' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosSDWANPolicyRoute -Name 'Branch-Route' -DestinationNetwork 'Branch-Net' -LinkSelection SelectSDWANProfile -SDWANProfileName 'Branch-Profile'

        Creates a route that sends matching traffic through the named SD-WAN profile.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANPolicyRoute
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

    # IPFamily must always be present on the wire for this entity, unlike SDWANProfile's
    # IPFamily, which the firewall accepts omitted.
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
        Updates an SD-WAN policy route on a Sophos Firewall.

        .DESCRIPTION
        Changes one or more fields of an existing SD-WAN policy route. The cmdlet reads
        the current route first and sends the complete entity back, so fields you do not
        pass keep their current value. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for routing objects.

        .PARAMETER Name
        Required. Name of the route to update. Accepts pipeline input by property name.

        .PARAMETER Description
        Optional. Free-text description, maximum 255 characters. If omitted, the current
        value is kept.

        .PARAMETER IPFamily
        Optional. Address family of the route. Valid values: IPv4, IPv6. If omitted, the
        current value is kept.

        .PARAMETER SourceNetwork
        Optional. Complete replacement list of source network or host object names. If
        omitted, the current list is kept.

        .PARAMETER DestinationNetwork
        Optional. Complete replacement list of destination network or host object names.
        If omitted, the current list is kept.

        .PARAMETER Service
        Optional. Complete replacement list of service names. If omitted, the current list
        is kept.

        .PARAMETER User
        Optional. Complete replacement list of user or group names. If omitted, the
        current list is kept.

        .PARAMETER ApplicationObject
        Optional. Complete replacement list of application object names. If omitted, the
        current list is kept.

        .PARAMETER LinkSelection
        Optional. Method of link selection. Valid values: SelectGateways,
        SelectSDWANProfile. If omitted, the current value is kept.

        .PARAMETER SDWANProfileName
        Optional. Name of the assigned SD-WAN profile. If omitted, the current value is
        kept.

        .PARAMETER Gateway
        Optional. Primary gateway for the route. If omitted, the current value is kept.

        .PARAMETER BackupGateway
        Optional. Backup gateway used when the primary gateway fails. If omitted, the
        current value is kept.

        .PARAMETER Healthcheck
        Optional. Route behavior when all gateways are down. Valid values: ON, OFF. If
        omitted, the current value is kept.

        .PARAMETER Interface
        Optional. Incoming interface that receives the packets this route matches. If
        omitted, the current value is kept.

        .PARAMETER DSCPMarking
        Optional. DSCP codepoint to match, as a bare number (0-63) optionally followed by
        -ClassName. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts a route name by property name, so Get-SfosSDWANPolicyRoute
        | Set-SfosSDWANPolicyRoute works.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSDWANPolicyRoute -Name 'Branch-Route' -Interface 'Port2' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSDWANPolicyRoute -Name 'Branch-Route' -Interface 'Port2'

        Changes the incoming interface of the route. All other fields keep their current
        value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANPolicyRoute
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes an SD-WAN policy route from a Sophos Firewall.

        .DESCRIPTION
        Deletes an SD-WAN policy route under Routing > SD-WAN Routes. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for routing objects.

        .PARAMETER Name
        Required. Name of the route to remove. Accepts pipeline input.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts a route name, so Get-SfosSDWANPolicyRoute |
        Remove-SfosSDWANPolicyRoute works.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosSDWANPolicyRoute -Name 'Branch-Route' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosSDWANPolicyRoute -Name 'Branch-Route'

        Removes the SD-WAN policy route named Branch-Route.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANPolicyRoute
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves the enabled state of SD-WAN policy routes from a Sophos Firewall.

        .DESCRIPTION
        Returns the enabled/disabled status of every SD-WAN policy route. The identifying
        field of this entity is SDWANPolicyRouteName, not Name. Filters are applied on the
        client, against the full list of records. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER NameLike
        Optional. Returns only records whose route name contains the given text anywhere.
        This is a substring match, not a wildcard pattern. If omitted, the name is not
        used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

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
        System.Management.Automation.PSCustomObject. One object per route, with the
        properties SDWANPolicyRouteName and Status (ON or OFF). Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no record
        matches.

        .EXAMPLE
        Get-SfosSDWANPolicyRouteStatus

        Lists the enabled state of every SD-WAN policy route on the firewall of the current
        connection.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosSDWANPolicyRouteStatus
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
        [object]$Session,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # No Filter block: this entity answers 'Transaction fail' for any Filter, even one
    # matching an existing record. The full list is fetched and filtered client-side.
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

    # This entity's data rows carry their own code-less <Status>ON/OFF</Status>, and the
    # entity has no <Name> sibling to protect them under the shared status heuristic. A
    # coded status goes through the generic check; a code-less status is only accepted
    # here when it reads ON, OFF, or the empty-result wording.
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
        Enables or disables an SD-WAN policy route on a Sophos Firewall.

        .DESCRIPTION
        Changes the enabled state of an existing SD-WAN policy route. This is the only
        write operation for this entity; there is no separate create or delete. The
        cmdlet reads the status back after writing and reports an error if the route name
        does not exist or the status does not match what was requested. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for routing objects.

        .PARAMETER SDWANPolicyRouteName
        Required. Name of the route to toggle. Aliased as Name, so both
        Get-SfosSDWANPolicyRoute and Get-SfosSDWANPolicyRouteStatus bind by property name
        through the pipeline.

        .PARAMETER Status
        Required. New state of the route. Valid values: ON, OFF.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts a route name by property name, so Get-SfosSDWANPolicyRoute
        | Set-SfosSDWANPolicyRouteStatus works.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update or the change cannot be confirmed.

        .EXAMPLE
        Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName 'Branch-Route' -Status OFF -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName 'Branch-Route' -Status OFF

        Disables the SD-WAN policy route named Branch-Route.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSDWANPolicyRouteStatus
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

        # A coded 200 here does not guarantee the named route exists - confirm by reading
        # the status back, so a caller cannot mistake a silent no-op for success.
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

# Group: Static and multicast routing.
# Entities: UnicastRoute, MulticastRoute, MulticastConfiguration (read-only),
# PIMDynamicRouting.
#
# UnicastRoute has no Name element; it is identified by the composite key
# DestinationIP + Netmask, and Netmask is dotted-decimal on the wire, not a prefix
# length. Its own <Status>ON/OFF</Status> data field has no <Name> sibling, so
# Get-SfosUnicastRoute scopes the API-status check to responses that carry no
# <DestinationIP>, rather than to the whole response. The firewall accepts more than
# one UnicastRoute with the same DestinationIP and Netmask; New-SfosUnicastRoute
# checks for an existing match first and refuses to create an ambiguous duplicate.
#
# MulticastConfiguration has no documented write operation, so there is no
# Set-SfosMulticastConfiguration. PIMDynamicRouting is a device-wide dynamic-routing
# singleton.

#region UnicastRoute

<#
        .SYNOPSIS
        Retrieves static routes from a Sophos Firewall.

        .DESCRIPTION
        Returns the unicast static routes defined under Routing > Static Routes. A route
        has no name; it is identified by the combination of destination address and
        netmask. Use this cmdlet to review the existing routes or to feed them into
        another cmdlet through the pipeline. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly.

        .PARAMETER DestinationIPLike
        Optional. Returns only routes whose destination address contains the given text
        anywhere. This is a substring match, not a wildcard pattern. If omitted, the
        destination is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

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
        System.Management.Automation.PSCustomObject. One object per route, with the
        properties IPFamily, DestinationIP, Netmask, Gateway, Interface, Distance,
        AdministrativeDistance, Blackhole, Status and Description. Netmask is
        dotted-decimal, and Status is the route's own enabled flag (ON or OFF). Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosUnicastRoute

        Lists every static route on the firewall of the current connection.

        .EXAMPLE
        Get-SfosUnicastRoute -DestinationIPLike '203.0.113'

        Lists the routes whose destination address contains '203.0.113'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosUnicastRoute
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
        [object]$Session,

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

    # UnicastRoute's own <Status>ON/OFF</Status> data field is code-less and has no <Name>
    # sibling, so it would be misread as a broken API status under the generic heuristic.
    # An actual API status always appears on a <UnicastRoute> node with no <DestinationIP>,
    # so the check is scoped to that shape.
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
        Creates a static route on a Sophos Firewall.

        .DESCRIPTION
        Creates a unicast static route under Routing > Static Routes. The firewall does
        not enforce destination and netmask as a unique key, so this cmdlet checks for an
        existing route with the same destination and netmask first and refuses to create
        an ambiguous duplicate. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with write permission
        for routing objects.

        .PARAMETER DestinationIP
        Required. Destination IPv4 or IPv6 address of the route, maximum 45 characters.
        Must not be a multicast or loopback address.

        .PARAMETER Netmask
        Required. Netmask of the destination, dotted-decimal, for example
        '255.255.255.0'.

        .PARAMETER IPFamily
        Optional. Address family of the route. Default: IPv4.

        .PARAMETER Gateway
        Optional. Gateway IPv4 or IPv6 address for the route. If omitted, no gateway is
        set.

        .PARAMETER Interface
        Optional. Egress interface for the route. If omitted, no interface is set.

        .PARAMETER Distance
        Optional. Routing metric, 0-255. Default: 0.

        .PARAMETER AdministrativeDistance
        Optional. Administrative distance, 1-255. Default: 1.

        .PARAMETER Blackhole
        Optional. Creates a blackhole route. Valid values: Enable, Disable. Default:
        Disable.

        .PARAMETER Status
        Optional. Turns the route on or off. Valid values: ON, OFF. Default: ON.

        .PARAMETER Description
        Optional. Free-text description of the route, maximum 255 characters. If omitted,
        no description is set.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation, or if a route with the same destination and netmask already exists.

        .EXAMPLE
        New-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Interface 'Port1' -Status OFF -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Interface 'Port1' -Status OFF -Description 'Test segment via Port1'

        Creates a disabled static route toward 203.0.113.0/24 through Port1.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # The firewall does not enforce DestinationIP+Netmask as a unique key. Checked here so
    # this cmdlet cannot itself create an ambiguous duplicate.
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
        Updates a static route on a Sophos Firewall.

        .DESCRIPTION
        Changes one or more fields of an existing static route. Because an update fails on
        this entity, the cmdlet removes the route identified by -DestinationIP and -Netmask
        and recreates it with the merged field values, so the route briefly does not exist
        during the call. If the recreate step fails, the route is left removed rather than
        silently reverted. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with write permission for
        routing objects.

        .PARAMETER DestinationIP
        Required. Destination address of the route to update, together with -Netmask.

        .PARAMETER Netmask
        Required. Netmask of the route to update, dotted-decimal, together with
        -DestinationIP.

        .PARAMETER Gateway
        Optional. Gateway IPv4 or IPv6 address for the route. If omitted, the current
        value is kept.

        .PARAMETER Interface
        Optional. Egress interface for the route. If omitted, the current value is kept.

        .PARAMETER Distance
        Optional. Routing metric, 0-255. If omitted, the current value is kept.

        .PARAMETER AdministrativeDistance
        Optional. Administrative distance, 1-255. If omitted, the current value is kept.

        .PARAMETER Blackhole
        Optional. Creates or removes a blackhole route. Valid values: Enable, Disable. If
        omitted, the current value is kept.

        .PARAMETER Status
        Optional. Turns the route on or off. Valid values: ON, OFF. If omitted, the current
        value is kept.

        .PARAMETER Description
        Optional. Free-text description of the route. If omitted, the current value is
        kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal or the recreate.

        .EXAMPLE
        Set-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Description 'Backup path via Port1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -Description 'Backup path via Port1'

        Changes the description of the route. All other fields keep their current value.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        # impossible to update. Only pass the value when it exists.
        if ($targetBlackhole) { $newArgs['Blackhole'] = $targetBlackhole }

        New-SfosUnicastRoute @newArgs
    }
}

<#
        .SYNOPSIS
        Removes a static route from a Sophos Firewall.

        .DESCRIPTION
        Deletes the static route identified by -DestinationIP and -Netmask. The cmdlet
        reads the route first and sends its complete field set with the removal request.
        It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission for routing
        objects.

        .PARAMETER DestinationIP
        Required. Destination address of the route to remove, together with -Netmask.

        .PARAMETER Netmask
        Required. Netmask of the route to remove, dotted-decimal, together with
        -DestinationIP.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the route does not exist
        or the firewall rejects the removal.

        .EXAMPLE
        Remove-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosUnicastRoute -DestinationIP '203.0.113.0' -Netmask '255.255.255.0'

        Removes the static route toward 203.0.113.0/24.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves multicast routes from a Sophos Firewall.

        .DESCRIPTION
        Returns the multicast routes defined under Routing > Multicast Routing. A route
        has no name; it is identified by the combination of source address and multicast
        address. Use this cmdlet to review the existing routes or to feed them into
        another cmdlet through the pipeline. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly.

        You can combine both filters. The firewall itself evaluates only the
        SourceIPAddress filter, so both filters are applied again on the client. The
        result therefore always matches both filters you gave.

        .PARAMETER SourceIPAddressLike
        Optional. Returns only routes whose source address contains the given text
        anywhere. This is a substring match, not a wildcard pattern. If omitted, the
        source address is not used to filter.

        .PARAMETER MulticastAddressLike
        Optional. Returns only routes whose multicast address contains the given text
        anywhere. Applied on the client. If omitted, the multicast address is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

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
        System.Management.Automation.PSCustomObject. One object per route, with the
        properties SourceIPAddress, SourceTunnel, SourceInterface, MulticastAddress and
        DestinationInterfaceList. DestinationInterfaceList is a list of objects with
        Interface and TunnelType. Returns System.Xml.XmlElement when -AsXml is used, and
        an empty array when no object matches.

        .EXAMPLE
        Get-SfosMulticastRoute

        Lists every multicast route on the firewall of the current connection.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosMulticastRoute
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
        [object]$Session,

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
        Creates a multicast route on a Sophos Firewall.

        .DESCRIPTION
        Creates a multicast route under Routing > Multicast Routing. Multicast route
        write operations do not work on the current firmware. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for routing objects.

        .PARAMETER SourceIPAddress
        Required. Source IPv4 address of the multicast traffic. Must not be a multicast,
        reserved, loopback, unspecified, broadcast or link-local address.

        .PARAMETER MulticastAddress
        Required. Destination multicast IPv4 address, the multicast group.

        .PARAMETER SourceInterface
        Optional. Source interface to accept the multicast traffic on. If omitted, no
        source interface is set.

        .PARAMETER SourceTunnel
        Optional. Source tunnel type instead of a plain interface. Valid values:
        SystemInterface, IPSec, GRE.

        .PARAMETER DestinationInterface
        Required. One or more destination interface names to forward the multicast traffic
        to. Must be the same length as -DestinationTunnelType.

        .PARAMETER DestinationTunnelType
        Required. Tunnel type for each entry in -DestinationInterface, matched by
        position. Valid values: SystemInterface, IPSec, GRE. Must be the same length as
        -DestinationInterface.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosMulticastRoute -SourceIPAddress '203.0.113.10' -MulticastAddress '239.255.255.10' -DestinationInterface 'Port1' -DestinationTunnelType 'SystemInterface' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a multicast route on a Sophos Firewall.

        .DESCRIPTION
        Changes one or more fields of an existing multicast route. The cmdlet reads the
        current route first and sends the complete entity back, so fields you do not pass
        keep their current value. Multicast route write operations do not work on the
        current firmware. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with write permission for
        routing objects.

        .PARAMETER SourceIPAddress
        Required. Source address of the route to update, together with -MulticastAddress.

        .PARAMETER MulticastAddress
        Required. Multicast group address of the route to update, together with
        -SourceIPAddress.

        .PARAMETER SourceInterface
        Optional. Source interface to accept the multicast traffic on. If omitted, the
        current value is kept.

        .PARAMETER SourceTunnel
        Optional. Source tunnel type. Valid values: SystemInterface, IPSec, GRE. If
        omitted, the current value is kept.

        .PARAMETER DestinationInterface
        Optional. Complete replacement list of destination interface names. Must be the
        same length as -DestinationTunnelType when both are supplied. If omitted, the
        current list is kept.

        .PARAMETER DestinationTunnelType
        Optional. Tunnel type for each entry in -DestinationInterface, matched by
        position. If omitted, the current list is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. Accepts a route by property name, so Get-SfosMulticastRoute |
        Set-SfosMulticastRoute works.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosMulticastRoute -SourceIPAddress '203.0.113.10' -MulticastAddress '239.255.255.10' -DestinationInterface 'Port1' -DestinationTunnelType 'SystemInterface' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        # @() must wrap the WHOLE if/else: a one-element array returned from an if branch
        # unrolls to a scalar on assignment, and indexing that scalar string later takes
        # its first CHARACTER ('Port2' -> 'P') - only bites when the existing route has
        # exactly one destination.
        $targetDestInterfaces = @(if ($bp.ContainsKey('DestinationInterface')) { $DestinationInterface } else { $current.DestinationInterfaceList | ForEach-Object { $_.Interface } })
        $targetDestTunnelTypes = @(if ($bp.ContainsKey('DestinationTunnelType')) { $DestinationTunnelType } else { $current.DestinationInterfaceList | ForEach-Object { $_.TunnelType } })

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
        Removes a multicast route from a Sophos Firewall.

        .DESCRIPTION
        Deletes the multicast route identified by -SourceIPAddress and -MulticastAddress.
        Multicast route write operations do not work on the current firmware. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for routing objects.

        .PARAMETER SourceIPAddress
        Required. Source address of the route to remove, together with
        -MulticastAddress.

        .PARAMETER MulticastAddress
        Required. Multicast group address of the route to remove, together with
        -SourceIPAddress.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosMulticastRoute -SourceIPAddress '203.0.113.10' -MulticastAddress '239.255.255.10' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves the multicast forwarding setting from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide multicast forwarding setting. This is a singleton; there
        is exactly one instance per firewall, and there is no write operation for it, so
        this module has no matching Set cmdlet. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a
        PowerShell object. Useful when you need a field that the standard output does not
        show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with the property
        MulticastForwardingSetting. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosMulticastConfiguration

        Shows whether multicast forwarding is enabled device-wide.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosMulticastConfiguration {
    # PSUseSingularNouns is suppressed on purpose: <MulticastConfiguration> is the entity's
    # own singleton name, not a plural container - it has no singular child element, so the
    # Sophos wire spelling is used as-is.
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
        Retrieves the PIM dynamic routing configuration from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide PIM-SM dynamic multicast routing configuration. This is a
        singleton; there is exactly one instance per firewall. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a
        PowerShell object. Useful when you need a field that the standard output does not
        show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with the properties
        ManagePIM, InterfaceList, CandidateRP, StaticRPIP and StaticRPGroupIP. Returns
        System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosPIMDynamicRouting

        Shows whether dynamic PIM routing is enabled device-wide.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
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
        [object]$Session,

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
        Updates the PIM dynamic routing configuration on a Sophos Firewall.

        .DESCRIPTION
        Changes one or more fields of the device-wide PIM dynamic routing singleton. The
        cmdlet reads the current settings first and sends the complete entity back, so
        fields you do not pass keep their current value. ManagePIM turns dynamic
        multicast routing on or off for the whole device. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for routing objects.

        .PARAMETER ManagePIM
        Optional. Enables or disables PIM dynamic multicast routing on the device. Valid
        values: Enable, Disable. If omitted, the current value is kept.

        .PARAMETER InterfaceList
        Optional. Complete replacement list of interfaces on which PIM is enabled. If
        omitted, the current list is kept.

        .PARAMETER CandidateRP
        Optional. Selects how the rendezvous point is determined. Valid values: Disable,
        Static, Dynamic. If omitted, the current value is kept.

        .PARAMETER StaticRPIP
        Optional. Unicast IP address used as the static rendezvous point, when
        -CandidateRP is Static. If omitted, the current value is kept.

        .PARAMETER StaticRPGroupIP
        Optional. Complete replacement list of multicast group addresses or networks
        served by the static rendezvous point. If omitted, the current list is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        routing objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosPIMDynamicRouting -ManagePIM Enable -InterfaceList 'Port1' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosPIMDynamicRouting -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetManagePIM = if ($PSBoundParameters.ContainsKey('ManagePIM')) { $ManagePIM } else { [string]$existing.ManagePIM }
    # @() must wrap the whole if/else: a one-element array from a branch unrolls to a
    # scalar on assignment.
    $targetInterfaces = @(if ($PSBoundParameters.ContainsKey('InterfaceList')) { $InterfaceList } else { $existing.InterfaceList })
    $targetCandidateRP = if ($PSBoundParameters.ContainsKey('CandidateRP')) { $CandidateRP } else { [string]$existing.CandidateRP }
    $targetStaticRPIP = if ($PSBoundParameters.ContainsKey('StaticRPIP')) { $StaticRPIP } else { [string]$existing.StaticRPIP }
    $targetStaticRPGroupIP = @(if ($PSBoundParameters.ContainsKey('StaticRPGroupIP')) { $StaticRPGroupIP } else { $existing.StaticRPGroupIP })

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

