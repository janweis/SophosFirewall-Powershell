#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }

<#
        .SYNOPSIS
        Manages VPN on a Sophos Firewall: IPsec, SSL VPN, L2TP, PPTP, VPN profiles and failover groups.

        .DESCRIPTION
        Functions for the CONFIGURE > VPN area of the Sophos Firewall XML API (SFOS 22.0). The
        web admin splits this area into "Site-to-site VPN" and "Remote access VPN"; the API
        keeps one category, and so does this module.

        The module covers:
        - IPsec connections, VPN profiles (IKE policies) and failover groups
        - SSL VPN: tunnel access settings, policies, bookmarks and bookmark groups, and
          site-to-site client and server connections
        - L2TP and PPTP: the two configuration singletons, their member lists, and L2TP
          connections
        - The Sophos Connect client (read only)

        Connect once with Connect-SfosFirewall, then call the functions without connection
        parameters.

        .EXAMPLE
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosVPNProfile | Format-Table Name, KeyingMethod
        Get-SfosIPsecConnection
        Get-SfosSSLTunnelAccessSettings

        .EXAMPLE
        Get-SfosVPNProfile | Format-Table Name
        Remove-SfosVPNProfile -Name "Branch-IKEv2" -Confirm:$false
#>

#requires -Version 5.1
#requires -Modules SophosFirewall.Core

# SophosFirewall.VPN - IPsec core (VPNIPSecConnection, VPNProfile, VPNFailoverGroup,
# SophosConnectClient).
#
# Two structural points that apply across this region:
#
# 1. The write-operation response envelope is not the same shape as the Get envelope for
#    VPNIPSecConnection and VPNFailoverGroup. A <Get> wraps the data one level deeper than
#    the entity name (<VPNIPSecConnection><Configuration>...</Configuration>
#    </VPNIPSecConnection>, <VPNFailoverGroup><GroupDetail>...</GroupDetail>
#    </VPNFailoverGroup>), but <Set operation="add"> and (per the entity's own delete
#    contract) <Remove> answer with the outer entity element stripped entirely - the
#    response root goes straight to <Configuration>/<GroupDetail>. Consequently
#    Assert-SfosApiReturnSuccess is called with a different -ObjectName for Get
#    ('VPNIPSecConnection/Configuration', 'VPNFailoverGroup/GroupDetail') than for
#    New/Set/Remove ('Configuration', 'GroupDetail') on the same entity. Getting this wrong
#    does not throw - Get-SfosApiStatus finds no node and Assert-SfosApiReturnSuccess
#    silently returns as "no status", which would hide a real 501/504 as success. VPNProfile
#    does not have this problem: its Get, Add, Update and Remove responses all place
#    <Status> directly under <VPNProfile> with no extra wrapper, so one -ObjectName value
#    ('VPNProfile') covers every operation.
#
# 2. Set-SfosIPsecConnection follows the FileType/-Template pattern for PresharedKey:
#    -PresharedKey exists on New- (the field is documented and accepted in isolation by the
#    firewall's field-level validator), but is not accepted on Set-, because a
#    read-modify-write cannot preserve a value the module has not confirmed Get returns.

#region VPNIPSecConnection

<#
.SYNOPSIS
    Retrieves IPsec connection objects from a Sophos Firewall.

.DESCRIPTION
    Returns the IPsec connections defined under VPN > IPsec connections. Use this cmdlet to
    review existing connections or feed them into another cmdlet through the pipeline. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER ConnectionTypeLike
    Optional. Returns only objects whose connection type contains the given text anywhere.
    Applied on the client. If omitted, the connection type is not used to filter.

.PARAMETER RemoteHostLike
    Optional. Returns only objects whose remote host contains the given text anywhere.
    Applied on the client. If omitted, the remote host is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per IPsec connection, with
    properties such as Name, ConnectionType, Policy, AuthenticationType, PresharedKey,
    LocalSubnet, RemoteNetworkList, LocalID, RemoteID and Status. PresharedKey is returned as
    a hashed value, never as the plaintext key. Returns System.Xml.XmlElement when -AsXml is
    used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosIPsecConnection

    Lists every IPsec connection on the firewall of the current connection.

.EXAMPLE
    Get-SfosIPsecConnection -NameLike 'Branch'

    Lists all IPsec connections whose name contains 'Branch'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosIPsecConnection
#>
function Get-SfosIPsecConnection {
    [CmdletBinding()]
    param(
        [string]$NameLike,
        [string]$ConnectionTypeLike,
        [string]$RemoteHostLike,

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
  <VPNIPSecConnection>
    <Configuration>
      $filterXml
    </Configuration>
  </VPNIPSecConnection>
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
        throw "Error retrieving VPNIPSecConnection objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Get wraps data one level deeper than the entity name - see the fragment header comment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNIPSecConnection/Configuration' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/VPNIPSecConnection/Configuration[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $remoteNetworkNodes = @($node.SelectNodes('RemoteNetwork/Network'))
        $allowedUserNodes = @($node.SelectNodes('AllowedUser/User'))
        $presharedKeyNode = $node.SelectSingleNode('PresharedKey')

        [PSCustomObject]@{
            Name                      = [string]$node.Name
            Description               = [string]$node.Description
            ConnectionType            = [string]$node.ConnectionType
            Policy                    = [string]$node.Policy
            ActionOnVPNRestart        = [string]$node.ActionOnVPNRestart
            AuthenticationType        = [string]$node.AuthenticationType
            # Get returns PresharedKey as a salted hash, re-salted on every single write
            # regardless of content - same as SSLBookmark.Password (see that cmdlet's
            # .NOTES). Set-SfosIPsecConnection resends it with its hashform attribute so a
            # read-modify-write does not clear the key.
            PresharedKey              = if ($presharedKeyNode) { [string]$presharedKeyNode.InnerText } else { '' }
            PresharedKeyHashForm      = if ($presharedKeyNode -and $presharedKeyNode.Attributes['hashform']) { [string]$presharedKeyNode.Attributes['hashform'].Value } else { '' }
            LocalCertificate          = [string]$node.LocalCertificate
            RemoteCertificate         = [string]$node.RemoteCertificate
            SubnetFamily              = [string]$node.SubnetFamily
            EndpointFamily            = [string]$node.EndpointFamily
            LocalWANPort              = [string]$node.LocalWANPort
            AliasLocalWANPort         = [string]$node.AliasLocalWANPort
            RemoteHost                = [string]$node.RemoteHost
            LocalSubnet               = [string]$node.LocalSubnet
            NATedLAN                  = [string]$node.NATedLAN
            LocalIDType               = [string]$node.LocalIDType
            LocalID                   = [string]$node.LocalID
            AllowNATTraversal         = [string]$node.AllowNATTraversal
            RemoteNetworkList         = [string[]]@($remoteNetworkNodes | ForEach-Object -Process { [string]$_.InnerText } | Where-Object -FilterScript { $_ })
            RemoteIDType              = [string]$node.RemoteIDType
            RemoteID                  = [string]$node.RemoteID
            UserAuthenticationMode    = [string]$node.UserAuthenticationMode
            Username                  = [string]$node.Username
            AllowedUserList           = [string[]]@($allowedUserNodes | ForEach-Object -Process { [string]$_.InnerText } | Where-Object -FilterScript { $_ })
            Protocol                  = [string]$node.Protocol
            LocalPort                 = [string]$node.LocalPort
            RemotePort                = [string]$node.RemotePort
            DisconnectOnIdleInterval  = [string]$node.DisconnectOnIdleInterval
            Status                    = [string]$node.Status
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($ConnectionTypeLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.ConnectionType -like "*$ConnectionTypeLike*" })
    }
    if ($RemoteHostLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.RemoteHost -like "*$RemoteHostLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a new VPNIPSecConnection object on the Sophos Firewall.

.DESCRIPTION
    Creates an IPsec connection under VPN > IPsec connections, for site-to-site,
    host-to-host, remote-access or route-based tunnels. A newly created connection is
    inactive until it is switched on separately with Set-SfosIPsecConnection. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection, 1 to 100 characters. Must not contain a hyphen.

.PARAMETER ConnectionType
    Required. Type of the connection: RemoteAccess, SiteToSite, HostToHost or
    TunnelInterface.

.PARAMETER LocalIDType
    Required. Type of the local ID: DNS, IP Address, Email or DER ASN1 DN (X.509).

.PARAMETER LocalID
    Required. Local ID value, in the format matching -LocalIDType.

.PARAMETER RemoteIDType
    Required. Type of the remote ID: DNS, IP Address, Email or DER ASN1 DN (X.509).

.PARAMETER RemoteID
    Required. Remote ID value, in the format matching -RemoteIDType.

.PARAMETER LocalSubnet
    Optional. Name of an existing IPHost object for the local subnet. If omitted, no local
    subnet is sent.

.PARAMETER AliasLocalWANPort
    Required. Alias of the local WAN port, for example Port2.

.PARAMETER Description
    Optional. Free-text description of the connection. If omitted, the description is left
    empty.

.PARAMETER Policy
    Optional. Name of an existing VPN profile (IKE policy) to use for this connection. If
    omitted, the field is left empty.

.PARAMETER ActionOnVPNRestart
    Optional. Action to take on a VPN restart: Disable, RespondOnly or Initiate. If omitted,
    the field is left empty.

.PARAMETER AuthenticationType
    Optional. Authentication method: PresharedKey, DigitalCertificate or RSAKey. If omitted,
    the field is left empty.

.PARAMETER PresharedKey
    Optional. Pre-shared key, as a SecureString, 5 to 64 characters. Required by the
    firewall when -AuthenticationType is PresharedKey. If omitted, no key is sent.

.PARAMETER LocalCertificate
    Optional. Name of the local (appliance) certificate. If omitted, the field is left
    empty.

.PARAMETER RemoteCertificate
    Optional. Name of the remote certificate. If omitted, the field is left empty.

.PARAMETER SubnetFamily
    Optional. Address family of the subnets: IPv4, IPv6 or Dual. Default: IPv4.

.PARAMETER EndpointFamily
    Optional. Address family of the tunnel endpoints: IPv4 or IPv6. Default: IPv4.

.PARAMETER LocalWANPort
    Optional. Local listening interface, for example Port2. If omitted, the value of
    -AliasLocalWANPort is used.

.PARAMETER RemoteHost
    Optional. Remote peer host name or IP address.

.PARAMETER NATedLAN
    Optional. Name of an IPHost object used to NAT the local LAN. If omitted, the field is
    left empty.

.PARAMETER AllowNATTraversal
    Optional. Allows NAT traversal: Enable or Disable. If omitted, the field is left empty.

.PARAMETER RemoteNetwork
    Optional. Names of one or more existing IPHost/network objects for the remote network.
    If omitted, no remote network is sent.

.PARAMETER UserAuthenticationMode
    Optional. User authentication mode for this connection: Disable, AsServer or AsClient.
    If omitted, the field is left empty.

.PARAMETER ConnectionUsername
    Optional. User name for this connection's own user authentication. Unrelated to the
    -Username connection parameter used for the API login. If omitted, the field is left
    empty.

.PARAMETER ConnectionPassword
    Optional. Password for this connection's own user authentication, as a SecureString.
    Unrelated to the -Password connection parameter used for the API login. If omitted, the
    field is left empty.

.PARAMETER AllowedUser
    Optional. Names of one or more users allowed to use this connection. If omitted, no
    allowed users are sent.

.PARAMETER Protocol
    Optional. Protocol carried by the tunnel: ALL, UDP, TCP or ICMP. If omitted, the field
    is left empty.

.PARAMETER LocalPort
    Optional. Local port, 1-65535 or *. Default: *.

.PARAMETER RemotePort
    Optional. Remote port, 1-65535 or *. Default: *.

.PARAMETER DisconnectOnIdleInterval
    Optional. Idle disconnect interval, in seconds. If omitted, the field is left empty.

.PARAMETER Status
    Optional. Initial state of the connection: Active or Deactive. Default: Deactive.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    $psk = Read-Host -AsSecureString -Prompt 'Pre-shared key'
    New-SfosIPsecConnection -Name 'ExampleTunnel' -ConnectionType TunnelInterface `
        -Policy 'Head office (IKEv2)' -AuthenticationType PresharedKey -PresharedKey $psk `
        -AliasLocalWANPort 'Port2' -EndpointFamily IPv4 -SubnetFamily Dual -Protocol ALL `
        -UserAuthenticationMode Disable -RemoteHost '198.51.100.10' `
        -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
        -RemoteIDType 'IP Address' -RemoteID '198.51.100.10' `
        -ActionOnVPNRestart Initiate -Status Deactive -WhatIf

    Shows what a route-based site-to-site tunnel would look like without sending it to the
    firewall.

.EXAMPLE
    $psk = Read-Host -AsSecureString -Prompt 'Pre-shared key'
    New-SfosIPsecConnection -Name 'ExampleTunnel' -ConnectionType TunnelInterface `
        -Policy 'Head office (IKEv2)' -AuthenticationType PresharedKey -PresharedKey $psk `
        -AliasLocalWANPort 'Port2' -EndpointFamily IPv4 -SubnetFamily Dual -Protocol ALL `
        -UserAuthenticationMode Disable -RemoteHost '198.51.100.10' `
        -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
        -RemoteIDType 'IP Address' -RemoteID '198.51.100.10' `
        -ActionOnVPNRestart Initiate -Status Deactive

    Creates the connection in an inactive state. Activate it afterwards with
    Set-SfosIPsecConnection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosIPsecConnection
#>
function New-SfosIPsecConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RemoteAccess', 'SiteToSite', 'HostToHost', 'TunnelInterface')]
        [string]$ConnectionType,

        [Parameter(Mandatory)]
        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$LocalIDType,

        [Parameter(Mandatory)]
        [string]$LocalID,

        [Parameter(Mandatory)]
        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$RemoteIDType,

        [Parameter(Mandatory)]
        [string]$RemoteID,

        [string]$LocalSubnet,

        [Parameter(Mandatory)]
        [string]$AliasLocalWANPort,

        [string]$Description = '',
        [string]$Policy,
        [ValidateSet('Disable', 'RespondOnly', 'Initiate')]
        [string]$ActionOnVPNRestart,
        [ValidateSet('PresharedKey', 'DigitalCertificate', 'RSAKey')]
        [string]$AuthenticationType,
        [SecureString]$PresharedKey,
        [string]$LocalCertificate,
        [string]$RemoteCertificate,
        [ValidateSet('IPv4', 'IPv6', 'Dual')]
        [string]$SubnetFamily = 'IPv4',
        [ValidateSet('IPv4', 'IPv6')]
        [string]$EndpointFamily = 'IPv4',
        [string]$LocalWANPort,
        [string]$RemoteHost,
        [string]$NATedLAN,
        [ValidateSet('Enable', 'Disable')]
        [string]$AllowNATTraversal,
        [string[]]$RemoteNetwork,
        [ValidateSet('Disable', 'AsServer', 'AsClient')]
        [string]$UserAuthenticationMode,
        [string]$ConnectionUsername,
        [SecureString]$ConnectionPassword,
        [string[]]$AllowedUser,
        [ValidateSet('ALL', 'UDP', 'TCP', 'ICMP')]
        [string]$Protocol,
        [string]$LocalPort = '*',
        [string]$RemotePort = '*',
        [int]$DisconnectOnIdleInterval,
        [ValidateSet('Active', 'Deactive')]
        [string]$Status = 'Deactive',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # A hyphenated Name is rejected with a field-specific 501 naming
    # /VPNIPSecConnection/Configuration/Name, the same defect as SiteToSiteServer and
    # L2TPConnection (see those cmdlets' .NOTES). Checked here rather than through
    # -ValidatePattern so the error names the entity and explains why, matching this
    # project's other client-side pre-checks.
    if ($Name -match '-') {
        throw "The VPNIPSecConnection object name '$Name' must not contain a hyphen; the firewall rejects it with a field-specific 501 on Configuration/Name."
    }

    # With -LocalWANPort omitted, every SiteToSite/TunnelInterface create fails - the
    # firewall needs both AliasLocalWANPort and LocalWANPort populated with the same
    # interface. Default LocalWANPort to the alias unless the caller overrides it.
    if (-not $PSBoundParameters.ContainsKey('LocalWANPort')) {
        $LocalWANPort = $AliasLocalWANPort
    }

    if (-not $PSCmdlet.ShouldProcess("VPNIPSecConnection '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $e = { param($t) ConvertTo-SfosXmlEscaped -Text $t }

    $remoteNetworkXml = ''
    foreach ($net in $RemoteNetwork) {
        $remoteNetworkXml += "<Network>$(& $e $net)</Network>"
    }
    $allowedUserXml = ''
    foreach ($user in $AllowedUser) {
        $allowedUserXml += "<User>$(& $e $user)</User>"
    }

    $connectionPasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('ConnectionPassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ConnectionPassword)
        try {
            $connectionPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }

    $presharedKeyPlain = ''
    if ($PSBoundParameters.ContainsKey('PresharedKey')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PresharedKey)
        try {
            $presharedKeyPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }

    $optionalXml = ''
    if ($Policy) { $optionalXml += "<Policy>$(& $e $Policy)</Policy>" }
    if ($ActionOnVPNRestart) { $optionalXml += "<ActionOnVPNRestart>$ActionOnVPNRestart</ActionOnVPNRestart>" }
    if ($AuthenticationType) { $optionalXml += "<AuthenticationType>$AuthenticationType</AuthenticationType>" }
    if ($PSBoundParameters.ContainsKey('PresharedKey')) { $optionalXml += "<PresharedKey>$(& $e $presharedKeyPlain)</PresharedKey>" }
    if ($LocalCertificate) { $optionalXml += "<LocalCertificate>$(& $e $LocalCertificate)</LocalCertificate>" }
    if ($RemoteCertificate) { $optionalXml += "<RemoteCertificate>$(& $e $RemoteCertificate)</RemoteCertificate>" }
    if ($LocalSubnet) { $optionalXml += "<LocalSubnet>$(& $e $LocalSubnet)</LocalSubnet>" }
    if ($LocalWANPort) { $optionalXml += "<LocalWANPort>$(& $e $LocalWANPort)</LocalWANPort>" }
    if ($RemoteHost) { $optionalXml += "<RemoteHost>$(& $e $RemoteHost)</RemoteHost>" }
    if ($NATedLAN) { $optionalXml += "<NATedLAN>$(& $e $NATedLAN)</NATedLAN>" }
    if ($AllowNATTraversal) { $optionalXml += "<AllowNATTraversal>$AllowNATTraversal</AllowNATTraversal>" }
    if ($remoteNetworkXml) { $optionalXml += "<RemoteNetwork>$remoteNetworkXml</RemoteNetwork>" }
    if ($UserAuthenticationMode) { $optionalXml += "<UserAuthenticationMode>$UserAuthenticationMode</UserAuthenticationMode>" }
    if ($ConnectionUsername) { $optionalXml += "<Username>$(& $e $ConnectionUsername)</Username>" }
    if ($PSBoundParameters.ContainsKey('ConnectionPassword')) { $optionalXml += "<Password>$(& $e $connectionPasswordPlain)</Password>" }
    if ($allowedUserXml) { $optionalXml += "<AllowedUser>$allowedUserXml</AllowedUser>" }
    if ($Protocol) { $optionalXml += "<Protocol>$Protocol</Protocol>" }
    if ($LocalPort) { $optionalXml += "<LocalPort>$(& $e $LocalPort)</LocalPort>" }
    if ($RemotePort) { $optionalXml += "<RemotePort>$(& $e $RemotePort)</RemotePort>" }
    if ($PSBoundParameters.ContainsKey('DisconnectOnIdleInterval')) { $optionalXml += "<DisconnectOnIdleInterval>$DisconnectOnIdleInterval</DisconnectOnIdleInterval>" }

    $inner = @"
<Set operation="add">
  <VPNIPSecConnection>
    <Configuration>
      <Name>$(& $e $Name)</Name>
      <Description>$(& $e $Description)</Description>
      <ConnectionType>$ConnectionType</ConnectionType>
      <SubnetFamily>$SubnetFamily</SubnetFamily>
      <EndpointFamily>$EndpointFamily</EndpointFamily>
      <AliasLocalWANPort>$(& $e $AliasLocalWANPort)</AliasLocalWANPort>
      <LocalIDType>$LocalIDType</LocalIDType>
      <LocalID>$(& $e $LocalID)</LocalID>
      <RemoteIDType>$RemoteIDType</RemoteIDType>
      <RemoteID>$(& $e $RemoteID)</RemoteID>
      $optionalXml
      <Status>$Status</Status>
    </Configuration>
  </VPNIPSecConnection>
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
        throw "Error creating VPNIPSecConnection object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Write responses strip the outer entity wrapper - see the fragment header comment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Configuration' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing IPsec connection on a Sophos Firewall.

.DESCRIPTION
    Updates an IPsec connection under VPN > IPsec connections. Reads the current object
    first and sends the complete entity back, changing only the fields you pass; fields you
    omit keep their current value. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with permission to change
    VPN objects.

    Passing -Status also activates or deactivates the connection. This action is only sent
    when you set -Status explicitly, because the connection's active state is not part of
    what Get-SfosIPsecConnection reports back.

.PARAMETER Name
    Required. Name of the IPsec connection to update. Must not contain a hyphen. Accepts
    pipeline input by property name.

.PARAMETER Description
    Optional. Free-text description of the connection. If omitted, the current value is
    kept.

.PARAMETER Policy
    Optional. Name of an existing VPN profile (IKE policy). If omitted, the current value is
    kept.

.PARAMETER ActionOnVPNRestart
    Optional. Action to take on a VPN restart: Disable, RespondOnly or Initiate. If omitted,
    the current value is kept.

.PARAMETER PresharedKey
    Optional. New pre-shared key, as a SecureString. If omitted, the current key is kept.

.PARAMETER LocalWANPort
    Optional. Local listening interface. If omitted, the current value is kept.

.PARAMETER AliasLocalWANPort
    Optional. Alias of the local WAN port. If omitted, the current value is kept.

.PARAMETER SubnetFamily
    Optional. Address family of the subnets: IPv4, IPv6 or Dual. If omitted, the current
    value is kept.

.PARAMETER RemoteHost
    Optional. Remote peer host name or IP address. If omitted, the current value is kept.

.PARAMETER LocalSubnet
    Optional. Name of an existing IPHost object for the local subnet. If omitted, the
    current value is kept.

.PARAMETER LocalIDType
    Optional. Type of the local ID: DNS, IP Address, Email or DER ASN1 DN (X.509). If
    omitted, the current value is kept.

.PARAMETER LocalID
    Optional. Local ID value, in the format matching -LocalIDType. If omitted, the current
    value is kept.

.PARAMETER RemoteNetwork
    Optional. Complete replacement list of remote network object names. If omitted, the
    current list is kept.

.PARAMETER RemoteIDType
    Optional. Type of the remote ID: DNS, IP Address, Email or DER ASN1 DN (X.509). If
    omitted, the current value is kept.

.PARAMETER RemoteID
    Optional. Remote ID value, in the format matching -RemoteIDType. If omitted, the current
    value is kept.

.PARAMETER UserAuthenticationMode
    Optional. User authentication mode for this connection: Disable, AsServer or AsClient.
    If omitted, the current value is kept.

.PARAMETER Protocol
    Optional. Protocol carried by the tunnel: ALL, UDP, TCP or ICMP. If omitted, the current
    value is kept.

.PARAMETER Status
    Optional. Activates or deactivates the connection: Active or Deactive. If omitted, the
    connection's active state is left unchanged.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosIPsecConnection.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosIPsecConnection -Name 'ExampleTunnel' -Status Active -WhatIf

    Shows what activating the connection would do without sending it to the firewall.

.EXAMPLE
    Set-SfosIPsecConnection -Name 'ExampleTunnel' -Status Active

    Activates the connection. All other fields keep their current value.

.EXAMPLE
    Get-SfosIPsecConnection -NameLike 'ExampleTunnel' | Set-SfosIPsecConnection -Description 'Updated'

    Updates the description of the matching connection through the pipeline.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosIPsecConnection

.LINK
    New-SfosIPsecConnection
#>
function Set-SfosIPsecConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$Description,
        [string]$Policy,
        [ValidateSet('Disable', 'RespondOnly', 'Initiate')]
        [string]$ActionOnVPNRestart,
        [SecureString]$PresharedKey,
        [string]$LocalWANPort,
        [string]$AliasLocalWANPort,
        [ValidateSet('IPv4', 'IPv6', 'Dual')]
        [string]$SubnetFamily,
        [string]$RemoteHost,
        [string]$LocalSubnet,
        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$LocalIDType,
        [string]$LocalID,
        [string[]]$RemoteNetwork,
        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$RemoteIDType,
        [string]$RemoteID,
        [ValidateSet('Disable', 'AsServer', 'AsClient')]
        [string]$UserAuthenticationMode,
        [ValidateSet('ALL', 'UDP', 'TCP', 'ICMP')]
        [string]$Protocol,
        [ValidateSet('Active', 'Deactive')]
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
        $e = { param($t) ConvertTo-SfosXmlEscaped -Text $t }
    }

    process {
        $bp = $PSBoundParameters

        # A hyphenated Name is rejected the same way as on New-SfosIPsecConnection - see
        # that cmdlet's .NOTES.
        if ($Name -match '-') {
            throw "The VPNIPSecConnection object name '$Name' must not contain a hyphen; the firewall rejects it with a field-specific 501 on Configuration/Name."
        }

        $existing = @(Get-SfosIPsecConnection -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNIPSecConnection object '$Name' was not found."
        }
        $current = $existing[0]

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$current.Description }
        $targetPolicy = if ($bp.ContainsKey('Policy')) { $Policy } else { [string]$current.Policy }
        $targetAction = if ($bp.ContainsKey('ActionOnVPNRestart')) { $ActionOnVPNRestart } else { [string]$current.ActionOnVPNRestart }
        $targetSubnetFamily = if ($bp.ContainsKey('SubnetFamily')) { $SubnetFamily } else { [string]$current.SubnetFamily }
        $targetLocalWANPort = if ($bp.ContainsKey('LocalWANPort')) { $LocalWANPort } else { [string]$current.LocalWANPort }
        $targetAlias = if ($bp.ContainsKey('AliasLocalWANPort')) { $AliasLocalWANPort } else { [string]$current.AliasLocalWANPort }
        $targetRemoteHost = if ($bp.ContainsKey('RemoteHost')) { $RemoteHost } else { [string]$current.RemoteHost }
        $targetLocalSubnet = if ($bp.ContainsKey('LocalSubnet')) { $LocalSubnet } else { [string]$current.LocalSubnet }
        $targetLocalIDType = if ($bp.ContainsKey('LocalIDType')) { $LocalIDType } else { [string]$current.LocalIDType }
        $targetLocalID = if ($bp.ContainsKey('LocalID')) { $LocalID } else { [string]$current.LocalID }
        $targetRemoteNetwork = if ($bp.ContainsKey('RemoteNetwork')) { $RemoteNetwork } else { $current.RemoteNetworkList }
        $targetRemoteIDType = if ($bp.ContainsKey('RemoteIDType')) { $RemoteIDType } else { [string]$current.RemoteIDType }
        $targetRemoteID = if ($bp.ContainsKey('RemoteID')) { $RemoteID } else { [string]$current.RemoteID }
        $targetUserAuthMode = if ($bp.ContainsKey('UserAuthenticationMode')) { $UserAuthenticationMode } else { [string]$current.UserAuthenticationMode }
        $targetProtocol = if ($bp.ContainsKey('Protocol')) { $Protocol } else { [string]$current.Protocol }
        $targetStatus = if ($bp.ContainsKey('Status')) { $Status } else { [string]$current.Status }

        if (-not $PSCmdlet.ShouldProcess("VPNIPSecConnection '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $remoteNetworkXml = ''
        foreach ($net in @($targetRemoteNetwork)) {
            $remoteNetworkXml += "<Network>$(& $e $net)</Network>"
        }
        $allowedUserXml = ''
        foreach ($user in @($current.AllowedUserList)) {
            $allowedUserXml += "<User>$(& $e $user)</User>"
        }

        # PresharedKey: a caller-supplied value goes out as bare plaintext; a preserved value
        # is the hash Get returned and must be resent with its hashform attribute, or the
        # update fails outright with code 515 for a PresharedKey-authenticated connection -
        # see .NOTES.
        $presharedKeyXml = ''
        if ($bp.ContainsKey('PresharedKey')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PresharedKey)
            try {
                $presharedKeyPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
            $presharedKeyXml = "<PresharedKey>$(& $e $presharedKeyPlain)</PresharedKey>"
        }
        elseif ($current.PresharedKey) {
            $hfEsc = & $e $current.PresharedKeyHashForm
            $presharedKeyXml = "<PresharedKey hashform=`"$hfEsc`">$(& $e $current.PresharedKey)</PresharedKey>"
        }

        $optionalXml = ''
        if ($current.LocalCertificate) { $optionalXml += "<LocalCertificate>$(& $e $current.LocalCertificate)</LocalCertificate>" }
        if ($current.RemoteCertificate) { $optionalXml += "<RemoteCertificate>$(& $e $current.RemoteCertificate)</RemoteCertificate>" }
        if ($current.NATedLAN) { $optionalXml += "<NATedLAN>$(& $e $current.NATedLAN)</NATedLAN>" }
        if ($current.AllowNATTraversal) { $optionalXml += "<AllowNATTraversal>$($current.AllowNATTraversal)</AllowNATTraversal>" }
        if ($current.Username) { $optionalXml += "<Username>$(& $e $current.Username)</Username>" }
        if ($allowedUserXml) { $optionalXml += "<AllowedUser>$allowedUserXml</AllowedUser>" }
        if ($current.LocalPort) { $optionalXml += "<LocalPort>$(& $e $current.LocalPort)</LocalPort>" }
        if ($current.RemotePort) { $optionalXml += "<RemotePort>$(& $e $current.RemotePort)</RemotePort>" }
        if ($current.DisconnectOnIdleInterval) { $optionalXml += "<DisconnectOnIdleInterval>$($current.DisconnectOnIdleInterval)</DisconnectOnIdleInterval>" }

        $inner = @"
<Set operation="update">
  <VPNIPSecConnection>
    <Configuration>
      <Name>$(& $e $Name)</Name>
      <Description>$(& $e $targetDescription)</Description>
      <ConnectionType>$($current.ConnectionType)</ConnectionType>
      <Policy>$(& $e $targetPolicy)</Policy>
      <ActionOnVPNRestart>$targetAction</ActionOnVPNRestart>
      <AuthenticationType>$($current.AuthenticationType)</AuthenticationType>
      $presharedKeyXml
      <SubnetFamily>$targetSubnetFamily</SubnetFamily>
      <EndpointFamily>$($current.EndpointFamily)</EndpointFamily>
      <LocalWANPort>$(& $e $targetLocalWANPort)</LocalWANPort>
      <AliasLocalWANPort>$(& $e $targetAlias)</AliasLocalWANPort>
      <RemoteHost>$(& $e $targetRemoteHost)</RemoteHost>
      <LocalSubnet>$(& $e $targetLocalSubnet)</LocalSubnet>
      <LocalIDType>$targetLocalIDType</LocalIDType>
      <LocalID>$(& $e $targetLocalID)</LocalID>
      <RemoteNetwork>$remoteNetworkXml</RemoteNetwork>
      <RemoteIDType>$targetRemoteIDType</RemoteIDType>
      <RemoteID>$(& $e $targetRemoteID)</RemoteID>
      <UserAuthenticationMode>$targetUserAuthMode</UserAuthenticationMode>
      <Protocol>$targetProtocol</Protocol>
      $optionalXml
      <Status>$targetStatus</Status>
    </Configuration>
  </VPNIPSecConnection>
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
            throw "Error updating VPNIPSecConnection object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Configuration' -Action 'update' -Target $Name

        # The Configuration/Status field just written does not toggle the connection's real
        # enabled state - see .NOTES. Only fired when the caller explicitly asked for
        # -Status, since this cmdlet has no way to read the toggle back to preserve it on
        # updates that do not touch -Status.
        if ($bp.ContainsKey('Status')) {
            $nameEscForToggle = & $e $Name
            if ($targetStatus -eq 'Active') {
                $innerToggle = '<Set operation="update"><VPNIPSecConnection><Active><Name>' + $nameEscForToggle + '</Name></Active></VPNIPSecConnection></Set>'
                $toggleObjectName = 'Active'
                $toggleAction = 'activate'
            }
            else {
                $innerToggle = '<Set operation="update"><VPNIPSecConnection><DeActive><Name>' + $nameEscForToggle + '</Name></DeActive></VPNIPSecConnection></Set>'
                $toggleObjectName = 'DeActive'
                $toggleAction = 'deactivate'
            }

            try {
                $toggleResponse = Invoke-SfosApi -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -InnerXml $innerToggle -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
            }
            catch {
                throw "Error switching VPNIPSecConnection object '$Name' to Status '$targetStatus': $($_.Exception.Message)"
            }

            $toggleXmlResponse = [xml]$toggleResponse.Content
            # Write responses for this pair are rooted at <Active>/<DeActive>, not
            # <Configuration> - see the fragment header comment's cross-cutting finding.
            Assert-SfosApiReturnSuccess -Xml $toggleXmlResponse -ObjectName $toggleObjectName -Action $toggleAction -Target $Name
        }
    }
}

<#
.SYNOPSIS
    Removes an IPsec connection from a Sophos Firewall.

.DESCRIPTION
    Removes an IPsec connection under VPN > IPsec connections. Reads the object first and
    throws a clear error if it does not exist, then reads it back afterwards to confirm the
    removal took effect. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with permission to change VPN
    objects.

.PARAMETER Name
    Required. Name of the connection to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosIPsecConnection.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the connection cannot be
    removed.

.EXAMPLE
    Remove-SfosIPsecConnection -Name 'ExampleTunnel' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosIPsecConnection -Name 'ExampleTunnel' -Confirm:$false

    Removes the connection without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosIPsecConnection
#>
function Remove-SfosIPsecConnection {
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
        $existing = @(Get-SfosIPsecConnection -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNIPSecConnection object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("VPNIPSecConnection '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # The shallow <Remove><VPNIPSecConnection><Name>x</Name></VPNIPSecConnection>
        # </Remove> form answers HTTP 200 and deletes nothing - the same class of defect as
        # Remove-SfosSSLBookmark. The form that actually deletes nests Name one level deeper,
        # under <Configuration>, matching the entity's own Get/Set shape.
        $inner = @"
<Remove>
  <VPNIPSecConnection>
    <Configuration>
      <Name>$nameEsc</Name>
    </Configuration>
  </VPNIPSecConnection>
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
            throw "Error removing VPNIPSecConnection object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Configuration' -Action 'remove' -Target $Name

        # Belt and braces: the shallow form above answered 200 while changing nothing, so a
        # successful status alone is not trusted here - read the object back and throw if it
        # is still present, matching the Remove-SfosSSLBookmark/-SSLVPNPolicy pattern.
        $stillPresent = @(Get-SfosIPsecConnection -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($stillPresent.Count -gt 0) {
            throw "The Sophos API reported success removing VPNIPSecConnection object '$Name', but the object is still present on the firewall."
        }
    }
}

#endregion

#region VPNProfile

<#
.SYNOPSIS
    Retrieves VPN profiles (IKE policies) from a Sophos Firewall.

.DESCRIPTION
    Returns the VPN profiles defined under VPN > IPsec profiles. A VPN profile is an IKE
    policy that IPsec connections reference for their phase-1 and phase-2 settings. Some
    profiles are predefined by the firewall. Use this cmdlet to review existing profiles or
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
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per VPN profile, with properties
    such as Name, KeyingMethod, and the phase-1/phase-2 fields the firewall stores for it.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no object
    matches.

.EXAMPLE
    Get-SfosVPNProfile

    Lists every VPN profile on the firewall of the current connection.

.EXAMPLE
    Get-SfosVPNProfile -NameLike 'IKEv2'

    Lists all VPN profiles whose name contains 'IKEv2'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosVPNProfile
#>
function Get-SfosVPNProfile {
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
  <VPNProfile>
    $filterXml
  </VPNProfile>
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
        throw "Error retrieving VPNProfile objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNProfile' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/VPNProfile[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $phase1Node = $node.SelectSingleNode('Phase1')
        $phase2Node = $node.SelectSingleNode('Phase2')
        $dhGroupNodes = @()
        if ($phase1Node) {
            $dhGroupNodes = @($phase1Node.SelectNodes('SupportedDHGroups/DHGroup'))
        }

        $phase1 = [PSCustomObject]@{
            EncryptionAlgorithm1        = [string]$phase1Node.EncryptionAlgorithm1
            AuthenticationAlgorithm1    = [string]$phase1Node.AuthenticationAlgorithm1
            EncryptionAlgorithm2        = [string]$phase1Node.EncryptionAlgorithm2
            AuthenticationAlgorithm2    = [string]$phase1Node.AuthenticationAlgorithm2
            EncryptionAlgorithm3        = [string]$phase1Node.EncryptionAlgorithm3
            AuthenticationAlgorithm3    = [string]$phase1Node.AuthenticationAlgorithm3
            DHGroupList                 = [string[]]@($dhGroupNodes | ForEach-Object -Process { [string]$_.InnerText } | Where-Object -FilterScript { $_ })
            KeyLife                     = [string]$phase1Node.KeyLife
            ReKeyMargin                 = [string]$phase1Node.ReKeyMargin
            'RandomizeRe-KeyingMarginBy' = [string]$phase1Node.'RandomizeRe-KeyingMarginBy'
            DeadPeerDetection           = [string]$phase1Node.DeadPeerDetection
            CheckPeerAfterEvery         = [string]$phase1Node.CheckPeerAfterEvery
            WaitForResponseUpto         = [string]$phase1Node.WaitForResponseUpto
            ActionWhenPeerUnreachable   = [string]$phase1Node.ActionWhenPeerUnreachable
        }
        $phase2 = [PSCustomObject]@{
            EncryptionAlgorithm1     = [string]$phase2Node.EncryptionAlgorithm1
            AuthenticationAlgorithm1 = [string]$phase2Node.AuthenticationAlgorithm1
            EncryptionAlgorithm2     = [string]$phase2Node.EncryptionAlgorithm2
            AuthenticationAlgorithm2 = [string]$phase2Node.AuthenticationAlgorithm2
            EncryptionAlgorithm3     = [string]$phase2Node.EncryptionAlgorithm3
            AuthenticationAlgorithm3 = [string]$phase2Node.AuthenticationAlgorithm3
            PFSGroup                 = [string]$phase2Node.PFSGroup
            KeyLife                  = [string]$phase2Node.KeyLife
        }

        [PSCustomObject]@{
            Name                        = [string]$node.Name
            Description                 = [string]$node.Description
            KeyingMethod                = [string]$node.KeyingMethod
            AllowReKeying               = [string]$node.AllowReKeying
            KeyNegotiationTries         = [string]$node.KeyNegotiationTries
            AuthenticationMode          = [string]$node.AuthenticationMode
            PassDataInCompressedFormat  = [string]$node.PassDataInCompressedFormat
            UseStrictProfile            = [string]$node.UseStrictProfile
            Phase1                      = $phase1
            Phase2                      = $phase2
            LocalSPI                    = [string]$node.LocalSPI
            RemoteSPI                   = [string]$node.RemoteSPI
            InboundEncryptionKey        = [string]$node.InboundEncryptionKey
            OutboundEncryptionKey       = [string]$node.OutboundEncryptionKey
            InboundAuthenticationKey    = [string]$node.InboundAuthenticationKey
            OutboundAuthenticationKey   = [string]$node.OutboundAuthenticationKey
            sha2_96_truncate            = [string]$node.sha2_96_truncate
            keyexchange                 = [string]$node.keyexchange
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
    Creates a new VPN profile (IKE policy) on a Sophos Firewall.

.DESCRIPTION
    Creates a VPN profile under VPN > IPsec profiles, defining the phase-1 and phase-2 IKE
    settings that IPsec connections reference. Only the Automatic keying method is
    implemented; Manual keying is accepted by -KeyingMethod but its associated fields are
    not sent. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with permission to change VPN objects.

    Although the vendor documentation marks several phase-1 and phase-2 fields optional, the
    firewall rejects a create request that omits them. Supply -SupportedDHGroup,
    -DeadPeerDetection, -CheckPeerAfterEvery, -WaitForResponseUpto,
    -ActionWhenPeerUnreachable and -PFSGroup, or use the defaults this cmdlet already sends
    for them.

.PARAMETER Name
    Required. Name of the profile, 1 to 60 characters.

.PARAMETER AuthenticationMode
    Required. IKE authentication mode: MainMode or AggressiveMode.

.PARAMETER Phase1EncryptionAlgorithm1
    Required. Phase-1 primary encryption algorithm: DES, 3DES, AES128, AES192, AES256,
    TwoFish, BlowFish, Serpent, AES128GCM16, AES192GCM16 or AES256GCM16.

.PARAMETER Phase1AuthenticationAlgorithm1
    Required. Phase-1 primary authentication algorithm: MD5, SHA1, SHA2_256, SHA2_384 or
    SHA2_512.

.PARAMETER Phase1KeyLife
    Required. Phase-1 key life, in seconds, 120-86400.

.PARAMETER Phase1ReKeyMargin
    Required. Phase-1 re-key margin, in seconds, 30-999.

.PARAMETER Phase1RandomizeReKeyingMarginBy
    Required. Phase-1 re-keying margin randomization percentage, 0-100.

.PARAMETER Phase2EncryptionAlgorithm1
    Required. Phase-2 primary encryption algorithm: the same values as
    -Phase1EncryptionAlgorithm1, plus AES128GMAC, AES192GMAC and AES256GMAC.

.PARAMETER Phase2AuthenticationAlgorithm1
    Required. Phase-2 primary authentication algorithm: the same values as
    -Phase1AuthenticationAlgorithm1.

.PARAMETER Phase2KeyLife
    Required. Phase-2 key life, in seconds, 120-86400.

.PARAMETER Description
    Optional. Free-text description, up to 255 characters. If omitted, the description is
    left empty.

.PARAMETER KeyingMethod
    Optional. Keying method: Automatic or Manual. Default: Automatic. See .DESCRIPTION for
    the Manual limitation.

.PARAMETER AllowReKeying
    Optional. Allows automatic re-keying: Enable or Disable. Default: Enable.

.PARAMETER KeyNegotiationTries
    Optional. Number of key negotiation retries, 0-50. Default: 3.

.PARAMETER PassDataInCompressedFormat
    Optional. Compresses tunnel data before encryption: Enable or Disable. Default: Disable.

.PARAMETER UseStrictProfile
    Optional. Rejects connections that do not exactly match this profile: Enable or
    Disable. Default: Disable.

.PARAMETER SupportedDHGroup
    Required. One or more Diffie-Hellman group identifiers in the firewall's own format, for
    example '14(DH2048)'.

.PARAMETER DeadPeerDetection
    Optional. Dead peer detection: Enable or Disable. Default: Enable.

.PARAMETER CheckPeerAfterEvery
    Optional. Dead peer detection probe interval, in seconds. Default: 30.

.PARAMETER WaitForResponseUpto
    Optional. Dead peer detection response timeout, in seconds. Default: 120.

.PARAMETER ActionWhenPeerUnreachable
    Optional. Action when the peer is unreachable: Disconnect, Hold or ReInitiate. Default:
    Disconnect.

.PARAMETER Phase2EncryptionAlgorithm2
    Optional. Phase-2 secondary encryption algorithm. If omitted, the field is left empty.

.PARAMETER Phase2AuthenticationAlgorithm2
    Optional. Phase-2 secondary authentication algorithm. If omitted, the field is left
    empty.

.PARAMETER PFSGroup
    Optional. Perfect Forward Secrecy group: SameasPhase-I, None, or a Diffie-Hellman group
    identifier. Default: SameasPhase-I.

.PARAMETER keyexchange
    Optional. IKE version: ikev1 or ikev2. If omitted, the firewall uses ikev2.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosVPNProfile -Name 'BranchProfile' -AuthenticationMode MainMode `
        -Phase1EncryptionAlgorithm1 AES256 -Phase1AuthenticationAlgorithm1 SHA2_256 `
        -Phase1KeyLife 3600 -Phase1ReKeyMargin 120 -Phase1RandomizeReKeyingMarginBy 100 `
        -Phase2EncryptionAlgorithm1 AES256 -Phase2AuthenticationAlgorithm1 SHA2_256 `
        -Phase2KeyLife 3600 -SupportedDHGroup '14(DH2048)' -WhatIf

    Shows what the profile would look like without sending it to the firewall.

.EXAMPLE
    New-SfosVPNProfile -Name 'BranchProfile' -AuthenticationMode MainMode `
        -Phase1EncryptionAlgorithm1 AES256 -Phase1AuthenticationAlgorithm1 SHA2_256 `
        -Phase1KeyLife 3600 -Phase1ReKeyMargin 120 -Phase1RandomizeReKeyingMarginBy 100 `
        -Phase2EncryptionAlgorithm1 AES256 -Phase2AuthenticationAlgorithm1 SHA2_256 `
        -Phase2KeyLife 3600 -SupportedDHGroup '14(DH2048)'

    Creates the profile with the given phase-1 and phase-2 settings.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNProfile
#>
function New-SfosVPNProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('MainMode', 'AggressiveMode')]
        [string]$AuthenticationMode,

        [Parameter(Mandatory)]
        [ValidateSet('DES', '3DES', 'AES128', 'AES192', 'AES256', 'TwoFish', 'BlowFish', 'Serpent', 'AES128GCM16', 'AES192GCM16', 'AES256GCM16')]
        [string]$Phase1EncryptionAlgorithm1,

        [Parameter(Mandatory)]
        [ValidateSet('MD5', 'SHA1', 'SHA2_256', 'SHA2_384', 'SHA2_512')]
        [string]$Phase1AuthenticationAlgorithm1,

        [Parameter(Mandatory)]
        [ValidateRange(120, 86400)]
        [int]$Phase1KeyLife,

        [Parameter(Mandatory)]
        [ValidateRange(30, 999)]
        [int]$Phase1ReKeyMargin,

        [Parameter(Mandatory)]
        [ValidateRange(0, 100)]
        [int]$Phase1RandomizeReKeyingMarginBy,

        [Parameter(Mandatory)]
        [ValidateSet('DES', '3DES', 'AES128', 'AES192', 'AES256', 'TwoFish', 'BlowFish', 'Serpent', 'AES128GCM16', 'AES192GCM16', 'AES256GCM16', 'AES128GMAC', 'AES192GMAC', 'AES256GMAC')]
        [string]$Phase2EncryptionAlgorithm1,

        [Parameter(Mandatory)]
        [ValidateSet('MD5', 'SHA1', 'SHA2_256', 'SHA2_384', 'SHA2_512')]
        [string]$Phase2AuthenticationAlgorithm1,

        [Parameter(Mandatory)]
        [ValidateRange(120, 86400)]
        [int]$Phase2KeyLife,

        [ValidateLength(0, 255)]
        [string]$Description = '',
        [ValidateSet('Automatic', 'Manual')]
        [string]$KeyingMethod = 'Automatic',
        [ValidateSet('Enable', 'Disable')]
        [string]$AllowReKeying = 'Enable',
        [ValidateRange(0, 50)]
        [int]$KeyNegotiationTries = 3,
        [ValidateSet('Enable', 'Disable')]
        [string]$PassDataInCompressedFormat = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$UseStrictProfile = 'Disable',
        [Parameter(Mandatory)]
        [string[]]$SupportedDHGroup,
        [ValidateSet('Enable', 'Disable')]
        [string]$DeadPeerDetection = 'Enable',
        [int]$CheckPeerAfterEvery = 30,
        [int]$WaitForResponseUpto = 120,
        [ValidateSet('Disconnect', 'Hold', 'ReInitiate')]
        [string]$ActionWhenPeerUnreachable = 'Disconnect',
        [string]$Phase2EncryptionAlgorithm2,
        [string]$Phase2AuthenticationAlgorithm2,
        [string]$PFSGroup = 'SameasPhase-I',
        [ValidateSet('ikev1', 'ikev2')]
        [string]$keyexchange,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("VPNProfile '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $e = { param($t) ConvertTo-SfosXmlEscaped -Text $t }

    $dhGroupXml = ''
    foreach ($grp in $SupportedDHGroup) {
        $dhGroupXml += "<DHGroup>$(& $e $grp)</DHGroup>"
    }
    $dhWrapperXml = if ($dhGroupXml) { "<SupportedDHGroups>$dhGroupXml</SupportedDHGroups>" } else { '' }

    # Mandatory on create despite the documentation marking all four "No" - see .NOTES - so
    # they are always sent, backed by parameter defaults rather than a conditional
    # ContainsKey check.
    $phase1OptionalXml = "<DeadPeerDetection>$DeadPeerDetection</DeadPeerDetection><CheckPeerAfterEvery>$CheckPeerAfterEvery</CheckPeerAfterEvery><WaitForResponseUpto>$WaitForResponseUpto</WaitForResponseUpto><ActionWhenPeerUnreachable>$ActionWhenPeerUnreachable</ActionWhenPeerUnreachable>"

    $phase2OptionalXml = ''
    if ($Phase2EncryptionAlgorithm2) { $phase2OptionalXml += "<EncryptionAlgorithm2>$Phase2EncryptionAlgorithm2</EncryptionAlgorithm2>" }
    if ($Phase2AuthenticationAlgorithm2) { $phase2OptionalXml += "<AuthenticationAlgorithm2>$Phase2AuthenticationAlgorithm2</AuthenticationAlgorithm2>" }
    if ($PFSGroup) { $phase2OptionalXml += "<PFSGroup>$(& $e $PFSGroup)</PFSGroup>" }

    $keyexchangeXml = if ($keyexchange) { "<keyexchange>$keyexchange</keyexchange>" } else { '' }

    $inner = @"
<Set operation="add">
  <VPNProfile>
    <Name>$(& $e $Name)</Name>
    <Description>$(& $e $Description)</Description>
    <KeyingMethod>$KeyingMethod</KeyingMethod>
    <AllowReKeying>$AllowReKeying</AllowReKeying>
    <KeyNegotiationTries>$KeyNegotiationTries</KeyNegotiationTries>
    <AuthenticationMode>$AuthenticationMode</AuthenticationMode>
    <PassDataInCompressedFormat>$PassDataInCompressedFormat</PassDataInCompressedFormat>
    <UseStrictProfile>$UseStrictProfile</UseStrictProfile>
    <Phase1>
      <EncryptionAlgorithm1>$Phase1EncryptionAlgorithm1</EncryptionAlgorithm1>
      <AuthenticationAlgorithm1>$Phase1AuthenticationAlgorithm1</AuthenticationAlgorithm1>
      $dhWrapperXml
      <KeyLife>$Phase1KeyLife</KeyLife>
      <ReKeyMargin>$Phase1ReKeyMargin</ReKeyMargin>
      <RandomizeRe-KeyingMarginBy>$Phase1RandomizeReKeyingMarginBy</RandomizeRe-KeyingMarginBy>
      $phase1OptionalXml
    </Phase1>
    <Phase2>
      <EncryptionAlgorithm1>$Phase2EncryptionAlgorithm1</EncryptionAlgorithm1>
      <AuthenticationAlgorithm1>$Phase2AuthenticationAlgorithm1</AuthenticationAlgorithm1>
      $phase2OptionalXml
      <KeyLife>$Phase2KeyLife</KeyLife>
    </Phase2>
    $keyexchangeXml
  </VPNProfile>
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
        throw "Error creating VPNProfile object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNProfile' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing VPN profile (IKE policy) on a Sophos Firewall.

.DESCRIPTION
    Updates a VPN profile under VPN > IPsec profiles. Reads the current object first and
    sends the complete entity back, changing only the fields you pass; fields you omit keep
    their current value. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with permission to change VPN
    objects.

    Some profiles are predefined by the firewall. Updating one of them changes the IKE
    settings for every IPsec connection that references it.

.PARAMETER Name
    Required. Name of the profile to update. Accepts pipeline input by property name.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER AllowReKeying
    Optional. Allows automatic re-keying: Enable or Disable. If omitted, the current value
    is kept.

.PARAMETER KeyNegotiationTries
    Optional. Number of key negotiation retries, 0-50. If omitted, the current value is
    kept.

.PARAMETER AuthenticationMode
    Optional. IKE authentication mode: MainMode or AggressiveMode. If omitted, the current
    value is kept.

.PARAMETER PassDataInCompressedFormat
    Optional. Compresses tunnel data before encryption: Enable or Disable. If omitted, the
    current value is kept.

.PARAMETER UseStrictProfile
    Optional. Rejects connections that do not exactly match this profile: Enable or
    Disable. If omitted, the current value is kept.

.PARAMETER Phase1EncryptionAlgorithm1
    Optional. Phase-1 primary encryption algorithm. If omitted, the current value is kept.

.PARAMETER Phase1AuthenticationAlgorithm1
    Optional. Phase-1 primary authentication algorithm. If omitted, the current value is
    kept.

.PARAMETER Phase1KeyLife
    Optional. Phase-1 key life, in seconds. If omitted, the current value is kept.

.PARAMETER Phase1ReKeyMargin
    Optional. Phase-1 re-key margin, in seconds. If omitted, the current value is kept.

.PARAMETER Phase1RandomizeReKeyingMarginBy
    Optional. Phase-1 re-keying margin randomization percentage. If omitted, the current
    value is kept.

.PARAMETER SupportedDHGroup
    Optional. Complete replacement list of Diffie-Hellman group identifiers in the
    firewall's own format, for example '14(DH2048)'. If omitted, the current list is kept.

.PARAMETER DeadPeerDetection
    Optional. Dead peer detection: Enable or Disable. If omitted, the current value is kept.

.PARAMETER CheckPeerAfterEvery
    Optional. Dead peer detection probe interval, in seconds. If omitted, the current value
    is kept.

.PARAMETER WaitForResponseUpto
    Optional. Dead peer detection response timeout, in seconds. If omitted, the current
    value is kept.

.PARAMETER ActionWhenPeerUnreachable
    Optional. Action when the peer is unreachable: Disconnect, Hold or ReInitiate. If
    omitted, the current value is kept.

.PARAMETER Phase2EncryptionAlgorithm1
    Optional. Phase-2 primary encryption algorithm. If omitted, the current value is kept.

.PARAMETER Phase2AuthenticationAlgorithm1
    Optional. Phase-2 primary authentication algorithm. If omitted, the current value is
    kept.

.PARAMETER PFSGroup
    Optional. Perfect Forward Secrecy group. If omitted, the current value is kept.

.PARAMETER Phase2KeyLife
    Optional. Phase-2 key life, in seconds. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The profile Name, by property name, for example from Get-SfosVPNProfile.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosVPNProfile -Name 'BranchProfile' -Description 'Updated' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosVPNProfile -Name 'BranchProfile' -Description 'Updated'

    Updates the description. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNProfile
#>
function Set-SfosVPNProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$Description,
        [ValidateSet('Enable', 'Disable')]
        [string]$AllowReKeying,
        [ValidateRange(0, 50)]
        [int]$KeyNegotiationTries,
        [ValidateSet('MainMode', 'AggressiveMode')]
        [string]$AuthenticationMode,
        [ValidateSet('Enable', 'Disable')]
        [string]$PassDataInCompressedFormat,
        [ValidateSet('Enable', 'Disable')]
        [string]$UseStrictProfile,
        [string]$Phase1EncryptionAlgorithm1,
        [string]$Phase1AuthenticationAlgorithm1,
        [int]$Phase1KeyLife,
        [int]$Phase1ReKeyMargin,
        [int]$Phase1RandomizeReKeyingMarginBy,
        [string[]]$SupportedDHGroup,
        [ValidateSet('Enable', 'Disable')]
        [string]$DeadPeerDetection,
        [int]$CheckPeerAfterEvery,
        [int]$WaitForResponseUpto,
        [ValidateSet('Disconnect', 'Hold', 'ReInitiate')]
        [string]$ActionWhenPeerUnreachable,
        [string]$Phase2EncryptionAlgorithm1,
        [string]$Phase2AuthenticationAlgorithm1,
        [string]$PFSGroup,
        [int]$Phase2KeyLife,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
        $e = { param($t) ConvertTo-SfosXmlEscaped -Text $t }
    }

    process {
        $bp = $PSBoundParameters

        $existing = @(Get-SfosVPNProfile -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNProfile object '$Name' was not found."
        }
        $current = $existing[0]

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$current.Description }
        $targetAllowReKeying = if ($bp.ContainsKey('AllowReKeying')) { $AllowReKeying } else { [string]$current.AllowReKeying }
        $targetKeyNegotiationTries = if ($bp.ContainsKey('KeyNegotiationTries')) { $KeyNegotiationTries } else { $current.KeyNegotiationTries }
        $targetAuthMode = if ($bp.ContainsKey('AuthenticationMode')) { $AuthenticationMode } else { [string]$current.AuthenticationMode }
        $targetCompressed = if ($bp.ContainsKey('PassDataInCompressedFormat')) { $PassDataInCompressedFormat } else { [string]$current.PassDataInCompressedFormat }
        $targetStrict = if ($bp.ContainsKey('UseStrictProfile')) { $UseStrictProfile } else { [string]$current.UseStrictProfile }

        $targetP1Enc1 = if ($bp.ContainsKey('Phase1EncryptionAlgorithm1')) { $Phase1EncryptionAlgorithm1 } else { $current.Phase1.EncryptionAlgorithm1 }
        $targetP1Auth1 = if ($bp.ContainsKey('Phase1AuthenticationAlgorithm1')) { $Phase1AuthenticationAlgorithm1 } else { $current.Phase1.AuthenticationAlgorithm1 }
        $targetP1KeyLife = if ($bp.ContainsKey('Phase1KeyLife')) { $Phase1KeyLife } else { $current.Phase1.KeyLife }
        $targetP1ReKeyMargin = if ($bp.ContainsKey('Phase1ReKeyMargin')) { $Phase1ReKeyMargin } else { $current.Phase1.ReKeyMargin }
        $targetP1Randomize = if ($bp.ContainsKey('Phase1RandomizeReKeyingMarginBy')) { $Phase1RandomizeReKeyingMarginBy } else { $current.Phase1.'RandomizeRe-KeyingMarginBy' }
        $targetDHGroups = if ($bp.ContainsKey('SupportedDHGroup')) { $SupportedDHGroup } else { $current.Phase1.DHGroupList }
        $targetDPD = if ($bp.ContainsKey('DeadPeerDetection')) { $DeadPeerDetection } else { [string]$current.Phase1.DeadPeerDetection }
        $targetCheckPeer = if ($bp.ContainsKey('CheckPeerAfterEvery')) { $CheckPeerAfterEvery } else { $current.Phase1.CheckPeerAfterEvery }
        $targetWaitResp = if ($bp.ContainsKey('WaitForResponseUpto')) { $WaitForResponseUpto } else { $current.Phase1.WaitForResponseUpto }
        $targetActionUnreach = if ($bp.ContainsKey('ActionWhenPeerUnreachable')) { $ActionWhenPeerUnreachable } else { [string]$current.Phase1.ActionWhenPeerUnreachable }

        $targetP2Enc1 = if ($bp.ContainsKey('Phase2EncryptionAlgorithm1')) { $Phase2EncryptionAlgorithm1 } else { $current.Phase2.EncryptionAlgorithm1 }
        $targetP2Auth1 = if ($bp.ContainsKey('Phase2AuthenticationAlgorithm1')) { $Phase2AuthenticationAlgorithm1 } else { $current.Phase2.AuthenticationAlgorithm1 }
        $targetPFSGroup = if ($bp.ContainsKey('PFSGroup')) { $PFSGroup } else { [string]$current.Phase2.PFSGroup }
        $targetP2KeyLife = if ($bp.ContainsKey('Phase2KeyLife')) { $Phase2KeyLife } else { $current.Phase2.KeyLife }

        if (-not $PSCmdlet.ShouldProcess("VPNProfile '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $dhGroupXml = ''
        foreach ($grp in @($targetDHGroups)) {
            $dhGroupXml += "<DHGroup>$(& $e $grp)</DHGroup>"
        }
        $dhWrapperXml = if ($dhGroupXml) { "<SupportedDHGroups>$dhGroupXml</SupportedDHGroups>" } else { '' }

        $inner = @"
<Set operation="update">
  <VPNProfile>
    <Name>$(& $e $Name)</Name>
    <Description>$(& $e $targetDescription)</Description>
    <KeyingMethod>$($current.KeyingMethod)</KeyingMethod>
    <AllowReKeying>$targetAllowReKeying</AllowReKeying>
    <KeyNegotiationTries>$targetKeyNegotiationTries</KeyNegotiationTries>
    <AuthenticationMode>$targetAuthMode</AuthenticationMode>
    <PassDataInCompressedFormat>$targetCompressed</PassDataInCompressedFormat>
    <UseStrictProfile>$targetStrict</UseStrictProfile>
    <Phase1>
      <EncryptionAlgorithm1>$targetP1Enc1</EncryptionAlgorithm1>
      <AuthenticationAlgorithm1>$targetP1Auth1</AuthenticationAlgorithm1>
      $dhWrapperXml
      <KeyLife>$targetP1KeyLife</KeyLife>
      <ReKeyMargin>$targetP1ReKeyMargin</ReKeyMargin>
      <RandomizeRe-KeyingMarginBy>$targetP1Randomize</RandomizeRe-KeyingMarginBy>
      <DeadPeerDetection>$targetDPD</DeadPeerDetection>
      <CheckPeerAfterEvery>$targetCheckPeer</CheckPeerAfterEvery>
      <WaitForResponseUpto>$targetWaitResp</WaitForResponseUpto>
      <ActionWhenPeerUnreachable>$targetActionUnreach</ActionWhenPeerUnreachable>
    </Phase1>
    <Phase2>
      <EncryptionAlgorithm1>$targetP2Enc1</EncryptionAlgorithm1>
      <AuthenticationAlgorithm1>$targetP2Auth1</AuthenticationAlgorithm1>
      <PFSGroup>$(& $e $targetPFSGroup)</PFSGroup>
      <KeyLife>$targetP2KeyLife</KeyLife>
    </Phase2>
    <keyexchange>$($current.keyexchange)</keyexchange>
  </VPNProfile>
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
            throw "Error updating VPNProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNProfile' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a VPN profile (IKE policy) from a Sophos Firewall.

.DESCRIPTION
    Removes a VPN profile under VPN > IPsec profiles. Reads the object first and throws a
    clear error if it does not exist. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly, and an account with permission to
    change VPN objects. Removing a profile that IPsec connections still reference affects
    those connections.

.PARAMETER Name
    Required. Name of the profile to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The profile Name, by property name, for example from Get-SfosVPNProfile.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the profile cannot be removed.

.EXAMPLE
    Remove-SfosVPNProfile -Name 'BranchProfile' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosVPNProfile -Name 'BranchProfile' -Confirm:$false

    Removes the profile without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNProfile
#>
function Remove-SfosVPNProfile {
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
        $existing = @(Get-SfosVPNProfile -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNProfile object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("VPNProfile '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <VPNProfile>
    <Name>$nameEsc</Name>
  </VPNProfile>
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
            throw "Error removing VPNProfile object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNProfile' -Action 'remove' -Target $Name
    }
}

#endregion

#region VPNFailoverGroup

<#
.SYNOPSIS
    Retrieves VPN failover groups from a Sophos Firewall.

.DESCRIPTION
    Returns the VPN failover groups defined under VPN > Failover groups. A failover group
    holds an ordered list of IPsec connections the firewall switches between when the active
    one goes down. Use this cmdlet to review existing groups or feed them into another
    cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is changed.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

.PARAMETER NameLike
    Optional. Returns only groups whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per failover group, with the
    ordered list of member connections. Returns System.Xml.XmlElement when -AsXml is used,
    and an empty array when no object matches.

.EXAMPLE
    Get-SfosVPNFailoverGroup

    Lists every VPN failover group on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosVPNFailoverGroup
#>
function Get-SfosVPNFailoverGroup {
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
  <VPNFailoverGroup>
    <GroupDetail>
      $filterXml
    </GroupDetail>
  </VPNFailoverGroup>
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
        throw "Error retrieving VPNFailoverGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VPNFailoverGroup/GroupDetail' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/VPNFailoverGroup/GroupDetail[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $connectionNodes = @($node.SelectNodes('MemberConnections/Connection'))
        $failoverIfNodes = @($node.SelectNodes('FailoverCondition/FailoverIF'))
        $failoverList = foreach ($ifNode in $failoverIfNodes) {
            [PSCustomObject]@{
                Protocol = [string]$ifNode.Protocol
                Port     = [string]$ifNode.Port
            }
        }

        [PSCustomObject]@{
            Name                  = [string]$node.Name
            MemberConnectionList  = [string[]]@($connectionNodes | ForEach-Object -Process { [string]$_.InnerText } | Where-Object -FilterScript { $_ })
            MailNotification      = [string]$node.MailNotification
            AutomaticFailback     = [string]$node.AutomaticFailback
            FailoverConditionList = @($failoverList)
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
    Creates a new VPN failover group on a Sophos Firewall.

.DESCRIPTION
    Creates a failover group under VPN > Failover groups, an ordered list of IPsec
    connections the firewall switches between when the active one goes down. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the failover group. Starts with a letter; letters, digits and
    underscore only.

.PARAMETER Connection
    Required. Names of one or more existing IPsec connections, in failover order.

.PARAMETER MailNotification
    Required. Sends an e-mail notification on failover: Enable or Disable.

.PARAMETER AutomaticFailback
    Optional. Switches back to the primary connection automatically once it is available
    again: Enable or Disable. If omitted, the field is left empty.

.PARAMETER FailoverCondition
    Optional. One or more failover conditions, each a PSCustomObject with a Protocol
    property (PING or TCP) and an optional Port property. If omitted, no conditions are
    sent.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosVPNFailoverGroup -Name 'BranchFailover' -Connection 'ExampleTunnel' `
        -MailNotification Disable -WhatIf

    Shows what the failover group would look like without sending it to the firewall.

.EXAMPLE
    New-SfosVPNFailoverGroup -Name 'BranchFailover' -Connection 'ExampleTunnel' `
        -MailNotification Disable

    Creates a failover group with a single member connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNFailoverGroup
#>
function New-SfosVPNFailoverGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$Connection,

        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$MailNotification,

        [ValidateSet('Enable', 'Disable')]
        [string]$AutomaticFailback,

        [PSCustomObject[]]$FailoverCondition,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("VPNFailoverGroup '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $e = { param($t) ConvertTo-SfosXmlEscaped -Text $t }

    $connectionXml = ''
    foreach ($conn in $Connection) {
        $connectionXml += "<Connection>$(& $e $conn)</Connection>"
    }

    $failoverXml = ''
    foreach ($cond in $FailoverCondition) {
        $protocolEsc = & $e ([string]$cond.Protocol)
        $portEsc = & $e ([string]$cond.Port)
        $failoverXml += "<FailoverIF><Protocol>$protocolEsc</Protocol><Port>$portEsc</Port></FailoverIF>"
    }
    $failoverWrapperXml = if ($failoverXml) { "<FailoverCondition>$failoverXml</FailoverCondition>" } else { '' }
    $automaticFailbackXml = if ($AutomaticFailback) { "<AutomaticFailback>$AutomaticFailback</AutomaticFailback>" } else { '' }

    $inner = @"
<Set operation="add">
  <VPNFailoverGroup>
    <GroupDetail>
      <Name>$(& $e $Name)</Name>
      <MemberConnections>$connectionXml</MemberConnections>
      <MailNotification>$MailNotification</MailNotification>
      $automaticFailbackXml
      $failoverWrapperXml
    </GroupDetail>
  </VPNFailoverGroup>
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
        throw "Error creating VPNFailoverGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Write responses strip the outer entity wrapper - see the fragment header comment.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing VPN failover group on a Sophos Firewall.

.DESCRIPTION
    Updates a failover group under VPN > Failover groups. Reads the current object first
    and sends the complete entity back, changing only the fields you pass; fields you omit
    keep their current value. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with permission to change VPN
    objects. Add-SfosVPNFailoverGroupMember and Remove-SfosVPNFailoverGroupMember use this
    cmdlet internally.

.PARAMETER Name
    Required. Name of the failover group to update. Accepts pipeline input by property
    name.

.PARAMETER Connection
    Optional. Complete replacement list of member connection names, in failover order. If
    omitted, the current list is kept.

.PARAMETER MailNotification
    Optional. Sends an e-mail notification on failover: Enable or Disable. If omitted, the
    current value is kept.

.PARAMETER AutomaticFailback
    Optional. Switches back to the primary connection automatically once it is available
    again: Enable or Disable. If omitted, the current value is kept.

.PARAMETER FailoverCondition
    Optional. Complete replacement list of failover conditions, each a PSCustomObject with a
    Protocol property (PING or TCP) and an optional Port property. If omitted, the current
    list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The group Name, by property name, for example from
    Get-SfosVPNFailoverGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosVPNFailoverGroup -Name 'BranchFailover' -MailNotification Enable -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosVPNFailoverGroup -Name 'BranchFailover' -MailNotification Enable

    Turns on failover e-mail notifications. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNFailoverGroup
#>
function Set-SfosVPNFailoverGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string[]]$Connection,
        [ValidateSet('Enable', 'Disable')]
        [string]$MailNotification,
        [ValidateSet('Enable', 'Disable')]
        [string]$AutomaticFailback,
        [PSCustomObject[]]$FailoverCondition,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
        $e = { param($t) ConvertTo-SfosXmlEscaped -Text $t }
    }

    process {
        $bp = $PSBoundParameters

        $existing = @(Get-SfosVPNFailoverGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNFailoverGroup object '$Name' was not found."
        }
        $current = $existing[0]

        $targetConnection = if ($bp.ContainsKey('Connection')) { $Connection } else { $current.MemberConnectionList }
        $targetMailNotification = if ($bp.ContainsKey('MailNotification')) { $MailNotification } else { [string]$current.MailNotification }
        $targetAutoFailback = if ($bp.ContainsKey('AutomaticFailback')) { $AutomaticFailback } else { [string]$current.AutomaticFailback }
        $targetFailover = if ($bp.ContainsKey('FailoverCondition')) { $FailoverCondition } else { $current.FailoverConditionList }

        if (@($targetConnection).Count -eq 0) {
            throw "VPNFailoverGroup '$Name': at least one member Connection is required; the current object has none and none was supplied."
        }

        if (-not $PSCmdlet.ShouldProcess("VPNFailoverGroup '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $connectionXml = ''
        foreach ($conn in @($targetConnection)) {
            $connectionXml += "<Connection>$(& $e $conn)</Connection>"
        }
        $failoverXml = ''
        foreach ($cond in @($targetFailover)) {
            $protocolEsc = & $e ([string]$cond.Protocol)
            $portEsc = & $e ([string]$cond.Port)
            $failoverXml += "<FailoverIF><Protocol>$protocolEsc</Protocol><Port>$portEsc</Port></FailoverIF>"
        }

        $inner = @"
<Set operation="update">
  <VPNFailoverGroup>
    <GroupDetail>
      <Name>$(& $e $Name)</Name>
      <MemberConnections>$connectionXml</MemberConnections>
      <MailNotification>$targetMailNotification</MailNotification>
      <AutomaticFailback>$targetAutoFailback</AutomaticFailback>
      <FailoverCondition>$failoverXml</FailoverCondition>
    </GroupDetail>
  </VPNFailoverGroup>
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
            throw "Error updating VPNFailoverGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a VPN failover group from a Sophos Firewall.

.DESCRIPTION
    Removes a failover group under VPN > Failover groups. Reads the object first and throws
    a clear error if it does not exist. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects. The member IPsec connections themselves are not
    removed.

.PARAMETER Name
    Required. Name of the failover group to remove. Accepts pipeline input by property
    name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The group Name, by property name, for example from
    Get-SfosVPNFailoverGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the group cannot be removed.

.EXAMPLE
    Remove-SfosVPNFailoverGroup -Name 'BranchFailover' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosVPNFailoverGroup -Name 'BranchFailover' -Confirm:$false

    Removes the failover group without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNFailoverGroup
#>
function Remove-SfosVPNFailoverGroup {
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
        $existing = @(Get-SfosVPNFailoverGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNFailoverGroup object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("VPNFailoverGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <VPNFailoverGroup>
    <Name>$nameEsc</Name>
  </VPNFailoverGroup>
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
            throw "Error removing VPNFailoverGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GroupDetail' -Action 'remove' -Target $Name
    }
}

<#
.SYNOPSIS
    Adds an IPsec connection to a VPN failover group's member list.

.DESCRIPTION
    Reads the current failover group, adds the given connection name to its member list if
    not already present, and writes the complete list back. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the failover group to update. Accepts pipeline input by property
    name.

.PARAMETER Connection
    Required. Name of the IPsec connection to add.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The group Name, by property name, for example from
    Get-SfosVPNFailoverGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Add-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'ExampleTunnel' -WhatIf

    Shows what would be added without sending the request to the firewall.

.EXAMPLE
    Add-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'ExampleTunnel'

    Adds the connection to the failover group.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNFailoverGroup

.LINK
    Remove-SfosVPNFailoverGroupMember
#>
function Add-SfosVPNFailoverGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Connection,

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
        $existing = @(Get-SfosVPNFailoverGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNFailoverGroup object '$Name' was not found."
        }

        $currentMembers = @($existing[0].MemberConnectionList)
        if ($currentMembers -contains $Connection) {
            Write-Verbose "Connection '$Connection' is already a member of VPNFailoverGroup '$Name'."
            return
        }

        $newMembers = $currentMembers + $Connection

        Set-SfosVPNFailoverGroup -Name $Name -Connection $newMembers `
            -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck
    }
}

<#
.SYNOPSIS
    Removes an IPsec connection from a VPN failover group's member list.

.DESCRIPTION
    Reads the current failover group, removes the given connection name from its member
    list, and writes the reduced list back. A failover group needs at least one member, so
    the cmdlet throws instead of sending a request that would empty the list. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the failover group to update. Accepts pipeline input by property
    name.

.PARAMETER Connection
    Required. Name of the IPsec connection to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The group Name, by property name, for example from
    Get-SfosVPNFailoverGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Remove-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'ExampleTunnel' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'ExampleTunnel'

    Removes the connection from the failover group.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosVPNFailoverGroup

.LINK
    Add-SfosVPNFailoverGroupMember
#>
function Remove-SfosVPNFailoverGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Connection,

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
        $existing = @(Get-SfosVPNFailoverGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The VPNFailoverGroup object '$Name' was not found."
        }

        $currentMembers = @($existing[0].MemberConnectionList)
        if ($currentMembers -notcontains $Connection) {
            Write-Verbose "Connection '$Connection' is not a member of VPNFailoverGroup '$Name'."
            return
        }

        $newMembers = @($currentMembers | Where-Object -FilterScript { $_ -ne $Connection })
        if ($newMembers.Count -eq 0) {
            throw "VPNFailoverGroup '$Name': cannot remove '$Connection', it is the only remaining member and the entity requires at least one."
        }

        Set-SfosVPNFailoverGroup -Name $Name -Connection $newMembers `
            -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # A write that answers 200 and changes nothing is worse than a thrown error - read
        # back and confirm the member is actually gone, per this project's convention for
        # every cmdlet whose own name promises a removal.
        $after = @(Get-SfosVPNFailoverGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })
        if ($after.Count -gt 0 -and (@($after[0].MemberConnectionList) -contains $Connection)) {
            throw "VPNFailoverGroup '$Name': the update reported success but '$Connection' is still listed as a member."
        }
    }
}

#endregion

#region SophosConnectClient

<#
.SYNOPSIS
    Retrieves the Sophos Connect client configuration from a Sophos Firewall.

.DESCRIPTION
    Returns the Sophos Connect client settings under VPN > Sophos Connect client. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly. There is no
    matching cmdlet to change these settings.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with a Reset property. Returns
    System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosSophosConnectClient

    Shows the Sophos Connect client settings of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosSophosConnectClient {
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

    $inner = '<Get><SophosConnectClient></SophosConnectClient></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SophosConnectClient object: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SophosConnectClient' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SophosConnectClient')
    if (-not $node) {
        return
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        Reset = [string]$node.Reset
    }
}

#endregion

#requires -Version 5.1
#requires -Modules SophosFirewall.Core

# SophosFirewall.VPN - SSLVPN (SSLTunnelAccessSettings, SSLVPNPolicy, SSLBookmark,
# SSLBookmarkGroup, SiteToSiteClient, SiteToSiteServer).
#
# Cross-cutting points:
#
# 1. SSLVPNPolicy is one API entity with two sub-shapes, TunnelPolicy and ClientlessPolicy,
#    that share the <SSLVPNPolicy> wrapper only on Get. On Add/Update the response root is
#    the bare sub-type element (<TunnelPolicy>/<ClientlessPolicy>), not <SSLVPNPolicy> - so
#    the status must be read from /Response/TunnelPolicy/Status or
#    /Response/ClientlessPolicy/Status. On Remove the response nests one level deeper still:
#    /Response/SSLVPNPolicy/TunnelPolicy/Status. Three different status paths for the same
#    entity, used exactly as observed below.
# 2. SSLVPNPolicy.PolicyMembers writes back onto the referenced UserGroup: adding a group as
#    a policy member sets that group's own <SSLVPNPolicy>/<ClientlessPolicy> fields to the
#    policy's name as a side effect. Treat every group reference as a write to that group.
#    New-/Set-SfosSSLVPNPolicy document this prominently - never pass a production group
#    name to -Member.
# 3. Deleting a TunnelPolicy/ClientlessPolicy that a group still references answers 504
#    ("Deleting entity referred by another entity") or 500 ("Deleted some configurations.
#    Couldn't delete all.") and deletes nothing; the group's own policy reference has to be
#    cleared first (Set-SfosUserGroup -SSLVPNPolicy '' -ClientlessPolicy '', in the
#    Authentication module), then the policy, then the group. Remove-SfosSSLVPNPolicy does
#    not attempt this automatically - it is not this cmdlet's entity to modify - and just
#    surfaces the firewall's own error.
# 4. Remove on SSLBookmark is a no-op on this firmware: every shape tried - bare <Name>,
#    <Name> plus <Type>, the full object, and even the undocumented
#    <Set operation="remove"> - answers code 200 "Configuration applied successfully" and
#    the object is still present on the very next Get. Documented delete operation, used
#    exactly as specified, silently does nothing. Remove-SfosSSLBookmark reads the object
#    back after the call and throws if it is still there, rather than reporting the
#    firewall's false success. Removal of an existing SSLBookmark is therefore only possible
#    through the web admin.
# 5. SSLBookmark.Password comes back from Get in hashed form
#    (<Password hashform="mode1">$sfos$7$0$...</Password>), never in plaintext - but unlike
#    SophosConnectClient/FileType-Template, the update resends that hash together with its
#    hashform attribute, the mechanism the config export uses for pre-hashed secrets. The
#    stored hash text still changes on every write (re-salted), so whether the firewall
#    treats the resent hash as the same password or as new plaintext cannot be established
#    without a real portal login. Same standing caveat as the RADIUS shared secret. So,
#    normal read-modify-write is safe here: Set-SfosSSLBookmark reads the current (hashed)
#    Password and resends it verbatim when the caller does not pass -Password.
# 6. SiteToSiteClient.ServerConfigurationFile is a genuine file upload (.apc/.epc), not a
#    text field - the doc sample itself says so. Every attempt to create a SiteToSiteClient
#    through this module's urlencoded reqxml transport failed with a field-less 500: with no
#    ServerConfigurationFile element, with an empty element, and with a base64 placeholder
#    string in it. Core has no multipart transport. New-/Set-/Get-/Remove-SfosSiteToSiteClient
#    are implemented documentation-faithful; because Add never succeeds, whether
#    FilePassword/the proxy Password survive a read-modify-write cannot be established -
#    Set-SfosSiteToSiteClient does not attempt to preserve them (see its .NOTES).
# 7. SiteToSiteServer.Name rejects a hyphen: <Set operation="add"> with
#    Name=Portal-S2SServer1 answers 501 naming /SiteToSiteServer/Name; the same request
#    with the hyphen removed succeeds.

#region SSLTunnelAccessSettings

<#
.SYNOPSIS
    Retrieves the SSL VPN tunnel access settings from a Sophos Firewall.

.DESCRIPTION
    Returns the tunnel access settings under VPN > SSL VPN (Remote Access) > Tunnel access
    control. This is a device-wide singleton: there is exactly one object and it has no
    name. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with the tunnel access settings,
    such as DebugMode and SSLServerCertificate. Returns System.Xml.XmlElement when -AsXml is
    used.

.EXAMPLE
    Get-SfosSSLTunnelAccessSettings

    Shows the SSL VPN tunnel access settings of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosSSLTunnelAccessSettings
#>
function Get-SfosSSLTunnelAccessSettings {
    # PSUseSingularNouns is suppressed on purpose: <SSLTunnelAccessSettings> is the entity's
    # own singleton name, not a plural container - it has no singular child element.
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

    $inner = '<Get><SSLTunnelAccessSettings></SSLTunnelAccessSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SSLTunnelAccessSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTunnelAccessSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SSLTunnelAccessSettings')
    if (-not $node) {
        return
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        Protocol                 = [string]$node.Protocol
        SSLServerCertificate     = [string]$node.SSLServerCertificate
        OverrideHostName         = [string]$node.OverrideHostName
        Port                     = [string]$node.Port
        StartIP                  = [string]$node.IPLeaseRange.StartIP
        EndIP                    = [string]$node.IPLeaseRange.EndIP
        SubnetMask               = [string]$node.SubnetMask
        IPv6Lease                = [string]$node.IPv6Lease
        IPv6Prefix               = [string]$node.IPv6Prefix
        LeaseMode                = [string]$node.LeaseMode
        PrimaryDNSIPv4           = [string]$node.PrimaryDNSIPv4
        SecondaryDNSIPv4         = [string]$node.SecondaryDNSIPv4
        PrimaryWINSIPv4          = [string]$node.PrimaryWINSIPv4
        SecondaryWINSIPv4        = [string]$node.SecondaryWINSIPv4
        DomainName               = [string]$node.DomainName
        DisconnectDeadPeerAfter  = [string]$node.DisconnectDeadPeerAfter
        DisconnectIdlePeerAfter  = [string]$node.DisconnectIdlePeerAfter
        EncryptionAlgorithm      = [string]$node.EncryptionAlgorithm
        AuthenticationAlgorithm  = [string]$node.AuthenticationAlgorithm
        Keysize                  = [string]$node.Keysize
        KeyLifetime              = [string]$node.KeyLifetime
        DebugMode                = [string]$node.DebugMode
        SecurityHeartbeat        = [string]$node.SecurityHeartbeat
        SaveCredential           = [string]$node.SaveCredential
        TwoFAToken               = [string]$node.TwoFAToken
        AdLogon                  = [string]$node.AdLogon
        AutoConnect              = [string]$node.AutoConnect
        HostorDNSName            = [string]$node.HostorDNSName
        StaticIPAddresses        = [string]$node.StaticIPAddresses
    }
}

<#
.SYNOPSIS
    Updates the SSL VPN tunnel access settings on a Sophos Firewall.

.DESCRIPTION
    Updates the tunnel access settings under VPN > SSL VPN (Remote Access) > Tunnel access
    control, a device-wide singleton that affects every SSL VPN client. Reads the current
    object first and sends the complete entity back, changing only the fields you pass;
    fields you omit keep their current value. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER Protocol
    Optional. Transport protocol for the tunnel: TCP or UDP. If omitted, the current value
    is kept.

.PARAMETER SSLServerCertificate
    Optional. Name of the certificate used for the SSL VPN listener. If omitted, the current
    value is kept.

.PARAMETER OverrideHostName
    Optional. Host name advertised to clients instead of the appliance's own. If omitted,
    the current value is kept.

.PARAMETER SslPort
    Optional. SSL VPN listening port, 1-65535. If omitted, the current value is kept. Named
    -SslPort, not -Port, because -Port is the API management port (connection parameter).

.PARAMETER StartIP
    Optional. Start of the client IP lease range. If omitted, the current value is kept.

.PARAMETER EndIP
    Optional. End of the client IP lease range. If omitted, the current value is kept.

.PARAMETER SubnetMask
    Optional. Subnet mask for leased addresses. If omitted, the current value is kept.

.PARAMETER IPv6Lease
    Optional. IPv6 lease address. If omitted, the current value is kept.

.PARAMETER IPv6Prefix
    Optional. IPv6 prefix length, 64-112. If omitted, the current value is kept.

.PARAMETER LeaseMode
    Optional. Address families leased to clients: IPv4 or 'IPv4 and IPv6'. If omitted, the
    current value is kept.

.PARAMETER PrimaryDNSIPv4
    Optional. Primary DNS server handed to clients. If omitted, the current value is kept.

.PARAMETER SecondaryDNSIPv4
    Optional. Secondary DNS server handed to clients. If omitted, the current value is kept.

.PARAMETER PrimaryWINSIPv4
    Optional. Primary WINS server handed to clients. If omitted, the current value is kept.

.PARAMETER SecondaryWINSIPv4
    Optional. Secondary WINS server handed to clients. If omitted, the current value is
    kept.

.PARAMETER DomainName
    Optional. Domain suffix handed to clients. If omitted, the current value is kept.

.PARAMETER DisconnectDeadPeerAfter
    Optional. Seconds before a dead peer is disconnected, 60-1800. If omitted, the current
    value is kept.

.PARAMETER DisconnectIdlePeerAfter
    Optional. Minutes before an idle peer is disconnected, 15-360. If omitted, the current
    value is kept.

.PARAMETER EncryptionAlgorithm
    Optional. Cipher used for the tunnel. If omitted, the current value is kept.

.PARAMETER AuthenticationAlgorithm
    Optional. Hash algorithm used for the tunnel. If omitted, the current value is kept.

.PARAMETER Keysize
    Optional. Key size: 1024bit or 2048bit. If omitted, the current value is kept.

.PARAMETER KeyLifetime
    Optional. Key lifetime, in seconds, 60-86400. If omitted, the current value is kept.

.PARAMETER DebugMode
    Optional. Debug logging: Enable or Disable. If omitted, the current value is kept.

.PARAMETER SecurityHeartbeat
    Optional. Security Heartbeat requirement: Enable or Disable. If omitted, the current
    value is kept.

.PARAMETER SaveCredential
    Optional. Allows the SSL VPN client to save the user's login credential: Enable or
    Disable. If omitted, the current value is kept.

.PARAMETER TwoFAToken
    Optional. Requires a two-factor token: Enable or Disable. If omitted, the current value
    is kept.

.PARAMETER AdLogon
    Optional. Uses the client's Windows logon credentials: Enable or Disable. If omitted,
    the current value is kept.

.PARAMETER AutoConnect
    Optional. Connects the tunnel automatically: Enable or Disable. If omitted, the current
    value is kept.

.PARAMETER HostorDNSName
    Optional. Reachability check target used when -AutoConnect is Enable. If omitted, the
    current value is kept.

.PARAMETER StaticIPAddresses
    Optional. Assigns static IP addresses to clients: Enable or Disable. If omitted, the
    current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSSLTunnelAccessSettings -DebugMode Enable -WhatIf

    Shows what enabling debug logging would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSSLTunnelAccessSettings -DebugMode Enable

    Enables debug logging. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLTunnelAccessSettings
#>
function Set-SfosSSLTunnelAccessSettings {
    # PSUseSingularNouns is suppressed on purpose: <SSLTunnelAccessSettings> is the entity's
    # own singleton name, not a plural container - it has no singular child element.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    # PSAvoidUsingPlainTextForPassword on -SaveCredential is a false positive: it is an
    # Enable/Disable policy toggle controlling whether the SSL VPN client is allowed to save
    # the user's login credential, not a credential itself.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'SaveCredential')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('TCP', 'UDP')]
        [string]$Protocol,

        [string]$SSLServerCertificate,
        [string]$OverrideHostName,

        [ValidateRange(1, 65535)]
        [int]$SslPort,

        [string]$StartIP,
        [string]$EndIP,
        [string]$SubnetMask,
        [string]$IPv6Lease,

        [ValidateRange(64, 112)]
        [int]$IPv6Prefix,

        [ValidateSet('IPv4', 'IPv4 and IPv6')]
        [string]$LeaseMode,

        [string]$PrimaryDNSIPv4,
        [string]$SecondaryDNSIPv4,
        [string]$PrimaryWINSIPv4,
        [string]$SecondaryWINSIPv4,
        [string]$DomainName,

        [ValidateRange(60, 1800)]
        [int]$DisconnectDeadPeerAfter,

        [ValidateRange(15, 360)]
        [int]$DisconnectIdlePeerAfter,

        [string]$EncryptionAlgorithm,
        [string]$AuthenticationAlgorithm,

        [ValidateSet('1024bit', '2048bit')]
        [string]$Keysize,

        [ValidateRange(60, 86400)]
        [int]$KeyLifetime,

        [ValidateSet('Enable', 'Disable')]
        [string]$DebugMode,

        [ValidateSet('Enable', 'Disable')]
        [string]$SecurityHeartbeat,

        [ValidateSet('Enable', 'Disable')]
        [string]$SaveCredential,

        [ValidateSet('Enable', 'Disable')]
        [string]$TwoFAToken,

        [ValidateSet('Enable', 'Disable')]
        [string]$AdLogon,

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoConnect,

        [string]$HostorDNSName,

        [ValidateSet('Enable', 'Disable')]
        [string]$StaticIPAddresses,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    $current = Get-SfosSSLTunnelAccessSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (-not $current) {
        throw 'SSLTunnelAccessSettings could not be read from the firewall; refusing to update blind.'
    }

    if (-not $PSCmdlet.ShouldProcess("SSLTunnelAccessSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $t = @{}
    foreach ($name in 'Protocol', 'SSLServerCertificate', 'OverrideHostName', 'StartIP', 'EndIP',
        'SubnetMask', 'IPv6Lease', 'IPv6Prefix', 'LeaseMode', 'PrimaryDNSIPv4', 'SecondaryDNSIPv4',
        'PrimaryWINSIPv4', 'SecondaryWINSIPv4', 'DomainName', 'DisconnectDeadPeerAfter',
        'DisconnectIdlePeerAfter', 'EncryptionAlgorithm', 'AuthenticationAlgorithm', 'Keysize',
        'KeyLifetime', 'DebugMode', 'SecurityHeartbeat', 'SaveCredential', 'TwoFAToken', 'AdLogon',
        'AutoConnect', 'HostorDNSName', 'StaticIPAddresses') {
        $t[$name] = if ($bp.ContainsKey($name)) { (Get-Variable -Name $name -ValueOnly) } else { $current.$name }
    }
    $t['Port'] = if ($bp.ContainsKey('SslPort')) { $SslPort } else { $current.Port }

    $portEsc = ConvertTo-SfosXmlEscaped -Text ([string]$t['Port'])
    $hostNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$t['OverrideHostName'])
    $startIpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$t['StartIP'])
    $endIpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$t['EndIP'])
    $endIpXml = if ($t['EndIP']) { "<EndIP>$endIpEsc</EndIP>" } else { '' }
    $domainEsc = ConvertTo-SfosXmlEscaped -Text ([string]$t['DomainName'])
    $hostOrDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$t['HostorDNSName'])

    $inner = @"
<Set operation="update">
  <SSLTunnelAccessSettings>
    <Protocol>$($t['Protocol'])</Protocol>
    <SSLServerCertificate>$($t['SSLServerCertificate'])</SSLServerCertificate>
    <OverrideHostName>$hostNameEsc</OverrideHostName>
    <Port>$portEsc</Port>
    <IPLeaseRange>
      <StartIP>$startIpEsc</StartIP>
      $endIpXml
    </IPLeaseRange>
    <SubnetMask>$($t['SubnetMask'])</SubnetMask>
    <IPv6Lease>$($t['IPv6Lease'])</IPv6Lease>
    <IPv6Prefix>$($t['IPv6Prefix'])</IPv6Prefix>
    <LeaseMode>$($t['LeaseMode'])</LeaseMode>
    <PrimaryDNSIPv4>$($t['PrimaryDNSIPv4'])</PrimaryDNSIPv4>
    <SecondaryDNSIPv4>$($t['SecondaryDNSIPv4'])</SecondaryDNSIPv4>
    <PrimaryWINSIPv4>$($t['PrimaryWINSIPv4'])</PrimaryWINSIPv4>
    <SecondaryWINSIPv4>$($t['SecondaryWINSIPv4'])</SecondaryWINSIPv4>
    <DomainName>$domainEsc</DomainName>
    <DisconnectDeadPeerAfter>$($t['DisconnectDeadPeerAfter'])</DisconnectDeadPeerAfter>
    <DisconnectIdlePeerAfter>$($t['DisconnectIdlePeerAfter'])</DisconnectIdlePeerAfter>
    <EncryptionAlgorithm>$($t['EncryptionAlgorithm'])</EncryptionAlgorithm>
    <AuthenticationAlgorithm>$($t['AuthenticationAlgorithm'])</AuthenticationAlgorithm>
    <Keysize>$($t['Keysize'])</Keysize>
    <KeyLifetime>$($t['KeyLifetime'])</KeyLifetime>
    <DebugMode>$($t['DebugMode'])</DebugMode>
    <SecurityHeartbeat>$($t['SecurityHeartbeat'])</SecurityHeartbeat>
    <SaveCredential>$($t['SaveCredential'])</SaveCredential>
    <TwoFAToken>$($t['TwoFAToken'])</TwoFAToken>
    <AdLogon>$($t['AdLogon'])</AdLogon>
    <AutoConnect>$($t['AutoConnect'])</AutoConnect>
    <HostorDNSName>$hostOrDnsEsc</HostorDNSName>
    <StaticIPAddresses>$($t['StaticIPAddresses'])</StaticIPAddresses>
  </SSLTunnelAccessSettings>
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
        throw "Error updating SSLTunnelAccessSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLTunnelAccessSettings' -Action 'update'
}

#endregion

#region SSLVPNPolicy

<#
.SYNOPSIS
    Retrieves SSL VPN policies from a Sophos Firewall.

.DESCRIPTION
    Returns the SSL VPN policies defined under VPN > SSL VPN (Remote Access) > Policies. A
    policy is either a Tunnel policy or a Clientless policy. Use this cmdlet to review
    existing policies or feed them into another cmdlet through the pipeline. The cmdlet
    only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only policies whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern, applied on the client. If omitted, the name is
    not used to filter.

.PARAMETER PolicyType
    Optional. Returns only policies of one type: Tunnel or Clientless. If omitted, both
    types are returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per policy. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosSSLVPNPolicy -PolicyType Clientless

    Lists every Clientless SSL VPN policy on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosSSLVPNPolicy
#>
function Get-SfosSSLVPNPolicy {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [ValidateSet('Tunnel', 'Clientless')]
        [string]$PolicyType,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><SSLVPNPolicy></SSLVPNPolicy></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SSLVPNPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Real errors (529 invalid module, login failure, ...) surface at the top level; the
    # empty-result status is nested under a sub-type (see .NOTES) and is not an error, so it
    # is not passed through Assert-SfosApiReturnSuccess here - it is handled below instead.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLVPNPolicy' -Action 'get'
    foreach ($sub in 'TunnelPolicy', 'ClientlessPolicy') {
        $statusNode = $XmlResponse.SelectSingleNode("/Response/SSLVPNPolicy/$sub/Status[not(@code)]")
        if ($statusNode -and $statusNode.InnerText -notmatch 'records\s+Zero') {
            throw "Sophos API returned a status without a code while trying to get SSLVPNPolicy. '$($statusNode.InnerText)'"
        }
    }

    $tunnelNodes = @($XmlResponse.SelectNodes('/Response/SSLVPNPolicy/TunnelPolicy[Name]'))
    $clientlessNodes = @($XmlResponse.SelectNodes('/Response/SSLVPNPolicy/ClientlessPolicy[Name]'))

    $objects = @()
    if ($PolicyType -ne 'Clientless') {
        $objects += foreach ($node in $tunnelNodes) {
            $resourceNodes = @($node.SelectNodes('PermittedNetworkResourcesIPv4/Resource'))
            $resource6Nodes = @($node.SelectNodes('PermittedNetworkResourcesIPv6/Resource'))
            $memberNodes = @($node.SelectNodes('PolicyMembers/Member'))
            [PSCustomObject]@{
                Name                          = [string]$node.Name
                PolicyType                    = 'Tunnel'
                Description                   = [string]$node.Description
                PolicyMembers                 = @($memberNodes | ForEach-Object { [string]$_.InnerText })
                UseAsDefaultGateway           = [string]$node.UseAsDefaultGateway
                PermittedNetworkResourcesIPv4 = @($resourceNodes | ForEach-Object { [string]$_.InnerText })
                PermittedNetworkResourcesIPv6 = @($resource6Nodes | ForEach-Object { [string]$_.InnerText })
                DisconnectIdleClients         = [string]$node.DisconnectIdleClients
                OverrideGlobalTimeout         = [string]$node.OverrideGlobalTimeout
            }
        }
    }
    if ($PolicyType -ne 'Tunnel') {
        $objects += foreach ($node in $clientlessNodes) {
            $memberNodes = @($node.SelectNodes('PolicyMembers/Member'))
            $groupNodes = @($node.SelectNodes('WebAccessibleResources/BookmarkGroups'))
            $bookmarkNodes = @($node.SelectNodes('WebAccessibleResources/Bookmarks'))
            [PSCustomObject]@{
                Name                     = [string]$node.Name
                PolicyType               = 'Clientless'
                Description              = [string]$node.Description
                PolicyMembers            = @($memberNodes | ForEach-Object { [string]$_.InnerText })
                RestrictWebApplications  = [string]$node.RestrictWebApplications
                BookmarkGroups           = @($groupNodes | ForEach-Object { [string]$_.InnerText })
                Bookmarks                = @($bookmarkNodes | ForEach-Object { [string]$_.InnerText })
            }
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @(($tunnelNodes + $clientlessNodes) | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a new SSL VPN policy on a Sophos Firewall.

.DESCRIPTION
    Creates a Tunnel or Clientless policy under VPN > SSL VPN (Remote Access) > Policies. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with permission to change VPN objects.

    Naming a user group in -Member changes that group's own SSL VPN policy assignment as a
    side effect. Use a dedicated test group while trying this cmdlet out; to undo the
    change on a group, set its policy assignment back to its original value with
    Set-SfosUserGroup (Authentication module).

.PARAMETER Name
    Required. Name of the policy. Must not contain a comma.

.PARAMETER PolicyType
    Required. Type of the policy: Tunnel or Clientless.

.PARAMETER Description
    Optional. Free-text description. If omitted, the description is left empty.

.PARAMETER Member
    Optional. Names of one or more user groups to assign this policy to. See the warning in
    .DESCRIPTION about the side effect on the named groups. If omitted, no group is
    assigned.

.PARAMETER UseAsDefaultGateway
    Tunnel policies only. Routes all client traffic through the tunnel: On or Off. Default:
    Off (split tunnel).

.PARAMETER PermittedNetworkResourcesIPv4
    Tunnel policies only. Names of IPv4 resources (IPHost or IPHostGroup) reachable through
    the tunnel. If omitted, no resources are sent.

.PARAMETER PermittedNetworkResourcesIPv6
    Tunnel policies only. Names of IPv6 resources reachable through the tunnel. If omitted,
    no resources are sent.

.PARAMETER DisconnectIdleClients
    Tunnel policies only. Disconnects idle clients: On or Off. Default: Off, which uses the
    global tunnel access setting.

.PARAMETER OverrideGlobalTimeout
    Tunnel policies only. Idle timeout, in minutes, 15-360. Requires
    -DisconnectIdleClients On.

.PARAMETER RestrictWebApplications
    Clientless policies only. Restricts access to the assigned bookmarks and bookmark
    groups: Enable or Disable. Default: Disable.

.PARAMETER BookmarkGroup
    Clientless policies only. Names of one or more bookmark groups accessible in web mode.
    If omitted, no bookmark groups are sent.

.PARAMETER Bookmark
    Clientless policies only. Names of one or more bookmarks accessible in web mode. If
    omitted, no bookmarks are sent.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosSSLVPNPolicy -Name 'MyTunnelPolicy' -PolicyType Tunnel -Member 'MyTestGroup' `
        -PermittedNetworkResourcesIPv4 'MyTestNetwork' -WhatIf

    Shows what the policy would look like without sending it to the firewall.

.EXAMPLE
    New-SfosSSLVPNPolicy -Name 'MyTunnelPolicy' -PolicyType Tunnel -Member 'MyTestGroup' `
        -PermittedNetworkResourcesIPv4 'MyTestNetwork'

    Creates a Tunnel policy and assigns it to a dedicated test group.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLVPNPolicy
#>
function New-SfosSSLVPNPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Tunnel', 'Clientless')]
        [string]$PolicyType,

        [string]$Description = '',

        [string[]]$Member = @(),

        [ValidateSet('On', 'Off')]
        [string]$UseAsDefaultGateway = 'Off',

        [string[]]$PermittedNetworkResourcesIPv4 = @(),
        [string[]]$PermittedNetworkResourcesIPv6 = @(),

        [ValidateSet('On', 'Off')]
        [string]$DisconnectIdleClients = 'Off',

        [ValidateRange(15, 360)]
        [int]$OverrideGlobalTimeout,

        [ValidateSet('Enable', 'Disable')]
        [string]$RestrictWebApplications = 'Disable',

        [string[]]$BookmarkGroup = @(),
        [string[]]$Bookmark = @(),

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("SSLVPNPolicy '$Name' ($PolicyType) on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $memberXml = ($Member | ForEach-Object { "<Member>$(ConvertTo-SfosXmlEscaped -Text $_)</Member>" }) -join ''

    if ($PolicyType -eq 'Tunnel') {
        $res4Xml = ($PermittedNetworkResourcesIPv4 | ForEach-Object { "<Resource>$(ConvertTo-SfosXmlEscaped -Text $_)</Resource>" }) -join ''
        $res6Xml = ($PermittedNetworkResourcesIPv6 | ForEach-Object { "<Resource>$(ConvertTo-SfosXmlEscaped -Text $_)</Resource>" }) -join ''
        $timeoutXml = if ($PSBoundParameters.ContainsKey('OverrideGlobalTimeout')) { "<OverrideGlobalTimeout>$OverrideGlobalTimeout</OverrideGlobalTimeout>" } else { '' }

        $inner = @"
<Set operation="add">
  <SSLVPNPolicy>
    <TunnelPolicy>
      <Name>$nameEsc</Name>
      <Description>$descEsc</Description>
      <PolicyMembers>$memberXml</PolicyMembers>
      <UseAsDefaultGateway>$UseAsDefaultGateway</UseAsDefaultGateway>
      <PermittedNetworkResourcesIPv4>$res4Xml</PermittedNetworkResourcesIPv4>
      <PermittedNetworkResourcesIPv6>$res6Xml</PermittedNetworkResourcesIPv6>
      <DisconnectIdleClients>$DisconnectIdleClients</DisconnectIdleClients>
      $timeoutXml
    </TunnelPolicy>
  </SSLVPNPolicy>
</Set>
"@
        $objectName = 'TunnelPolicy'
    }
    else {
        $groupXml = ($BookmarkGroup | ForEach-Object { "<BookmarkGroups>$(ConvertTo-SfosXmlEscaped -Text $_)</BookmarkGroups>" }) -join ''
        $bookmarkXml = ($Bookmark | ForEach-Object { "<Bookmarks>$(ConvertTo-SfosXmlEscaped -Text $_)</Bookmarks>" }) -join ''

        $inner = @"
<Set operation="add">
  <SSLVPNPolicy>
    <ClientlessPolicy>
      <Name>$nameEsc</Name>
      <Description>$descEsc</Description>
      <PolicyMembers>$memberXml</PolicyMembers>
      <RestrictWebApplications>$RestrictWebApplications</RestrictWebApplications>
      <WebAccessibleResources>$groupXml$bookmarkXml</WebAccessibleResources>
    </ClientlessPolicy>
  </SSLVPNPolicy>
</Set>
"@
        $objectName = 'ClientlessPolicy'
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error creating SSLVPNPolicy object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName $objectName -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SSL VPN policy on a Sophos Firewall.

.DESCRIPTION
    Updates a Tunnel or Clientless policy under VPN > SSL VPN (Remote Access) > Policies.
    Reads the current object first and sends the complete entity back, changing only the
    fields you pass; fields you omit keep their current value. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with permission to change VPN objects.

    Naming a user group in -Member changes that group's own SSL VPN policy assignment as a
    side effect. Use a dedicated test group while trying this cmdlet out; to undo the
    change on a group, set its policy assignment back to its original value with
    Set-SfosUserGroup (Authentication module).

.PARAMETER Name
    Required. Name of the policy to update. Accepts pipeline input by property name.

.PARAMETER PolicyType
    Optional. Type of the policy: Tunnel or Clientless. If omitted, the current object's own
    type is used.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER Member
    Optional. Complete replacement list of user group names. See the warning in
    .DESCRIPTION about the side effect on the named groups. If omitted, the current list is
    kept.

.PARAMETER UseAsDefaultGateway
    Tunnel policies only. Routes all client traffic through the tunnel: On or Off. If
    omitted, the current value is kept.

.PARAMETER PermittedNetworkResourcesIPv4
    Tunnel policies only. Complete replacement list of IPv4 resource names. If omitted, the
    current list is kept.

.PARAMETER PermittedNetworkResourcesIPv6
    Tunnel policies only. Complete replacement list of IPv6 resource names. If omitted, the
    current list is kept.

.PARAMETER DisconnectIdleClients
    Tunnel policies only. Disconnects idle clients: On or Off. If omitted, the current value
    is kept.

.PARAMETER OverrideGlobalTimeout
    Tunnel policies only. Idle timeout, in minutes, 15-360. If omitted, the current value is
    kept.

.PARAMETER RestrictWebApplications
    Clientless policies only. Restricts access to the assigned bookmarks and bookmark
    groups: Enable or Disable. If omitted, the current value is kept.

.PARAMETER BookmarkGroup
    Clientless policies only. Complete replacement list of bookmark group names. If omitted,
    the current list is kept.

.PARAMETER Bookmark
    Clientless policies only. Complete replacement list of bookmark names. If omitted, the
    current list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The policy Name, by property name, for example from Get-SfosSSLVPNPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSSLVPNPolicy -Name 'MyClientlessPolicy' -Description 'Updated' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSSLVPNPolicy -Name 'MyClientlessPolicy' -Description 'Updated'

    Updates the description. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLVPNPolicy
#>
function Set-SfosSSLVPNPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [ValidateSet('Tunnel', 'Clientless')]
        [string]$PolicyType,

        [string]$Description,
        [string[]]$Member,

        [ValidateSet('On', 'Off')]
        [string]$UseAsDefaultGateway,

        [string[]]$PermittedNetworkResourcesIPv4,
        [string[]]$PermittedNetworkResourcesIPv6,

        [ValidateSet('On', 'Off')]
        [string]$DisconnectIdleClients,

        [ValidateRange(15, 360)]
        [int]$OverrideGlobalTimeout,

        [ValidateSet('Enable', 'Disable')]
        [string]$RestrictWebApplications,

        [string[]]$BookmarkGroup,
        [string[]]$Bookmark,

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

        $existing = @(Get-SfosSSLVPNPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLVPNPolicy object '$Name' was not found."
        }
        $current = $existing[0]

        $targetType = if ($bp.ContainsKey('PolicyType')) { $PolicyType } else { $current.PolicyType }
        if ($bp.ContainsKey('PolicyType') -and $PolicyType -ne $current.PolicyType) {
            throw "SSLVPNPolicy '$Name' is a $($current.PolicyType) policy; -PolicyType $PolicyType does not match. Changing a policy's type is not supported by this API."
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $targetDesc = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDesc
        $targetMembers = if ($bp.ContainsKey('Member')) { $Member } else { $current.PolicyMembers }
        $memberXml = (@($targetMembers) | ForEach-Object { "<Member>$(ConvertTo-SfosXmlEscaped -Text $_)</Member>" }) -join ''

        if (-not $PSCmdlet.ShouldProcess("SSLVPNPolicy '$Name' ($targetType) on $($params.Firewall)", 'Update')) {
            return
        }

        if ($targetType -eq 'Tunnel') {
            $targetGw = if ($bp.ContainsKey('UseAsDefaultGateway')) { $UseAsDefaultGateway } else { $current.UseAsDefaultGateway }
            $targetRes4 = if ($bp.ContainsKey('PermittedNetworkResourcesIPv4')) { $PermittedNetworkResourcesIPv4 } else { $current.PermittedNetworkResourcesIPv4 }
            $targetRes6 = if ($bp.ContainsKey('PermittedNetworkResourcesIPv6')) { $PermittedNetworkResourcesIPv6 } else { $current.PermittedNetworkResourcesIPv6 }
            $targetIdle = if ($bp.ContainsKey('DisconnectIdleClients')) { $DisconnectIdleClients } else { $current.DisconnectIdleClients }
            $targetTimeout = if ($bp.ContainsKey('OverrideGlobalTimeout')) { $OverrideGlobalTimeout } else { $current.OverrideGlobalTimeout }

            $res4Xml = (@($targetRes4) | ForEach-Object { "<Resource>$(ConvertTo-SfosXmlEscaped -Text $_)</Resource>" }) -join ''
            $res6Xml = (@($targetRes6) | ForEach-Object { "<Resource>$(ConvertTo-SfosXmlEscaped -Text $_)</Resource>" }) -join ''
            $timeoutXml = if ($targetTimeout) { "<OverrideGlobalTimeout>$targetTimeout</OverrideGlobalTimeout>" } else { '' }

            $inner = @"
<Set operation="update">
  <SSLVPNPolicy>
    <TunnelPolicy>
      <Name>$nameEsc</Name>
      <Description>$descEsc</Description>
      <PolicyMembers>$memberXml</PolicyMembers>
      <UseAsDefaultGateway>$targetGw</UseAsDefaultGateway>
      <PermittedNetworkResourcesIPv4>$res4Xml</PermittedNetworkResourcesIPv4>
      <PermittedNetworkResourcesIPv6>$res6Xml</PermittedNetworkResourcesIPv6>
      <DisconnectIdleClients>$targetIdle</DisconnectIdleClients>
      $timeoutXml
    </TunnelPolicy>
  </SSLVPNPolicy>
</Set>
"@
            $objectName = 'TunnelPolicy'
        }
        else {
            $targetRestrict = if ($bp.ContainsKey('RestrictWebApplications')) { $RestrictWebApplications } else { $current.RestrictWebApplications }
            $targetGroups = if ($bp.ContainsKey('BookmarkGroup')) { $BookmarkGroup } else { $current.BookmarkGroups }
            $targetBookmarks = if ($bp.ContainsKey('Bookmark')) { $Bookmark } else { $current.Bookmarks }

            $groupXml = (@($targetGroups) | ForEach-Object { "<BookmarkGroups>$(ConvertTo-SfosXmlEscaped -Text $_)</BookmarkGroups>" }) -join ''
            $bookmarkXml = (@($targetBookmarks) | ForEach-Object { "<Bookmarks>$(ConvertTo-SfosXmlEscaped -Text $_)</Bookmarks>" }) -join ''

            $inner = @"
<Set operation="update">
  <SSLVPNPolicy>
    <ClientlessPolicy>
      <Name>$nameEsc</Name>
      <Description>$descEsc</Description>
      <PolicyMembers>$memberXml</PolicyMembers>
      <RestrictWebApplications>$targetRestrict</RestrictWebApplications>
      <WebAccessibleResources>$groupXml$bookmarkXml</WebAccessibleResources>
    </ClientlessPolicy>
  </SSLVPNPolicy>
</Set>
"@
            $objectName = 'ClientlessPolicy'
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating SSLVPNPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName $objectName -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SSL VPN policy from a Sophos Firewall.

.DESCRIPTION
    Removes a Tunnel or Clientless policy under VPN > SSL VPN (Remote Access) > Policies.
    Reads the object first, to resolve -PolicyType when not passed and to throw a clear
    error if it does not exist. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with permission to change
    VPN objects.

    If a user group still has this policy assigned, the removal fails. Clear the group's
    policy assignment first with Set-SfosUserGroup (Authentication module), then remove the
    policy.

.PARAMETER Name
    Required. Name of the policy to remove. Accepts pipeline input by property name.

.PARAMETER PolicyType
    Optional. Type of the policy: Tunnel or Clientless. If omitted, the type is resolved
    from the existing object.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The policy Name, by property name, for example from Get-SfosSSLVPNPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the policy cannot be removed.

.EXAMPLE
    Remove-SfosSSLVPNPolicy -Name 'MyClientlessPolicy' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosSSLVPNPolicy -Name 'MyClientlessPolicy' -Confirm:$false

    Removes the policy without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLVPNPolicy
#>
function Remove-SfosSSLVPNPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [ValidateSet('Tunnel', 'Clientless')]
        [string]$PolicyType,

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
        $existing = @(Get-SfosSSLVPNPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLVPNPolicy object '$Name' was not found."
        }
        $targetType = if ($PSBoundParameters.ContainsKey('PolicyType')) { $PolicyType } else { $existing[0].PolicyType }

        if (-not $PSCmdlet.ShouldProcess("SSLVPNPolicy '$Name' ($targetType) on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $typeTag = if ($targetType -eq 'Tunnel') { 'TunnelPolicy' } else { 'ClientlessPolicy' }

        $inner = "<Remove><SSLVPNPolicy><$typeTag><Name>$nameEsc</Name></$typeTag></SSLVPNPolicy></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing SSLVPNPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName "SSLVPNPolicy/$typeTag" -Action 'remove' -Target $Name
    }
}

#endregion

#region SSLBookmark

<#
.SYNOPSIS
    Retrieves SSL VPN bookmarks from a Sophos Firewall.

.DESCRIPTION
    Returns the SSL VPN bookmarks defined under VPN > SSL VPN (Remote Access) > Bookmarks. A
    bookmark is a shortcut to an internal resource, such as RDP or a web application, offered
    to Clientless SSL VPN users. Use this cmdlet to review existing bookmarks or feed them
    into another cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall
    is changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only bookmarks whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER TypeLike
    Optional. Returns only bookmarks whose type contains the given text anywhere. Applied on
    the client. If omitted, the type is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per bookmark. When -AutoLogin is
    Enable, the stored password is returned as PasswordHash and PasswordHashForm, never as
    plain text. Returns System.Xml.XmlElement when -AsXml is used, and an empty array when
    no object matches.

.EXAMPLE
    Get-SfosSSLBookmark -NameLike 'Intranet'

    Lists all SSL VPN bookmarks whose name contains 'Intranet'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosSSLBookmark
#>
function Get-SfosSSLBookmark {
    [CmdletBinding()]
    param(
        [string]$NameLike,
        [string]$TypeLike,

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
  <SSLBookmark>
    $filterXml
  </SSLBookmark>
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
        throw "Error retrieving SSLBookmark objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmark' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SSLBookmark[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $domainNodes = @($node.SelectNodes('RefferredDomains/Domains'))
        [PSCustomObject]@{
            Name              = [string]$node.Name
            Description       = [string]$node.Description
            Type              = [string]$node.Type
            URL               = [string]$node.URL
            ShareSession      = [string]$node.ShareSession
            AutoLogin         = [string]$node.AutoLogin
            UserName          = [string]$node.UserName
            # SelectSingleNode, not $node.Password: with the hashform attribute present the
            # XmlElement adapter hands back the element object, and [string] on that yields
            # the literal type name "System.Xml.XmlElement". A Set that resent that as the
            # preserved value would silently replace the real login password. Exposed as
            # hash + form, like the RADIUS shared secret, so Set-SfosSSLBookmark can resend
            # both.
            PasswordHash      = if ($pwNode = $node.SelectSingleNode('Password')) { $pwNode.InnerText } else { '' }
            PasswordHashForm  = if ($pwNode) { $pwNode.GetAttribute('hashform') } else { '' }
            Port              = [string]$node.Port
            Domain            = [string]$node.Domain
            Domains           = @($domainNodes | ForEach-Object { [string]$_.InnerText })
            ProtocolSecurity  = [string]$node.ProtocolSecurity
            InitRemoteFolder  = [string]$node.InitRemoteFolder
            PrivateKey        = [string]$node.PrivateKey
            PublicHostKey     = [string]$node.PublicHostKey
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($TypeLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Type -like "*$TypeLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a new SSL VPN bookmark on a Sophos Firewall.

.DESCRIPTION
    Creates a bookmark under VPN > SSL VPN (Remote Access) > Bookmarks, a shortcut to an
    internal resource offered to Clientless SSL VPN users. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the bookmark, up to 50 characters.

.PARAMETER Type
    Required. Protocol of the target resource: HTTP, HTTPS, RDP, TELNET, SSH, FTP, FTPS,
    SFTP, SMB or VNC.

.PARAMETER URL
    Required. URL or host name of the target resource, up to 250 characters.

.PARAMETER Description
    Optional. Free-text description. If omitted, the description is left empty.

.PARAMETER ShareSession
    Optional. Shares the login session with other bookmarks of the same type: Enable or
    Disable. Default: Disable.

.PARAMETER AutoLogin
    Optional. Logs the user in automatically using -LoginUserName and -SecurePassword (or
    -PrivateKey for SSH/SFTP): Enable or Disable. Default: Disable.

.PARAMETER LoginUserName
    Optional. Login user name, used when -AutoLogin is Enable. Named -LoginUserName, not
    -UserName, because -Username is the connection parameter used for the API login.

.PARAMETER SecurePassword
    Optional. Login password, as a SecureString, used when -AutoLogin is Enable. Named
    -SecurePassword, not -Password, because -Password is the connection parameter used for
    the API login.

.PARAMETER BookmarkPort
    Optional. Port number of the target service. If omitted, the field is left empty.

.PARAMETER Domain
    Optional. Domain name, used for RDP or SMB. If omitted, the field is left empty.

.PARAMETER Domains
    HTTP/HTTPS bookmarks only. Additional domains or URLs this bookmark's session may reach.
    If omitted, no additional domains are sent.

.PARAMETER ProtocolSecurity
    RDP bookmarks only. Security layer: RDP, TLS or NLA. NLA requires -AutoLogin Enable. If
    omitted, the field is left empty.

.PARAMETER InitRemoteFolder
    FTP/FTPS/SFTP/SMB bookmarks only. Initial remote directory, up to 250 characters. If
    omitted, the field is left empty.

.PARAMETER PrivateKey
    SSH/SFTP bookmarks only. Private key text. If omitted, the field is left empty.

.PARAMETER PublicHostKey
    SSH/FTPS/SFTP bookmarks only. Public host key text. If omitted, the field is left empty.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosSSLBookmark -Name 'MyBookmark' -Type HTTP -URL 'intranet.example' -BookmarkPort 80 -WhatIf

    Shows what the bookmark would look like without sending it to the firewall.

.EXAMPLE
    New-SfosSSLBookmark -Name 'MyBookmark' -Type HTTP -URL 'intranet.example' -BookmarkPort 80

    Creates an HTTP bookmark pointing at the given host and port.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLBookmark
#>
function New-SfosSSLBookmark {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('HTTP', 'HTTPS', 'RDP', 'TELNET', 'SSH', 'FTP', 'FTPS', 'SFTP', 'SMB', 'VNC')]
        [string]$Type,

        [Parameter(Mandatory)]
        [ValidateLength(1, 250)]
        [string]$URL,

        [string]$Description = '',

        [ValidateSet('Enable', 'Disable')]
        [string]$ShareSession = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoLogin = 'Disable',

        [string]$LoginUserName,
        [SecureString]$SecurePassword,
        [string]$BookmarkPort,
        [string]$Domain,
        [string[]]$Domains = @(),

        [ValidateSet('RDP', 'TLS', 'NLA')]
        [string]$ProtocolSecurity,

        [ValidateLength(0, 250)]
        [string]$InitRemoteFolder,

        [string]$PrivateKey,
        [string]$PublicHostKey,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("SSLBookmark '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $securePasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('SecurePassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        try {
            $securePasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $urlEsc = ConvertTo-SfosXmlEscaped -Text $URL
    $userEsc = ConvertTo-SfosXmlEscaped -Text $LoginUserName
    $passEsc = ConvertTo-SfosXmlEscaped -Text $securePasswordPlain
    $portEsc = ConvertTo-SfosXmlEscaped -Text $BookmarkPort
    $domainEsc = ConvertTo-SfosXmlEscaped -Text $Domain
    $folderEsc = ConvertTo-SfosXmlEscaped -Text $InitRemoteFolder
    $pkEsc = ConvertTo-SfosXmlEscaped -Text $PrivateKey
    $phkEsc = ConvertTo-SfosXmlEscaped -Text $PublicHostKey
    $domainsXml = ($Domains | ForEach-Object { "<Domains>$(ConvertTo-SfosXmlEscaped -Text $_)</Domains>" }) -join ''

    $optionalXml = ''
    if ($LoginUserName) { $optionalXml += "<UserName>$userEsc</UserName>" }
    if ($PSBoundParameters.ContainsKey('SecurePassword')) { $optionalXml += "<Password>$passEsc</Password>" }
    if ($BookmarkPort) { $optionalXml += "<Port>$portEsc</Port>" }
    if ($Domain) { $optionalXml += "<Domain>$domainEsc</Domain>" }
    if ($domainsXml) { $optionalXml += "<RefferredDomains>$domainsXml</RefferredDomains>" }
    if ($ProtocolSecurity) { $optionalXml += "<ProtocolSecurity>$ProtocolSecurity</ProtocolSecurity>" }
    if ($InitRemoteFolder) { $optionalXml += "<InitRemoteFolder>$folderEsc</InitRemoteFolder>" }
    if ($PrivateKey) { $optionalXml += "<PrivateKey>$pkEsc</PrivateKey>" }
    if ($PublicHostKey) { $optionalXml += "<PublicHostKey>$phkEsc</PublicHostKey>" }

    $inner = @"
<Set operation="add">
  <SSLBookmark>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <Type>$Type</Type>
    <URL>$urlEsc</URL>
    <ShareSession>$ShareSession</ShareSession>
    <AutoLogin>$AutoLogin</AutoLogin>
    $optionalXml
  </SSLBookmark>
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
        throw "Error creating SSLBookmark object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmark' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SSL VPN bookmark on a Sophos Firewall.

.DESCRIPTION
    Updates a bookmark under VPN > SSL VPN (Remote Access) > Bookmarks. Reads the current
    object first and sends the complete entity back, changing only the fields you pass;
    fields you omit keep their current value. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects. If you omit -SecurePassword, the cmdlet resends
    the stored password hash unchanged rather than clearing it.

.PARAMETER Name
    Required. Name of the bookmark to update. Accepts pipeline input by property name.

.PARAMETER Type
    Optional. Protocol of the target resource. If omitted, the current value is kept.

.PARAMETER URL
    Optional. URL or host name of the target resource. If omitted, the current value is
    kept.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER ShareSession
    Optional. Shares the login session with other bookmarks of the same type: Enable or
    Disable. If omitted, the current value is kept.

.PARAMETER AutoLogin
    Optional. Logs the user in automatically: Enable or Disable. If omitted, the current
    value is kept.

.PARAMETER LoginUserName
    Optional. Login user name. Named -LoginUserName, not -UserName, because -Username is
    the connection parameter used for the API login. If omitted, the current value is kept.

.PARAMETER SecurePassword
    Optional. Login password, as a SecureString. If omitted, the current stored password
    hash is kept.

.PARAMETER BookmarkPort
    Optional. Port number of the target service. If omitted, the current value is kept.

.PARAMETER Domain
    Optional. Domain name, used for RDP or SMB. If omitted, the current value is kept.

.PARAMETER Domains
    Optional. Complete replacement list of additional domains or URLs (HTTP/HTTPS
    bookmarks only). If omitted, the current list is kept.

.PARAMETER ProtocolSecurity
    Optional. RDP security layer: RDP, TLS or NLA. If omitted, the current value is kept.

.PARAMETER InitRemoteFolder
    Optional. Initial remote directory (FTP/FTPS/SFTP/SMB bookmarks only). If omitted, the
    current value is kept.

.PARAMETER PrivateKey
    Optional. Private key text (SSH/SFTP bookmarks only). If omitted, the current value is
    kept.

.PARAMETER PublicHostKey
    Optional. Public host key text (SSH/FTPS/SFTP bookmarks only). If omitted, the current
    value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The bookmark Name, by property name, for example from
    Get-SfosSSLBookmark.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSSLBookmark -Name 'MyBookmark' -Description 'Updated' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSSLBookmark -Name 'MyBookmark' -Description 'Updated'

    Updates the description. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLBookmark
#>
function Set-SfosSSLBookmark {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [ValidateSet('HTTP', 'HTTPS', 'RDP', 'TELNET', 'SSH', 'FTP', 'FTPS', 'SFTP', 'SMB', 'VNC')]
        [string]$Type,

        [string]$URL,
        [string]$Description,

        [ValidateSet('Enable', 'Disable')]
        [string]$ShareSession,

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoLogin,

        [string]$LoginUserName,
        [SecureString]$SecurePassword,
        [string]$BookmarkPort,
        [string]$Domain,
        [string[]]$Domains,

        [ValidateSet('RDP', 'TLS', 'NLA')]
        [string]$ProtocolSecurity,

        [string]$InitRemoteFolder,
        [string]$PrivateKey,
        [string]$PublicHostKey,

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

        $existing = @(Get-SfosSSLBookmark -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLBookmark object '$Name' was not found."
        }
        $current = $existing[0]

        $securePasswordPlain = $null
        if ($bp.ContainsKey('SecurePassword')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
            try {
                $securePasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
        }

        $t = @{
            Type             = if ($bp.ContainsKey('Type')) { $Type } else { $current.Type }
            URL              = if ($bp.ContainsKey('URL')) { $URL } else { $current.URL }
            Description      = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }
            ShareSession     = if ($bp.ContainsKey('ShareSession')) { $ShareSession } else { $current.ShareSession }
            AutoLogin        = if ($bp.ContainsKey('AutoLogin')) { $AutoLogin } else { $current.AutoLogin }
            UserName         = if ($bp.ContainsKey('LoginUserName')) { $LoginUserName } else { $current.UserName }
            # Caller-supplied plaintext goes out as a bare <Password>; a preserved value is
            # the HASH read back by Get and must be resent together with its hashform
            # attribute, or the firewall treats the hash text as a new plaintext password.
            Password         = if ($bp.ContainsKey('SecurePassword')) { $securePasswordPlain } else { $current.PasswordHash }
            PasswordHashForm = if ($bp.ContainsKey('SecurePassword')) { '' } else { $current.PasswordHashForm }
            Port             = if ($bp.ContainsKey('BookmarkPort')) { $BookmarkPort } else { $current.Port }
            Domain           = if ($bp.ContainsKey('Domain')) { $Domain } else { $current.Domain }
            Domains          = if ($bp.ContainsKey('Domains')) { $Domains } else { $current.Domains }
            ProtocolSecurity = if ($bp.ContainsKey('ProtocolSecurity')) { $ProtocolSecurity } else { $current.ProtocolSecurity }
            InitRemoteFolder = if ($bp.ContainsKey('InitRemoteFolder')) { $InitRemoteFolder } else { $current.InitRemoteFolder }
            PrivateKey       = if ($bp.ContainsKey('PrivateKey')) { $PrivateKey } else { $current.PrivateKey }
            PublicHostKey    = if ($bp.ContainsKey('PublicHostKey')) { $PublicHostKey } else { $current.PublicHostKey }
        }

        if (-not $PSCmdlet.ShouldProcess("SSLBookmark '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $urlEsc = ConvertTo-SfosXmlEscaped -Text $t.URL
        $descEsc = ConvertTo-SfosXmlEscaped -Text $t.Description
        $userEsc = ConvertTo-SfosXmlEscaped -Text $t.UserName
        $passEsc = ConvertTo-SfosXmlEscaped -Text $t.Password
        $portEsc = ConvertTo-SfosXmlEscaped -Text $t.Port
        $domainEsc = ConvertTo-SfosXmlEscaped -Text $t.Domain
        $folderEsc = ConvertTo-SfosXmlEscaped -Text $t.InitRemoteFolder
        $pkEsc = ConvertTo-SfosXmlEscaped -Text $t.PrivateKey
        $phkEsc = ConvertTo-SfosXmlEscaped -Text $t.PublicHostKey
        $domainsXml = (@($t.Domains) | ForEach-Object { "<Domains>$(ConvertTo-SfosXmlEscaped -Text $_)</Domains>" }) -join ''

        $optionalXml = ''
        if ($t.UserName) { $optionalXml += "<UserName>$userEsc</UserName>" }
        if ($t.Password) {
            if ($t.PasswordHashForm) {
                $hfEsc = ConvertTo-SfosXmlEscaped -Text $t.PasswordHashForm
                $optionalXml += "<Password hashform=`"$hfEsc`">$passEsc</Password>"
            } else {
                $optionalXml += "<Password>$passEsc</Password>"
            }
        }
        if ($t.Port) { $optionalXml += "<Port>$portEsc</Port>" }
        if ($t.Domain) { $optionalXml += "<Domain>$domainEsc</Domain>" }
        if ($domainsXml) { $optionalXml += "<RefferredDomains>$domainsXml</RefferredDomains>" }
        if ($t.ProtocolSecurity) { $optionalXml += "<ProtocolSecurity>$($t.ProtocolSecurity)</ProtocolSecurity>" }
        if ($t.InitRemoteFolder) { $optionalXml += "<InitRemoteFolder>$folderEsc</InitRemoteFolder>" }
        if ($t.PrivateKey) { $optionalXml += "<PrivateKey>$pkEsc</PrivateKey>" }
        if ($t.PublicHostKey) { $optionalXml += "<PublicHostKey>$phkEsc</PublicHostKey>" }

        $inner = @"
<Set operation="update">
  <SSLBookmark>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <Type>$($t.Type)</Type>
    <URL>$urlEsc</URL>
    <ShareSession>$($t.ShareSession)</ShareSession>
    <AutoLogin>$($t.AutoLogin)</AutoLogin>
    $optionalXml
  </SSLBookmark>
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
            throw "Error updating SSLBookmark object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmark' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SSL VPN bookmark from a Sophos Firewall.

.DESCRIPTION
    Removes a bookmark under VPN > SSL VPN (Remote Access) > Bookmarks. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with permission to change VPN objects. The cmdlet reads the object back
    afterwards and throws if it is still present, instead of reporting success for a removal
    that did not take effect.

.PARAMETER Name
    Required. Name of the bookmark to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The bookmark Name, by property name, for example from
    Get-SfosSSLBookmark.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the bookmark cannot be removed.

.EXAMPLE
    Remove-SfosSSLBookmark -Name 'MyBookmark' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosSSLBookmark -Name 'MyBookmark' -Confirm:$false

    Removes the bookmark without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLBookmark
#>
function Remove-SfosSSLBookmark {
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
        $existing = @(Get-SfosSSLBookmark -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLBookmark object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SSLBookmark '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SSLBookmark><Name>$nameEsc</Name></SSLBookmark></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing SSLBookmark object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmark' -Action 'remove' -Target $Name

        # The firewall reports success here even when it deleted nothing (see .DESCRIPTION),
        # so success has to be confirmed independently before this cmdlet agrees with it.
        $stillThere = @(Get-SfosSSLBookmark -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($stillThere.Count -gt 0) {
            throw "The Sophos API reported success removing SSLBookmark object '$Name', but the object is still present on the firewall. This is a confirmed firmware defect on SFOS 22.0 - see this cmdlet's .NOTES."
        }
    }
}

#endregion

#region SSLBookmarkGroup

<#
.SYNOPSIS
    Retrieves SSL VPN bookmark groups from a Sophos Firewall.

.DESCRIPTION
    Returns the SSL VPN bookmark groups defined under VPN > SSL VPN (Remote Access) >
    Bookmark groups. A bookmark group bundles bookmarks so they can be assigned to a
    Clientless SSL VPN policy together. Use this cmdlet to review existing groups or feed
    them into another cmdlet through the pipeline. The cmdlet only reads; nothing on the
    firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only groups whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per bookmark group. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosSSLBookmarkGroup

    Lists every SSL VPN bookmark group on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosSSLBookmarkGroup
#>
function Get-SfosSSLBookmarkGroup {
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
  <SSLBookmarkGroup>
    $filterXml
  </SSLBookmarkGroup>
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
        throw "Error retrieving SSLBookmarkGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmarkGroup' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SSLBookmarkGroup[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $bookmarkNodes = @($node.SelectNodes('BookmarkList/Bookmark'))
        [PSCustomObject]@{
            Name         = [string]$node.Name
            Description  = [string]$node.Description
            BookmarkList = @($bookmarkNodes | ForEach-Object { [string]$_.InnerText })
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
    Creates a new SSL VPN bookmark group on a Sophos Firewall.

.DESCRIPTION
    Creates a bookmark group under VPN > SSL VPN (Remote Access) > Bookmark groups. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the bookmark group, up to 50 characters.

.PARAMETER Bookmark
    Required. Names of one or more existing bookmarks.

.PARAMETER Description
    Optional. Free-text description. If omitted, the description is left empty.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Bookmark 'MyBookmark' -WhatIf

    Shows what the group would look like without sending it to the firewall.

.EXAMPLE
    New-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Bookmark 'MyBookmark'

    Creates a bookmark group with a single member bookmark.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLBookmarkGroup
#>
function New-SfosSSLBookmarkGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateCount(1, [int]::MaxValue)]
        [string[]]$Bookmark,

        [string]$Description = '',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("SSLBookmarkGroup '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $bookmarkXml = ($Bookmark | ForEach-Object { "<Bookmark>$(ConvertTo-SfosXmlEscaped -Text $_)</Bookmark>" }) -join ''

    $inner = @"
<Set operation="add">
  <SSLBookmarkGroup>
    <Name>$nameEsc</Name>
    <BookmarkList>$bookmarkXml</BookmarkList>
    <Description>$descEsc</Description>
  </SSLBookmarkGroup>
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
        throw "Error creating SSLBookmarkGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmarkGroup' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SSL VPN bookmark group on a Sophos Firewall.

.DESCRIPTION
    Updates a bookmark group under VPN > SSL VPN (Remote Access) > Bookmark groups. Reads
    the current object first and sends the complete entity back, changing only the fields
    you pass; fields you omit keep their current value. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the group to update. Accepts pipeline input by property name.

.PARAMETER Bookmark
    Optional. Complete replacement list of member bookmark names. If omitted, the current
    list is kept.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The group Name, by property name, for example from
    Get-SfosSSLBookmarkGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Description 'Updated' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Description 'Updated'

    Updates the description. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLBookmarkGroup
#>
function Set-SfosSSLBookmarkGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string[]]$Bookmark,
        [string]$Description,

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

        $existing = @(Get-SfosSSLBookmarkGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLBookmarkGroup object '$Name' was not found."
        }
        $current = $existing[0]

        $targetBookmarks = if ($bp.ContainsKey('Bookmark')) { $Bookmark } else { $current.BookmarkList }
        $targetDesc = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }

        if (-not $PSCmdlet.ShouldProcess("SSLBookmarkGroup '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDesc
        $bookmarkXml = (@($targetBookmarks) | ForEach-Object { "<Bookmark>$(ConvertTo-SfosXmlEscaped -Text $_)</Bookmark>" }) -join ''

        $inner = @"
<Set operation="update">
  <SSLBookmarkGroup>
    <Name>$nameEsc</Name>
    <BookmarkList>$bookmarkXml</BookmarkList>
    <Description>$descEsc</Description>
  </SSLBookmarkGroup>
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
            throw "Error updating SSLBookmarkGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmarkGroup' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SSL VPN bookmark group from a Sophos Firewall.

.DESCRIPTION
    Removes a bookmark group under VPN > SSL VPN (Remote Access) > Bookmark groups. Reads
    the object first and throws a clear error if it does not exist. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with permission to change VPN objects. The member bookmarks themselves
    are not removed.

.PARAMETER Name
    Required. Name of the group to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The group Name, by property name, for example from
    Get-SfosSSLBookmarkGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the group cannot be removed.

.EXAMPLE
    Remove-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Confirm:$false

    Removes the group without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSSLBookmarkGroup
#>
function Remove-SfosSSLBookmarkGroup {
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
        $existing = @(Get-SfosSSLBookmarkGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SSLBookmarkGroup object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SSLBookmarkGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SSLBookmarkGroup><Name>$nameEsc</Name></SSLBookmarkGroup></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing SSLBookmarkGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SSLBookmarkGroup' -Action 'remove' -Target $Name
    }
}

<#
.SYNOPSIS
    Adds a bookmark to an SSL VPN bookmark group's member list.

.DESCRIPTION
    Reads the current bookmark group, adds the given bookmark name to its member list if
    not already present, and writes the complete list back. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with permission to change VPN objects.

.PARAMETER GroupName
    Required. Name of the bookmark group to update. Accepts pipeline input by property
    name.

.PARAMETER Bookmark
    Required. Name of the bookmark to add. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. GroupName and Bookmark, by property name, for example from
    Get-SfosSSLBookmarkGroup and Get-SfosSSLBookmark.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Add-SfosSSLBookmarkGroupMember -GroupName 'MyBookmarkGroup' -Bookmark 'MyBookmark' -WhatIf

    Shows what would be added without sending the request to the firewall.

.EXAMPLE
    Add-SfosSSLBookmarkGroupMember -GroupName 'MyBookmarkGroup' -Bookmark 'MyBookmark'

    Adds the bookmark to the group.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosSSLBookmarkGroup

.LINK
    Remove-SfosSSLBookmarkGroupMember
#>
function Add-SfosSSLBookmarkGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$GroupName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Bookmark,

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
        $existing = @(Get-SfosSSLBookmarkGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $GroupName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $GroupName })

        if ($existing.Count -eq 0) {
            throw "The SSLBookmarkGroup object '$GroupName' was not found."
        }

        if ($existing[0].BookmarkList -contains $Bookmark) {
            return
        }
        $newList = @($existing[0].BookmarkList) + $Bookmark

        if (-not $PSCmdlet.ShouldProcess("SSLBookmarkGroup '$GroupName' on $($params.Firewall)", "Add member '$Bookmark'")) {
            return
        }

        Set-SfosSSLBookmarkGroup -Name $GroupName -Bookmark $newList `
            -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
            -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false
    }
}

<#
.SYNOPSIS
    Removes a bookmark from an SSL VPN bookmark group's member list.

.DESCRIPTION
    Reads the current bookmark group, removes the given bookmark name from its member list,
    and writes the remaining list back. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects. A bookmark group needs at least one member; the
    firewall rejects a request that would empty the list.

.PARAMETER GroupName
    Required. Name of the bookmark group to update. Accepts pipeline input by property
    name.

.PARAMETER Bookmark
    Required. Name of the bookmark to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. GroupName and Bookmark, by property name, for example from
    Get-SfosSSLBookmarkGroup and Get-SfosSSLBookmark.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Remove-SfosSSLBookmarkGroupMember -GroupName 'MyBookmarkGroup' -Bookmark 'MyBookmark' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosSSLBookmarkGroupMember -GroupName 'MyBookmarkGroup' -Bookmark 'MyBookmark'

    Removes the bookmark from the group.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosSSLBookmarkGroup

.LINK
    Add-SfosSSLBookmarkGroupMember
#>
function Remove-SfosSSLBookmarkGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$GroupName,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Bookmark,

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
        $existing = @(Get-SfosSSLBookmarkGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $GroupName `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $GroupName })

        if ($existing.Count -eq 0) {
            throw "The SSLBookmarkGroup object '$GroupName' was not found."
        }

        if ($existing[0].BookmarkList -notcontains $Bookmark) {
            return
        }
        $newList = @($existing[0].BookmarkList | Where-Object { $_ -ne $Bookmark })

        if (-not $PSCmdlet.ShouldProcess("SSLBookmarkGroup '$GroupName' on $($params.Firewall)", "Remove member '$Bookmark'")) {
            return
        }

        Set-SfosSSLBookmarkGroup -Name $GroupName -Bookmark $newList `
            -Firewall $params.Firewall -Port $params.Port -Username $params.Username `
            -Password $params.Password -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false
    }
}

#endregion

#region SiteToSiteClient

<#
.SYNOPSIS
    Retrieves SSL VPN site-to-site client connections from a Sophos Firewall.

.DESCRIPTION
    Returns the client connections defined under VPN > SSL VPN (Site-to-site) > Client
    connections. Use this cmdlet to review existing connections or feed them into another
    cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is changed.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

.PARAMETER NameLike
    Optional. Returns only connections whose name contains the given text anywhere. This is
    a substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per client connection. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosSiteToSiteClient

    Lists every SSL VPN site-to-site client connection on the firewall of the current
    connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosSiteToSiteClient
#>
function Get-SfosSiteToSiteClient {
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
  <SiteToSiteClient>
    $filterXml
  </SiteToSiteClient>
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
        throw "Error retrieving SiteToSiteClient objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteClient' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SiteToSiteClient[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name                 = [string]$node.Name
            Description          = [string]$node.Description
            HttpProxyServer      = [string]$node.HttpProxyServer
            ProxyServer          = [string]$node.ProxyServer
            ProxyPort            = [string]$node.ProxyPort
            ProxyAuthentication  = [string]$node.ProxyAuthentication
            Username             = [string]$node.Username
            PeerHost             = [string]$node.PeerHost
            HostName             = [string]$node.HostName
            Status               = [string]$node.Status
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
    Creates a new SSL VPN site-to-site client connection on a Sophos Firewall.

.DESCRIPTION
    Creates a client connection under VPN > SSL VPN (Site-to-site) > Client connections,
    from a configuration file exported on the server side. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection, up to 50 characters. Starts with a letter; letters,
    digits and underscore only.

.PARAMETER ServerConfigurationFile
    Required. Content of the .apc/.epc configuration file exported from the SSL VPN server
    side.

.PARAMETER FilePassword
    Optional. Password protecting the configuration file, as a SecureString, up to 60
    characters. If omitted, no password is sent.

.PARAMETER Description
    Optional. Free-text description, up to 255 characters. If omitted, the description is
    left empty.

.PARAMETER HttpProxyServer
    Optional. Routes the connection through an HTTP proxy: Enable or Disable. Default:
    Disable.

.PARAMETER ProxyServer
    Required when -HttpProxyServer is Enable. Proxy server name.

.PARAMETER ProxyPort
    Required when -HttpProxyServer is Enable. Proxy server port.

.PARAMETER ProxyAuthentication
    Optional. Authenticates against the proxy: Enable or Disable. Default: Disable.

.PARAMETER ProxyUsername
    Used when -ProxyAuthentication is Enable. Proxy authentication user name.

.PARAMETER ProxySecurePassword
    Used when -ProxyAuthentication is Enable. Proxy authentication password, as a
    SecureString.

.PARAMETER PeerHost
    Optional. Overrides the peer host name from the configuration file: Enable or Disable.
    Default: Disable.

.PARAMETER HostName
    Required when -PeerHost is Enable. Override host name.

.PARAMETER Status
    Optional. Initial state of the connection: On or Off. If omitted, the field is left
    empty.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosSiteToSiteClient -Name 'MyS2SClient' -ServerConfigurationFile $apcFileContent -WhatIf

    Shows what the connection would look like without sending it to the firewall.

.EXAMPLE
    New-SfosSiteToSiteClient -Name 'MyS2SClient' -ServerConfigurationFile $apcFileContent

    Creates a client connection from the given configuration file content.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSiteToSiteClient
#>
function New-SfosSiteToSiteClient {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_]*$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$ServerConfigurationFile,

        [SecureString]$FilePassword,

        [ValidateLength(0, 255)]
        [string]$Description = '',

        [ValidateSet('Enable', 'Disable')]
        [string]$HttpProxyServer = 'Disable',

        [string]$ProxyServer,
        [int]$ProxyPort,

        [ValidateSet('Enable', 'Disable')]
        [string]$ProxyAuthentication = 'Disable',

        [string]$ProxyUsername,
        [SecureString]$ProxySecurePassword,

        [ValidateSet('Enable', 'Disable')]
        [string]$PeerHost = 'Disable',

        [string]$HostName,

        [ValidateSet('On', 'Off')]
        [string]$Status,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($HttpProxyServer -eq 'Enable' -and (-not $ProxyServer -or -not $ProxyPort)) {
        throw "SiteToSiteClient '$Name': -HttpProxyServer Enable requires -ProxyServer and -ProxyPort."
    }
    if ($PeerHost -eq 'Enable' -and -not $HostName) {
        throw "SiteToSiteClient '$Name': -PeerHost Enable requires -HostName."
    }

    if (-not $PSCmdlet.ShouldProcess("SiteToSiteClient '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $cfgEsc = ConvertTo-SfosXmlEscaped -Text $ServerConfigurationFile

    $filePasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('FilePassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($FilePassword)
        try {
            $filePasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }
    $proxySecurePasswordPlain = ''
    if ($PSBoundParameters.ContainsKey('ProxySecurePassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ProxySecurePassword)
        try {
            $proxySecurePasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
    }

    $optionalXml = ''
    if ($PSBoundParameters.ContainsKey('FilePassword')) { $optionalXml += "<FilePassword>$(ConvertTo-SfosXmlEscaped -Text $filePasswordPlain)</FilePassword>" }
    if ($HttpProxyServer -eq 'Enable') {
        $optionalXml += "<ProxyServer>$(ConvertTo-SfosXmlEscaped -Text $ProxyServer)</ProxyServer>"
        $optionalXml += "<ProxyPort>$ProxyPort</ProxyPort>"
    }
    if ($ProxyAuthentication -eq 'Enable') {
        $optionalXml += "<Username>$(ConvertTo-SfosXmlEscaped -Text $ProxyUsername)</Username>"
        $optionalXml += "<Password>$(ConvertTo-SfosXmlEscaped -Text $proxySecurePasswordPlain)</Password>"
    }
    if ($PeerHost -eq 'Enable') {
        $optionalXml += "<HostName>$(ConvertTo-SfosXmlEscaped -Text $HostName)</HostName>"
    }
    if ($Status) { $optionalXml += "<Status>$Status</Status>" }

    $inner = @"
<Set operation="add">
  <SiteToSiteClient>
    <Name>$nameEsc</Name>
    <ServerConfigurationFile>$cfgEsc</ServerConfigurationFile>
    <HttpProxyServer>$HttpProxyServer</HttpProxyServer>
    <ProxyAuthentication>$ProxyAuthentication</ProxyAuthentication>
    <PeerHost>$PeerHost</PeerHost>
    <Description>$descEsc</Description>
    $optionalXml
  </SiteToSiteClient>
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
        throw "Error creating SiteToSiteClient object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteClient' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SSL VPN site-to-site client connection on a Sophos Firewall.

.DESCRIPTION
    Updates a client connection under VPN > SSL VPN (Site-to-site) > Client connections.
    Reads the current object first and sends the complete entity back, changing only the
    fields you pass; most fields you omit keep their current value. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with permission to change VPN objects.

    -FilePassword and -ProxySecurePassword are the exception: if you omit them, they are not
    resent, so an existing password may not be preserved across an update.

.PARAMETER Name
    Required. Name of the connection to update. Accepts pipeline input by property name.

.PARAMETER ServerConfigurationFile
    Optional. Content of the .apc/.epc configuration file. If omitted, the current value is
    kept.

.PARAMETER FilePassword
    Optional. Password protecting the configuration file, as a SecureString. See the note
    in .DESCRIPTION about this field.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER HttpProxyServer
    Optional. Routes the connection through an HTTP proxy: Enable or Disable. If omitted,
    the current value is kept.

.PARAMETER ProxyServer
    Optional. Proxy server name. If omitted, the current value is kept.

.PARAMETER ProxyPort
    Optional. Proxy server port. If omitted, the current value is kept.

.PARAMETER ProxyAuthentication
    Optional. Authenticates against the proxy: Enable or Disable. If omitted, the current
    value is kept.

.PARAMETER ProxyUsername
    Optional. Proxy authentication user name. If omitted, the current value is kept.

.PARAMETER ProxySecurePassword
    Optional. Proxy authentication password, as a SecureString. See the note in
    .DESCRIPTION about this field.

.PARAMETER PeerHost
    Optional. Overrides the peer host name from the configuration file: Enable or Disable.
    If omitted, the current value is kept.

.PARAMETER HostName
    Optional. Override host name. If omitted, the current value is kept.

.PARAMETER Status
    Optional. State of the connection: On or Off. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosSiteToSiteClient.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSiteToSiteClient -Name 'MyS2SClient' -Description 'Updated' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSiteToSiteClient -Name 'MyS2SClient' -Description 'Updated'

    Updates the description. Most other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSiteToSiteClient
#>
function Set-SfosSiteToSiteClient {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$ServerConfigurationFile,
        [SecureString]$FilePassword,
        [string]$Description,

        [ValidateSet('Enable', 'Disable')]
        [string]$HttpProxyServer,

        [string]$ProxyServer,
        [int]$ProxyPort,

        [ValidateSet('Enable', 'Disable')]
        [string]$ProxyAuthentication,

        [string]$ProxyUsername,
        [SecureString]$ProxySecurePassword,

        [ValidateSet('Enable', 'Disable')]
        [string]$PeerHost,

        [string]$HostName,

        [ValidateSet('On', 'Off')]
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
        $bp = $PSBoundParameters

        $existing = @(Get-SfosSiteToSiteClient -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SiteToSiteClient object '$Name' was not found."
        }
        $current = $existing[0]

        $t = @{
            HttpProxyServer     = if ($bp.ContainsKey('HttpProxyServer')) { $HttpProxyServer } else { $current.HttpProxyServer }
            ProxyServer         = if ($bp.ContainsKey('ProxyServer')) { $ProxyServer } else { $current.ProxyServer }
            ProxyPort           = if ($bp.ContainsKey('ProxyPort')) { $ProxyPort } else { $current.ProxyPort }
            ProxyAuthentication = if ($bp.ContainsKey('ProxyAuthentication')) { $ProxyAuthentication } else { $current.ProxyAuthentication }
            ProxyUsername       = if ($bp.ContainsKey('ProxyUsername')) { $ProxyUsername } else { $current.Username }
            PeerHost            = if ($bp.ContainsKey('PeerHost')) { $PeerHost } else { $current.PeerHost }
            HostName            = if ($bp.ContainsKey('HostName')) { $HostName } else { $current.HostName }
            Description         = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }
            Status              = if ($bp.ContainsKey('Status')) { $Status } else { $current.Status }
        }
        $targetConfig = if ($bp.ContainsKey('ServerConfigurationFile')) { $ServerConfigurationFile } else { $null }

        $filePasswordPlain = $null
        if ($bp.ContainsKey('FilePassword')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($FilePassword)
            try {
                $filePasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
        }
        $proxySecurePasswordPlain = $null
        if ($bp.ContainsKey('ProxySecurePassword')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ProxySecurePassword)
            try {
                $proxySecurePasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
        }

        if (-not $PSCmdlet.ShouldProcess("SiteToSiteClient '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $descEsc = ConvertTo-SfosXmlEscaped -Text $t.Description

        $optionalXml = ''
        if ($targetConfig) { $optionalXml += "<ServerConfigurationFile>$(ConvertTo-SfosXmlEscaped -Text $targetConfig)</ServerConfigurationFile>" }
        if ($bp.ContainsKey('FilePassword')) { $optionalXml += "<FilePassword>$(ConvertTo-SfosXmlEscaped -Text $filePasswordPlain)</FilePassword>" }
        if ($t.HttpProxyServer -eq 'Enable') {
            $optionalXml += "<ProxyServer>$(ConvertTo-SfosXmlEscaped -Text $t.ProxyServer)</ProxyServer>"
            $optionalXml += "<ProxyPort>$($t.ProxyPort)</ProxyPort>"
        }
        if ($t.ProxyAuthentication -eq 'Enable') {
            $optionalXml += "<Username>$(ConvertTo-SfosXmlEscaped -Text $t.ProxyUsername)</Username>"
            if ($bp.ContainsKey('ProxySecurePassword')) { $optionalXml += "<Password>$(ConvertTo-SfosXmlEscaped -Text $proxySecurePasswordPlain)</Password>" }
        }
        if ($t.PeerHost -eq 'Enable') { $optionalXml += "<HostName>$(ConvertTo-SfosXmlEscaped -Text $t.HostName)</HostName>" }
        if ($t.Status) { $optionalXml += "<Status>$($t.Status)</Status>" }

        $inner = @"
<Set operation="update">
  <SiteToSiteClient>
    <Name>$nameEsc</Name>
    <HttpProxyServer>$($t.HttpProxyServer)</HttpProxyServer>
    <ProxyAuthentication>$($t.ProxyAuthentication)</ProxyAuthentication>
    <PeerHost>$($t.PeerHost)</PeerHost>
    <Description>$descEsc</Description>
    $optionalXml
  </SiteToSiteClient>
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
            throw "Error updating SiteToSiteClient object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteClient' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SSL VPN site-to-site client connection from a Sophos Firewall.

.DESCRIPTION
    Removes a client connection under VPN > SSL VPN (Site-to-site) > Client connections.
    Reads the object first and throws a clear error if it does not exist. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosSiteToSiteClient.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the connection cannot be
    removed.

.EXAMPLE
    Remove-SfosSiteToSiteClient -Name 'MyS2SClient' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosSiteToSiteClient -Name 'MyS2SClient' -Confirm:$false

    Removes the connection without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSiteToSiteClient
#>
function Remove-SfosSiteToSiteClient {
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
        $existing = @(Get-SfosSiteToSiteClient -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SiteToSiteClient object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SiteToSiteClient '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SiteToSiteClient><Name>$nameEsc</Name></SiteToSiteClient></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing SiteToSiteClient object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteClient' -Action 'remove' -Target $Name
    }
}

#endregion

#region SiteToSiteServer

<#
.SYNOPSIS
    Retrieves SSL VPN site-to-site server connections from a Sophos Firewall.

.DESCRIPTION
    Returns the server connections defined under VPN > SSL VPN (Site-to-site) > Server
    connections. Use this cmdlet to review existing connections or feed them into another
    cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is changed.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only connections whose name contains the given text anywhere. This is
    a substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per server connection. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosSiteToSiteServer -NameLike 'Branch'

    Lists all SSL VPN site-to-site server connections whose name contains 'Branch'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosSiteToSiteServer
#>
function Get-SfosSiteToSiteServer {
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
  <SiteToSiteServer>
    $filterXml
  </SiteToSiteServer>
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
        throw "Error retrieving SiteToSiteServer objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteServer' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SiteToSiteServer[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $localNodes = @($node.SelectNodes('LocalNetworks/Network'))
        $remoteNodes = @($node.SelectNodes('RemoteNetworks/Network'))
        [PSCustomObject]@{
            Name           = [string]$node.Name
            Description    = [string]$node.Description
            StaticIP       = [string]$node.StaticIP
            PeerIP         = [string]$node.PeerIP
            LocalNetworks  = @($localNodes | ForEach-Object { [string]$_.InnerText })
            RemoteNetworks = @($remoteNodes | ForEach-Object { [string]$_.InnerText })
            Status         = [string]$node.Status
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
    Creates a new SSL VPN site-to-site server connection on a Sophos Firewall.

.DESCRIPTION
    Creates a server connection under VPN > SSL VPN (Site-to-site) > Server connections. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection, up to 50 characters. Must not contain a hyphen.

.PARAMETER LocalNetworks
    Required. Names of one or more existing IPHost/IPHostGroup objects reachable on the
    local side.

.PARAMETER RemoteNetworks
    Required. Names of one or more existing IPHost/IPHostGroup objects reachable on the
    remote side.

.PARAMETER Description
    Optional. Free-text description, up to 255 characters. If omitted, the description is
    left empty.

.PARAMETER StaticIP
    Optional. Uses a static virtual IP for this tunnel: Enable or Disable. Default: Disable.

.PARAMETER PeerIP
    Required when -StaticIP is Enable. Static virtual IP address.

.PARAMETER Status
    Optional. State of the connection: On or Off. If omitted, the field is left empty.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosSiteToSiteServer -Name 'MyS2SServer' -LocalNetworks 'MyLocalNet' `
        -RemoteNetworks 'MyRemoteNet' -WhatIf

    Shows what the connection would look like without sending it to the firewall.

.EXAMPLE
    New-SfosSiteToSiteServer -Name 'MyS2SServer' -LocalNetworks 'MyLocalNet' `
        -RemoteNetworks 'MyRemoteNet'

    Creates a server connection between the given local and remote networks.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSiteToSiteServer
#>
function New-SfosSiteToSiteServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_]*$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateCount(1, [int]::MaxValue)]
        [string[]]$LocalNetworks,

        [Parameter(Mandatory)]
        [ValidateCount(1, [int]::MaxValue)]
        [string[]]$RemoteNetworks,

        [ValidateLength(0, 255)]
        [string]$Description = '',

        [ValidateSet('Enable', 'Disable')]
        [string]$StaticIP = 'Disable',

        [string]$PeerIP,

        [ValidateSet('On', 'Off')]
        [string]$Status,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($StaticIP -eq 'Enable' -and -not $PeerIP) {
        throw "SiteToSiteServer '$Name': -StaticIP Enable requires -PeerIP."
    }

    if (-not $PSCmdlet.ShouldProcess("SiteToSiteServer '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $localXml = ($LocalNetworks | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
    $remoteXml = ($RemoteNetworks | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
    $peerIpXml = if ($StaticIP -eq 'Enable') { "<PeerIP>$(ConvertTo-SfosXmlEscaped -Text $PeerIP)</PeerIP>" } else { '' }
    $statusXml = if ($Status) { "<Status>$Status</Status>" } else { '' }

    $inner = @"
<Set operation="add">
  <SiteToSiteServer>
    <Name>$nameEsc</Name>
    <StaticIP>$StaticIP</StaticIP>
    $peerIpXml
    <LocalNetworks>$localXml</LocalNetworks>
    <RemoteNetworks>$remoteXml</RemoteNetworks>
    <Description>$descEsc</Description>
    $statusXml
  </SiteToSiteServer>
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
        throw "Error creating SiteToSiteServer object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteServer' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SSL VPN site-to-site server connection on a Sophos Firewall.

.DESCRIPTION
    Updates a server connection under VPN > SSL VPN (Site-to-site) > Server connections.
    Reads the current object first and sends the complete entity back, changing only the
    fields you pass; fields you omit keep their current value. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection to update. Accepts pipeline input by property name.

.PARAMETER LocalNetworks
    Optional. Complete replacement list of local network object names. If omitted, the
    current list is kept.

.PARAMETER RemoteNetworks
    Optional. Complete replacement list of remote network object names. If omitted, the
    current list is kept.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER StaticIP
    Optional. Uses a static virtual IP for this tunnel: Enable or Disable. If omitted, the
    current value is kept.

.PARAMETER PeerIP
    Optional. Static virtual IP address, used when -StaticIP is Enable. If omitted, the
    current value is kept.

.PARAMETER Status
    Optional. State of the connection: On or Off. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosSiteToSiteServer.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosSiteToSiteServer -Name 'MyS2SServer' -Description 'Updated' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosSiteToSiteServer -Name 'MyS2SServer' -Description 'Updated'

    Updates the description. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSiteToSiteServer
#>
function Set-SfosSiteToSiteServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string[]]$LocalNetworks,
        [string[]]$RemoteNetworks,
        [string]$Description,

        [ValidateSet('Enable', 'Disable')]
        [string]$StaticIP,

        [string]$PeerIP,

        [ValidateSet('On', 'Off')]
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
        $bp = $PSBoundParameters

        $existing = @(Get-SfosSiteToSiteServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SiteToSiteServer object '$Name' was not found."
        }
        $current = $existing[0]

        $targetLocal = if ($bp.ContainsKey('LocalNetworks')) { $LocalNetworks } else { $current.LocalNetworks }
        $targetRemote = if ($bp.ContainsKey('RemoteNetworks')) { $RemoteNetworks } else { $current.RemoteNetworks }
        $targetDesc = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }
        $targetStaticIP = if ($bp.ContainsKey('StaticIP')) { $StaticIP } else { $current.StaticIP }
        $targetPeerIP = if ($bp.ContainsKey('PeerIP')) { $PeerIP } else { $current.PeerIP }
        $targetStatus = if ($bp.ContainsKey('Status')) { $Status } else { $current.Status }

        if ($targetStaticIP -eq 'Enable' -and -not $targetPeerIP) {
            throw "SiteToSiteServer '$Name': -StaticIP Enable requires PeerIP, either from the current object or from the call."
        }

        if (-not $PSCmdlet.ShouldProcess("SiteToSiteServer '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDesc
        $localXml = (@($targetLocal) | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
        $remoteXml = (@($targetRemote) | ForEach-Object { "<Network>$(ConvertTo-SfosXmlEscaped -Text $_)</Network>" }) -join ''
        $peerIpXml = if ($targetStaticIP -eq 'Enable') { "<PeerIP>$(ConvertTo-SfosXmlEscaped -Text $targetPeerIP)</PeerIP>" } else { '' }
        $statusXml = if ($targetStatus) { "<Status>$targetStatus</Status>" } else { '' }

        $inner = @"
<Set operation="update">
  <SiteToSiteServer>
    <Name>$nameEsc</Name>
    <StaticIP>$targetStaticIP</StaticIP>
    $peerIpXml
    <LocalNetworks>$localXml</LocalNetworks>
    <RemoteNetworks>$remoteXml</RemoteNetworks>
    <Description>$descEsc</Description>
    $statusXml
  </SiteToSiteServer>
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
            throw "Error updating SiteToSiteServer object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteServer' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SSL VPN site-to-site server connection from a Sophos Firewall.

.DESCRIPTION
    Removes a server connection under VPN > SSL VPN (Site-to-site) > Server connections.
    Reads the object first and throws a clear error if it does not exist. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosSiteToSiteServer.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the connection cannot be
    removed.

.EXAMPLE
    Remove-SfosSiteToSiteServer -Name 'MyS2SServer' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosSiteToSiteServer -Name 'MyS2SServer' -Confirm:$false

    Removes the connection without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSiteToSiteServer
#>
function Remove-SfosSiteToSiteServer {
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
        $existing = @(Get-SfosSiteToSiteServer -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SiteToSiteServer object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SiteToSiteServer '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SiteToSiteServer><Name>$nameEsc</Name></SiteToSiteServer></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing SiteToSiteServer object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SiteToSiteServer' -Action 'remove' -Target $Name
    }
}

#endregion

#requires -Version 5.1
#requires -Modules SophosFirewall.Core

# SophosFirewall.VPN - L2TP and PPTP legacy tunnel protocols
# Entities: L2TPConfiguration (doc folder L2TPConfiguration, singleton), L2TPConnection (doc
# folder L2TPConnection), PPTPConfiguration (doc folder PPTPConfiguration, singleton).
#
# Cross-cutting points that apply to every function in this region:
#
# 1. The response root element for a write is not the outer entity name - it is whichever
#    sub-element the operation actually touched, and it differs by operation:
#      - Set (update) on the *Settings sub-object: response root is <L2TPSettings> /
#        <PPTPSettings> directly under <Response>, not <L2TPConfiguration><L2TPSettings>.
#        Assert-SfosApiReturnSuccess therefore needs -ObjectName 'L2TPSettings' /
#        'PPTPSettings', not the entity name.
#      - Set (update) adding a member: response root is <L2TPMembers> / <PPTPMembers>
#        directly under <Response>. -ObjectName 'L2TPMembers' / 'PPTPMembers'.
#      - Remove of a member: response root nests one level deeper than Set does -
#        <L2TPConfiguration><L2TPMembers>...</L2TPMembers></L2TPConfiguration>.
#        -ObjectName 'L2TPConfiguration/L2TPMembers' / 'PPTPConfiguration/PPTPMembers'
#        (Assert-SfosApiReturnSuccess accepts a path here; it is spliced directly into the
#        XPath it builds).
#      - Add/Edit/Remove on L2TPConnection: response root is <L2TPConnection><Configuration>,
#        i.e. -ObjectName 'L2TPConnection/Configuration' - the same path Get uses for a
#        populated or code-bearing result. A bare <L2TPConnection><Name>...</L2TPConnection>
#        (no <Configuration> wrapper) on Remove produces a completely empty response body
#        (no <Status> anywhere, not even a code-less one) - that shape is silently ignored
#        by the firewall, not merely rejected.
#    None of this is documented; every path above was read directly off a real response.
#
# 2. PPTPConfiguration's sample XML on the ConfigurePPTP operation page wraps its settings in
#    <Configuration>, but the wire - both what Get returns and what a Set's own status
#    response echoes back - uses <PPTPSettings>, mirroring L2TPConfiguration's own
#    <L2TPSettings> naming. <Configuration> produces the same "did not even validate"
#    symptom as any other wrong element name; <PPTPSettings> is what this module sends.
#
# 3. StartIP, EndIP and PrimaryDNSServer are mandatory on every Set of *Settings, including
#    an update that changes nothing at all: echoing the unconfigured baseline
#    (<L2TPGeneralSettings>Disable</L2TPGeneralSettings><LeaseIPFromRadiusServer>Disable</...)
#    straight back is rejected with 501, naming exactly those three elements as missing -
#    even though L2TPGeneralSettings stays Disable throughout and Get itself omits all three
#    elements entirely when they were never configured. In other words: the singleton's
#    factory/never-configured state cannot be round-tripped through Set at all without
#    introducing a real IP range and DNS server, and once introduced there is no value that
#    clears them back to "absent" again (the same three elements are demanded on every
#    subsequent Set too). Because this field is a one-way structural ratchet with no path
#    back to "unset", Set-SfosL2TPConfiguration/Set-SfosPPTPConfiguration were deliberately
#    not exercised end-to-end against a real write - see both functions' .NOTES. The
#    *Members sub-object has no such dependency (see point 4) and was exercised end-to-end,
#    including a full field-toggle-and-revert.
#
# 4. L2TPMembers/PPTPMembers is independent of *Settings validation (a Set touching only the
#    member list succeeds even while the mandatory IP-range fields above remain unset) and
#    is genuinely reversible, not append-only: Set adds a member (code 201), Remove takes it
#    back off again (code 200), and a Get in between and after matches the original baseline
#    exactly both times - unlike the append-only URLList/SecurityPolicyList quirks
#    documented elsewhere in this project for other entities.
#
# 5. Get on the two singletons returns no <Status> element at all on a normal (non-error)
#    response - only a failed Set produces one. That is consistent with
#    Assert-SfosApiReturnSuccess's own contract (no status found => treated as success) and
#    needs no special handling in Get-SfosL2TPConfiguration/Get-SfosPPTPConfiguration.
#
# 6. Get-SfosL2TPConnection's empty-result shape differs between an unfiltered and a
#    filtered call: unfiltered, an empty firewall answers the usual
#    '<L2TPConnection><Configuration><Status>No. of records Zero.</Status></Configuration></
#    L2TPConnection>'; filtered (a <Filter> sent, no match), it instead answers a bare
#    self-closing '<L2TPConnection/>' with no <Configuration> and no <Status> at all. Both
#    shapes are handled identically here because this cmdlet counts nodes that carry a
#    <Name> rather than inspecting <Status> to decide "empty" - see Get-SfosGatewayHost's
#    precedent.

#region L2TPConfiguration

<#
.SYNOPSIS
    Retrieves the L2TP configuration from a Sophos Firewall.

.DESCRIPTION
    Returns the L2TP settings under VPN > L2TP. This is a device-wide singleton: there is
    exactly one object and it has no name. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with the L2TP settings and member
    list. Fields that were never configured on the firewall, such as AssignIPFrom or
    PrimaryDNSServer, come back as an empty string. Returns System.Xml.XmlElement when
    -AsXml is used.

.EXAMPLE
    Get-SfosL2TPConfiguration

    Shows the L2TP configuration of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosL2TPConfiguration
#>
function Get-SfosL2TPConfiguration {
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

    $inner = '<Get><L2TPConfiguration></L2TPConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving the L2TPConfiguration object: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'L2TPSettings' -Action 'get' -Target 'L2TPConfiguration'

    $node = $XmlResponse.SelectSingleNode('/Response/L2TPConfiguration')
    if (-not $node) {
        throw 'Error retrieving the L2TPConfiguration object: the firewall did not return the singleton.'
    }

    if ($AsXml) {
        return $node
    }

    $settings = $node.SelectSingleNode('L2TPSettings')
    $memberNodes = @($node.SelectNodes('L2TPMembers/UserName'))

    return [PSCustomObject]@{
        L2TPGeneralSettings    = [string]$settings.L2TPGeneralSettings
        StartIP                = [string]$settings.AssignIPFrom.StartIP
        EndIP                   = [string]$settings.AssignIPFrom.EndIP
        LeaseIPFromRadiusServer = [string]$settings.LeaseIPFromRadiusServer
        PrimaryDNSServer        = [string]$settings.PrimaryDNSServer
        SecondaryDNSServer      = [string]$settings.SecondaryDNSServer
        PrimaryWINSServer       = [string]$settings.PrimaryWINSServer
        SecondaryWINSServer     = [string]$settings.SecondaryWINSServer
        MemberList               = @($memberNodes | ForEach-Object -Process { [string]$_.InnerText })
    }
}

<#
.SYNOPSIS
    Updates the L2TP configuration on a Sophos Firewall.

.DESCRIPTION
    Updates the L2TP settings under VPN > L2TP, a device-wide singleton. Reads the current
    object first and sends the complete entity back, changing only the fields you pass;
    fields you omit keep their current value. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

    Once -StartIP, -EndIP and -PrimaryDNSServer have been set for the first time, the
    unconfigured state cannot be restored afterward through this API; there is no value
    that clears them back to empty. Confirm the values before you write them.

.PARAMETER L2TPGeneralSettings
    Optional. Enables L2TP: Enable or Disable. If omitted, the current value is kept.

.PARAMETER StartIP
    Optional. Start of the IP range leased to L2TP clients. If omitted, the current value
    is kept. Required together with -EndIP and -PrimaryDNSServer on every update once the
    singleton has been configured.

.PARAMETER EndIP
    Optional. End of the IP range leased to L2TP clients. If omitted, the current value is
    kept.

.PARAMETER LeaseIPFromRadiusServer
    Optional. Leases the client IP through RADIUS instead of the local range: Enable or
    Disable. If omitted, the current value is kept.

.PARAMETER PrimaryDNSServer
    Optional. Primary DNS server handed to L2TP clients. If omitted, the current value is
    kept.

.PARAMETER SecondaryDNSServer
    Optional. Secondary DNS server handed to L2TP clients. If omitted, the current value is
    kept.

.PARAMETER PrimaryWINSServer
    Optional. Primary WINS server handed to L2TP clients. If omitted, the current value is
    kept.

.PARAMETER SecondaryWINSServer
    Optional. Secondary WINS server handed to L2TP clients. If omitted, the current value is
    kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosL2TPConfiguration -StartIP '203.0.113.10' -EndIP '203.0.113.20' `
        -PrimaryDNSServer '203.0.113.1' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosL2TPConfiguration -StartIP '203.0.113.10' -EndIP '203.0.113.20' `
        -PrimaryDNSServer '203.0.113.1' -Confirm:$false

    Configures the L2TP IP lease range and DNS server without asking for confirmation, for
    use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosL2TPConfiguration
#>
function Set-SfosL2TPConfiguration {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$L2TPGeneralSettings,

        [string]$StartIP,
        [string]$EndIP,

        [ValidateSet('Enable', 'Disable')]
        [string]$LeaseIPFromRadiusServer,

        [string]$PrimaryDNSServer,
        [string]$SecondaryDNSServer,
        [string]$PrimaryWINSServer,
        [string]$SecondaryWINSServer,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    $current = Get-SfosL2TPConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetGeneral = if ($bp.ContainsKey('L2TPGeneralSettings')) { $L2TPGeneralSettings } else { $current.L2TPGeneralSettings }
    $targetStartIP = if ($bp.ContainsKey('StartIP')) { $StartIP } else { $current.StartIP }
    $targetEndIP = if ($bp.ContainsKey('EndIP')) { $EndIP } else { $current.EndIP }
    $targetLease = if ($bp.ContainsKey('LeaseIPFromRadiusServer')) { $LeaseIPFromRadiusServer } else { $current.LeaseIPFromRadiusServer }
    $targetPrimaryDns = if ($bp.ContainsKey('PrimaryDNSServer')) { $PrimaryDNSServer } else { $current.PrimaryDNSServer }
    $targetSecondaryDns = if ($bp.ContainsKey('SecondaryDNSServer')) { $SecondaryDNSServer } else { $current.SecondaryDNSServer }
    $targetPrimaryWins = if ($bp.ContainsKey('PrimaryWINSServer')) { $PrimaryWINSServer } else { $current.PrimaryWINSServer }
    $targetSecondaryWins = if ($bp.ContainsKey('SecondaryWINSServer')) { $SecondaryWINSServer } else { $current.SecondaryWINSServer }

    # SFOS requires these three unconditionally on every update, even one that changes
    # nothing else - see .NOTES.
    if (-not $targetStartIP -or -not $targetEndIP -or -not $targetPrimaryDns) {
        throw 'Set-SfosL2TPConfiguration: the Sophos API requires StartIP, EndIP and PrimaryDNSServer on every update, even when the current object has none configured - supply -StartIP, -EndIP and -PrimaryDNSServer.'
    }

    if (-not $PSCmdlet.ShouldProcess("L2TPConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    $startIPEsc = ConvertTo-SfosXmlEscaped -Text $targetStartIP
    $endIPEsc = ConvertTo-SfosXmlEscaped -Text $targetEndIP
    $primaryDnsEsc = ConvertTo-SfosXmlEscaped -Text $targetPrimaryDns
    $secondaryDnsXml = if ($targetSecondaryDns) { "<SecondaryDNSServer>$(ConvertTo-SfosXmlEscaped -Text $targetSecondaryDns)</SecondaryDNSServer>" } else { '' }
    $primaryWinsXml = if ($targetPrimaryWins) { "<PrimaryWINSServer>$(ConvertTo-SfosXmlEscaped -Text $targetPrimaryWins)</PrimaryWINSServer>" } else { '' }
    $secondaryWinsXml = if ($targetSecondaryWins) { "<SecondaryWINSServer>$(ConvertTo-SfosXmlEscaped -Text $targetSecondaryWins)</SecondaryWINSServer>" } else { '' }

    $inner = @"
<Set operation="update">
  <L2TPConfiguration>
    <L2TPSettings>
      <L2TPGeneralSettings>$targetGeneral</L2TPGeneralSettings>
      <AssignIPFrom>
        <StartIP>$startIPEsc</StartIP>
        <EndIP>$endIPEsc</EndIP>
      </AssignIPFrom>
      <LeaseIPFromRadiusServer>$targetLease</LeaseIPFromRadiusServer>
      <PrimaryDNSServer>$primaryDnsEsc</PrimaryDNSServer>
      $secondaryDnsXml
      $primaryWinsXml
      $secondaryWinsXml
    </L2TPSettings>
  </L2TPConfiguration>
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
        throw "Error updating the L2TPConfiguration object: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'L2TPSettings' -Action 'update' -Target 'L2TPConfiguration'
}

<#
.SYNOPSIS
    Adds a user to the L2TP configuration's member list.

.DESCRIPTION
    Reads the current L2TP configuration, adds the given local user to its member list if
    not already present, and writes the complete list back. Adding a member does not
    require an IP lease range to be configured. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER MemberName
    Required. Name of an existing local user to grant L2TP access to. Accepts pipeline
    input by value and by property name. Named -MemberName, not -UserName, because
    -Username is the connection parameter used for the API login.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. MemberName, by value or by property name, for example from
    Get-SfosL2TPConfiguration's MemberList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Add-SfosL2TPConfigurationMember -MemberName 'VPNUser1' -WhatIf

    Shows what would be added without sending the request to the firewall.

.EXAMPLE
    Add-SfosL2TPConfigurationMember -MemberName 'VPNUser1'

    Grants the local user L2TP access.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosL2TPConfiguration

.LINK
    Remove-SfosL2TPConfigurationMember
#>
function Add-SfosL2TPConfigurationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$MemberName,

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
        if (-not $PSCmdlet.ShouldProcess("L2TPConfiguration member '$MemberName' on $($params.Firewall)", 'Add')) {
            return
        }

        $userEsc = ConvertTo-SfosXmlEscaped -Text $MemberName

        $inner = @"
<Set operation="update">
  <L2TPConfiguration>
    <L2TPMembers>
      <UserName>$userEsc</UserName>
    </L2TPMembers>
  </L2TPConfiguration>
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
            throw "Error adding L2TPConfiguration member '$MemberName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'L2TPMembers' -Action 'add member' -Target $MemberName
    }
}

<#
.SYNOPSIS
    Removes a user from the L2TP configuration's member list.

.DESCRIPTION
    Reads the current L2TP configuration, removes the given local user from its member
    list, and writes the remaining list back. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER MemberName
    Required. Name of the local user to remove from the L2TP member list. Accepts pipeline
    input by property name. Named -MemberName, not -UserName, because -Username is the
    connection parameter used for the API login.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. MemberName, by property name, for example from
    Get-SfosL2TPConfiguration's MemberList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Remove-SfosL2TPConfigurationMember -MemberName 'VPNUser1' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosL2TPConfigurationMember -MemberName 'VPNUser1'

    Revokes the local user's L2TP access.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosL2TPConfiguration

.LINK
    Add-SfosL2TPConfigurationMember
#>
function Remove-SfosL2TPConfigurationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$MemberName,

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
        if (-not $PSCmdlet.ShouldProcess("L2TPConfiguration member '$MemberName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $userEsc = ConvertTo-SfosXmlEscaped -Text $MemberName

        $inner = @"
<Remove>
  <L2TPConfiguration>
    <L2TPMembers>
      <UserName>$userEsc</UserName>
    </L2TPMembers>
  </L2TPConfiguration>
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
            throw "Error removing L2TPConfiguration member '$MemberName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'L2TPConfiguration/L2TPMembers' -Action 'remove member' -Target $MemberName
    }
}

#endregion

#region L2TPConnection

<#
.SYNOPSIS
    Retrieves L2TP connections from a Sophos Firewall.

.DESCRIPTION
    Returns the L2TP connections defined under VPN > L2TP > Connections. Use this cmdlet to
    review existing connections or feed them into another cmdlet through the pipeline. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only connections whose name contains the given text anywhere. This is
    a substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
    objects. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per L2TP connection. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosL2TPConnection

    Lists every L2TP connection on the firewall of the current connection.

.EXAMPLE
    Get-SfosL2TPConnection -NameLike 'Branch'

    Lists all L2TP connections whose name contains 'Branch'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    New-SfosL2TPConnection
#>
function Get-SfosL2TPConnection {
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
  <L2TPConnection>
    $filterXml
  </L2TPConnection>
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
        throw "Error retrieving L2TPConnection objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'L2TPConnection/Configuration' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/L2TPConnection/Configuration[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $networkNodes = @($node.SelectNodes('RemoteLANNetwork/Network'))

        [PSCustomObject]@{
            Name                      = [string]$node.Name
            Description               = [string]$node.Description
            Policy                    = [string]$node.Policy
            ActionOnVPNRestart        = [string]$node.ActionOnVPNRestart
            AuthenticationType        = [string]$node.AuthenticationType
            PresharedKey              = [string]$node.PresharedKey
            LocalCertificate          = [string]$node.LocalCertificate
            LocalWANPort              = [string]$node.LocalWANPort
            AliasLocalWANPort         = [string]$node.AliasLocalWANPort
            LocalIDType               = [string]$node.LocalIDType
            LocalID                   = [string]$node.LocalID
            RemoteHost                = [string]$node.RemoteHost
            AllowNATTraversal         = [string]$node.AllowNATTraversal
            RemoteLANNetworkList      = @($networkNodes | ForEach-Object -Process { [string]$_.InnerText })
            RemoteIDType              = [string]$node.RemoteIDType
            RemoteID                  = [string]$node.RemoteID
            LocalPort                 = [string]$node.LocalPort
            RemotePort                = [string]$node.RemotePort
            DisconnectOnIdleInterval  = [string]$node.DisconnectOnIdleInterval
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
    Creates a new L2TP connection on a Sophos Firewall.

.DESCRIPTION
    Creates an L2TP connection under VPN > L2TP > Connections. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection, up to 50 characters. Starts with a letter; letters,
    digits and underscore only.

.PARAMETER Description
    Optional. Free-text description, up to 255 characters. If omitted, the description is
    left empty.

.PARAMETER Policy
    Optional. Name of an existing VPN profile, for example DefaultL2TP. If omitted, the
    field is left empty.

.PARAMETER ActionOnVPNRestart
    Required. Behavior when the VPN service restarts: Disable or RespondOnly.

.PARAMETER AuthenticationType
    Required. Authentication method: PresharedKey or DigitalCertificate.

.PARAMETER PresharedKey
    Required when -AuthenticationType is PresharedKey. Pre-shared key, as a SecureString.

.PARAMETER LocalCertificate
    Required when -AuthenticationType is DigitalCertificate. Name of the local certificate
    to present.

.PARAMETER LocalWANPort
    Optional. Local WAN interface name, for example Port2. If omitted, the field is left
    empty.

.PARAMETER AliasLocalWANPort
    Required. Alias of the local WAN port to bind the connection to.

.PARAMETER LocalIDType
    Optional. Type of the local ID: DNS, IP Address, Email or DER ASN1 DN (X.509). If
    omitted, the field is left empty.

.PARAMETER LocalID
    Required. Local ID value, in the format matching -LocalIDType.

.PARAMETER RemoteHost
    Required. IP address or host name of the remote peer, or * for any.

.PARAMETER AllowNATTraversal
    Optional. Allows NAT traversal: Enable or Disable. Default: Enable.

.PARAMETER RemoteLANNetwork
    Required. Names of one or more existing IPHost objects (type Network) describing the
    remote LAN reachable through this connection.

.PARAMETER RemoteIDType
    Optional. Type of the remote ID: DNS, IP Address, Email or DER ASN1 DN (X.509). If
    omitted, the field is left empty.

.PARAMETER RemoteID
    Required. Remote ID value, in the format matching -RemoteIDType.

.PARAMETER LocalPort
    Required. Local UDP port, 1-65535 or *.

.PARAMETER RemotePort
    Required. Remote UDP port, 1-65535 or *.

.PARAMETER DisconnectOnIdleInterval
    Optional. Idle disconnect timer, in seconds, 120-999. If omitted, the field is left
    empty.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    New-SfosL2TPConnection -Name 'BranchL2TP' -ActionOnVPNRestart Disable `
        -AuthenticationType PresharedKey -PresharedKey (Read-Host -AsSecureString) `
        -AliasLocalWANPort 'Port2' -LocalID '203.0.113.1' -RemoteHost '203.0.113.10' `
        -RemoteLANNetwork 'RemoteNet' -RemoteID '203.0.113.10' -LocalPort 1701 `
        -RemotePort '*' -WhatIf

    Shows what the connection would look like without sending it to the firewall.

.EXAMPLE
    New-SfosL2TPConnection -Name 'BranchL2TP' -ActionOnVPNRestart Disable `
        -AuthenticationType PresharedKey -PresharedKey (Read-Host -AsSecureString) `
        -AliasLocalWANPort 'Port2' -LocalID '203.0.113.1' -RemoteHost '203.0.113.10' `
        -RemoteLANNetwork 'RemoteNet' -RemoteID '203.0.113.10' -LocalPort 1701 `
        -RemotePort '*'

    Creates an L2TP connection authenticated with a pre-shared key.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosL2TPConnection
#>
function New-SfosL2TPConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_]*$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description = '',

        [string]$Policy,

        [Parameter(Mandatory)]
        [ValidateSet('Disable', 'RespondOnly')]
        [string]$ActionOnVPNRestart,

        [Parameter(Mandatory)]
        [ValidateSet('PresharedKey', 'DigitalCertificate')]
        [string]$AuthenticationType,

        [SecureString]$PresharedKey,
        [string]$LocalCertificate,

        [string]$LocalWANPort,

        [Parameter(Mandatory)]
        [string]$AliasLocalWANPort,

        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$LocalIDType,

        [Parameter(Mandatory)]
        [string]$LocalID,

        [Parameter(Mandatory)]
        [string]$RemoteHost,

        [ValidateSet('Enable', 'Disable')]
        [string]$AllowNATTraversal = 'Enable',

        [Parameter(Mandatory)]
        [string[]]$RemoteLANNetwork,

        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$RemoteIDType,

        [Parameter(Mandatory)]
        [string]$RemoteID,

        [Parameter(Mandatory)]
        [string]$LocalPort,

        [Parameter(Mandatory)]
        [string]$RemotePort,

        [ValidateRange(120, 999)]
        [int]$DisconnectOnIdleInterval,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    if ($AuthenticationType -eq 'PresharedKey' -and -not $PSBoundParameters.ContainsKey('PresharedKey')) {
        throw "L2TPConnection '$Name': -AuthenticationType PresharedKey requires -PresharedKey."
    }
    if ($AuthenticationType -eq 'DigitalCertificate' -and -not $LocalCertificate) {
        throw "L2TPConnection '$Name': -AuthenticationType DigitalCertificate requires -LocalCertificate."
    }

    if (-not $PSCmdlet.ShouldProcess("L2TPConnection '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $presharedKeyPlain = ''
    if ($PSBoundParameters.ContainsKey('PresharedKey')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PresharedKey)
        try { $presharedKeyPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::FreeBSTR($bstr) }
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    $policyXml = if ($Policy) { "<Policy>$(ConvertTo-SfosXmlEscaped -Text $Policy)</Policy>" } else { '' }
    $authFieldXml = if ($AuthenticationType -eq 'PresharedKey') {
        "<PresharedKey>$(ConvertTo-SfosXmlEscaped -Text $presharedKeyPlain)</PresharedKey>"
    }
    else {
        "<LocalCertificate>$(ConvertTo-SfosXmlEscaped -Text $LocalCertificate)</LocalCertificate>"
    }
    $localWanPortXml = if ($LocalWANPort) { "<LocalWANPort>$(ConvertTo-SfosXmlEscaped -Text $LocalWANPort)</LocalWANPort>" } else { '' }
    $aliasEsc = ConvertTo-SfosXmlEscaped -Text $AliasLocalWANPort
    $localIdTypeXml = if ($LocalIDType) { "<LocalIDType>$LocalIDType</LocalIDType>" } else { '' }
    $localIdEsc = ConvertTo-SfosXmlEscaped -Text $LocalID
    $remoteHostEsc = ConvertTo-SfosXmlEscaped -Text $RemoteHost
    $networkXml = ''
    foreach ($net in $RemoteLANNetwork) {
        $networkXml += "<Network>$(ConvertTo-SfosXmlEscaped -Text $net)</Network>"
    }
    $remoteIdTypeXml = if ($RemoteIDType) { "<RemoteIDType>$RemoteIDType</RemoteIDType>" } else { '' }
    $remoteIdEsc = ConvertTo-SfosXmlEscaped -Text $RemoteID
    $localPortEsc = ConvertTo-SfosXmlEscaped -Text $LocalPort
    $remotePortEsc = ConvertTo-SfosXmlEscaped -Text $RemotePort
    $idleXml = if ($bp.ContainsKey('DisconnectOnIdleInterval')) { "<DisconnectOnIdleInterval>$DisconnectOnIdleInterval</DisconnectOnIdleInterval>" } else { '' }

    $inner = @"
<Set operation="add">
  <L2TPConnection>
    <Configuration>
      <Name>$nameEsc</Name>
      <Description>$descEsc</Description>
      $policyXml
      <ActionOnVPNRestart>$ActionOnVPNRestart</ActionOnVPNRestart>
      <AuthenticationType>$AuthenticationType</AuthenticationType>
      $authFieldXml
      $localWanPortXml
      <AliasLocalWANPort>$aliasEsc</AliasLocalWANPort>
      $localIdTypeXml
      <LocalID>$localIdEsc</LocalID>
      <RemoteHost>$remoteHostEsc</RemoteHost>
      <AllowNATTraversal>$AllowNATTraversal</AllowNATTraversal>
      <RemoteLANNetwork>$networkXml</RemoteLANNetwork>
      $remoteIdTypeXml
      <RemoteID>$remoteIdEsc</RemoteID>
      <LocalPort>$localPortEsc</LocalPort>
      <RemotePort>$remotePortEsc</RemotePort>
      $idleXml
    </Configuration>
  </L2TPConnection>
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
        throw "Error creating L2TPConnection object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # The write status for L2TPConnection lands FLAT at /Response/Configuration/Status for
    # create and update - NOT nested under L2TPConnection like Get and Remove report. The
    # nested path here made a 500/501 answer invisible and the cmdlet fail-open (reported
    # success, created nothing).
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Configuration' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing L2TP connection on a Sophos Firewall.

.DESCRIPTION
    Updates an L2TP connection under VPN > L2TP > Connections. Reads the current object
    first and sends the complete entity back, changing only the fields you pass; fields you
    omit keep their current value. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with permission to change
    VPN objects.

    -PresharedKey and -LocalCertificate are the exception: whichever one the resolved
    -AuthenticationType needs, you must supply it explicitly on every call. It is not read
    back from the current object.

.PARAMETER Name
    Required. Name of the connection to update. Accepts pipeline input by property name.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER Policy
    Optional. Name of an existing VPN profile. If omitted, the current value is kept.

.PARAMETER ActionOnVPNRestart
    Optional. Behavior when the VPN service restarts: Disable or RespondOnly. If omitted,
    the current value is kept.

.PARAMETER AuthenticationType
    Optional. Authentication method: PresharedKey or DigitalCertificate. If omitted, the
    current value is kept.

.PARAMETER PresharedKey
    Required whenever the resolved -AuthenticationType is PresharedKey. Pre-shared key, as a
    SecureString. See the note in .DESCRIPTION about this field.

.PARAMETER LocalCertificate
    Required whenever the resolved -AuthenticationType is DigitalCertificate. Name of the
    local certificate to present. See the note in .DESCRIPTION about this field.

.PARAMETER LocalWANPort
    Optional. Local WAN interface name. If omitted, the current value is kept.

.PARAMETER AliasLocalWANPort
    Optional. Alias of the local WAN port. If omitted, the current value is kept.

.PARAMETER LocalIDType
    Optional. Type of the local ID: DNS, IP Address, Email or DER ASN1 DN (X.509). If
    omitted, the current value is kept.

.PARAMETER LocalID
    Optional. Local ID value. If omitted, the current value is kept.

.PARAMETER RemoteHost
    Optional. IP address, host name or * of the remote peer. If omitted, the current value
    is kept.

.PARAMETER AllowNATTraversal
    Optional. Allows NAT traversal: Enable or Disable. If omitted, the current value is
    kept.

.PARAMETER RemoteLANNetwork
    Optional. Complete replacement list of remote LAN IPHost object names. If omitted, the
    current list is kept.

.PARAMETER RemoteIDType
    Optional. Type of the remote ID: DNS, IP Address, Email or DER ASN1 DN (X.509). If
    omitted, the current value is kept.

.PARAMETER RemoteID
    Optional. Remote ID value. If omitted, the current value is kept.

.PARAMETER LocalPort
    Optional. Local UDP port, 1-65535 or *. If omitted, the current value is kept.

.PARAMETER RemotePort
    Optional. Remote UDP port, 1-65535 or *. If omitted, the current value is kept.

.PARAMETER DisconnectOnIdleInterval
    Optional. Idle disconnect timer, in seconds, 120-999. If omitted, the current value is
    kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosL2TPConnection.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosL2TPConnection -Name 'BranchL2TP' -AuthenticationType PresharedKey `
        -PresharedKey (Read-Host -AsSecureString) -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosL2TPConnection -Name 'BranchL2TP' -AuthenticationType PresharedKey `
        -PresharedKey (Read-Host -AsSecureString)

    Sets a new pre-shared key. All other fields keep their current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosL2TPConnection
#>
function Set-SfosL2TPConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$Description,
        [string]$Policy,

        [ValidateSet('Disable', 'RespondOnly')]
        [string]$ActionOnVPNRestart,

        [ValidateSet('PresharedKey', 'DigitalCertificate')]
        [string]$AuthenticationType,

        [SecureString]$PresharedKey,
        [string]$LocalCertificate,

        [string]$LocalWANPort,
        [string]$AliasLocalWANPort,

        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$LocalIDType,

        [string]$LocalID,
        [string]$RemoteHost,

        [ValidateSet('Enable', 'Disable')]
        [string]$AllowNATTraversal,

        [string[]]$RemoteLANNetwork,

        [ValidateSet('DNS', 'IP Address', 'Email', 'DER ASN1 DN (X.509)')]
        [string]$RemoteIDType,

        [string]$RemoteID,
        [string]$LocalPort,
        [string]$RemotePort,

        [ValidateRange(120, 999)]
        [int]$DisconnectOnIdleInterval,

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

        $existing = @(Get-SfosL2TPConnection -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The L2TPConnection object '$Name' was not found."
        }
        $current = $existing[0]

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }
        $targetPolicy = if ($bp.ContainsKey('Policy')) { $Policy } else { $current.Policy }
        $targetAction = if ($bp.ContainsKey('ActionOnVPNRestart')) { $ActionOnVPNRestart } else { $current.ActionOnVPNRestart }
        $targetAuthType = if ($bp.ContainsKey('AuthenticationType')) { $AuthenticationType } else { $current.AuthenticationType }
        $targetLocalWanPort = if ($bp.ContainsKey('LocalWANPort')) { $LocalWANPort } else { $current.LocalWANPort }
        $targetAlias = if ($bp.ContainsKey('AliasLocalWANPort')) { $AliasLocalWANPort } else { $current.AliasLocalWANPort }
        $targetLocalIdType = if ($bp.ContainsKey('LocalIDType')) { $LocalIDType } else { $current.LocalIDType }
        $targetLocalId = if ($bp.ContainsKey('LocalID')) { $LocalID } else { $current.LocalID }
        $targetRemoteHost = if ($bp.ContainsKey('RemoteHost')) { $RemoteHost } else { $current.RemoteHost }
        $targetNat = if ($bp.ContainsKey('AllowNATTraversal')) { $AllowNATTraversal } else { $current.AllowNATTraversal }
        $targetNetworks = if ($bp.ContainsKey('RemoteLANNetwork')) { $RemoteLANNetwork } else { $current.RemoteLANNetworkList }
        $targetRemoteIdType = if ($bp.ContainsKey('RemoteIDType')) { $RemoteIDType } else { $current.RemoteIDType }
        $targetRemoteId = if ($bp.ContainsKey('RemoteID')) { $RemoteID } else { $current.RemoteID }
        $targetLocalPort = if ($bp.ContainsKey('LocalPort')) { $LocalPort } else { $current.LocalPort }
        $targetRemotePort = if ($bp.ContainsKey('RemotePort')) { $RemotePort } else { $current.RemotePort }
        $targetIdleBound = $bp.ContainsKey('DisconnectOnIdleInterval')
        $targetIdle = if ($targetIdleBound) { $DisconnectOnIdleInterval } else { $current.DisconnectOnIdleInterval }

        # PresharedKey/LocalCertificate are deliberately NOT read from $current - see .NOTES.
        if ($targetAuthType -eq 'PresharedKey' -and -not $bp.ContainsKey('PresharedKey')) {
            throw "L2TPConnection '$Name': the resolved AuthenticationType is PresharedKey, which requires -PresharedKey to be supplied on every Set call (it is not read back from the current object - see .NOTES)."
        }
        if ($targetAuthType -eq 'DigitalCertificate' -and -not $LocalCertificate) {
            throw "L2TPConnection '$Name': the resolved AuthenticationType is DigitalCertificate, which requires -LocalCertificate to be supplied on every Set call (it is not read back from the current object - see .NOTES)."
        }

        if (-not $PSCmdlet.ShouldProcess("L2TPConnection '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $presharedKeyPlain = ''
        if ($bp.ContainsKey('PresharedKey')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PresharedKey)
            try { $presharedKeyPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
            finally { [Runtime.InteropServices.Marshal]::FreeBSTR($bstr) }
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
        $policyXml = if ($targetPolicy) { "<Policy>$(ConvertTo-SfosXmlEscaped -Text $targetPolicy)</Policy>" } else { '' }
        $authFieldXml = if ($targetAuthType -eq 'PresharedKey') {
            "<PresharedKey>$(ConvertTo-SfosXmlEscaped -Text $presharedKeyPlain)</PresharedKey>"
        }
        else {
            "<LocalCertificate>$(ConvertTo-SfosXmlEscaped -Text $LocalCertificate)</LocalCertificate>"
        }
        $localWanPortXml = if ($targetLocalWanPort) { "<LocalWANPort>$(ConvertTo-SfosXmlEscaped -Text $targetLocalWanPort)</LocalWANPort>" } else { '' }
        $aliasEsc = ConvertTo-SfosXmlEscaped -Text $targetAlias
        $localIdTypeXml = if ($targetLocalIdType) { "<LocalIDType>$targetLocalIdType</LocalIDType>" } else { '' }
        $localIdEsc = ConvertTo-SfosXmlEscaped -Text $targetLocalId
        $remoteHostEsc = ConvertTo-SfosXmlEscaped -Text $targetRemoteHost
        $networkXml = ''
        foreach ($net in @($targetNetworks)) {
            $networkXml += "<Network>$(ConvertTo-SfosXmlEscaped -Text $net)</Network>"
        }
        $remoteIdTypeXml = if ($targetRemoteIdType) { "<RemoteIDType>$targetRemoteIdType</RemoteIDType>" } else { '' }
        $remoteIdEsc = ConvertTo-SfosXmlEscaped -Text $targetRemoteId
        $localPortEsc = ConvertTo-SfosXmlEscaped -Text $targetLocalPort
        $remotePortEsc = ConvertTo-SfosXmlEscaped -Text $targetRemotePort
        $idleXml = if ($targetIdle) { "<DisconnectOnIdleInterval>$targetIdle</DisconnectOnIdleInterval>" } else { '' }

        $inner = @"
<Set operation="update">
  <L2TPConnection>
    <Configuration>
      <Name>$nameEsc</Name>
      <Description>$descEsc</Description>
      $policyXml
      <ActionOnVPNRestart>$targetAction</ActionOnVPNRestart>
      <AuthenticationType>$targetAuthType</AuthenticationType>
      $authFieldXml
      $localWanPortXml
      <AliasLocalWANPort>$aliasEsc</AliasLocalWANPort>
      $localIdTypeXml
      <LocalID>$localIdEsc</LocalID>
      <RemoteHost>$remoteHostEsc</RemoteHost>
      <AllowNATTraversal>$targetNat</AllowNATTraversal>
      <RemoteLANNetwork>$networkXml</RemoteLANNetwork>
      $remoteIdTypeXml
      <RemoteID>$remoteIdEsc</RemoteID>
      <LocalPort>$localPortEsc</LocalPort>
      <RemotePort>$remotePortEsc</RemotePort>
      $idleXml
    </Configuration>
  </L2TPConnection>
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
            throw "Error updating L2TPConnection object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        # Same flat path as create - see the comment there.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Configuration' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an L2TP connection from a Sophos Firewall.

.DESCRIPTION
    Removes an L2TP connection under VPN > L2TP > Connections. Reads the object first and
    throws a clear error if it does not exist. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER Name
    Required. Name of the connection to remove. Accepts pipeline input by property name.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. The connection Name, by property name, for example from
    Get-SfosL2TPConnection.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the connection cannot be
    removed.

.EXAMPLE
    Remove-SfosL2TPConnection -Name 'BranchL2TP' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosL2TPConnection -Name 'BranchL2TP' -Confirm:$false

    Removes the connection without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosL2TPConnection
#>
function Remove-SfosL2TPConnection {
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
        $existing = @(Get-SfosL2TPConnection -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The L2TPConnection object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("L2TPConnection '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <L2TPConnection>
    <Configuration>
      <Name>$nameEsc</Name>
    </Configuration>
  </L2TPConnection>
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
            throw "Error removing L2TPConnection object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'L2TPConnection/Configuration' -Action 'remove' -Target $Name
    }
}

#endregion

#region PPTPConfiguration

<#
.SYNOPSIS
    Retrieves the PPTP configuration from a Sophos Firewall.

.DESCRIPTION
    Returns the PPTP settings under VPN > PPTP. This is a device-wide singleton: there is
    exactly one object and it has no name. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object. Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with the PPTP settings and
    member list. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosPPTPConfiguration

    Shows the PPTP configuration of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosPPTPConfiguration
#>
function Get-SfosPPTPConfiguration {
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

    $inner = '<Get><PPTPConfiguration></PPTPConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving the PPTPConfiguration object: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PPTPSettings' -Action 'get' -Target 'PPTPConfiguration'

    $node = $XmlResponse.SelectSingleNode('/Response/PPTPConfiguration')
    if (-not $node) {
        throw 'Error retrieving the PPTPConfiguration object: the firewall did not return the singleton.'
    }

    if ($AsXml) {
        return $node
    }

    $settings = $node.SelectSingleNode('PPTPSettings')
    $memberNodes = @($node.SelectNodes('PPTPMembers/UserName'))

    return [PSCustomObject]@{
        PPTPGeneralSettings     = [string]$settings.PPTPGeneralSettings
        StartIP                 = [string]$settings.AssignIPFrom.StartIP
        EndIP                   = [string]$settings.AssignIPFrom.EndIP
        LeaseIPFromRadiusServer = [string]$settings.LeaseIPFromRadiusServer
        PrimaryDNSServer        = [string]$settings.PrimaryDNSServer
        SecondaryDNSServer      = [string]$settings.SecondaryDNSServer
        PrimaryWINSServer       = [string]$settings.PrimaryWINSServer
        SecondaryWINSServer     = [string]$settings.SecondaryWINSServer
        MemberList               = @($memberNodes | ForEach-Object -Process { [string]$_.InnerText })
    }
}

<#
.SYNOPSIS
    Updates the PPTP configuration on a Sophos Firewall.

.DESCRIPTION
    Updates the PPTP settings under VPN > PPTP, a device-wide singleton. Reads the current
    object first and sends the complete entity back, changing only the fields you pass;
    fields you omit keep their current value. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

    Once -StartIP, -EndIP and -PrimaryDNSServer have been set for the first time, the
    unconfigured state cannot be restored afterward through this API; there is no value
    that clears them back to empty. Confirm the values before you write them.

.PARAMETER PPTPGeneralSettings
    Optional. Enables PPTP: Enable or Disable. If omitted, the current value is kept.

.PARAMETER StartIP
    Optional. Start of the IP range leased to PPTP clients. If omitted, the current value
    is kept. Required together with -EndIP and -PrimaryDNSServer on every update once the
    singleton has been configured.

.PARAMETER EndIP
    Optional. End of the IP range leased to PPTP clients. If omitted, the current value is
    kept.

.PARAMETER LeaseIPFromRadiusServer
    Optional. Leases the client IP through RADIUS instead of the local range: Enable or
    Disable. If omitted, the current value is kept.

.PARAMETER PrimaryDNSServer
    Optional. Primary DNS server handed to PPTP clients. If omitted, the current value is
    kept.

.PARAMETER SecondaryDNSServer
    Optional. Secondary DNS server handed to PPTP clients. If omitted, the current value is
    kept.

.PARAMETER PrimaryWINSServer
    Optional. Primary WINS server handed to PPTP clients. If omitted, the current value is
    kept.

.PARAMETER SecondaryWINSServer
    Optional. Secondary WINS server handed to PPTP clients. If omitted, the current value is
    kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Set-SfosPPTPConfiguration -StartIP '203.0.113.30' -EndIP '203.0.113.40' `
        -PrimaryDNSServer '203.0.113.1' -WhatIf

    Shows what the change would do without sending it to the firewall.

.EXAMPLE
    Set-SfosPPTPConfiguration -StartIP '203.0.113.30' -EndIP '203.0.113.40' `
        -PrimaryDNSServer '203.0.113.1' -Confirm:$false

    Configures the PPTP IP lease range and DNS server without asking for confirmation, for
    use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosPPTPConfiguration
#>
function Set-SfosPPTPConfiguration {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$PPTPGeneralSettings,

        [string]$StartIP,
        [string]$EndIP,

        [ValidateSet('Enable', 'Disable')]
        [string]$LeaseIPFromRadiusServer,

        [string]$PrimaryDNSServer,
        [string]$SecondaryDNSServer,
        [string]$PrimaryWINSServer,
        [string]$SecondaryWINSServer,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    $current = Get-SfosPPTPConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetGeneral = if ($bp.ContainsKey('PPTPGeneralSettings')) { $PPTPGeneralSettings } else { $current.PPTPGeneralSettings }
    $targetStartIP = if ($bp.ContainsKey('StartIP')) { $StartIP } else { $current.StartIP }
    $targetEndIP = if ($bp.ContainsKey('EndIP')) { $EndIP } else { $current.EndIP }
    $targetLease = if ($bp.ContainsKey('LeaseIPFromRadiusServer')) { $LeaseIPFromRadiusServer } else { $current.LeaseIPFromRadiusServer }
    $targetPrimaryDns = if ($bp.ContainsKey('PrimaryDNSServer')) { $PrimaryDNSServer } else { $current.PrimaryDNSServer }
    $targetSecondaryDns = if ($bp.ContainsKey('SecondaryDNSServer')) { $SecondaryDNSServer } else { $current.SecondaryDNSServer }
    $targetPrimaryWins = if ($bp.ContainsKey('PrimaryWINSServer')) { $PrimaryWINSServer } else { $current.PrimaryWINSServer }
    $targetSecondaryWins = if ($bp.ContainsKey('SecondaryWINSServer')) { $SecondaryWINSServer } else { $current.SecondaryWINSServer }

    # SFOS requires these three unconditionally on every update, even one that changes
    # nothing else - see .NOTES.
    if (-not $targetStartIP -or -not $targetEndIP -or -not $targetPrimaryDns) {
        throw 'Set-SfosPPTPConfiguration: the Sophos API requires StartIP, EndIP and PrimaryDNSServer on every update, even when the current object has none configured - supply -StartIP, -EndIP and -PrimaryDNSServer.'
    }

    if (-not $PSCmdlet.ShouldProcess("PPTPConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    $startIPEsc = ConvertTo-SfosXmlEscaped -Text $targetStartIP
    $endIPEsc = ConvertTo-SfosXmlEscaped -Text $targetEndIP
    $primaryDnsEsc = ConvertTo-SfosXmlEscaped -Text $targetPrimaryDns
    $secondaryDnsXml = if ($targetSecondaryDns) { "<SecondaryDNSServer>$(ConvertTo-SfosXmlEscaped -Text $targetSecondaryDns)</SecondaryDNSServer>" } else { '' }
    $primaryWinsXml = if ($targetPrimaryWins) { "<PrimaryWINSServer>$(ConvertTo-SfosXmlEscaped -Text $targetPrimaryWins)</PrimaryWINSServer>" } else { '' }
    $secondaryWinsXml = if ($targetSecondaryWins) { "<SecondaryWINSServer>$(ConvertTo-SfosXmlEscaped -Text $targetSecondaryWins)</SecondaryWINSServer>" } else { '' }

    $inner = @"
<Set operation="update">
  <PPTPConfiguration>
    <PPTPSettings>
      <PPTPGeneralSettings>$targetGeneral</PPTPGeneralSettings>
      <AssignIPFrom>
        <StartIP>$startIPEsc</StartIP>
        <EndIP>$endIPEsc</EndIP>
      </AssignIPFrom>
      <LeaseIPFromRadiusServer>$targetLease</LeaseIPFromRadiusServer>
      <PrimaryDNSServer>$primaryDnsEsc</PrimaryDNSServer>
      $secondaryDnsXml
      $primaryWinsXml
      $secondaryWinsXml
    </PPTPSettings>
  </PPTPConfiguration>
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
        throw "Error updating the PPTPConfiguration object: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PPTPSettings' -Action 'update' -Target 'PPTPConfiguration'
}

<#
.SYNOPSIS
    Adds a user to the PPTP configuration's member list.

.DESCRIPTION
    Reads the current PPTP configuration, adds the given local user to its member list if
    not already present, and writes the complete list back. Adding a member does not
    require an IP lease range to be configured. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER MemberName
    Required. Name of an existing local user to grant PPTP access to. Accepts pipeline
    input by property name. Named -MemberName, not -UserName, because -Username is the
    connection parameter used for the API login.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. MemberName, by property name, for example from
    Get-SfosPPTPConfiguration's MemberList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Add-SfosPPTPConfigurationMember -MemberName 'VPNUser1' -WhatIf

    Shows what would be added without sending the request to the firewall.

.EXAMPLE
    Add-SfosPPTPConfigurationMember -MemberName 'VPNUser1'

    Grants the local user PPTP access.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosPPTPConfiguration

.LINK
    Remove-SfosPPTPConfigurationMember
#>
function Add-SfosPPTPConfigurationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$MemberName,

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
        if (-not $PSCmdlet.ShouldProcess("PPTPConfiguration member '$MemberName' on $($params.Firewall)", 'Add')) {
            return
        }

        $userEsc = ConvertTo-SfosXmlEscaped -Text $MemberName

        $inner = @"
<Set operation="update">
  <PPTPConfiguration>
    <PPTPMembers>
      <UserName>$userEsc</UserName>
    </PPTPMembers>
  </PPTPConfiguration>
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
            throw "Error adding PPTPConfiguration member '$MemberName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PPTPMembers' -Action 'add member' -Target $MemberName
    }
}

<#
.SYNOPSIS
    Removes a user from the PPTP configuration's member list.

.DESCRIPTION
    Reads the current PPTP configuration, removes the given local user from its member
    list, and writes the remaining list back. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with permission to change VPN objects.

.PARAMETER MemberName
    Required. Name of the local user to remove from the PPTP member list. Accepts pipeline
    input by property name. Named -MemberName, not -UserName, because -Username is the
    connection parameter used for the API login.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs permission to change VPN
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
    you work with more than one at a time. Any connection parameter you pass explicitly
    still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.String. MemberName, by property name, for example from
    Get-SfosPPTPConfiguration's MemberList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    request.

.EXAMPLE
    Remove-SfosPPTPConfigurationMember -MemberName 'VPNUser1' -WhatIf

    Shows what would be removed without sending the request to the firewall.

.EXAMPLE
    Remove-SfosPPTPConfigurationMember -MemberName 'VPNUser1'

    Revokes the local user's PPTP access.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosPPTPConfiguration

.LINK
    Add-SfosPPTPConfigurationMember
#>
function Remove-SfosPPTPConfigurationMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$MemberName,

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
        if (-not $PSCmdlet.ShouldProcess("PPTPConfiguration member '$MemberName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $userEsc = ConvertTo-SfosXmlEscaped -Text $MemberName

        $inner = @"
<Remove>
  <PPTPConfiguration>
    <PPTPMembers>
      <UserName>$userEsc</UserName>
    </PPTPMembers>
  </PPTPConfiguration>
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
            throw "Error removing PPTPConfiguration member '$MemberName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PPTPConfiguration/PPTPMembers' -Action 'remove member' -Target $MemberName
    }
}

#endregion

