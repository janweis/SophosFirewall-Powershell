#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }

<#
        .SYNOPSIS
        Manages VPN on Sophos Firewall: IPsec, SSL VPN, L2TP, PPTP, VPN profiles and failover groups.

        .DESCRIPTION
        PowerShell module for the CONFIGURE > VPN area of the Sophos XGS / SFOS 22.0 XML API.
        The web admin splits the same area into "Site-to-site VPN" and "Remote access VPN";
        the API keeps one category, and so does this module.

        This module provides functions to create, read, update, and delete:
        - IPsec connections, VPN profiles (IKE policies) and failover groups
        - SSL VPN: tunnel access settings, policies, bookmarks and bookmark groups,
          site-to-site client and server connections
        - L2TP and PPTP: the two settings singletons, their member lists, and L2TP connections
        - The Sophos Connect client (read; the write path is unconfirmed)

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect and inspect the VPN configuration
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosVPNProfile | Format-Table Name, KeyingMethod
        Get-SfosIPsecConnection
        Get-SfosSSLTunnelAccessSettings

        .EXAMPLE
        # Inspect the IKE profiles and remove a custom one. Creating a profile requires the
        # full phase-1/phase-2 parameter set - see New-SfosVPNProfile's own examples.
        Get-SfosVPNProfile | Format-Table Name
        Remove-SfosVPNProfile -Name "Branch-IKEv2"

        .NOTES
        Module Name: SophosFirewall.VPN
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+

        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)

        API Compatibility:
        - Sophos SFOS 22.0
        - Sophos XGS Firewall Series

        Total Functions: 51 (51 exported)
        - 15 IPsec, VPN profile, failover group and Sophos Connect functions
        - 24 SSL VPN functions
        - 12 L2TP and PPTP functions

        These cmdlets change who can build tunnels into a live network and how that traffic
        is keyed. Every Set-* reads the current object first and writes it back complete.

        Behaviour that differs from the vendor documentation was measured against a live
        appliance and is recorded in the .NOTES of the affected function. The most important
        ones:
        - Nine of thirteen wire element names differ from the documentation folder names
          (IPsecConnection is VPNIPSecConnection, SSLVPNTunnel is SSLTunnelAccessSettings,
          the SSLVPN connection entities are SiteToSiteClient/SiteToSiteServer, and the
          VPNProfile operation pages call the entity VPNPolicy).
        - Adding an IPsec connection, an L2TP connection or a site-to-site SSL VPN client is
          not satisfiable on this firmware through this transport: the appliance answers an
          opaque 545 (IPsec/L2TP, tied to AliasLocalWANPort) or a field-less 500 (client
          connections, whose ServerConfigurationFile is a file upload the XML API cannot
          carry). The cmdlets ship documentation-faithful and are marked unconfirmed.
          Because no such object could ever be created, whether Get returns the preshared
          key is unknown - no Set-* pretends to preserve one.
        - A member list on an SSL VPN policy writes BACK onto the referenced user group:
          creating a policy with -Member rewires that group's SSLVPNPolicy/ClientlessPolicy
          assignment. Treat group references as writes to the group.
        - Remove-SfosSSLBookmark is a no-op on this firmware: the appliance answers 200 and
          deletes nothing. The cmdlet reads back afterwards and throws.
        - Several mandatory fields are documented as optional (VPNProfile dead peer
          detection block, PFSGroup, failover MailNotification), and SiteToSiteServer and
          L2TPConnection names reject hyphens.

        Functions that could not be confirmed against the lab appliance are marked as such
        in their own .NOTES. They are implemented faithful to the documentation rather than
        omitted, but nothing about them should be assumed to work.
#>

#requires -Version 5.1
#requires -Modules SophosFirewall.Core

# SophosFirewall.VPN - Group A: IPsec core (VPNIPSecConnection, VPNProfile, VPNFailoverGroup,
# SophosConnectClient).
#
# Measured live against the SFOS lab (22.0, APIVersion 2200.1). Two cross-cutting findings
# that apply across this fragment:
#
# 1. The write-operation response envelope is NOT the same shape as the Get envelope for
#    VPNIPSecConnection and VPNFailoverGroup [measured]. A <Get> wraps the data one level
#    deeper than the entity name (<VPNIPSecConnection><Configuration>...</Configuration>
#    </VPNIPSecConnection>, <VPNFailoverGroup><GroupDetail>...</GroupDetail>
#    </VPNFailoverGroup>), but <Set operation="add"> and (per the entity's own delete
#    contract) <Remove> answer with the outer entity element stripped entirely - the response
#    root goes straight to <Configuration>/<GroupDetail>. Consequently
#    Assert-SfosApiReturnSuccess is called with a DIFFERENT -ObjectName for Get
#    ('VPNIPSecConnection/Configuration', 'VPNFailoverGroup/GroupDetail') than for
#    New/Set/Remove ('Configuration', 'GroupDetail') on the same entity. Getting this wrong
#    does not throw - Get-SfosApiStatus just finds no node and Assert-SfosApiReturnSuccess
#    silently returns as "no status", which would hide a real 501/504 as success. VPNProfile
#    does not have this problem: its Get, Add, Update and Remove responses all place <Status>
#    directly under <VPNProfile> with no extra wrapper, so one -ObjectName value ('VPNProfile')
#    covers every operation.
#
# 2. VPNIPSecConnection cannot be created live in this lab, and this blocks three things
#    documented in detail on New-SfosIPsecConnection: the connection itself, VPNFailoverGroup
#    (its mandatory Connection member has nothing valid to reference), and whether the
#    firewall returns PresharedKey/Username/Password on read. See New-SfosIPsecConnection's
#    .NOTES for the full account and the values tried for the blocking field
#    (AliasLocalWANPort). Because no VPNIPSecConnection object could ever be created,
#    Get-SfosIPsecConnection - the only way to learn whether the firewall returns
#    PresharedKey/Username/Password on read - was never exercised against a real object
#    either. Set-SfosIPsecConnection therefore follows the FileType/-Template pattern:
#    -PresharedKey exists on New- (the field is documented and the firewall's field-level
#    validator accepted it in isolation - see the New- .NOTES) but is NOT accepted on Set-,
#    since read-modify-write cannot be shown to preserve a value nothing ever confirmed Get
#    returns.

#region VPNIPSecConnection

<#
.SYNOPSIS
    Retrieves VPNIPSecConnection objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for VPNIPSecConnection objects (VPN > IPsec
    connections). By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to
    return the raw XML nodes.

    -NameLike is sent as the server-side filter key (substring match) and re-applied
    client-side together with every other filter, AND semantics, per the project's
    server-side filtering rule. -ConnectionTypeLike and -RemoteHostLike are client-side only.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side.

.PARAMETER ConnectionTypeLike
    Filters by ConnectionType, substring match. Client-side only.

.PARAMETER RemoteHostLike
    Filters by RemoteHost, substring match. Client-side only.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosIPsecConnection

.EXAMPLE
    Get-SfosIPsecConnection -NameLike 'Branch'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: an empty firewall answers HTTP 200 with '<VPNIPSecConnection>
    <Configuration><Status>No. of records Zero.</Status></Configuration></VPNIPSecConnection>'
    - note the extra <Configuration> wrapper the entity uses only on Get, see the fragment
    header comment - and this cmdlet returns @() for it.

    Follow-up (orchestrator session, live route-based tunnel build): a route-based
    TunnelInterface connection CAN be created on this firmware - see New-SfosIPsecConnection's
    updated .NOTES for the working recipe, superseding the "not satisfiable" finding below.
    Get was exercised against two such real objects. Confirmed: PresharedKey IS present on a
    real Get response, as a salted hash with a 'hashform' attribute
    (`<PresharedKey hashform="mode1">$sfos$7$0$...</PresharedKey>`), never plaintext, and the
    hash text changes on every single subsequent write regardless of whether the caller
    changed the key - identical finding to SSLBookmark.Password. Username/Password (the
    UserAuthenticationMode credential fields, unrelated to the API auth -Password) were not
    exercised, since both test connections used UserAuthenticationMode Disable.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/IPsecConnection/IPsecConnection.html

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
            # Measured live: Get returns PresharedKey as a salted hash, re-salted on every
            # single write regardless of content - same finding as SSLBookmark.Password (see
            # that cmdlet's .NOTES). Set-SfosIPsecConnection resends it with its hashform
            # attribute so a read-modify-write does not clear the key.
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
    Creates a VPNIPSecConnection (VPN > IPsec connections) using the Sophos Firewall XML API.
    Supports ShouldProcess; use -WhatIf to preview.

    CONFIRMED live for a route-based (ConnectionType 'TunnelInterface') site-to-site tunnel -
    see .NOTES for the exact working recipe, measured against two real firewalls. The earlier
    "not satisfiable" finding for ConnectionType 'SiteToSite' with an explicit -LocalSubnet
    was a dead end caused by -LocalSubnet/-RemoteNetwork, not by -AliasLocalWANPort as first
    suspected; a route-based connection needs neither.

.PARAMETER Name
    Name of the connection [doc, measured mandatory]. Starts with a letter, max 100 characters.
    MEASURED: a hyphen is rejected client-side with a clear error - see .NOTES - because the
    firewall itself answers a field-specific 501 on Configuration/Name for one, the same
    defect as SiteToSiteServer and L2TPConnection.

.PARAMETER ConnectionType
    'RemoteAccess', 'SiteToSite', 'HostToHost' or 'TunnelInterface' [doc, measured mandatory].

.PARAMETER LocalIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)' [doc, measured mandatory].

.PARAMETER LocalID
    Local ID value matching -LocalIDType [doc, measured mandatory].

.PARAMETER RemoteIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)' [doc, measured mandatory].

.PARAMETER RemoteID
    Remote ID value matching -RemoteIDType [doc, measured mandatory].

.PARAMETER LocalSubnet
    Name of an existing IPHost object representing the local subnet [doc: optional]. Route-based
    (TunnelInterface) connections do not use it - the working recipe in .NOTES sends neither
    -LocalSubnet nor -RemoteNetwork. Previously implemented as Mandatory based on an earlier,
    since-superseded SiteToSite investigation; corrected to optional, matching both the
    documentation and the confirmed live recipe.

.PARAMETER AliasLocalWANPort
    Alias of the local WAN port, for example 'Port2' [doc]. Measured mandatory - the field is
    named in <InvalidParams> whenever absent. Also populates -LocalWANPort when that parameter
    is not separately supplied - see .PARAMETER LocalWANPort and .NOTES.

.PARAMETER Description
    Free-text description [doc]. Optional.

.PARAMETER Policy
    Name of an existing VPNProfile [doc]. Optional.

.PARAMETER ActionOnVPNRestart
    'Disable', 'RespondOnly' or 'Initiate' [doc]. Optional.

.PARAMETER AuthenticationType
    'PresharedKey', 'DigitalCertificate' or 'RSAKey' [doc]. Optional.

.PARAMETER PresharedKey
    Pre-shared key, required by the firewall when -AuthenticationType is 'PresharedKey' [doc]. Supply as a SecureString (Read-Host -AsSecureString or ConvertTo-SecureString), 5-64
    characters. CONFIRMED live: Get-SfosIPsecConnection returns it afterwards as a salted
    hash, never plaintext - see Get-SfosIPsecConnection's .NOTES.

.PARAMETER LocalCertificate
    Name of the local (appliance) certificate [doc]. Optional.

.PARAMETER RemoteCertificate
    Name of the remote (external) certificate [doc]. Optional.

.PARAMETER SubnetFamily
    'IPv4', 'IPv6' or 'Dual' [doc]. Default: 'IPv4'. 'Dual' was missing from the original
    ValidateSet even though the documentation lists it and the confirmed working recipe for a
    route-based tunnel uses it.

.PARAMETER EndpointFamily
    'IPv4' or 'IPv6' [doc]. Default: 'IPv4'.

.PARAMETER LocalWANPort
    Local listening interface, for example 'Port2' [doc]. Optional - defaults to the value of
    -AliasLocalWANPort and is always sent. MEASURED: with this field omitted, every
    SiteToSite/TunnelInterface create failed; the firewall needs both fields present and set
    to the same interface. Override only if the two must genuinely differ.

.PARAMETER RemoteHost
    Remote peer host or IP address [doc]. Required in practice for SiteToSite/HostToHost, not
    enforced client-side because RemoteAccess does not use it.

.PARAMETER NATedLAN
    Name of an IPHost object used for NAT of the local LAN [doc]. Optional.

.PARAMETER AllowNATTraversal
    'Enable' or 'Disable' [doc]. Optional.

.PARAMETER RemoteNetwork
    One or more names of existing IPHost/Network objects for the remote network(s) [doc].
    Optional.

.PARAMETER UserAuthenticationMode
    'Disable', 'AsServer' or 'AsClient' [doc]. Optional.

.PARAMETER Username
    Username for user authentication mode [doc]. Optional.

.PARAMETER Password
    Password for user authentication mode [doc]. Optional. SecureString; converted to plain
    text only at the point the wire XML is built. This is a connection-specific credential
    field, unrelated to the -Password connection parameter used for API authentication
    further below.

.PARAMETER AllowedUser
    One or more allowed usernames [doc]. Optional.

.PARAMETER Protocol
    'ALL', 'UDP', 'TCP' or 'ICMP' [doc]. Optional.

.PARAMETER LocalPort
    Local port, 1-65535 or '*' [doc]. Default '*' - the documentation marks this Mandatory and
    an omitted element was rejected live with a 501; '*' (any port) matches the doc's own
    allowed values and this project's Protocol ALL default.

.PARAMETER RemotePort
    Remote port, 1-65535 or '*' [doc]. Default '*' - same finding as -LocalPort.

.PARAMETER DisconnectOnIdleInterval
    Idle disconnect interval in seconds [doc]. Optional.

.PARAMETER Status
    'Active' or 'Deactive' [doc]. Default: 'Deactive' - a newly created connection stays
    disabled unless the caller explicitly asks for 'Active', matching this project's
    fail-safe default pattern (compare -Healthcheck OFF on GatewayHost).

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

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for the API call.

.OUTPUTS
    None. Throws an exception if creation fails.

.EXAMPLE
    # CONFIRMED live recipe for a route-based (TunnelInterface) site-to-site tunnel - see
    # .NOTES. No -LocalSubnet/-RemoteNetwork; -LocalWANPort defaults from -AliasLocalWANPort.
    $psk = Read-Host -AsSecureString -Prompt 'Pre-shared key'
    New-SfosIPsecConnection -Name 'ExampleTunnel' -ConnectionType TunnelInterface `
        -Policy 'Head office (IKEv2)' -AuthenticationType PresharedKey -PresharedKey $psk `
        -AliasLocalWANPort 'Port2' -EndpointFamily IPv4 -SubnetFamily Dual -Protocol ALL `
        -UserAuthenticationMode Disable -RemoteHost '198.51.100.10' `
        -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
        -RemoteIDType 'IP Address' -RemoteID '198.51.100.10' `
        -ActionOnVPNRestart Initiate -Status Deactive -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    CONFIRMED live: a route-based site-to-site tunnel was built end to end between two real
    firewalls with exactly the recipe in .EXAMPLE (ConnectionType TunnelInterface; Policy
    'Head office (IKEv2)'; AuthenticationType PresharedKey; both -AliasLocalWANPort and
    -LocalWANPort set to the same WAN-zone interface; EndpointFamily IPv4; SubnetFamily Dual;
    Protocol ALL; UserAuthenticationMode Disable; LocalIDType/RemoteIDType 'IP Address'; no
    -LocalSubnet or -RemoteNetwork at all), created with -Status Deactive and switched on
    afterwards through Set-SfosIPsecConnection - see that cmdlet's .NOTES for the activation
    finding. This supersedes every claim below, which is kept for provenance: the original
    investigation used ConnectionType SiteToSite with an explicit -LocalSubnet and concluded
    -AliasLocalWANPort was the blocker (code 545). Both were wrong - 545 was
    -LocalSubnet/-RemoteNetwork forcing a route lookup this lab's addressing could not
    satisfy, not the alias field, and a route-based connection needs neither.

    Superseded investigation (kept for provenance): field-by-field validation was measured by
    provoking 501 responses and reading <InvalidParams>, which is how every -Mandatory
    parameter was originally confirmed. With ConnectionType SiteToSite and every other field
    supplied (Name, ConnectionType, Policy, ActionOnVPNRestart, AuthenticationType,
    PresharedKey, SubnetFamily, EndpointFamily, LocalWANPort, RemoteHost, LocalSubnet,
    LocalIDType, LocalID, RemoteNetwork, RemoteIDType, RemoteID, Status), the firewall kept
    rejecting the request with a 501 naming only AliasLocalWANPort, for every one of these
    values tried: 'Port1', 'Port1:0', 'Port1_0', 'Port1-0', 'Port1:1', '#Port1', '0', 'WAN',
    'Auto', and an omitted/empty element - all on Port1, this lab's LAN-zone interface, which
    has no interface Alias configured. Three further attempts used -AliasLocalWANPort 'Port2'
    (a real WAN-zone interface) instead: (1) the identical network object for both
    -LocalSubnet and -RemoteNetwork answered 503 "Entity having same parameter details
    already exists"; (2) distinct network objects, both ID fields, Status Deactive still
    failed with opaque code 545, identical in shape to the L2TPConnection finding in Group C
    of this module. Switching ConnectionType to TunnelInterface and dropping -LocalSubnet/
    -RemoteNetwork entirely is what actually cleared 545 - AliasLocalWANPort 'Port2' was
    correct all along.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/IPsecConnection/operations/AddFailoverGroupIPSECConnection%26EditIPSECConnection.html

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

    # Measured live: a hyphenated Name is rejected with a field-specific 501 naming
    # /VPNIPSecConnection/Configuration/Name, the same defect as SiteToSiteServer and
    # L2TPConnection (see those cmdlets' .NOTES). Checked here rather than through
    # -ValidatePattern so the error names the entity and explains why, matching this
    # project's other client-side pre-checks.
    if ($Name -match '-') {
        throw "The VPNIPSecConnection object name '$Name' must not contain a hyphen; the firewall rejects it with a field-specific 501 on Configuration/Name."
    }

    # Measured live: with -LocalWANPort omitted, every SiteToSite/TunnelInterface create
    # fails - the firewall needs both AliasLocalWANPort and LocalWANPort populated with the
    # same interface. Default LocalWANPort to the alias unless the caller overrides it.
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
    Updates an existing VPNIPSecConnection object on the Sophos Firewall.

.DESCRIPTION
    Updates a VPNIPSecConnection using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
    use -WhatIf to preview.

    CONFIRMED live end to end, including activation - see .NOTES. -PresharedKey IS a
    parameter here: Get-SfosIPsecConnection returns the key as a salted hash, and the hash
    plus its hashform attribute is resent whenever the caller does not supply a new key, or
    the update fails outright (measured: code 515) for a PresharedKey-authenticated
    connection whose PresharedKey element is missing.

.PARAMETER Name
    Name of the target connection. Mandatory; accepts pipeline input by property name.
    MEASURED: a hyphen is rejected client-side with a clear error, the same defect as on
    New-SfosIPsecConnection - see that cmdlet's .NOTES.

.PARAMETER Description
    Free-text description. If omitted, the existing value is kept.

.PARAMETER Policy
    Name of an existing VPNProfile. If omitted, the existing value is kept.

.PARAMETER ActionOnVPNRestart
    'Disable', 'RespondOnly' or 'Initiate'. If omitted, the existing value is kept.

.PARAMETER PresharedKey
    New pre-shared key, SecureString. If omitted, the hash Get-SfosIPsecConnection returned is
    resent with its hashform attribute so the key is preserved rather than cleared - see
    .DESCRIPTION.

.PARAMETER LocalWANPort
    Local listening interface. If omitted, the existing value is kept.

.PARAMETER AliasLocalWANPort
    Alias of the local WAN port. If omitted, the existing value is kept.

.PARAMETER SubnetFamily
    'IPv4', 'IPv6' or 'Dual' [doc]. If omitted, the existing value is kept. 'Dual' was missing
    from the original ValidateSet - see New-SfosIPsecConnection's matching fix.

.PARAMETER RemoteHost
    Remote peer host or IP address. If omitted, the existing value is kept.

.PARAMETER LocalSubnet
    Name of the local-subnet IPHost object. If omitted, the existing value is kept.

.PARAMETER LocalIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)'. If omitted, the existing value is
    kept.

.PARAMETER LocalID
    Local ID value. If omitted, the existing value is kept.

.PARAMETER RemoteNetwork
    Complete replacement list of remote network object names. If omitted, the existing list is
    kept.

.PARAMETER RemoteIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)'. If omitted, the existing value is
    kept.

.PARAMETER RemoteID
    Remote ID value. If omitted, the existing value is kept.

.PARAMETER UserAuthenticationMode
    'Disable', 'AsServer' or 'AsClient' [doc]. If omitted, the existing value is kept.

.PARAMETER Protocol
    'ALL', 'UDP', 'TCP' or 'ICMP' [doc]. If omitted, the existing value is kept.

.PARAMETER Status
    'Active' or 'Deactive'. If omitted, the existing value is kept, but the separate
    enable/disable toggle described in .NOTES is only sent when -Status is explicitly bound -
    see .NOTES for why this cmdlet cannot preserve that toggle's state on its own.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosIPsecConnection -Name 'ExampleTunnel' -Status Active -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    CONFIRMED live against two real firewalls, including the activation step. The
    Configuration/Status field alone does NOT enable a connection: sending a full field set
    with <Status>Active</Status> answers HTTP 200, but a Get immediately afterwards shows the
    Status field unchanged from before the call, and the web admin UI kept showing the
    connection as disabled. The documented sample XML for this operation lists four further,
    undocumented-elsewhere sibling elements that "will work only after the connection is
    created": <Active><Name>x</Name></Active>, <DeActive><Name>x</Name></DeActive>,
    <Connection><Name>x</Name></Connection>, <DisConnection><Name>x</Name></DisConnection>.
    Sending <Active>/<DeActive> as its own <Set operation="update"> against a real connection
    answered HTTP 200 with a response rooted at <Active>/<DeActive> instead of <Configuration>
    - so Assert-SfosApiReturnSuccess is called with -ObjectName 'Active'/'DeActive' for that
    call, not 'Configuration' - and the web admin UI changed from disabled to connected right
    after the <Active> call, confirmed visually. This toggle is NOT reflected anywhere Get can
    read: Configuration/Status stayed the same value throughout every DeActive/Active cycle
    tested, so this cmdlet cannot read-modify-write it and only sends it when the caller
    explicitly passes -Status - an omitted -Status leaves the toggle exactly as it was.
    <Connection>/<DisConnection> (force a reconnect) were not exercised; out of scope for this
    fix, which only had to make -Status Active actually enable the connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/IPsecConnection/operations/AddFailoverGroupIPSECConnection%26EditIPSECConnection.html

.LINK
    Get-SfosIPsecConnection
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

        # Measured live: a hyphenated Name is rejected the same way as on
        # New-SfosIPsecConnection - see that cmdlet's .NOTES.
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
        # is the HASH Get returned and must be resent with its hashform attribute, or the
        # update fails outright with code 515 for a PresharedKey-authenticated connection -
        # measured live, see .NOTES.
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

        # The Configuration/Status field just written does NOT toggle the connection's real
        # enabled state - measured live, see .NOTES. Only fired when the caller explicitly
        # asked for -Status, since this cmdlet has no way to read the toggle back to preserve
        # it on updates that do not touch -Status.
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
    Removes a VPNIPSecConnection object from the Sophos Firewall.

.DESCRIPTION
    Removes a VPNIPSecConnection using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist, rather than passing through the
    firewall's own answer for that case [measured: Remove on a nonexistent VPNIPSecConnection
    answers HTTP 200 with a body containing no VPNIPSecConnection element and no <Status> at
    all - not even a code-less one - which would otherwise read as silent success]. Supports
    ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the connection to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosIPsecConnection -Name 'ExampleTunnel' -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the "not found" pre-check (this cmdlet's own read-first design) against a
    name that never existed threw as expected. Removing a genuinely existing connection was
    not exercised, because none could be created in this lab (see New-SfosIPsecConnection's
    .NOTES).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/IPsecConnection/operations/Delete%20IPSec%20Connection.html

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

        # Measured live: the shallow <Remove><VPNIPSecConnection><Name>x</Name>
        # </VPNIPSecConnection></Remove> form answers HTTP 200 and deletes nothing - a
        # confirmed firmware no-op, the same class of defect as Remove-SfosSSLBookmark. The
        # form that actually deletes nests Name one level deeper, under <Configuration>,
        # matching the entity's own Get/Set shape.
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
    Retrieves VPNProfile objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for VPNProfile objects (VPN > IPsec profiles). By
    default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML
    nodes.

    -NameLike is sent as the server-side filter key (substring match) and re-applied
    client-side, per the project's server-side filtering rule. Unlike every other entity in
    this fragment, VPNProfile's Get/Add/Update/Remove responses all place <Status> directly
    under <VPNProfile> with no extra wrapper - see the fragment header comment.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosVPNProfile

.EXAMPLE
    Get-SfosVPNProfile -NameLike 'IKEv2'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live against all 9 predefined profiles and a temporary test profile (created,
    read, updated, removed, cleaned up). The 9 predefined profiles should not be modified -
    'Default Profile', 'DefaultHeadOffice', 'DefaultRemoteAccess', 'DefaultBranchOffice',
    'IKEv2', 'DefaultL2TP', 'Branch office (IKEv2)', 'Head office (IKEv2)',
    'Microsoft Azure (IKEv2)'.

    Measured: -NameLike with criteria="like" and no match answers the standard code-less
    '<Status>No. of records Zero.</Status>' this cmdlet treats as an empty result. A filter
    using criteria="=" (not used by this cmdlet) instead answers code 404 "IPsec profile
    doesn't exist." on no match - noted here because it does not fit this project's general
    "code-less status = empty result" rule and would need separate handling if criteria="="
    were ever used.

    DHGroupList is populated on the 9 predefined profiles and, once New-SfosVPNProfile's full
    field set (in particular DeadPeerDetection/CheckPeerAfterEvery/WaitForResponseUpto/
    ActionWhenPeerUnreachable) is sent, on created profiles too - an incomplete request shape
    produces a misleading empty DHGroupList, see New-SfosVPNProfile's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/VPNProfile/VPNProfile.html

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
    Creates a new VPNProfile object on the Sophos Firewall.

.DESCRIPTION
    Creates a VPNProfile (VPN > IPsec profiles) using the Sophos Firewall XML API. Only
    KeyingMethod 'Automatic' is implemented; Manual keying (LocalSPI/RemoteSPI/*Key fields)
    is documented but was never exercised against a live object - none of the 9 predefined
    profiles in this lab uses it. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the profile [doc, measured mandatory].

.PARAMETER AuthenticationMode
    'MainMode' or 'AggressiveMode' [doc, measured mandatory - the one field the firewall's
    validator names even on an otherwise-empty request].

.PARAMETER Phase1EncryptionAlgorithm1
    Phase 1 primary encryption algorithm [doc, measured mandatory]. One of 'DES', '3DES',
    'AES128', 'AES192', 'AES256', 'TwoFish', 'BlowFish', 'Serpent', 'AES128GCM16',
    'AES192GCM16', 'AES256GCM16'.

.PARAMETER Phase1AuthenticationAlgorithm1
    Phase 1 primary authentication algorithm [doc, measured mandatory]. One of 'MD5', 'SHA1',
    'SHA2_256', 'SHA2_384', 'SHA2_512'.

.PARAMETER Phase1KeyLife
    Phase 1 key life in seconds, 120-86400 [doc, measured mandatory].

.PARAMETER Phase1ReKeyMargin
    Phase 1 re-key margin in seconds, 30-999 [doc, measured mandatory].

.PARAMETER Phase1RandomizeReKeyingMarginBy
    Phase 1 re-keying margin randomization percentage, 0-100 [doc, measured mandatory].

.PARAMETER Phase2EncryptionAlgorithm1
    Phase 2 primary encryption algorithm [doc, measured mandatory]. As Phase1, plus
    'AES128GMAC', 'AES192GMAC', 'AES256GMAC'.

.PARAMETER Phase2AuthenticationAlgorithm1
    Phase 2 primary authentication algorithm [doc, measured mandatory]. As Phase1.

.PARAMETER Phase2KeyLife
    Phase 2 key life in seconds, 120-86400 [doc, measured mandatory].

.PARAMETER Description
    Free-text description, max 255 characters [doc]. Optional.

.PARAMETER KeyingMethod
    'Automatic' or 'Manual' [doc]. Default: 'Automatic' - Manual is accepted by the parameter
    validator but its associated fields are not implemented, see .DESCRIPTION.

.PARAMETER AllowReKeying
    'Enable' or 'Disable' [doc]. Default: 'Enable'.

.PARAMETER KeyNegotiationTries
    Number of key negotiation retries, 0-50 [doc]. Default: 3.

.PARAMETER PassDataInCompressedFormat
    'Enable' or 'Disable' [doc]. Default: 'Disable'.

.PARAMETER UseStrictProfile
    'Enable' or 'Disable' [doc]. Default: 'Disable'.

.PARAMETER SupportedDHGroup
    One or more DH group identifiers in the wire format, for example '14(DH2048)' [doc,
    measured mandatory on create - omitting it entirely is rejected with a 501 naming
    /VPNProfile/Phase1/SupportedDHGroups/DHGroup]. Confirmed round-trip: Get-SfosVPNProfile
    returns it back correctly once every other Phase1 field this cmdlet sends is present too -
    see .NOTES for the earlier, misleading result from an incomplete request.

.PARAMETER DeadPeerDetection
    'Enable' or 'Disable' [doc says optional; MEASURED CONTRADICTION - omitting this on create
    is rejected with a 501 naming /VPNProfile/Phase1/DeadPeerDetection]. Default: 'Enable'.

.PARAMETER CheckPeerAfterEvery
    Dead peer detection probe interval in seconds [doc says optional; measured mandatory on
    create, same as -DeadPeerDetection]. Default: 30.

.PARAMETER WaitForResponseUpto
    Dead peer detection response timeout in seconds [doc says optional; measured mandatory on
    create, same as -DeadPeerDetection]. Default: 120.

.PARAMETER ActionWhenPeerUnreachable
    'Disconnect', 'Hold' or 'ReInitiate' [doc says optional; measured mandatory on create,
    same as -DeadPeerDetection]. Default: 'Disconnect'.

.PARAMETER Phase2EncryptionAlgorithm2
    Phase 2 secondary encryption algorithm [doc]. Optional.

.PARAMETER Phase2AuthenticationAlgorithm2
    Phase 2 secondary authentication algorithm [doc]. Optional.

.PARAMETER PFSGroup
    Perfect Forward Secrecy group [doc says optional; MEASURED CONTRADICTION - omitting this
    on create is rejected with a 501 naming /VPNProfile/Phase2/PFSGroup]. 'SameasPhase-I',
    'None', or a DH group identifier. Default: 'SameasPhase-I'.

.PARAMETER keyexchange
    'ikev1' or 'ikev2' [doc]. Optional; the firewall defaults to 'ikev2' when omitted
    [measured].

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
    None. Throws an exception if creation fails.

.EXAMPLE
    New-SfosVPNProfile -Name 'BranchProfile' -AuthenticationMode MainMode `
        -Phase1EncryptionAlgorithm1 AES256 -Phase1AuthenticationAlgorithm1 SHA2_256 `
        -Phase1KeyLife 3600 -Phase1ReKeyMargin 120 -Phase1RandomizeReKeyingMarginBy 100 `
        -Phase2EncryptionAlgorithm1 AES256 -Phase2AuthenticationAlgorithm1 SHA2_256 `
        -Phase2KeyLife 3600 -SupportedDHGroup '14(DH2048)' -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live end to end, 4 times (created, read back with Get-SfosVPNProfile, updated,
    removed - see Set-SfosVPNProfile/Remove-SfosVPNProfile .NOTES). Every create answers code
    201 ("partially successful"), never a clean 200, with no field named as the cause - this
    is expected and treated as success (201 = success with warning). DHGroupList round-trips
    correctly through Get-SfosVPNProfile as long as this cmdlet's complete field set is sent,
    confirmed 3 consecutive times. An incomplete request - missing PFSGroup and/or the
    DeadPeerDetection/CheckPeerAfterEvery/WaitForResponseUpto/ActionWhenPeerUnreachable
    quartet - all four now required parameters, see their own .PARAMETER entries - makes
    SupportedDHGroups look silently dropped; it is not, once the request is actually complete.
    Kept here as a caution against reintroducing a partial request shape, since the 400 that
    quartet produces when missing contradicts the documentation table, which marks all four
    "No" (optional).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/VPNProfile/operations/AddVPNPolicy%26EditVPNPolicy.html

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

    # Measured mandatory on create despite the doc marking all four "No" - see .NOTES - so
    # they are always sent, backed by parameter defaults rather than a conditional ContainsKey
    # check.
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
    Updates an existing VPNProfile object on the Sophos Firewall.

.DESCRIPTION
    Updates a VPNProfile using the Sophos Firewall XML API. Reads the current object first and
    resends every field, overriding only what the caller explicitly passed (read-modify-write
    - SFOS replaces the whole entity on update). Supports ShouldProcess; use -WhatIf to
    preview.

    The 9 predefined profiles are TABU for this cmdlet - see Get-SfosVPNProfile's .NOTES for
    the list. This cmdlet does not block them technically (matching the existing
    Set-SfosWebFilterPolicy precedent for 'Default Policy' in this project); only this help
    text guards against it.

.PARAMETER Name
    Name of the target profile. Mandatory; accepts pipeline input by property name.

.PARAMETER Description
    Free-text description. If omitted, the existing value is kept.

.PARAMETER AllowReKeying
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER KeyNegotiationTries
    Number of key negotiation retries, 0-50. If omitted, the existing value is kept.

.PARAMETER AuthenticationMode
    'MainMode' or 'AggressiveMode'. If omitted, the existing value is kept.

.PARAMETER PassDataInCompressedFormat
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER UseStrictProfile
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER Phase1EncryptionAlgorithm1
    Phase 1 primary encryption algorithm. If omitted, the existing value is kept.

.PARAMETER Phase1AuthenticationAlgorithm1
    Phase 1 primary authentication algorithm. If omitted, the existing value is kept.

.PARAMETER Phase1KeyLife
    Phase 1 key life in seconds. If omitted, the existing value is kept.

.PARAMETER Phase1ReKeyMargin
    Phase 1 re-key margin in seconds. If omitted, the existing value is kept.

.PARAMETER Phase1RandomizeReKeyingMarginBy
    Phase 1 re-keying margin randomization percentage. If omitted, the existing value is kept.

.PARAMETER SupportedDHGroup
    Complete replacement list of DH group identifiers in the wire format, for example
    '14(DH2048)'. If omitted, the existing list (as returned by Get-SfosVPNProfile) is kept.

.PARAMETER DeadPeerDetection
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER CheckPeerAfterEvery
    Dead peer detection probe interval in seconds. If omitted, the existing value is kept.

.PARAMETER WaitForResponseUpto
    Dead peer detection response timeout in seconds. If omitted, the existing value is kept.

.PARAMETER ActionWhenPeerUnreachable
    'Disconnect', 'Hold' or 'ReInitiate'. If omitted, the existing value is kept.

.PARAMETER Phase2EncryptionAlgorithm1
    Phase 2 primary encryption algorithm. If omitted, the existing value is kept.

.PARAMETER Phase2AuthenticationAlgorithm1
    Phase 2 primary authentication algorithm. If omitted, the existing value is kept.

.PARAMETER PFSGroup
    Perfect Forward Secrecy group. If omitted, the existing value is kept.

.PARAMETER Phase2KeyLife
    Phase 2 key life in seconds. If omitted, the existing value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosVPNProfile -Name 'BranchProfile' -Description 'updated'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: updated a temporary test profile's Description only, then re-read it and
    confirmed every other field (KeyingMethod, AllowReKeying, KeyNegotiationTries, both
    Phase1/Phase2 blocks including DHGroupList) was unchanged - round trip clean, code 200.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/VPNProfile/operations/AddVPNPolicy%26EditVPNPolicy.html

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
    Removes a VPNProfile object from the Sophos Firewall.

.DESCRIPTION
    Removes a VPNProfile using the Sophos Firewall XML API. Reads the object first and throws
    a clear "not found" error if it does not exist, rather than passing through the firewall's
    own answer for that case [measured: Remove on a nonexistent VPNProfile answers code 200
    "Configuration applied successfully." - actively misleading, nothing was removed]. Supports
    ShouldProcess; use -WhatIf to preview.

    The 9 predefined profiles are TABU for this cmdlet - see Get-SfosVPNProfile's .NOTES for
    the list. Not technically blocked (matching this project's existing precedent for
    protected default objects); only this help text guards against it.

.PARAMETER Name
    Name of the profile to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosVPNProfile -Name 'BranchProfile'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removed two temporary test profiles, confirmed gone with a follow-up Get,
    then confirmed the "not found" error path against a name that never existed.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/VPNProfile/operations/Delete%20VPN%20Policy.html

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
    Retrieves VPNFailoverGroup objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for VPNFailoverGroup objects (VPN > Failover groups).
    By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw
    XML nodes.

    -NameLike is sent as the server-side filter key (substring match) and re-applied
    client-side, per the project's server-side filtering rule.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosVPNFailoverGroup

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: an empty firewall answers HTTP 200 with '<VPNFailoverGroup><GroupDetail>
    <Status>No. of records Zero.</Status></GroupDetail></VPNFailoverGroup>' - note the extra
    <GroupDetail> wrapper this entity uses only on Get, see the fragment header comment - and
    this cmdlet returns @() for it. No VPNFailoverGroup object could be created in this lab
    (its mandatory member connection has nothing valid to reference - see
    New-SfosVPNFailoverGroup's .NOTES), so the property shape below is derived from the
    documented sample XML only and was never confirmed against a live object.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/FailoverGroupConnection/FailoverGroupConnection.html

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
    Creates a new VPNFailoverGroup object on the Sophos Firewall.

.DESCRIPTION
    Creates a VPNFailoverGroup (VPN > Failover groups) using the Sophos Firewall XML API.
    Supports ShouldProcess; use -WhatIf to preview.

    UNCONFIRMED - see .NOTES. A VPNFailoverGroup needs at least one VPNIPSecConnection member
    [measured: an empty/missing MemberConnections answers "failed to bind json", not a normal
    field-validation 501], and no VPNIPSecConnection object could be created in this lab (see
    New-SfosIPsecConnection's .NOTES). Every other field this cmdlet sends was individually
    confirmed against the firewall's validator.

.PARAMETER Name
    Name of the failover group [doc, measured mandatory]. Starts with a letter; alphanumeric
    and underscore.

.PARAMETER Connection
    One or more names of existing VPNIPSecConnection objects [doc: "Mandatory: Yes"; measured:
    an empty list is rejected with a raw backend error rather than a field-level 501].

.PARAMETER MailNotification
    'Enable' or 'Disable' [doc says "No" (optional); MEASURED CONTRADICTION - omitting this
    field is rejected with a 501 naming it in <InvalidParams>, so this cmdlet treats it as
    mandatory regardless of the documentation].

.PARAMETER AutomaticFailback
    'Enable' or 'Disable' [doc]. Optional.

.PARAMETER FailoverCondition
    One or more failover conditions, each a PSCustomObject with Protocol ('PING' or 'TCP')
    and optionally Port [doc]. Optional.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    # Documentation-faithful shape; UNCONFIRMED to succeed in this lab, see .NOTES
    New-SfosVPNFailoverGroup -Name 'BranchFailover' -Connection 'ExampleTunnel' `
        -MailNotification Disable -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    NOT VERIFIED to succeed live - blocked transitively by New-SfosIPsecConnection's
    AliasLocalWANPort blocker (no valid -Connection value exists in this lab). Measured
    individually: a test failover group with only -Name answered a 400 naming MailNotification;
    adding MailNotification=Disable (with -Connection still absent) answered a distinct
    'failed to bind json' error, confirming the member list is required at the transport
    binding level, not just the field validator.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/FailoverGroupConnection/operations/AddFailoverConnectionGroup%26UpdateFailoverConnectionGroup..html

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
    Updates an existing VPNFailoverGroup object on the Sophos Firewall.

.DESCRIPTION
    Updates a VPNFailoverGroup using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
    use -WhatIf to preview.

    UNCONFIRMED live - see .NOTES. Used internally by Add-/Remove-SfosVPNFailoverGroupMember.

.PARAMETER Name
    Name of the target failover group. Mandatory; accepts pipeline input by property name.

.PARAMETER Connection
    Complete replacement list of member VPNIPSecConnection names. If omitted, the existing
    list is kept.

.PARAMETER MailNotification
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER AutomaticFailback
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER FailoverCondition
    Complete replacement list of failover conditions (PSCustomObject with Protocol,
    optionally Port). If omitted, the existing list is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosVPNFailoverGroup -Name 'BranchFailover' -MailNotification Enable -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    NOT VERIFIED live - no VPNFailoverGroup object could be created in this lab (see
    New-SfosVPNFailoverGroup's .NOTES), so this read-modify-write could not be exercised end
    to end.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/FailoverGroupConnection/operations/AddFailoverConnectionGroup%26UpdateFailoverConnectionGroup..html

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
    Removes a VPNFailoverGroup object from the Sophos Firewall.

.DESCRIPTION
    Removes a VPNFailoverGroup using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist, rather than passing through the
    firewall's own answer for that case [measured: Remove on a nonexistent VPNFailoverGroup
    answers HTTP 200 with a body containing no VPNFailoverGroup element and no <Status> at all
    - not even a code-less one - which would otherwise read as silent success]. Supports
    ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the failover group to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosVPNFailoverGroup -Name 'BranchFailover' -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the "not found" pre-check (this cmdlet's own read-first design) against a
    name that never existed threw as expected. Removing a genuinely existing failover group
    was not exercised, because none could be created in this lab (see
    New-SfosVPNFailoverGroup's .NOTES).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/FailoverGroupConnection/operations/Delete%20Failover%20Group.html

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
    Adds a VPNIPSecConnection to a VPNFailoverGroup's member list.

.DESCRIPTION
    Reads the current VPNFailoverGroup, adds the given connection name to its member list if
    not already present, and writes the complete list back via Set-SfosVPNFailoverGroup
    (read-modify-write - the member list is a whole-entity field like every other one on this
    entity, no append-only behaviour was measured or assumed). Supports ShouldProcess; use
    -WhatIf to preview.

    UNCONFIRMED live - transitively blocked, see Set-SfosVPNFailoverGroup's .NOTES.

.PARAMETER Name
    Name of the target failover group. Mandatory; accepts pipeline input by property name.

.PARAMETER Connection
    Name of the VPNIPSecConnection to add. Mandatory.

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
    None. Throws an exception if the operation fails.

.EXAMPLE
    Add-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'ExampleTunnel' -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    NOT VERIFIED live - see Set-SfosVPNFailoverGroup's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/FailoverGroupConnection/operations/AddFailoverConnectionGroup%26UpdateFailoverConnectionGroup..html

.LINK
    Get-SfosVPNFailoverGroup
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
    Removes a VPNIPSecConnection from a VPNFailoverGroup's member list.

.DESCRIPTION
    Reads the current VPNFailoverGroup, removes the given connection name from its member
    list, and writes the reduced list back via Set-SfosVPNFailoverGroup (read-modify-write).
    Since the entity requires at least one member, throws if this call would empty the list:
    the firewall's own doc marks Connection "Mandatory: Yes" so an empty list would be
    rejected at the API too; this cmdlet fails fast client-side instead. Supports
    ShouldProcess; use
    -WhatIf to preview.

    UNCONFIRMED live - transitively blocked, see Set-SfosVPNFailoverGroup's .NOTES.

.PARAMETER Name
    Name of the target failover group. Mandatory; accepts pipeline input by property name.

.PARAMETER Connection
    Name of the VPNIPSecConnection to remove. Mandatory.

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
    None. Throws an exception if the operation fails.

.EXAMPLE
    Remove-SfosVPNFailoverGroupMember -Name 'BranchFailover' -Connection 'ExampleTunnel' -WhatIf

.NOTES
    Minimum supported PowerShell version: 5.1
    NOT VERIFIED live - see Set-SfosVPNFailoverGroup's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/FailoverGroupConnection/operations/AddFailoverConnectionGroup%26UpdateFailoverConnectionGroup..html

.LINK
    Get-SfosVPNFailoverGroup
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
    Retrieves the SophosConnectClient configuration from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the SophosConnectClient entity (VPN > Sophos
    Connect client). Only Get is implemented for this entity - see .NOTES for why New-/Set-
    are deliberately not implemented in this fragment.

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
    Returns the raw XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosSophosConnectClient

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live (twice, in separate calls): the firewall answers HTTP 200 with
    '<SophosConnectClient><Reset>Yes</Reset></SophosConnectClient>' - no field from the
    documented Configure sample XML (Name, AliasInterface, AuthenticationType, PresharedKey,
    LocalIDType, LocalID, RemoteIDType, RemoteID, ...) is present. 'Reset' matches no
    documented parameter either. New-/Set-SfosSophosConnectClient are NOT implemented in this
    fragment: writing to the documented Configure operation was deliberately not tested, and
    unlike the Set-SfosGuestUserSettings precedent this project otherwise follows for
    untested settings singletons, there is no live Get shape at all here to build a
    documentation-consistent Set- against, since provoking even an error response would
    itself be a write attempt. A doc-only Set- would be guessing at both the field set AND
    the wire shape simultaneously.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/Cisco/Cisco.html
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

# SophosFirewall.VPN - Group B: SSLVPN (SSLTunnelAccessSettings, SSLVPNPolicy, SSLBookmark,
# SSLBookmarkGroup, SiteToSiteClient, SiteToSiteServer).
#
# Measured live against the SFOS lab (22.0, APIVersion 2200.1). Cross-cutting findings:
#
# 1. SSLVPNPolicy is one API entity with two live sub-shapes, TunnelPolicy and
#    ClientlessPolicy, that share the <SSLVPNPolicy> wrapper only on Get. On Add/Update the
#    response root is the bare sub-type element (<TunnelPolicy>/<ClientlessPolicy>), not
#    <SSLVPNPolicy> - so the status must be read from /Response/TunnelPolicy/Status or
#    /Response/ClientlessPolicy/Status. On Remove the response nests one level deeper still:
#    /Response/SSLVPNPolicy/TunnelPolicy/Status. Three different status paths for the same
#    entity, all measured live and used exactly as observed below.
# 2. SSLVPNPolicy.PolicyMembers writes back onto the referenced UserGroup: adding a group as
#    a policy member sets that group's own <SSLVPNPolicy>/<ClientlessPolicy> fields to the
#    policy's name as a side effect - confirmed live by reading the group back afterwards.
#    Treat every group reference as a write to that group. New-/Set-SfosSSLVPNPolicy document
#    this prominently - never pass a production group name to -Member.
# 3. Deleting a TunnelPolicy/ClientlessPolicy that a group still references answers 504
#    ("Deleting entity referred by another entity") or 500 ("Deleted some configurations.
#    Couldn't delete all.") and deletes nothing; the group's own policy reference has to be
#    cleared first (Set-SfosUserGroup -SSLVPNPolicy '' -ClientlessPolicy '', in the
#    Authentication module), then the policy, then the group. Remove-SfosSSLVPNPolicy does not
#    attempt this automatically - it is not this cmdlet's entity to modify - and just surfaces
#    the firewall's own error.
# 4. Remove on SSLBookmark is a confirmed no-op on this firmware: every shape tried - bare
#    <Name>, <Name> plus <Type>, the full object, and even the undocumented
#    <Set operation="remove"> - answers code 200 "Configuration applied successfully" and the
#    object is still present on the very next Get. Documented delete operation, used exactly
#    as specified, silently does nothing. Remove-SfosSSLBookmark reads the object back after
#    the call and throws if it is still there, rather than reporting the firewall's false
#    success. Removal of an existing SSLBookmark is therefore only possible through the web
#    admin.
# 5. SSLBookmark.Password comes back from Get in hashed form
#    (<Password hashform="mode1">$sfos$7$0$...</Password>), never in plaintext - but unlike
#    SophosConnectClient/FileType-Template, the update resends that hash together with its hashform
#    attribute, the mechanism the config export uses for pre-hashed secrets. The stored hash
#    TEXT still changes on every write (re-salted), so whether the firewall treats the
#    resent hash as the same password or as new plaintext is not measurable here - it would
#    take a real portal login. Same standing caveat as the RADIUS shared secret. So,
#    normal read-modify-write is safe here: Set-SfosSSLBookmark reads the current (hashed)
#    Password and resends it verbatim when the caller does not pass -Password.
# 6. SiteToSiteClient.ServerConfigurationFile is a genuine file upload (.apc/.epc), not a text
#    field - the doc sample itself says so. Every attempt to create a SiteToSiteClient through
#    this module's urlencoded reqxml transport failed with a field-less 500: with no
#    ServerConfigurationFile element, with an empty element, and with a base64 placeholder
#    string in it. Core has no multipart transport. New-/Set-/Get-/Remove-SfosSiteToSiteClient
#    are implemented documentation-faithful and marked unconfirmed; because Add never
#    succeeds, whether FilePassword/the proxy Password survive a read-modify-write could not
#    be measured - Set-SfosSiteToSiteClient does not attempt to preserve them (see its .NOTES).
# 7. SiteToSiteServer.Name rejects a hyphen: <Set operation="add"> with
#    Name=Portal-S2SServer1 answered 501 naming /SiteToSiteServer/Name; the same request
#    with the hyphen removed (PortalS2SServer1) succeeded.

#region SSLTunnelAccessSettings

<#
.SYNOPSIS
    Retrieves the SSLVPN tunnel access settings from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SSLTunnelAccessSettings (VPN > SSL VPN (Remote
    Access) > Tunnel access control), a device-wide singleton - there is exactly one object
    and it has no Name. Use -AsXml to return the raw XML node.

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
    Returns the raw XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosSSLTunnelAccessSettings

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: the sample XML on the Configure operation page also shows
    <CompressSSLVPNTraffic>, but the live object never returns it - not even as an empty
    element - regardless of configuration. Because Get cannot confirm its value,
    Set-SfosSSLTunnelAccessSettings has no -CompressSSLVPNTraffic parameter: a field this
    module cannot read back is not offered for write, so a read-modify-write update can never
    silently clear it.
    Verified live end-to-end as a singleton round trip: read the object, flip -DebugMode from
    Disable to Enable, re-read and confirmed only DebugMode differed from the baseline, set it
    back to Disable, re-read and confirmed an exact field-for-field match to the original
    baseline. No other field (including SSLServerCertificate and the management-adjacent
    fields) was written for verification.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNTunnel/SSLVPNTunnel.html

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
    Updates the SSLVPN tunnel access settings on the Sophos Firewall.

.DESCRIPTION
    Updates the SSLTunnelAccessSettings singleton (VPN > SSL VPN (Remote Access) > Tunnel
    access control) using the Sophos Firewall XML API. Reads the current object first and
    resends every field, overriding only what the caller explicitly passed (read-modify-write
    - SFOS replaces the whole entity on update). Supports ShouldProcess; use -WhatIf to
    preview.

    This is a device-wide singleton: every field affects every SSL VPN client. There is no
    -CompressSSLVPNTraffic parameter - see .NOTES.

.PARAMETER Protocol
    'TCP' or 'UDP'. If omitted, the existing value is kept.

.PARAMETER SSLServerCertificate
    Name of the certificate used for the SSL VPN listener. If omitted, the existing value is
    kept.

.PARAMETER OverrideHostName
    Hostname advertised to clients instead of the appliance's own. If omitted, the existing
    value is kept.

.PARAMETER SslPort
    SSL VPN listening port, 1-65535. If omitted, the existing value is kept. Named -SslPort,
    not -Port, because -Port is reserved for the API management port (connection parameter).

.PARAMETER StartIP
    Start of the client IP lease range. If omitted, the existing value is kept.

.PARAMETER EndIP
    End of the client IP lease range. If omitted, the existing value is kept.

.PARAMETER SubnetMask
    Subnet mask for leased addresses. If omitted, the existing value is kept.

.PARAMETER IPv6Lease
    IPv6 lease address. If omitted, the existing value is kept.

.PARAMETER IPv6Prefix
    IPv6 prefix length, 64-112. If omitted, the existing value is kept.

.PARAMETER LeaseMode
    'IPv4' or 'IPv4 and IPv6'. If omitted, the existing value is kept.

.PARAMETER PrimaryDNSIPv4
    Primary DNS server handed to clients. If omitted, the existing value is kept.

.PARAMETER SecondaryDNSIPv4
    Secondary DNS server handed to clients. If omitted, the existing value is kept.

.PARAMETER PrimaryWINSIPv4
    Primary WINS server handed to clients. If omitted, the existing value is kept.

.PARAMETER SecondaryWINSIPv4
    Secondary WINS server handed to clients. If omitted, the existing value is kept.

.PARAMETER DomainName
    Domain suffix handed to clients. If omitted, the existing value is kept.

.PARAMETER DisconnectDeadPeerAfter
    Seconds before a dead peer is disconnected, 60-1800. If omitted, the existing value is
    kept.

.PARAMETER DisconnectIdlePeerAfter
    Minutes before an idle peer is disconnected, 15-360. If omitted, the existing value is
    kept.

.PARAMETER EncryptionAlgorithm
    Cipher for the tunnel. If omitted, the existing value is kept.

.PARAMETER AuthenticationAlgorithm
    Hash algorithm for the tunnel. If omitted, the existing value is kept.

.PARAMETER Keysize
    '1024bit' or '2048bit'. If omitted, the existing value is kept.

.PARAMETER KeyLifetime
    Key lifetime in seconds, 60-86400. If omitted, the existing value is kept.

.PARAMETER DebugMode
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER SecurityHeartbeat
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER SaveCredential
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER TwoFAToken
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER AdLogon
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER AutoConnect
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER HostorDNSName
    Reachability check target used when -AutoConnect is 'Enable'. If omitted, the existing
    value is kept.

.PARAMETER StaticIPAddresses
    'Enable' or 'Disable'. If omitted, the existing value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    # Flip on debug logging without touching anything else
    Set-SfosSSLTunnelAccessSettings -DebugMode Enable

.NOTES
    Minimum supported PowerShell version: 5.1
    No -CompressSSLVPNTraffic parameter: Get-SfosSSLTunnelAccessSettings never returns this
    field even though the Configure operation page's sample XML includes it, so its current
    value can never be confirmed and a read-modify-write could silently clear it - see
    Get-SfosSSLTunnelAccessSettings's .NOTES.
    Verified live: flipped -DebugMode from Disable to Enable, confirmed every other field
    (including SSLServerCertificate, Port, IPLeaseRange, EncryptionAlgorithm and all others)
    was byte-for-byte unchanged from the pre-test baseline, then set -DebugMode back to
    Disable and confirmed an exact match to the original baseline. No other field of this
    singleton was written to the live appliance during verification.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNTunnel/operations/ConfigureSSLVPNTunnelAccess.html

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
    Retrieves SSLVPNPolicy objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SSLVPNPolicy objects (VPN > SSL VPN (Remote
    Access) > Policies). The entity has two live sub-shapes, Tunnel and Clientless, returned
    together under one <SSLVPNPolicy> wrapper on Get - see the region header comment. Use
    -PolicyType to return only one sub-shape. Use -AsXml to return the raw XML nodes.

.PARAMETER NameLike
    Filters by Name, substring match. Client-side only - unlike every other entity in this
    project, a server-side key was not tested against this entity because no filter test could
    be run without first creating a policy that referenced a group, and every such policy was
    a test object cleaned up before this cmdlet's final form; treat -NameLike here as
    unconfirmed for server-side support and implemented conservatively as client-side-only.

.PARAMETER PolicyType
    'Tunnel', 'Clientless', or omitted for both. Client-side filter.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosSSLVPNPolicy -PolicyType Clientless

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: an empty firewall answers HTTP 200 with the "no records" status nested one
    level deeper than every other entity in this project -
    <SSLVPNPolicy><ClientlessPolicy><Status>No. of records Zero.</Status></ClientlessPolicy></SSLVPNPolicy> -
    rather than a bare <SSLVPNPolicy><Status>...</Status></SSLVPNPolicy>. This cmdlet checks
    for status nodes at both the top level and nested under either sub-type before concluding
    the result is empty, and still throws on any status that carries a real error code at
    either level.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNPolicy/SSLVPNPolicy.html

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
    Creates a new SSLVPNPolicy object on the Sophos Firewall.

.DESCRIPTION
    Creates a Tunnel or Clientless SSLVPNPolicy (VPN > SSL VPN (Remote Access) > Policies)
    using the Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

    SECURITY / SIDE EFFECT: every name passed to -Member is written back onto that UserGroup's
    own SSLVPNPolicy/ClientlessPolicy assignment field - confirmed live (see the region header
    comment). Never pass a production group name here for testing; a real group's policy
    assignment will be silently overwritten. Use a dedicated test group.

.PARAMETER Name
    Name of the policy [doc]. Mandatory. No commas.

.PARAMETER PolicyType
    'Tunnel' or 'Clientless'. Mandatory - selects which sub-shape is created; see the region
    header comment for why the wire response root differs from <SSLVPNPolicy> for this
    operation.

.PARAMETER Description
    Free-text description [doc]. Optional.

.PARAMETER Member
    One or more UserGroup names to assign this policy to [doc]. Optional. SEE THE SECURITY
    NOTE ABOVE - this writes back onto the named group.

.PARAMETER UseAsDefaultGateway
    Tunnel only. 'On' or 'Off' [doc]. Default 'Off' (split tunnel).

.PARAMETER PermittedNetworkResourcesIPv4
    Tunnel only. IPv4 resources (IPHost/IPHostGroup names) reachable through the tunnel [doc].

.PARAMETER PermittedNetworkResourcesIPv6
    Tunnel only. IPv6 resources reachable through the tunnel [doc].

.PARAMETER DisconnectIdleClients
    Tunnel only. 'On' or 'Off' [doc]. Default uses the global SSLTunnelAccessSettings value.

.PARAMETER OverrideGlobalTimeout
    Tunnel only. Idle timeout in minutes, 15-360 [doc]. Requires -DisconnectIdleClients On.

.PARAMETER RestrictWebApplications
    Clientless only. 'Enable' or 'Disable' [doc]. Default 'Disable'.

.PARAMETER BookmarkGroup
    Clientless only. One or more SSLBookmarkGroup names accessible in web mode [doc].

.PARAMETER Bookmark
    Clientless only. One or more SSLBookmark names accessible in web mode [doc].

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
    None. Throws an exception if creation fails.

.EXAMPLE
    # Tunnel policy against a dedicated test group, never a production one
    New-SfosSSLVPNPolicy -Name 'MyTunnelPolicy' -PolicyType Tunnel -Member 'MyTestGroup' `
        -PermittedNetworkResourcesIPv4 'MyTestNetwork'

.NOTES
    Minimum supported PowerShell version: 5.1
    The "Web Access" field (values 1 or 6) in the documentation's Attribute/Parameter table has
    no corresponding element anywhere in the sample XML and never appeared on any live object -
    it is a table/sample mismatch and is not implemented.
    Verified live end-to-end for both sub-types, against a dedicated throwaway test group
    (not a production group - see the .DESCRIPTION security note): created a Tunnel policy
    (code 201) and a Clientless policy (code 200) referencing that group, confirmed both via
    Get-SfosSSLVPNPolicy with the expected fields, then removed them (see
    Remove-SfosSSLVPNPolicy).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNPolicy/operations/AddSSLVPNPolicy%26EditSSLVPNPolicy.html

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
    Updates an existing SSLVPNPolicy object on the Sophos Firewall.

.DESCRIPTION
    Updates a Tunnel or Clientless SSLVPNPolicy using the Sophos Firewall XML API. Reads the
    current object first (via Get-SfosSSLVPNPolicy, which also supplies -PolicyType when not
    passed) and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

    SECURITY / SIDE EFFECT: same as New-SfosSSLVPNPolicy - every name in -Member is written
    back onto that UserGroup. Never pass a production group name.

.PARAMETER Name
    Name of the target policy. Mandatory; accepts pipeline input by property name.

.PARAMETER PolicyType
    'Tunnel' or 'Clientless'. If omitted, resolved from the existing object (both sub-types
    share the Name space, so the current object's own type is used, not guessed).

.PARAMETER Description
    If omitted, the existing value is kept.

.PARAMETER Member
    Complete replacement list of UserGroup names. If omitted, the existing list is kept. SEE
    THE SECURITY NOTE ON New-SfosSSLVPNPolicy.

.PARAMETER UseAsDefaultGateway
    Tunnel only. If omitted, the existing value is kept.

.PARAMETER PermittedNetworkResourcesIPv4
    Tunnel only. Complete replacement list. If omitted, the existing list is kept.

.PARAMETER PermittedNetworkResourcesIPv6
    Tunnel only. Complete replacement list. If omitted, the existing list is kept.

.PARAMETER DisconnectIdleClients
    Tunnel only. If omitted, the existing value is kept.

.PARAMETER OverrideGlobalTimeout
    Tunnel only. If omitted, the existing value is kept.

.PARAMETER RestrictWebApplications
    Clientless only. If omitted, the existing value is kept.

.PARAMETER BookmarkGroup
    Clientless only. Complete replacement list. If omitted, the existing list is kept.

.PARAMETER Bookmark
    Clientless only. Complete replacement list. If omitted, the existing list is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosSSLVPNPolicy -Name 'MyClientlessPolicy' -Description 'Updated'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: updated the Clientless test policy's Description only, re-read it and
    confirmed PolicyMembers, RestrictWebApplications and the Bookmarks list were unchanged
    (status code 200) - full round trip including the response's own status path
    (/Response/ClientlessPolicy/Status, not /Response/SSLVPNPolicy/Status - see the region
    header comment).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNPolicy/operations/AddSSLVPNPolicy%26EditSSLVPNPolicy.html

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
    Removes an SSLVPNPolicy object from the Sophos Firewall.

.DESCRIPTION
    Removes a Tunnel or Clientless SSLVPNPolicy using the Sophos Firewall XML API. Reads the
    object first (to resolve -PolicyType when not passed and to produce a clean "not found"
    error) and sends the nested Remove shape this entity requires -
    <Remove><SSLVPNPolicy><TunnelPolicy><Name>...</Name></TunnelPolicy></SSLVPNPolicy></Remove> -
    with the status at /Response/SSLVPNPolicy/<Type>/Status, one level deeper than Add/Update's
    own response (see the region header comment). Supports ShouldProcess; use -WhatIf to
    preview.

    If a UserGroup still has this policy assigned (via -Member on New-/Set-SfosSSLVPNPolicy -
    see their security note), the firewall answers 504 or 500 and deletes nothing; this cmdlet
    does not clear that assignment automatically, since UserGroup is not this entity's to
    modify - clear it first with Set-SfosUserGroup -SSLVPNPolicy '' -ClientlessPolicy '' (or
    the corresponding parameter) from the Authentication module.

.PARAMETER Name
    Name of the policy to remove. Mandatory; accepts pipeline input by property name.

.PARAMETER PolicyType
    'Tunnel' or 'Clientless'. If omitted, resolved from the existing object.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosSSLVPNPolicy -Name 'MyClientlessPolicy'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removing a policy still referenced by a test group answered 504
    ("Deleting entity referred by another entity") for Clientless and 500 ("Deleted some
    configurations. Couldn't delete all.") for Tunnel, and neither was actually deleted;
    clearing the group's SSLVPNPolicy/ClientlessPolicy fields via Set-SfosUserGroup and
    retrying both removals then answered 200 and a follow-up Get confirmed both gone.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNPolicy/operations/Delete%20SSL%20VPN%20Policy.html

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
    Retrieves SSLBookmark objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SSLBookmark objects (VPN > SSL VPN (Remote
    Access) > Bookmarks). Use -AsXml to return the raw XML nodes.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key (exact-match tested
    live and confirmed working for this entity) and re-applied client-side.

.PARAMETER TypeLike
    Filters by Type, substring match. Client-side only.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosSSLBookmark -NameLike 'Intranet'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: when -AutoLogin is 'Enable', Get returns <Password hashform="mode1"> with a
    hashed value, never plaintext. Exposed as PasswordHash/PasswordHashForm (SelectSingleNode,
    because the adapter property returns the element object once the attribute exists) so
    Set-SfosSSLBookmark can resend both - hash without hashform is taken as a new plaintext.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmark/SSLVPNBookmark.html

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
            # XmlElement adapter hands back the element OBJECT, and [string] on that yields
            # the literal type name "System.Xml.XmlElement". A Set that resent that as the
            # preserved value silently replaced the real login password - measured live, the
            # stored hash changed between two Sets. Exposed as hash + form, like the RADIUS
            # shared secret, so Set-SfosSSLBookmark can resend both.
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
    Creates a new SSLBookmark object on the Sophos Firewall.

.DESCRIPTION
    Creates an SSLBookmark (VPN > SSL VPN (Remote Access) > Bookmarks) using the Sophos
    Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the bookmark [doc]. Mandatory. Max 50 characters.

.PARAMETER Type
    'HTTP', 'HTTPS', 'RDP', 'TELNET', 'SSH', 'FTP', 'FTPS', 'SFTP', 'SMB', or 'VNC' [doc].
    Mandatory.

.PARAMETER URL
    URL or host for the bookmark [doc]. Mandatory. Max 250 characters.

.PARAMETER Description
    Free-text description [doc]. Optional.

.PARAMETER ShareSession
    'Enable' or 'Disable' [doc]. Default 'Disable'.

.PARAMETER AutoLogin
    'Enable' or 'Disable' [doc]. Default 'Disable'. When 'Enable', -LoginUserName and
    -SecurePassword (or -PrivateKey for SSH/SFTP) should be supplied.

.PARAMETER LoginUserName
    Login username, wire element <UserName>, used when -AutoLogin is 'Enable' [doc, table
    marks this "Mandatory: Yes" but the sample XML - and a live create - show it is only
    required with AutoLogin, not unconditionally; a bookmark created with AutoLogin Disable
    and no UserName succeeded]. Named -LoginUserName, not -UserName, because -Username
    (case-insensitively identical in PowerShell) is reserved for the API connection
    credential.

.PARAMETER SecurePassword
    Login password, used when -AutoLogin is 'Enable' [doc]. SecureString; named -SecurePassword
    (not -Password, which is reserved for the API connection credential) and converted to plain
    text only at the point the wire XML is built - see .NOTES for how it round-trips.

.PARAMETER Port
    Port number for the target service [doc]. Optional.

.PARAMETER Domain
    Domain name, used for RDP or SMB [doc]. Optional.

.PARAMETER Domains
    HTTP/HTTPS only: additional domains/URLs this bookmark's session may reach [doc]. Optional.

.PARAMETER ProtocolSecurity
    RDP only: 'RDP', 'TLS', or 'NLA' [doc]. Optional. NLA requires -AutoLogin 'Enable' [doc].

.PARAMETER InitRemoteFolder
    FTP/FTPS/SFTP/SMB only: initial remote directory [doc]. Optional. Max 250 characters.

.PARAMETER PrivateKey
    SSH/SFTP only: private key text [doc]. Optional.

.PARAMETER PublicHostKey
    SSH/FTPS/SFTP only: public host key text [doc]. Optional.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    New-SfosSSLBookmark -Name 'MyBookmark' -Type HTTP -URL 'intranet.example' -Port 80

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: created with AutoLogin Disable and no UserName/Password (succeeded, code
    200, contradicting the doc table's "Mandatory: Yes" on UserName), and separately with
    AutoLogin Enable plus UserName/Password (succeeded, code 200) - see
    Get-SfosSSLBookmark's .NOTES and the region header comment for the Password round-trip
    finding.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmark/operations/AddSSLVPNBookmark%26EditSSLVPNBookmark.html

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
    Updates an existing SSLBookmark object on the Sophos Firewall.

.DESCRIPTION
    Updates an SSLBookmark using the Sophos Firewall XML API. Reads the current object first
    and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the target bookmark. Mandatory; accepts pipeline input by property name.

.PARAMETER Type
    If omitted, the existing value is kept.

.PARAMETER URL
    If omitted, the existing value is kept.

.PARAMETER Description
    If omitted, the existing value is kept.

.PARAMETER ShareSession
    If omitted, the existing value is kept.

.PARAMETER AutoLogin
    If omitted, the existing value is kept.

.PARAMETER LoginUserName
    Wire element <UserName>. If omitted, the existing value is kept. Named -LoginUserName,
    not -UserName, because -Username (case-insensitively identical in PowerShell) is reserved
    for the API connection credential.

.PARAMETER SecurePassword
    SecureString; converted to plain text only at the point the wire XML is built. If omitted,
    the existing (hashed) value read back from the firewall is resent unchanged - see .NOTES
    for why this is safe for this specific field.

.PARAMETER BookmarkPort
    If omitted, the existing value is kept.

.PARAMETER Domain
    If omitted, the existing value is kept.

.PARAMETER Domains
    Complete replacement list. If omitted, the existing list is kept.

.PARAMETER ProtocolSecurity
    If omitted, the existing value is kept.

.PARAMETER InitRemoteFolder
    If omitted, the existing value is kept.

.PARAMETER PrivateKey
    If omitted, the existing value is kept.

.PARAMETER PublicHostKey
    If omitted, the existing value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosSSLBookmark -Name 'MyBookmark' -Description 'Updated'

.NOTES
    Minimum supported PowerShell version: 5.1
    Password round-trip, unusually safe for a secret field: Get-SfosSSLBookmark returns
    Password hashed (<Password hashform="mode1">$sfos$7$0$...</Password>), never plaintext.
    Measured live: the stored hash text changes on EVERY update, with or without the hashform
    attribute - the firewall re-salts. The update therefore resends hash plus hashform (the
    vendor's mechanism for pre-hashed secrets); whether that preserves the password
    semantically cannot be verified without a portal login. Pass -SecurePassword explicitly
    where certainty matters. A value on a
    second update produced a visibly different hash. So, unlike SophosConnectClient or
    FileType/-Template, normal read-modify-write is safe here and -SecurePassword is exposed
    on this cmdlet.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmark/operations/AddSSLVPNBookmark%26EditSSLVPNBookmark.html

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
    Removes an SSLBookmark object from the Sophos Firewall.

.DESCRIPTION
    Attempts to remove an SSLBookmark using the Sophos Firewall XML API, then reads the object
    back and throws if it is still present - see the region header comment. Supports
    ShouldProcess; use -WhatIf to preview.

    THIS OPERATION IS A CONFIRMED NO-OP ON THIS FIRMWARE (SFOS 22.0). The Remove call answers
    HTTP 200 "Configuration applied successfully" and the object is never actually deleted, in
    every shape tried (bare Name, Name plus Type, the full object, and the undocumented
    Set operation="remove"). This cmdlet cannot fix the firmware; it can only avoid reporting
    the firewall's false success by reading the object back and throwing.

.PARAMETER Name
    Name of the bookmark to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails, or if the firewall reports success but the
    object is still present (see .DESCRIPTION).

.EXAMPLE
    Remove-SfosSSLBookmark -Name 'MyBookmark'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live, reproduced four times against two different test objects: Remove answered
    code 200 every time, and Get-SfosSSLBookmark found the object present immediately
    afterwards each time, including after a 5-second wait (ruling out an async apply delay)
    and after trying an undocumented <Set operation="remove"> instead of <Remove> (rejected
    with 501, confirming only add/update are valid operations here). Documented delete
    operation, used exactly as specified, silently does nothing.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmark/operations/Delete%20SSLVPN%20Bookmark.html

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
    Retrieves SSLBookmarkGroup objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SSLBookmarkGroup objects (VPN > SSL VPN (Remote
    Access) > Bookmark groups). Use -AsXml to return the raw XML nodes.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosSSLBookmarkGroup

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmarkGroup/SSLVPNBookmarkGroup.html

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
    Creates a new SSLBookmarkGroup object on the Sophos Firewall.

.DESCRIPTION
    Creates an SSLBookmarkGroup (VPN > SSL VPN (Remote Access) > Bookmark groups) using the
    Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the bookmark group [doc]. Mandatory. Max 50 characters.

.PARAMETER Bookmark
    One or more existing SSLBookmark names [doc]. Mandatory - a group needs at least one
    member; an empty BookmarkList is rejected by the firewall with 501 naming
    BookmarkList/Bookmark (measured).

.PARAMETER Description
    Free-text description [doc]. Optional.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    New-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Bookmark 'MyBookmark'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: created with one member (code 200), confirmed via Get.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmarkGroup/operations/AddSSLVPNBookmarkGroup%26EditSSLVPNBookmarkGroup.html

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
    Updates an existing SSLBookmarkGroup object on the Sophos Firewall.

.DESCRIPTION
    Updates an SSLBookmarkGroup using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the target group. Mandatory; accepts pipeline input by property name.

.PARAMETER Bookmark
    Complete replacement list of member bookmark names. If omitted, the existing list is
    kept. Unlike WebFilterCategory's URLList, this list genuinely shrinks and grows - see
    .NOTES.

.PARAMETER Description
    If omitted, the existing value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup' -Description 'Updated'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: created a group with two members, updated it with a one-member list, and
    Get afterwards showed exactly one member - list replacement genuinely shrinks here, unlike
    the append-only WebFilterCategory.URLList / FirewallRuleGroup.SecurityPolicyList. Sending
    an empty list is rejected outright by the firewall (501 naming BookmarkList/Bookmark)
    rather than silently ignored - a safe failure mode, so
    Remove-SfosSSLBookmarkGroupMember does not need the read-back-and-throw guard that
    Remove-SfosFirewallRuleGroupMember needs.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmarkGroup/operations/AddSSLVPNBookmarkGroup%26EditSSLVPNBookmarkGroup.html

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
    Removes an SSLBookmarkGroup object from the Sophos Firewall.

.DESCRIPTION
    Removes an SSLBookmarkGroup using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist. Supports ShouldProcess; use -WhatIf
    to preview.

.PARAMETER Name
    Name of the group to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosSSLBookmarkGroup -Name 'MyBookmarkGroup'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removed a test group (code 200), confirmed gone with a follow-up Get.
    Unlike SSLBookmark, Remove genuinely works for this entity.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmarkGroup/operations/Delete%20SSLVPN%20Bookmark%20Group.html

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
    Adds a member bookmark to an SSLBookmarkGroup.

.DESCRIPTION
    Reads the group's current BookmarkList, adds the given bookmark name if not already
    present, and writes the complete list back (read-modify-write). Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER GroupName
    Name of the target SSLBookmarkGroup. Mandatory; accepts pipeline input by property name.

.PARAMETER Bookmark
    Name of the SSLBookmark to add. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Add-SfosSSLBookmarkGroupMember -GroupName 'MyBookmarkGroup' -Bookmark 'MyBookmark'

.NOTES
    Minimum supported PowerShell version: 5.1
    Uses Set-SfosSSLBookmarkGroup's confirmed-working (non-append-only) list replacement - see
    that cmdlet's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmarkGroup/operations/AddSSLVPNBookmarkGroup%26EditSSLVPNBookmarkGroup.html

.LINK
    Set-SfosSSLBookmarkGroup
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
    Removes a member bookmark from an SSLBookmarkGroup.

.DESCRIPTION
    Reads the group's current BookmarkList, removes the given bookmark name, and writes the
    remaining list back (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER GroupName
    Name of the target SSLBookmarkGroup. Mandatory; accepts pipeline input by property name.

.PARAMETER Bookmark
    Name of the SSLBookmark to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Remove-SfosSSLBookmarkGroupMember -GroupName 'MyBookmarkGroup' -Bookmark 'MyBookmark'

.NOTES
    Minimum supported PowerShell version: 5.1
    Removing the last member is not silently swallowed: the firewall itself rejects an empty
    BookmarkList with 501 naming BookmarkList/Bookmark (measured on Set-SfosSSLBookmarkGroup),
    so this cmdlet does not need the read-back-and-throw guard that
    Remove-SfosFirewallRuleGroupMember needs for an append-only list - the API already fails
    loudly here.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/SSLVPNBookmarkGroup/operations/AddSSLVPNBookmarkGroup%26EditSSLVPNBookmarkGroup.html

.LINK
    Set-SfosSSLBookmarkGroup
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
    Retrieves SiteToSiteClient objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SiteToSiteClient objects (VPN > SSL VPN (Site-to-
    site) > Client connections). Use -AsXml to return the raw XML nodes.

    UNCONFIRMED AS A WRITE PATH - see New-SfosSiteToSiteClient's .DESCRIPTION and the region
    header comment. Get itself is a plain, documented, working operation and is implemented
    normally; it simply has nothing to read on this lab firewall, since no object could be
    created through this module's transport.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side, per this project's usual pattern - not independently confirmed for this
    entity since no live object could be created to filter for.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosSiteToSiteClient

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live only for the empty-result path: an empty firewall answers HTTP 200 with
    "No. of records Zero." as usual, returned here as @().

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20client%20connection/SSLVPNClientConnection.html

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
    Creates a new SiteToSiteClient object on the Sophos Firewall.

.DESCRIPTION
    Attempts to create a SiteToSiteClient (VPN > SSL VPN (Site-to-site) > Client connections)
    using the Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

    UNCONFIRMED / BLOCKED ON THIS TRANSPORT. -ServerConfigurationFile takes the content of a
    Sophos-issued .apc/.epc file, which the documentation's own sample marks as a file upload,
    not a text field. Every attempt to create an object through this module's urlencoded reqxml
    POST failed with a field-less 500 - with no ServerConfigurationFile element, with an empty
    element, and with a base64 placeholder string in it (see the region header comment). Core
    has no multipart transport, so this cmdlet cannot be verified end-to-end here; it is
    implemented per the documented field set and marked unconfirmed.

.PARAMETER Name
    Name of the connection [doc]. Mandatory. Max 50 characters. First character A-Za-z, rest
    A-Za-z0-9_.

.PARAMETER ServerConfigurationFile
    Content of a .apc/.epc configuration file exported from the SSL VPN server side [doc].
    Mandatory per the documentation. See .DESCRIPTION - not confirmed to work through this
    transport.

.PARAMETER FilePassword
    Password protecting the configuration file, if any [doc]. Optional. SecureString;
    converted to plain text only at the point the wire XML is built. [doc] caps this at 60
    characters, not enforced client-side because ValidateLength cannot be applied to a
    SecureString parameter. Preservability on update could not be measured - see
    Set-SfosSiteToSiteClient's .NOTES.

.PARAMETER Description
    Free-text description [doc]. Optional. Max 255 characters.

.PARAMETER HttpProxyServer
    'Enable' or 'Disable' [doc]. Default 'Disable'.

.PARAMETER ProxyServer
    Proxy server name, required when -HttpProxyServer is 'Enable' [doc].

.PARAMETER ProxyPort
    Proxy server port, required when -HttpProxyServer is 'Enable' [doc].

.PARAMETER ProxyAuthentication
    'Enable' or 'Disable' [doc]. Default 'Disable'.

.PARAMETER ProxyUsername
    Proxy authentication username, used when -ProxyAuthentication is 'Enable' [doc].

.PARAMETER ProxySecurePassword
    Proxy authentication password, used when -ProxyAuthentication is 'Enable' [doc].
    SecureString; converted to plain text only at the point the wire XML is built. See the
    DESCRIPTION section above - preservability unmeasured, same as -FilePassword.

.PARAMETER PeerHost
    'Enable' or 'Disable' - override the peer hostname from the configuration file [doc].
    Default 'Disable'.

.PARAMETER HostName
    Override hostname, required when -PeerHost is 'Enable' [doc].

.PARAMETER Status
    'On' or 'Off' [doc]. Optional.

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
    None. Throws an exception if creation fails - which, per .DESCRIPTION, is the observed
    outcome for every variant tried on this firmware/transport combination.

.EXAMPLE
    # Documentation-faithful call; confirmed to fail with a field-less 500 on this transport
    New-SfosSiteToSiteClient -Name 'MyS2SClient' -ServerConfigurationFile $apcFileContent

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: three variants all answered code 500 with no <InvalidParams> detail -
    omitting -ServerConfigurationFile entirely, passing an empty string, and passing a base64
    placeholder string. No variant succeeded, so whether FilePassword/proxy-Password survive
    could not be measured either way.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20client%20connection/operations/addsslvpnclientconnection%26editsslvpnclientconnection.html

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
    Updates an existing SiteToSiteClient object on the Sophos Firewall.

.DESCRIPTION
    Updates a SiteToSiteClient using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

    UNCONFIRMED - see New-SfosSiteToSiteClient's .DESCRIPTION; no object of this type could be
    created to update.

.PARAMETER Name
    Name of the target connection. Mandatory; accepts pipeline input by property name.

.PARAMETER ServerConfigurationFile
    If omitted, the existing value is kept. See .NOTES - Get does not return this field's
    content in any tested scenario (no object ever existed to test against), so "kept" here
    means "resent as read back", unverified.

.PARAMETER FilePassword
    SecureString; converted to plain text only at the point the wire XML is built. If omitted,
    not resent. Get-SfosSiteToSiteClient never confirmed to return this field - unlike
    SSLBookmark's Password, there is no live evidence either way for this one, so it is
    treated conservatively as not preservable:
    omitting it here does not clear a value this cmdlet cannot see, but it also cannot
    guarantee an existing password survives an update that touches other fields.

.PARAMETER Description
    If omitted, the existing value is kept.

.PARAMETER HttpProxyServer
    If omitted, the existing value is kept.

.PARAMETER ProxyServer
    If omitted, the existing value is kept.

.PARAMETER ProxyPort
    If omitted, the existing value is kept.

.PARAMETER ProxyAuthentication
    If omitted, the existing value is kept.

.PARAMETER ProxyUsername
    If omitted, the existing value is kept.

.PARAMETER ProxySecurePassword
    SecureString; converted to plain text only at the point the wire XML is built. If omitted,
    not resent - see -FilePassword.

.PARAMETER PeerHost
    If omitted, the existing value is kept.

.PARAMETER HostName
    If omitted, the existing value is kept.

.PARAMETER Status
    If omitted, the existing value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosSiteToSiteClient -Name 'MyS2SClient' -Description 'Updated'

.NOTES
    Minimum supported PowerShell version: 5.1
    Not verified against the live firewall - New-SfosSiteToSiteClient could not create an
    object to update, for the reasons in its own .NOTES. Implemented per the documented
    Add/Edit contract (the same operation page covers both) and this project's
    read-modify-write rule.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20client%20connection/operations/addsslvpnclientconnection%26editsslvpnclientconnection.html

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
    Removes a SiteToSiteClient object from the Sophos Firewall.

.DESCRIPTION
    Removes a SiteToSiteClient using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist. Supports ShouldProcess; use -WhatIf
    to preview.

.PARAMETER Name
    Name of the connection to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosSiteToSiteClient -Name 'MyS2SClient'

.NOTES
    Minimum supported PowerShell version: 5.1
    Not verified against the live firewall - no object of this type could be created to
    remove, per New-SfosSiteToSiteClient's .NOTES. Implemented per the documented Delete
    operation (Name only, status codes 200/500/504 per the doc page).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20client%20connection/operations/delete%20sslvpn%20client%20connection.html

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
    Retrieves SiteToSiteServer objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SiteToSiteServer objects (VPN > SSL VPN (Site-to-
    site) > Server connections). Use -AsXml to return the raw XML nodes.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key (criteria="like"
    tested live and confirmed working - a filtered Get on this entity's Name field returned
    the expected single object) and re-applied client-side.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosSiteToSiteServer -NameLike 'Branch'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: created a test object, confirmed both an exact-match Get and this
    -NameLike substring Get returned it, then confirmed the empty-result path
    ("No. of records Zero.") after removal.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20server%20connection/SSLVPNServerConnection.html

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
    Creates a new SiteToSiteServer object on the Sophos Firewall.

.DESCRIPTION
    Creates a SiteToSiteServer (VPN > SSL VPN (Site-to-site) > Server connections) using the
    Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the connection [doc]. Mandatory. Max 50 characters. MEASURED: a hyphen is
    rejected - <Set operation="add"> with a hyphenated Name answered 501 naming
    /SiteToSiteServer/Name; the identical request without the hyphen succeeded. This conflicts
    with the test-object naming convention used elsewhere.
    header comment. Validated here with a pattern that excludes hyphens.

.PARAMETER LocalNetworks
    One or more existing IPHost/IPHostGroup names reachable on the local side [doc]. Mandatory.

.PARAMETER RemoteNetworks
    One or more existing IPHost/IPHostGroup names reachable on the remote side [doc].
    Mandatory.

.PARAMETER Description
    Free-text description [doc]. Optional. Max 255 characters.

.PARAMETER StaticIP
    'Enable' or 'Disable' - use a static virtual IP for this tunnel [doc]. Default 'Disable'.

.PARAMETER PeerIP
    Static virtual IP address, required when -StaticIP is 'Enable' [doc]. Excludes loopback
    and unspecified addresses per the doc; not independently verified live (StaticIP Disable
    was the tested path).

.PARAMETER Status
    'On' or 'Off' [doc]. Optional.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    New-SfosSiteToSiteServer -Name 'MyS2SServer' -LocalNetworks 'MyLocalNet' -RemoteNetworks 'MyRemoteNet'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live end-to-end: created with -StaticIP Disable and one IPHost reference each for
    -LocalNetworks/-RemoteNetworks (code 200), confirmed via Get with the expected fields,
    updated the description only via Set-SfosSiteToSiteServer (code 200) and confirmed the
    networks were unchanged, then removed it (code 200) and confirmed it was gone. Also
    confirmed the error paths: removing the same name again answered a status with an empty
    code attribute and "Operation could not be performed on Entity.", and updating a
    nonexistent name answered code 500 with the same message - both correctly surfaced as
    failures by Assert-SfosApiReturnSuccess, not silent successes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20server%20connection/operations/addsslvpnserverconnection%26editsslvpnserverconnection.html

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
    Updates an existing SiteToSiteServer object on the Sophos Firewall.

.DESCRIPTION
    Updates a SiteToSiteServer using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the target connection. Mandatory; accepts pipeline input by property name.

.PARAMETER LocalNetworks
    Complete replacement list. If omitted, the existing list is kept.

.PARAMETER RemoteNetworks
    Complete replacement list. If omitted, the existing list is kept.

.PARAMETER Description
    If omitted, the existing value is kept.

.PARAMETER StaticIP
    If omitted, the existing value is kept.

.PARAMETER PeerIP
    If omitted, the existing value is kept (when the resolved -StaticIP is 'Enable'; ignored
    when 'Disable').

.PARAMETER Status
    If omitted, the existing value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosSiteToSiteServer -Name 'MyS2SServer' -Description 'Updated'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: see New-SfosSiteToSiteServer's .NOTES for the full round trip this cmdlet
    was part of.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20server%20connection/operations/addsslvpnserverconnection%26editsslvpnserverconnection.html

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
    Removes a SiteToSiteServer object from the Sophos Firewall.

.DESCRIPTION
    Removes a SiteToSiteServer using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist, rather than passing through the
    firewall's own misleading answer for that case. Supports ShouldProcess; use -WhatIf to
    preview.

.PARAMETER Name
    Name of the connection to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosSiteToSiteServer -Name 'MyS2SServer'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removed a test object (code 200), confirmed gone with a follow-up Get, then
    confirmed the error path - removing the same name again answered a status with an empty
    code attribute and "Operation could not be performed on Entity.", correctly surfaced as a
    failure by Assert-SfosApiReturnSuccess (an empty code is not "no code at all", so it is not
    read as an empty-result success).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/configure/vpn/sslvpn%20server%20connection/operations/delete%20sslvpn%20server%20connection.html

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

# SophosFirewall.VPN - Group C: L2TP and PPTP legacy tunnel protocols
# Entities: L2TPConfiguration (doc folder L2TPConfiguration, singleton), L2TPConnection (doc
# folder L2TPConnection), PPTPConfiguration (doc folder PPTPConfiguration, singleton).
#
# Measured live against the SFOS lab (22.0, APIVersion 2200.1). Cross-cutting findings that
# apply to every function in this fragment:
#
# 1. The response root element for a write is not the outer entity name - it is whichever
#    sub-element the operation actually touched, and it differs by operation:
#      - Set (update) on the *Settings sub-object: response root is <L2TPSettings> /
#        <PPTPSettings> directly under <Response>, NOT <L2TPConfiguration><L2TPSettings>.
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
#        i.e. -ObjectName 'L2TPConnection/Configuration' - the SAME path Get uses for a
#        populated or code-bearing result. A first attempt at Remove using a bare
#        <L2TPConnection><Name>.../<L2TPConnection> (no <Configuration> wrapper) produced a
#        completely empty response body (no <Status> anywhere, not even a code-less one) -
#        that shape is silently ignored by the firewall, not merely rejected.
#    None of this is documented; every path above was read directly off a live response.
#
# 2. PPTPConfiguration's sample XML on the ConfigurePPTP operation page wraps its settings in
#    <Configuration>, but the wire - both what Get returns and what a Set's own status
#    response echoes back - uses <PPTPSettings>, mirroring L2TPConfiguration's own
#    <L2TPSettings> naming. <Configuration> was tried and produces the same "did not even
#    validate" symptom as any other wrong element name; <PPTPSettings> is what this fragment
#    sends.
#
# 3. StartIP, EndIP and PrimaryDNSServer are mandatory on EVERY Set of *Settings, including a
#    ple that changes nothing at all: echoing the lab's own unconfigured baseline
#    (<L2TPGeneralSettings>Disable</L2TPGeneralSettings><LeaseIPFromRadiusServer>Disable</...)
#    straight back was rejected with 501, naming exactly those three elements as missing -
#    even though L2TPGeneralSettings stayed Disable throughout and Get itself omits all three
#    elements entirely when they were never configured. In other words: the singleton's
#    factory/never-configured state cannot be round-tripped through Set at all without
#    introducing a real IP range and DNS server, and once introduced there is no value that
#    clears them back to "absent" again (the same three elements are demanded on every
#    subsequent Set too). Because this field is a one-way structural ratchet with no path
#    back to "unset", Set-SfosL2TPConfiguration/Set-SfosPPTPConfiguration were deliberately
#    NOT write-tested end-to-end - see both functions' .NOTES. The *Members sub-object has no
#    such dependency (confirmed - see finding 4) and WAS write-tested end-to-end, including a
#    full field-toggle-and-revert.
#
# 4. L2TPMembers/PPTPMembers is independent of *Settings validation (a Set touching only the
#    member list succeeds even while the mandatory IP-range fields above remain unset) and is
#    genuinely reversible, not append-only: Set adds a member (measured code 201), Remove
#    takes it back off again (measured code 200), and a Get in between and after matched the
#    original baseline exactly both times - unlike the append-only URLList/SecurityPolicyList
#    quirks documented elsewhere in this project for other entities.
#
# 5. Get on the two singletons returns no <Status> element at all on a normal (non-error)
#    response - only a failed Set produces one. That is consistent with Assert-
#    SfosApiReturnSuccess's own contract (no status found => treated as success) and needs no
#    special handling in Get-SfosL2TPConfiguration/Get-SfosPPTPConfiguration.
#
# 6. Get-SfosL2TPConnection's empty-result shape differs between an unfiltered and a filtered
#    call: unfiltered, an empty firewall answers the usual
#    '<L2TPConnection><Configuration><Status>No. of records Zero.</Status></Configuration></
#    L2TPConnection>'; filtered (a <Filter> sent, no match), it instead answers a bare
#    self-closing '<L2TPConnection/>' with no <Configuration> and no <Status> at all. Both
#    shapes are handled identically here because this cmdlet counts nodes that carry a <Name>
#    rather than inspecting <Status> to decide "empty" - see Get-SfosGatewayHost's precedent.

#region L2TPConfiguration

<#
.SYNOPSIS
    Retrieves the L2TP configuration singleton from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the L2TPConfiguration object (VPN > L2TP). This
    is a singleton - there is exactly one on the firewall, with no name to filter by. Use
    -AsXml to return the raw XML node.

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
    Returns the raw XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosL2TPConfiguration

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: a normal (non-error) response carries no <Status> element at all, only the
    data. AssignIPFrom/PrimaryDNSServer/SecondaryDNSServer/PrimaryWINSServer/
    SecondaryWINSServer are omitted from the response entirely (not empty elements) when
    never configured - this cmdlet returns an empty string for each in that case, never
    $null. See the fragment header, finding 3, for why that "never configured" state cannot
    currently be changed via Set-SfosL2TPConfiguration without also introducing an IP range.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConfiguration/operations/ConfigureL2TP.html

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
    Updates the L2TP configuration singleton on the Sophos Firewall.

.DESCRIPTION
    Updates the L2TPConfiguration object using the Sophos Firewall XML API. Reads the current
    object first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER L2TPGeneralSettings
    'Enable' or 'Disable' [doc]. If omitted, the existing value is kept.

.PARAMETER StartIP
    Start of the IP range leased to L2TP clients [doc]. If omitted, the existing value is
    kept. SFOS requires this together with -EndIP and -PrimaryDNSServer on every update -
    see .NOTES.

.PARAMETER EndIP
    End of the IP range leased to L2TP clients [doc]. If omitted, the existing value is kept.

.PARAMETER LeaseIPFromRadiusServer
    'Enable' or 'Disable' - lease the client IP through RADIUS instead of the local range
    [doc]. If omitted, the existing value is kept.

.PARAMETER PrimaryDNSServer
    Primary DNS server handed to L2TP clients [doc]. If omitted, the existing value is kept.

.PARAMETER SecondaryDNSServer
    Secondary DNS server handed to L2TP clients [doc]. Optional; if omitted, the existing
    value is kept.

.PARAMETER PrimaryWINSServer
    Primary WINS server handed to L2TP clients [doc]. Optional; if omitted, the existing
    value is kept.

.PARAMETER SecondaryWINSServer
    Secondary WINS server handed to L2TP clients [doc]. Optional; if omitted, the existing
    value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    # Requires an IP range and DNS server the first time the singleton is ever configured -
    # see .NOTES.
    Set-SfosL2TPConfiguration -StartIP '203.0.113.10' -EndIP '203.0.113.20' -PrimaryDNSServer '203.0.113.1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Not write-tested against a live full toggle-and-revert, deliberately: once StartIP, EndIP
    and PrimaryDNSServer are supplied, there is no value that clears them back to "not
    configured" again, so a genuine test would leave the firewall in a state that cannot be
    undone through the API. Measured instead via the firewall's own field validation: sending
    the current object back completely unchanged (L2TPGeneralSettings=Disable,
    LeaseIPFromRadiusServer=Disable, an otherwise unconfigured singleton) was rejected with
    code 501, naming /L2TPConfiguration/L2TPSettings/AssignIPFrom/StartIP,
    /L2TPConfiguration/L2TPSettings/AssignIPFrom/EndIP and
    /L2TPConfiguration/L2TPSettings/PrimaryDNSServer as missing. That confirms the request
    shape and the -ObjectName 'L2TPSettings' status path used by this cmdlet (the error
    response's root element IS <L2TPSettings>, not <L2TPConfiguration>), but it also means
    those three fields are unconditionally mandatory on every update - including one that
    changes nothing - and, once supplied, the same three elements are demanded on every later
    call as well. The Members sub-object has no such constraint and WAS tested end-to-end with
    a full revert - see Add-/Remove-SfosL2TPConfigurationMember.
    ConfirmImpact is High: the original empty state is unrecoverable through the API once any
    value has been written (measured); automation must pass -Confirm:$false.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConfiguration/operations/ConfigureL2TP.html

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

    # Measured (see .NOTES): SFOS requires these three unconditionally on every update, even
    # one that changes nothing else.
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
    Adds a local user to the L2TPConfiguration object's L2TPMembers list using the Sophos
    Firewall XML API. This is independent of the L2TPSettings sub-object (see the fragment
    header, findings 3-4) - it does not require an IP range to be configured and does not
    touch one. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER MemberName
    Name of an existing local user to grant L2TP access to [doc]. Mandatory; accepts pipeline
    input by value and by property name. Named -MemberName rather than the wire's own
    -UserName because that would collide with this cmdlet's connection parameter -Username -
    PowerShell parameter (and alias) names are case-insensitive, so even an alias named
    'UserName' is rejected as a duplicate of 'Username' at function-definition time. Piping
    the plain strings from Get-SfosL2TPConfiguration's MemberList works via
    ValueFromPipeline; a custom object would need a property actually named MemberName.

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
    None. Throws an exception if the operation fails.

.EXAMPLE
    Add-SfosL2TPConfigurationMember -MemberName 'VPNUser1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live end-to-end: added an existing local account, confirmed it appeared in
    Get-SfosL2TPConfiguration's MemberList (code 201 "Operation partially successful" -
    treated as success per the published status table), then removed it again with
    Remove-SfosL2TPConfigurationMember and confirmed the object matched the original baseline
    exactly - L2TPGeneralSettings stayed 'Disable' throughout, so the L2TP service itself was
    never enabled. Error path also verified: a nonexistent user name is rejected with code
    500 "Operation could not be performed on Entity." and the member list is left unchanged.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConfiguration/operations/ConfigureL2TP.html

.LINK
    Get-SfosL2TPConfiguration
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
    Removes a local user from the L2TPConfiguration object's L2TPMembers list using the
    Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER MemberName
    Name of the local user to remove from the L2TP member list [doc]. Mandatory; accepts
    pipeline input by property name. See Add-SfosL2TPConfigurationMember's .PARAMETER
    MemberName for why this is not named -UserName.

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
    None. Throws an exception if the operation fails.

.EXAMPLE
    Remove-SfosL2TPConfigurationMember -MemberName 'VPNUser1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the response root for this operation is
    <L2TPConfiguration><L2TPMembers>, one level deeper than Add's <L2TPMembers> - hence
    -ObjectName 'L2TPConfiguration/L2TPMembers' here versus 'L2TPMembers' in
    Add-SfosL2TPConfigurationMember. See Add-SfosL2TPConfigurationMember's .NOTES for the
    full round-trip this cmdlet was verified as part of.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConfiguration/operations/ConfigureL2TP.html

.LINK
    Get-SfosL2TPConfiguration
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
    Retrieves L2TPConnection objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for L2TPConnection objects (VPN > L2TP > Connections).
    By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw
    XML nodes.

    -NameLike is sent as the server-side filter key (per the project's server-side filtering
    rule) and re-applied client-side with AND semantics together with every other filter.

.PARAMETER NameLike
    Filters by Name, substring match. Sent as the server-side filter key and re-applied
    client-side. Not confirmed to actually narrow results server-side - the lab has no
    L2TPConnection objects to test against - but the request shape matches every other
    entity in this project and a filtered empty-result call answered cleanly (a bare
    self-closing '<L2TPConnection/>', no error).

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    Get-SfosL2TPConnection

.EXAMPLE
    Get-SfosL2TPConnection -NameLike 'Branch'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: an unfiltered empty result answers
    '<L2TPConnection><Configuration><Status>No. of records Zero.</Status></Configuration></
    L2TPConnection>' (nested one level deeper than most entities in this project); a filtered
    empty result instead answers a bare self-closing '<L2TPConnection/>' with no <Status> at
    all. This cmdlet does not depend on either shape - it counts nodes carrying a <Name>
    child, matching the rest of the project's empty-result handling.

    No live L2TPConnection object could be created in this lab to confirm the field mapping
    below against real data (see New-SfosL2TPConnection's .NOTES for why) - it is implemented
    per the documented Add/Edit sample and Attribute table. PresharedKey is included in the
    mapping for completeness but whether Get actually returns it was not observed; treat its
    presence or absence here as unconfirmed either way.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConnection/operations/AddL2TPConnection%26EditL2TPConnection.html

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
    Creates a new L2TPConnection object on the Sophos Firewall.

.DESCRIPTION
    Creates an L2TPConnection using the Sophos Firewall XML API. Supports ShouldProcess; use
    -WhatIf to preview.

.PARAMETER Name
    Name of the L2TP connection [doc]. Mandatory. Must start with a letter and contain only
    letters, digits and underscores thereafter, max 50 characters [doc, measured] - a hyphen
    is rejected live with a field-specific 501, so this parameter's pattern disallows it too.

.PARAMETER Description
    Free-text description [doc]. Optional, max 255 characters.

.PARAMETER Policy
    VPN policy to use [doc]. Optional. One of the predefined profile names, for example
    'DefaultL2TP'.

.PARAMETER ActionOnVPNRestart
    Behaviour when the VPN service restarts [doc]. 'Disable' or 'RespondOnly'. Mandatory.

.PARAMETER AuthenticationType
    'PresharedKey' or 'DigitalCertificate' [doc]. Mandatory - discriminates which of
    -PresharedKey / -LocalCertificate is required, validated in the function body per the
    project's parameter-set/pipeline rule.

.PARAMETER PresharedKey
    The shared secret [doc]. Mandatory when -AuthenticationType is 'PresharedKey'. Supply as a SecureString (Read-Host -AsSecureString or ConvertTo-SecureString).

.PARAMETER LocalCertificate
    Name of the local certificate to present [doc]. Mandatory when -AuthenticationType is
    'DigitalCertificate'.

.PARAMETER LocalWANPort
    Raw local WAN interface name, for example 'Port2' [sample]. Optional.

.PARAMETER AliasLocalWANPort
    Local WAN port (or WAN link alias) to bind the connection to [doc]. Mandatory - measured
    live to be required unconditionally regardless of whether -LocalWANPort is also supplied.
    See .NOTES for what was and was not confirmed to be accepted here.

.PARAMETER LocalIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)' [doc]. Optional.

.PARAMETER LocalID
    Local ID value matching -LocalIDType [doc]. Mandatory.

.PARAMETER RemoteHost
    IP address or hostname of the remote peer, or '*' for any [doc]. Mandatory.

.PARAMETER AllowNATTraversal
    'Enable' or 'Disable' [doc]. Default 'Enable', per the documented default.

.PARAMETER RemoteLANNetwork
    One or more names of existing IPHost objects (HostType Network) describing the remote
    LAN(s) reachable through this connection [doc, measured]. Mandatory - measured live to
    reject a name that does not correspond to an existing IPHost object.

.PARAMETER RemoteIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)' [doc]. Optional.

.PARAMETER RemoteID
    Remote ID value matching -RemoteIDType [doc]. Mandatory.

.PARAMETER LocalPort
    Local UDP port, 1-65535 or '*' [doc]. Mandatory.

.PARAMETER RemotePort
    Remote UDP port, 1-65535 or '*' [doc]. Mandatory.

.PARAMETER DisconnectOnIdleInterval
    Idle disconnect timer in seconds, 120-999 [doc]. Optional; when omitted, the element is
    left out of the request entirely rather than sent as the documented default of 0 - see the
    Notes section below for why.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    New-SfosL2TPConnection -Name 'BranchL2TP' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey -PresharedKey 'Secret123' -AliasLocalWANPort 'Port2' -LocalID '203.0.113.1' -RemoteHost '203.0.113.10' -RemoteLANNetwork 'RemoteNet' -RemoteID '203.0.113.10' -LocalPort 1701 -RemotePort '*'

.NOTES
    Minimum supported PowerShell version: 5.1
    NOT confirmed to succeed end-to-end live - implemented documentation-faithful. Field-level
    findings:
      - -Name rejects a hyphen (501, field-specific).
      - -RemoteLANNetwork requires the name of an existing HostType-Network IPHost; a name
        with no matching object is rejected (501, field-specific).
      - -AliasLocalWANPort rejects a LAN-zone interface and the system pseudo-host '#Port1'
        with a field-specific 501 in every combination tried, with or without -LocalWANPort
        also present. A WAN-zone interface passes this field's own validation, but the
        request then fails with an opaque, field-less code 545 ('Operation failed...'),
        whether -RemoteHost is a specific address or '*', with and without -LocalWANPort. A
        full create could therefore not be completed.
      - Because no object was ever successfully created, whether Get-SfosL2TPConnection
        returns -PresharedKey (or -LocalCertificate) was never observed - see
        Set-SfosL2TPConnection's .NOTES for how that uncertainty is handled there.
      - -DisconnectOnIdleInterval: the documented default (0) is itself outside the documented
        valid range (120-999) and is rejected when sent explicitly; omitting the element
        entirely is accepted. This is a doc self-contradiction, not a defect in this cmdlet.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConnection/operations/AddL2TPConnection%26EditL2TPConnection.html

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
    Updates an existing L2TPConnection object on the Sophos Firewall.

.DESCRIPTION
    Updates an L2TPConnection using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update), EXCEPT for
    -PresharedKey/-LocalCertificate - see .NOTES for why those two are never read back from
    the current object. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER Name
    Name of the target connection. Mandatory; accepts pipeline input by property name.

.PARAMETER Description
    Free-text description. If omitted, the existing value is kept.

.PARAMETER Policy
    VPN policy to use. If omitted, the existing value is kept.

.PARAMETER ActionOnVPNRestart
    'Disable' or 'RespondOnly'. If omitted, the existing value is kept.

.PARAMETER AuthenticationType
    'PresharedKey' or 'DigitalCertificate'. If omitted, the existing value is kept - this is
    the discriminator for which of -PresharedKey/-LocalCertificate is required; see .NOTES.

.PARAMETER PresharedKey
    The shared secret. Mandatory whenever the resolved -AuthenticationType is 'PresharedKey' - Supply as a SecureString (Read-Host -AsSecureString or ConvertTo-SecureString).
    never read back from the current object, even if -AuthenticationType itself was not
    passed and comes from the current object. See .NOTES.

.PARAMETER LocalCertificate
    Name of the local certificate to present. Mandatory whenever the resolved
    -AuthenticationType is 'DigitalCertificate' - same treatment as -PresharedKey.

.PARAMETER LocalWANPort
    Raw local WAN interface name. If omitted, the existing value is kept.

.PARAMETER AliasLocalWANPort
    Local WAN port (or WAN link alias). If omitted, the existing value is kept.

.PARAMETER LocalIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)'. If omitted, the existing value is
    kept.

.PARAMETER LocalID
    Local ID value. If omitted, the existing value is kept.

.PARAMETER RemoteHost
    IP address, hostname or '*' of the remote peer. If omitted, the existing value is kept.

.PARAMETER AllowNATTraversal
    'Enable' or 'Disable'. If omitted, the existing value is kept.

.PARAMETER RemoteLANNetwork
    Complete replacement list of remote LAN IPHost object names. If omitted, the existing
    list is kept.

.PARAMETER RemoteIDType
    'DNS', 'IP Address', 'Email' or 'DER ASN1 DN (X.509)'. If omitted, the existing value is
    kept.

.PARAMETER RemoteID
    Remote ID value. If omitted, the existing value is kept.

.PARAMETER LocalPort
    Local UDP port, 1-65535 or '*'. If omitted, the existing value is kept.

.PARAMETER RemotePort
    Remote UDP port, 1-65535 or '*'. If omitted, the existing value is kept.

.PARAMETER DisconnectOnIdleInterval
    Idle disconnect timer in seconds, 120-999. If omitted, the existing value is kept when
    present; otherwise the element is left out - see New-SfosL2TPConnection's .NOTES on why 0
    is never sent.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosL2TPConnection -Name 'BranchL2TP' -AuthenticationType PresharedKey -PresharedKey 'NewSecret123'

.NOTES
    Minimum supported PowerShell version: 5.1
    NOT verified live - no L2TPConnection object could be created in this lab to update (see
    New-SfosL2TPConnection's .NOTES). Implemented per the documented Add/Edit contract and
    this project's read-modify-write rule, with one deliberate deviation: -PresharedKey and
    -LocalCertificate are NEVER read back from Get-SfosL2TPConnection's current output, even
    though every other field is. Whether Get actually returns either of these two fields was
    never observed live (no object ever existed to test), and per this project's rule that "a
    field that cannot be confirmed preserved must not be silently kept", this cmdlet instead
    demands the caller supply it explicitly on every call where the resolved
    -AuthenticationType needs it - the same requirement New-SfosL2TPConnection has. This
    avoids the alternative failure mode: silently reading an empty value back from Get and
    overwriting a real key with blank.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConnection/operations/AddL2TPConnection%26EditL2TPConnection.html

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
        # Same measured flat path as create - see the comment there.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Configuration' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an L2TPConnection object from the Sophos Firewall.

.DESCRIPTION
    Removes an L2TPConnection using the Sophos Firewall XML API. Reads the object first and
    throws a clear "not found" error if it does not exist, rather than passing through the
    firewall's own answer for that case [measured: Remove on a nonexistent L2TPConnection
    answers code 200 "Configuration applied successfully" - a false positive, not merely a
    misleading failure code as seen elsewhere in this project]. Supports ShouldProcess; use
    -WhatIf to preview.

.PARAMETER Name
    Name of the connection to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosL2TPConnection -Name 'BranchL2TP'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: '<Remove><L2TPConnection><Configuration><Name>.../Configuration></
    L2TPConnection></Remove>' against a name that was never created answered code 200
    "Configuration applied successfully" - a genuine false positive, not merely a misleading
    failure code as documented for Remove-Sfos* elsewhere in this project's known
    deviations. This is exactly why this cmdlet checks existence first via
    Get-SfosL2TPConnection rather than trusting the wire's own answer, and this check-first
    behaviour was confirmed to correctly throw "was not found" for that same name. A second
    request shape without the <Configuration> wrapper - '<L2TPConnection><Name>...</Name></
    L2TPConnection>' - was also tried and produced a completely empty response body (no
    <Status> of any kind); that shape is silently ignored, not merely rejected, so this
    cmdlet uses the wrapped shape exclusively. The actual deletion of a real object was not
    verified, since none could be created - see New-SfosL2TPConnection's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/L2TPConnection/operations/Delete%20L2TP%20Connection.html

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
    Retrieves the PPTP configuration singleton from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the PPTPConfiguration object (VPN > PPTP). This
    is a singleton - there is exactly one on the firewall, with no name to filter by. Use
    -AsXml to return the raw XML node.

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
    Returns the raw XML node instead of a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    Get-SfosPPTPConfiguration

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: the wire wraps the settings in <PPTPSettings>, not <Configuration> as
    shown in the ConfigurePPTP operation page's sample XML - see the fragment header,
    finding 2. Field-omission behaviour when unconfigured mirrors
    Get-SfosL2TPConfiguration - see that cmdlet's .NOTES.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/PPTPConfiguration/operations/ConfigurePPTP.html

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
    Updates the PPTP configuration singleton on the Sophos Firewall.

.DESCRIPTION
    Updates the PPTPConfiguration object using the Sophos Firewall XML API. Reads the current
    object first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write - SFOS replaces the whole entity on update). Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER PPTPGeneralSettings
    'Enable' or 'Disable' [doc]. If omitted, the existing value is kept.

.PARAMETER StartIP
    Start of the IP range leased to PPTP clients [doc]. If omitted, the existing value is
    kept. SFOS requires this together with -EndIP and -PrimaryDNSServer on every update -
    see .NOTES.

.PARAMETER EndIP
    End of the IP range leased to PPTP clients [doc]. If omitted, the existing value is kept.

.PARAMETER LeaseIPFromRadiusServer
    'Enable' or 'Disable' - lease the client IP through RADIUS instead of the local range
    [doc]. If omitted, the existing value is kept.

.PARAMETER PrimaryDNSServer
    Primary DNS server handed to PPTP clients [doc]. If omitted, the existing value is kept.

.PARAMETER SecondaryDNSServer
    Secondary DNS server handed to PPTP clients [doc]. Optional; if omitted, the existing
    value is kept.

.PARAMETER PrimaryWINSServer
    Primary WINS server handed to PPTP clients [doc]. Optional; if omitted, the existing
    value is kept.

.PARAMETER SecondaryWINSServer
    Secondary WINS server handed to PPTP clients [doc]. Optional; if omitted, the existing
    value is kept.

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
    None. Throws an exception if the update fails.

.EXAMPLE
    Set-SfosPPTPConfiguration -StartIP '203.0.113.30' -EndIP '203.0.113.40' -PrimaryDNSServer '203.0.113.1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Not write-tested against a live full toggle-and-revert, for the same reason and with the
    same measured evidence as Set-SfosL2TPConfiguration - see that cmdlet's .NOTES. The equivalent
    validation response for this entity named
    /PPTPConfiguration/PPTPSettings/AssignIPFrom/StartIP,
    /PPTPConfiguration/PPTPSettings/AssignIPFrom/EndIP and
    /PPTPConfiguration/PPTPSettings/PrimaryDNSServer when the lab's own unchanged baseline
    (PPTPGeneralSettings=Disable, LeaseIPFromRadiusServer=Disable) was echoed back, confirming
    both the -ObjectName 'PPTPSettings' status path and the same unconditional-mandatory
    behaviour. The Members sub-object has no such constraint and WAS tested end-to-end with a
    full revert - see Add-/Remove-SfosPPTPConfigurationMember.
    ConfirmImpact is High: the original empty state is unrecoverable through the
    API once any value has been written (measured); automation must pass -Confirm:$false.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/PPTPConfiguration/operations/ConfigurePPTP.html

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

    # Measured (see .NOTES): SFOS requires these three unconditionally on every update, even
    # one that changes nothing else.
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
    Adds a local user to the PPTPConfiguration object's PPTPMembers list using the Sophos
    Firewall XML API. This is independent of the PPTPSettings sub-object - it does not
    require an IP range to be configured and does not touch one. Supports ShouldProcess; use
    -WhatIf to preview.

.PARAMETER MemberName
    Name of an existing local user to grant PPTP access to [doc]. Mandatory; accepts pipeline
    input by property name. See Add-SfosL2TPConfigurationMember's .PARAMETER MemberName for
    why this is not named -UserName.

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
    None. Throws an exception if the operation fails.

.EXAMPLE
    Add-SfosPPTPConfigurationMember -MemberName 'VPNUser1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live end-to-end: added an existing local account, confirmed it appeared in
    Get-SfosPPTPConfiguration's MemberList (code 201 "Operation partially successful" -
    treated as success per the published status table), then removed it again with
    Remove-SfosPPTPConfigurationMember and confirmed the object matched the original baseline
    exactly - PPTPGeneralSettings stayed 'Disable' throughout, so the PPTP service itself was
    never enabled.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/PPTPConfiguration/operations/ConfigurePPTP.html

.LINK
    Get-SfosPPTPConfiguration
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
    Removes a local user from the PPTPConfiguration object's PPTPMembers list using the
    Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

.PARAMETER MemberName
    Name of the local user to remove from the PPTP member list [doc]. Mandatory; accepts
    pipeline input by property name. See Add-SfosL2TPConfigurationMember's .PARAMETER
    MemberName for why this is not named -UserName.

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
    None. Throws an exception if the operation fails.

.EXAMPLE
    Remove-SfosPPTPConfigurationMember -MemberName 'VPNUser1'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the response root for this operation is
    <PPTPConfiguration><PPTPMembers>, one level deeper than Add's <PPTPMembers> - hence
    -ObjectName 'PPTPConfiguration/PPTPMembers' here versus 'PPTPMembers' in
    Add-SfosPPTPConfigurationMember. See Add-SfosPPTPConfigurationMember's .NOTES for the
    full round-trip this cmdlet was verified as part of.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/CONFIGURE/VPN/PPTPConfiguration/operations/ConfigurePPTP.html

.LINK
    Get-SfosPPTPConfiguration
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

