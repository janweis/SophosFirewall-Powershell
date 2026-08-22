#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.4.0' }
<#
        .SYNOPSIS
        Manages network configuration on Sophos Firewall: interfaces, VLANs, zones, gateways,
        DNS, DHCP, ARP and tunnels.

        .DESCRIPTION
        Functions for the CONFIGURE > Network area of the Sophos XGS / SFOS 22.0 XML API.

        The module creates, reads, updates and deletes:
        - Interfaces, VLANs, link aggregation groups, bridge pairs and interface aliases
        - Zones, including the ApplianceAccess service groups
        - Gateways
        - DNS host entries, DNS request routes and dynamic DNS
        - DHCP servers (IPv4 and IPv6), DHCP relays and the DHCP server status switch
        - Static ARP entries and router advertisements
        - IP tunnels, GRE tunnels and GRE routes, TAP interfaces, RED devices,
          WiFi 6 interfaces and the cellular WAN

        Several of these are singletons: the DNS resolver settings, the ARP configuration, the
        gateway configuration and the cellular WAN have no name and no create or delete
        operation, only a read and an update.

        Total Functions: 117 (100 exported, 17 internal helpers) - see README.md for the full
        cmdlet table.

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        These cmdlets change the network configuration of a live appliance. A wrong address,
        zone or gateway can make the firewall unreachable over the network, with the API then
        equally unreachable to undo it. Use -WhatIf before a write, and read the help of the
        individual cmdlet for its specific risks first.

        .EXAMPLE
        # Connect and list the interfaces with their addresses. The IPv4 address, assignment
        # and netmask live under the nested .IPv4Configuration object, not on the top level.
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosInterface | Format-Table Name, NetworkZone,
            @{n='Assignment';e={$_.IPv4Configuration.Assignment}},
            @{n='IPAddress'; e={$_.IPv4Configuration.IPAddress}},
            @{n='Netmask';   e={$_.IPv4Configuration.Netmask}}

        .EXAMPLE
        # Add a VLAN on a physical port
        New-SfosVLAN -Name "DMZ-VLAN" -Interface "Port1" -VLANID 100 -Zone "DMZ" -IPv4Assignment Static -IPAddress "10.10.10.1" -Netmask "255.255.255.0"

        .EXAMPLE
        # Read a zone and its appliance access settings
        (Get-SfosZone -NameLike "DMZ").ApplianceAccess

        .EXAMPLE
        # Add a static DNS host entry. Address properties live on the address builder, because
        # one entry can carry several addresses with their own type, family and TTL.
        $address = New-SfosDNSHostEntryAddress -EntryType Manual -IPFamily IPv4 -IPAddress "10.0.0.10" -TTL 3600
        New-SfosDNSHostEntry -HostName "server.example.com" -Address $address

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Connect-SfosFirewall

        .LINK
        Get-SfosInterface

        .LINK
        Get-SfosZone
#>

# Helper functions are provided by SophosFirewall.Core module
# Module dependency is handled via RequiredModules in .psd1

#region Interface

# --- Interface ---
#
# Physical interfaces cannot be created or removed through this API - no add/remove
# operation is documented for Interface, only Get and a single Update. There is
# deliberately no New-SfosInterface or Remove-SfosInterface.
#
# <IPv4Configuration> and <IPv6Configuration> are not container elements. On the wire they
# are flat sibling scalars, exactly like every other field - <IPv4Configuration>Enable
# </IPv4Configuration> is the Enable/Disable flag itself, and <IPv4Assignment>, <IPAddress>,
# <Netmask>, <GatewayName>, <GatewayIP> are separate sibling elements next to it, not
# children of it. The New-SfosInterfaceIPv4Configuration / New-SfosInterfaceIPv6Configuration
# / New-SfosInterfaceMSSConfiguration builders below group these fields into one PowerShell
# object purely for ergonomics and for the InputObject-merge pattern needed for the
# read-modify-write below; ConvertTo-SfosInterfaceXml flattens that object back into sibling
# XML elements to match the wire format.
#
# Update replaces the whole entity. This is the single most dangerous property of this
# entity, because the fields it can silently clear are the ones that keep the session
# connected. Set-SfosInterface therefore always reads the current interface first
# (Get-SfosInterface -HardwareLike, exact-matched) and, for every field the caller did not
# explicitly pass, resends the value read from the firewall - IPv4Configuration,
# IPv6Configuration and MSS included as complete objects, never partially. A caller who does
# pass -IPv4Configuration/-IPv6Configuration/-MSS is expected to pass a complete object,
# typically produced by piping the existing one through the matching builder with
# -InputObject so only the field actually being changed is touched.
#
# <Status> here is a read-only connectivity/link string ("Connected, 10000 Mbps - Full
# Duplex, FEC off"), explicitly marked read-only in the vendor sample XML ("this tag is only
# read purpose"). It is returned by Get-SfosInterface but never sent by Set-SfosInterface.
# <InterfaceStatus> (ON/OFF) is the separate, writable admin up/down field. Core's status
# parsing does not confuse either with an API status, because neither carries a code
# attribute and both sit under a node that has a <Name>.
#
# The PPPoE reconnect schedule (<Schedule><DayOfWeek>/<Hour>/<Minute></Schedule>) is not
# implemented, the same posture SophosFirewall.Firewall takes with UserPolicy/
# HTTPBasedPolicy: declining to guess at a nested structure that has not been checked
# against a live response rather than shipping an unchecked subtree. The scalar PPPoE
# fields (Username, Password, ServiceName, ServiceName2, PreferredIP, LocalIP,
# LCPEchoInterval, LCPFailure, SchedulTimeForReconnect, DSLSetting) are modeled on
# IPv4Configuration, so a PPPoE-configured interface's values still round-trip through
# Get -> Set unchanged when the caller does not touch IPv4Configuration - they are simply
# not exposed as first-class New-/Set-SfosInterface scenarios.

<#
.SYNOPSIS
    Builds an IPv4Configuration object for use with Set-SfosInterface.

.DESCRIPTION
    Groups the IPv4 fields of an interface into one object, for use with the -IPv4Configuration
    parameter of Set-SfosInterface. This cmdlet makes no API call; it only builds an in-memory
    object.

    Pass the interface's current IPv4Configuration through -InputObject to keep every field you
    do not explicitly override. Without -InputObject, every field takes the parameter default.

.PARAMETER InputObject
    Optional. Existing IPv4Configuration object to use as a base, for example
    (Get-SfosInterface -HardwareLike 'Port1').IPv4Configuration. Accepts pipeline input. Fields
    you also pass as a parameter override the value from this object; every other field is
    copied unchanged.

.PARAMETER Configuration
    Optional. Whether IPv4 is enabled on this interface: 'Enable' or 'Disable'. Default:
    'Enable'.

.PARAMETER Assignment
    Optional. IPv4 address assignment method: 'Static', 'PPPoE' or 'DHCP'. Default: 'Static'.

.PARAMETER IPAddress
    Optional. Static IPv4 address. Only meaningful when Assignment is 'Static'.

.PARAMETER Netmask
    Optional. Static IPv4 subnet mask, dotted decimal. Only meaningful when Assignment is
    'Static'.

.PARAMETER GatewayName
    Optional. Name of the gateway object routed through this interface.

.PARAMETER GatewayIP
    Optional. Gateway IPv4 address.

.PARAMETER Username
    Optional. PPPoE username.

.PARAMETER Password
    Optional. PPPoE password, sent as plain text like every other field of this object.

.PARAMETER ServiceName
    Optional. PPPoE service name.

.PARAMETER ServiceName2
    Optional. PPPoE secondary or alternate service name.

.PARAMETER PreferredIP
    Optional. Preferred static ISP-assigned IP address for PPPoE.

.PARAMETER LocalIP
    Optional. Local IP endpoint for PPPoE.

.PARAMETER LCPEchoInterval
    Optional. LCP echo interval: 'Disable' or a number of seconds.

.PARAMETER LCPFailure
    Optional. LCP failure threshold: 'Disable' or a number of attempts.

.PARAMETER SchedulTimeForReconnect
    Optional. Whether PPPoE reconnects on a schedule: 'Enable' or 'Disable'. The schedule
    itself (day, hour, minute) is not part of this object.

.PARAMETER DSLSetting
    Optional. DSL modem setting: '0' (Disable), '1' (Enable VDSL) or '2' (Enable ADSL).

.PARAMETER VLANTag
    Optional. VLAN tag for the PPPoE session, where the provider requires one. If omitted, no
    tag is sent.

.INPUTS
    System.Management.Automation.PSCustomObject. An IPv4Configuration object, for example the
    IPv4Configuration property of a Get-SfosInterface result, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties Configuration,
    Assignment, IPAddress, Netmask, GatewayName, GatewayIP, Username, Password, ServiceName,
    ServiceName2, PreferredIP, LocalIP, LCPEchoInterval, LCPFailure, SchedulTimeForReconnect,
    DSLSetting and VLANTag.

.EXAMPLE
    (Get-SfosInterface -HardwareLike 'Port2').IPv4Configuration | New-SfosInterfaceIPv4Configuration -GatewayName 'NewGW'

    Takes the current IPv4 configuration of Port2 and changes only the gateway name; every
    other field keeps its current value.

.EXAMPLE
    New-SfosInterfaceIPv4Configuration -Assignment Static -IPAddress '10.0.0.1' -Netmask '255.255.255.0'

    Builds a new static IPv4 configuration object from scratch, for a new interface setup.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Interface/operations/Interface.html

.LINK
    Set-SfosInterface
#>
function New-SfosInterfaceIPv4Configuration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password')]
    # PSAvoidUsingUsernameAndPasswordParams is suppressed on purpose: -Username/-Password here
    # are the PPPoE credential fields the Interface entity's own XML schema defines, not this
    # module's API authentication (that pair is Firewall/Port/Username/Password further down
    # and is typed SecureString for Password). Renaming these two to avoid the analyzer would
    # break the 1:1 mapping to the wire element names.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Enable', 'Disable')]
        [string]$Configuration = 'Enable',

        [ValidateSet('Static', 'PPPoE', 'DHCP')]
        [string]$Assignment = 'Static',

        [string]$IPAddress = '',
        [string]$Netmask = '',
        [string]$GatewayName = '',
        [string]$GatewayIP = '',
        [string]$Username = '',
        [string]$Password = '',
        [string]$ServiceName = '',
        [string]$ServiceName2 = '',
        [string]$PreferredIP = '',
        [string]$LocalIP = '',
        [string]$LCPEchoInterval = '',
        [string]$LCPFailure = '',
        [string]$SchedulTimeForReconnect = '',
        [string]$DSLSetting = '',
        [string]$VLANTag = ''
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject

        function Resolve-Field {
            param($Name, $Value)
            if ($bp.ContainsKey($Name)) { return $Value }
            if ($hasBase) { return [string]$InputObject.$Name }
            return $Value
        }

        return [PSCustomObject]@{
            Configuration           = Resolve-Field 'Configuration' $Configuration
            Assignment              = Resolve-Field 'Assignment' $Assignment
            IPAddress                = Resolve-Field 'IPAddress' $IPAddress
            Netmask                  = Resolve-Field 'Netmask' $Netmask
            GatewayName              = Resolve-Field 'GatewayName' $GatewayName
            GatewayIP                = Resolve-Field 'GatewayIP' $GatewayIP
            Username                 = Resolve-Field 'Username' $Username
            Password                 = Resolve-Field 'Password' $Password
            ServiceName              = Resolve-Field 'ServiceName' $ServiceName
            ServiceName2             = Resolve-Field 'ServiceName2' $ServiceName2
            PreferredIP              = Resolve-Field 'PreferredIP' $PreferredIP
            LocalIP                  = Resolve-Field 'LocalIP' $LocalIP
            LCPEchoInterval          = Resolve-Field 'LCPEchoInterval' $LCPEchoInterval
            LCPFailure               = Resolve-Field 'LCPFailure' $LCPFailure
            SchedulTimeForReconnect  = Resolve-Field 'SchedulTimeForReconnect' $SchedulTimeForReconnect
            DSLSetting               = Resolve-Field 'DSLSetting' $DSLSetting
            VLANTag                  = Resolve-Field 'VLANTag' $VLANTag
        }
    }
}

<#
.SYNOPSIS
    Builds an IPv6Configuration object for use with Set-SfosInterface.

.DESCRIPTION
    Groups the IPv6 fields of an interface into one object, for use with the -IPv6Configuration
    parameter of Set-SfosInterface. This cmdlet makes no API call; it only builds an in-memory
    object.

    Pass the interface's current IPv6Configuration through -InputObject to keep every field you
    do not explicitly override. Without -InputObject, every field takes the parameter default.

.PARAMETER InputObject
    Optional. Existing IPv6Configuration object to use as a base, for example
    (Get-SfosInterface -HardwareLike 'Port1').IPv6Configuration. Accepts pipeline input. Fields
    you also pass as a parameter override the value from this object; every other field is
    copied unchanged.

.PARAMETER Configuration
    Optional. Whether IPv6 is enabled on this interface: 'Enable' or 'Disable'. Default:
    'Disable'.

.PARAMETER Assignment
    Optional. IPv6 address assignment method: 'Static', 'DHCP' or 'Delegated'. Default:
    'Static'.

.PARAMETER IPv6Address
    Optional. Static IPv6 address.

.PARAMETER Prefix
    Optional. IPv6 prefix length, 1-128.

.PARAMETER GatewayNameIpv6
    Optional. Name of the IPv6 gateway object.

.PARAMETER GatewayIPv6
    Optional. IPv6 gateway address.

.PARAMETER Mode
    Optional. DHCPv6 mode: 'Auto' or 'Manual'.

.PARAMETER DhcpOnly
    Optional. Whether only DHCPv6, without SLAAC, is used: 'Enable' or 'Disable'.

.PARAMETER AcceptOtherConfigfromDHCP
    Optional. Whether additional configuration, such as DNS, is accepted from DHCPv6: 'Enable'
    or 'Disable'.

.PARAMETER PrefixDelegation
    Optional. Enables IPv6 prefix delegation: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER PrefixPreference
    Optional. Enables a preferred prefix: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER PreferredPrefixAddress
    Optional. Preferred delegated prefix address.

.PARAMETER PreferredPrefixLength
    Optional. Preferred delegated prefix length, 48-64.

.PARAMETER UpstreamInterface
    Optional. Source interface for a delegated prefix.

.PARAMETER EnableRA
    Optional. Enables Router Advertisement on this interface: 'Enable' or 'Disable'.

.PARAMETER EnableDHCPv6Server
    Optional. Enables the DHCPv6 server on this interface: 'Enable' or 'Disable'.

.INPUTS
    System.Management.Automation.PSCustomObject. An IPv6Configuration object, for example the
    IPv6Configuration property of a Get-SfosInterface result, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties Configuration,
    Assignment, IPv6Address, Prefix, GatewayNameIpv6, GatewayIPv6, Mode, DhcpOnly,
    AcceptOtherConfigfromDHCP, PrefixDelegation, PrefixPreference, PreferredPrefixAddress,
    PreferredPrefixLength, UpstreamInterface, EnableRA and EnableDHCPv6Server.

.EXAMPLE
    New-SfosInterfaceIPv6Configuration -Configuration Enable -Assignment Static -IPv6Address '2001:db8::1' -Prefix 64

    Builds a static IPv6 configuration object, for a new interface setup.

.EXAMPLE
    (Get-SfosInterface -HardwareLike 'Port1').IPv6Configuration | New-SfosInterfaceIPv6Configuration -EnableRA Enable

    Takes the current IPv6 configuration of Port1 and enables Router Advertisement; every other
    field keeps its current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Interface/operations/Interface.html

.LINK
    Set-SfosInterface
#>
function New-SfosInterfaceIPv6Configuration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Enable', 'Disable')]
        [string]$Configuration = 'Disable',

        [ValidateSet('Static', 'DHCP', 'Delegated')]
        [string]$Assignment = 'Static',

        [string]$IPv6Address = '',
        [string]$Prefix = '',
        [string]$GatewayNameIpv6 = '',
        [string]$GatewayIPv6 = '',
        [string]$Mode = '',
        [string]$DhcpOnly = '',
        [string]$AcceptOtherConfigfromDHCP = '',
        [ValidateSet('Enable', 'Disable', '')]
        [string]$PrefixDelegation = 'Disable',
        [ValidateSet('Enable', 'Disable', '')]
        [string]$PrefixPreference = 'Disable',
        [string]$PreferredPrefixAddress = '',
        [string]$PreferredPrefixLength = '',
        [string]$UpstreamInterface = '',
        [string]$EnableRA = '',
        [string]$EnableDHCPv6Server = ''
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject

        function Resolve-Field {
            param($Name, $Value)
            if ($bp.ContainsKey($Name)) { return $Value }
            if ($hasBase) { return [string]$InputObject.$Name }
            return $Value
        }

        return [PSCustomObject]@{
            Configuration              = Resolve-Field 'Configuration' $Configuration
            Assignment                 = Resolve-Field 'Assignment' $Assignment
            IPv6Address                = Resolve-Field 'IPv6Address' $IPv6Address
            Prefix                     = Resolve-Field 'Prefix' $Prefix
            GatewayNameIpv6            = Resolve-Field 'GatewayNameIpv6' $GatewayNameIpv6
            GatewayIPv6                = Resolve-Field 'GatewayIPv6' $GatewayIPv6
            Mode                       = Resolve-Field 'Mode' $Mode
            DhcpOnly                   = Resolve-Field 'DhcpOnly' $DhcpOnly
            AcceptOtherConfigfromDHCP  = Resolve-Field 'AcceptOtherConfigfromDHCP' $AcceptOtherConfigfromDHCP
            PrefixDelegation           = Resolve-Field 'PrefixDelegation' $PrefixDelegation
            PrefixPreference           = Resolve-Field 'PrefixPreference' $PrefixPreference
            PreferredPrefixAddress     = Resolve-Field 'PreferredPrefixAddress' $PreferredPrefixAddress
            PreferredPrefixLength      = Resolve-Field 'PreferredPrefixLength' $PreferredPrefixLength
            UpstreamInterface          = Resolve-Field 'UpstreamInterface' $UpstreamInterface
            EnableRA                   = Resolve-Field 'EnableRA' $EnableRA
            EnableDHCPv6Server         = Resolve-Field 'EnableDHCPv6Server' $EnableDHCPv6Server
        }
    }
}

<#
.SYNOPSIS
    Builds an MSS override object for use with Set-SfosInterface.

.DESCRIPTION
    Wraps the two fields of an interface's MSS override, for use with the -MSS parameter of
    Set-SfosInterface. This cmdlet makes no API call; it only builds an in-memory object.

    Pass the interface's current MSS object through -InputObject to keep every field you do
    not explicitly override.

.PARAMETER InputObject
    Optional. Existing MSS object to use as a base, for example (Get-SfosInterface
    -HardwareLike 'Port1').MSS. Accepts pipeline input. Fields you also pass as a parameter
    override the value from this object; every other field is copied unchanged.

.PARAMETER OverrideMSS
    Optional. Whether to override the default MSS: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER MSSValue
    Optional. MSS value in bytes, 536-8960. Default: 1460.

.INPUTS
    System.Management.Automation.PSCustomObject. An MSS object, for example the MSS property
    of a Get-SfosInterface result, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties OverrideMSS
    and MSSValue.

.EXAMPLE
    New-SfosInterfaceMSSConfiguration -OverrideMSS Enable -MSSValue 1400

    Builds an MSS override object with a custom value.

.EXAMPLE
    (Get-SfosInterface -HardwareLike 'Port1').MSS | New-SfosInterfaceMSSConfiguration -OverrideMSS Disable

    Takes the current MSS object of Port1 and switches the override off.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Interface/operations/Interface.html

.LINK
    Set-SfosInterface
#>
function New-SfosInterfaceMSSConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Enable', 'Disable')]
        [string]$OverrideMSS = 'Disable',

        [ValidateRange(536, 8960)]
        [int]$MSSValue = 1460
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject

        $targetOverride = if ($bp.ContainsKey('OverrideMSS')) { $OverrideMSS } elseif ($hasBase) { [string]$InputObject.OverrideMSS } else { $OverrideMSS }
        $targetValue = if ($bp.ContainsKey('MSSValue')) { $MSSValue } elseif ($hasBase) { [string]$InputObject.MSSValue } else { $MSSValue }

        return [PSCustomObject]@{
            OverrideMSS = $targetOverride
            MSSValue    = $targetValue
        }
    }
}

<#
.SYNOPSIS
    Builds the update XML body for an Interface entity.

.DESCRIPTION
    Turns a fully resolved interface object into the XML that Set-SfosInterface sends to the
    firewall, and escapes every value. There is no create operation for this entity, only
    update: physical interfaces cannot be added or removed through the API.

.PARAMETER Interface
    Fully resolved interface object with Name, Hardware, NetworkZone, InterfaceStatus, MTU,
    AutoNegotiation, FEC, InterfaceSpeed, MACAddress, DHCPRapidCommit, BreakoutMembers,
    BreakoutSource, DADAttempts, AllowedRAServers, IPv4Configuration, IPv6Configuration and
    MSS properties.
#>
function ConvertTo-SfosInterfaceXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Interface
    )

    $e = { param($v) ConvertTo-SfosXmlEscaped -Text ([string]$v) }

    $v4 = $Interface.IPv4Configuration
    $v6 = $Interface.IPv6Configuration
    $mss = $Interface.MSS

    return @"
<Set operation="update">
  <Interface>
    <Name>$(& $e $Interface.Name)</Name>
    <Hardware>$(& $e $Interface.Hardware)</Hardware>
    <NetworkZone>$(& $e $Interface.NetworkZone)</NetworkZone>
    <IPv4Configuration>$(& $e $v4.Configuration)</IPv4Configuration>
    <IPv4Assignment>$(& $e $v4.Assignment)</IPv4Assignment>
    <IPAddress>$(& $e $v4.IPAddress)</IPAddress>
    <Netmask>$(& $e $v4.Netmask)</Netmask>
    <GatewayName>$(& $e $v4.GatewayName)</GatewayName>
    <GatewayIP>$(& $e $v4.GatewayIP)</GatewayIP>
    <Username>$(& $e $v4.Username)</Username>
    <Password>$(& $e $v4.Password)</Password>
    <ServiceName>$(& $e $v4.ServiceName)</ServiceName>
    <ServiceName2>$(& $e $v4.ServiceName2)</ServiceName2>
    <PreferredIP>$(& $e $v4.PreferredIP)</PreferredIP>
    <LocalIP>$(& $e $v4.LocalIP)</LocalIP>
    <LCPEchoInterval>$(& $e $v4.LCPEchoInterval)</LCPEchoInterval>
    <LCPFailure>$(& $e $v4.LCPFailure)</LCPFailure>
    <SchedulTimeForReconnect>$(& $e $v4.SchedulTimeForReconnect)</SchedulTimeForReconnect>
    <DSLSetting>$(& $e $v4.DSLSetting)</DSLSetting>
    <VLANTag>$(& $e $v4.VLANTag)</VLANTag>
    <IPv6Configuration>$(& $e $v6.Configuration)</IPv6Configuration>
    <IPv6Assignment>$(& $e $v6.Assignment)</IPv6Assignment>
    <IPv6Address>$(& $e $v6.IPv6Address)</IPv6Address>
    <Prefix>$(& $e $v6.Prefix)</Prefix>
    <GatewayNameIpv6>$(& $e $v6.GatewayNameIpv6)</GatewayNameIpv6>
    <GatewayIPv6>$(& $e $v6.GatewayIPv6)</GatewayIPv6>
    <Mode>$(& $e $v6.Mode)</Mode>
    <DhcpOnly>$(& $e $v6.DhcpOnly)</DhcpOnly>
    <AcceptOtherConfigfromDHCP>$(& $e $v6.AcceptOtherConfigfromDHCP)</AcceptOtherConfigfromDHCP>
    <PrefixDelegation>$(& $e $v6.PrefixDelegation)</PrefixDelegation>
    <PrefixPreference>$(& $e $v6.PrefixPreference)</PrefixPreference>
    <PreferredPrefixAddress>$(& $e $v6.PreferredPrefixAddress)</PreferredPrefixAddress>
    <PreferredPrefixLength>$(& $e $v6.PreferredPrefixLength)</PreferredPrefixLength>
    <UpstreamInterface>$(& $e $v6.UpstreamInterface)</UpstreamInterface>
    <EnableRA>$(& $e $v6.EnableRA)</EnableRA>
    <EnableDHCPv6Server>$(& $e $v6.EnableDHCPv6Server)</EnableDHCPv6Server>
    <DHCPRapidCommit>$(& $e $Interface.DHCPRapidCommit)</DHCPRapidCommit>
    <InterfaceSpeed>$(& $e $Interface.InterfaceSpeed)</InterfaceSpeed>
    <AutoNegotiation>$(& $e $Interface.AutoNegotiation)</AutoNegotiation>
    <FEC>$(& $e $Interface.FEC)</FEC>
    <BreakoutMembers>$(& $e $Interface.BreakoutMembers)</BreakoutMembers>
    <BreakoutSource>$(& $e $Interface.BreakoutSource)</BreakoutSource>
    <MTU>$(& $e $Interface.MTU)</MTU>
    <MSS>
      <OverrideMSS>$(& $e $mss.OverrideMSS)</OverrideMSS>
      <MSSValue>$(& $e $mss.MSSValue)</MSSValue>
    </MSS>
    <MACAddress>$(& $e $Interface.MACAddress)</MACAddress>
    <DADAttempts>$(& $e $Interface.DADAttempts)</DADAttempts>
    <AllowedRAServers>$(& $e $Interface.AllowedRAServers)</AllowedRAServers>
    <InterfaceStatus>$(& $e $Interface.InterfaceStatus)</InterfaceStatus>
  </Interface>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves the physical interfaces of a Sophos Firewall.

.DESCRIPTION
    Returns the physical Interface (port) objects of the firewall, including their IPv4 and
    IPv6 configuration and MSS override. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER HardwareLike
    Optional. Returns only interfaces whose hardware port name contains the given text
    anywhere. If omitted, the port name is not used to filter.

.PARAMETER NameLike
    Optional. Returns only interfaces whose descriptive name contains the given text anywhere.
    Applied on the client. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per interface, with the properties
    Name, Hardware, NetworkZone, InterfaceStatus, Status, MTU, AutoNegotiation, FEC,
    InterfaceSpeed, MACAddress, BreakoutMembers, BreakoutSource, DHCPRapidCommit, DADAttempts,
    AllowedRAServers, IPv4Configuration, IPv6Configuration and MSS. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no interface matches.

.EXAMPLE
    Get-SfosInterface | Format-Table Hardware, NetworkZone, InterfaceStatus

    Lists every physical interface with its zone and admin status.

.EXAMPLE
    Get-SfosInterface -HardwareLike 'Port1'

    Returns the interface on the port named Port1.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Interface/Interface.html

.LINK
    Set-SfosInterface
#>
function Get-SfosInterface {
    [CmdletBinding()]
    param(
        [string]$HardwareLike,
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
    if ($HardwareLike) {
        $hwLikeEsc = ConvertTo-SfosXmlEscaped -Text $HardwareLike
        $filterXml = ('<Filter><key name="Hardware" criteria="like">{0}</key></Filter>' -f $hwLikeEsc)
    }

    $inner = @"
<Get>
  <Interface>
    $filterXml
  </Interface>
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
        throw "Error retrieving Interface objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Interface' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/Interface[Hardware]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $ipv4Configuration = [PSCustomObject]@{
            Configuration           = [string]$node.IPv4Configuration
            Assignment              = [string]$node.IPv4Assignment
            IPAddress                = [string]$node.IPAddress
            Netmask                  = [string]$node.Netmask
            GatewayName              = [string]$node.GatewayName
            GatewayIP                = [string]$node.GatewayIP
            Username                 = [string]$node.Username
            Password                 = [string]$node.Password
            ServiceName              = [string]$node.ServiceName
            ServiceName2             = [string]$node.ServiceName2
            PreferredIP              = [string]$node.PreferredIP
            LocalIP                  = [string]$node.LocalIP
            LCPEchoInterval          = [string]$node.LCPEchoInterval
            LCPFailure               = [string]$node.LCPFailure
            SchedulTimeForReconnect  = [string]$node.SchedulTimeForReconnect
            DSLSetting               = [string]$node.DSLSetting
            VLANTag                  = [string]$node.VLANTag
        }

        $ipv6Configuration = [PSCustomObject]@{
            Configuration              = [string]$node.IPv6Configuration
            Assignment                 = [string]$node.IPv6Assignment
            IPv6Address                = [string]$node.IPv6Address
            Prefix                     = [string]$node.Prefix
            GatewayNameIpv6            = [string]$node.GatewayNameIpv6
            GatewayIPv6                = [string]$node.GatewayIPv6
            Mode                       = [string]$node.Mode
            DhcpOnly                   = [string]$node.DhcpOnly
            AcceptOtherConfigfromDHCP  = [string]$node.AcceptOtherConfigfromDHCP
            PrefixDelegation           = [string]$node.PrefixDelegation
            PrefixPreference           = [string]$node.PrefixPreference
            PreferredPrefixAddress     = [string]$node.PreferredPrefixAddress
            PreferredPrefixLength      = [string]$node.PreferredPrefixLength
            UpstreamInterface          = [string]$node.UpstreamInterface
            EnableRA                   = [string]$node.EnableRA
            EnableDHCPv6Server         = [string]$node.EnableDHCPv6Server
        }

        $mssConfiguration = [PSCustomObject]@{
            OverrideMSS = [string]$node.MSS.OverrideMSS
            MSSValue    = [string]$node.MSS.MSSValue
        }

        [PSCustomObject]@{
            Name              = [string]$node.Name
            Hardware          = [string]$node.Hardware
            NetworkZone       = [string]$node.NetworkZone
            InterfaceStatus   = [string]$node.InterfaceStatus
            Status            = [string]$node.Status
            MTU               = [string]$node.MTU
            AutoNegotiation   = [string]$node.AutoNegotiation
            FEC               = [string]$node.FEC
            InterfaceSpeed    = [string]$node.InterfaceSpeed
            MACAddress        = [string]$node.MACAddress
            BreakoutMembers   = [string]$node.BreakoutMembers
            BreakoutSource    = [string]$node.BreakoutSource
            DHCPRapidCommit   = [string]$node.DHCPRapidCommit
            DADAttempts       = [string]$node.DADAttempts
            AllowedRAServers  = [string]$node.AllowedRAServers
            IPv4Configuration = $ipv4Configuration
            IPv6Configuration = $ipv6Configuration
            MSS               = $mssConfiguration
        }
    }

    $objects = @($objects)
    if ($HardwareLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Hardware -like "*$HardwareLike*" })
    }
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptHw = @($objects | ForEach-Object -Process { $_.Hardware })
        return @($nodes | Where-Object -FilterScript { $keptHw -contains $_.Hardware })
    }

    return $objects
}

<#
.SYNOPSIS
    Updates a physical interface on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of a physical port: zone, admin status, MTU, link settings, IPv4 and
    IPv6 configuration, and the MSS override. Interfaces cannot be created or removed through
    the API; only an update is possible.

    The cmdlet reads the current interface first and sends every field back. Fields you do not
    pass keep their current value; IPv4Configuration, IPv6Configuration and MSS are always
    resent as complete objects, so a change to a single field such as -MTU does not drop the
    interface's IP assignment. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

    Changing the zone, IPv4 or IPv6 configuration of the interface that currently carries the
    management or API connection can make the firewall unreachable over the network. There is
    then no way to undo the change remotely; recovery needs local access to the appliance.
    Check the current configuration with Get-SfosInterface first, and use -WhatIf to preview
    the call.

.PARAMETER Hardware
    Required. Physical port name identifying the interface to update, for example 'Port1'.
    Accepts pipeline input by property name.

.PARAMETER Name
    Optional. Descriptive interface name. If omitted, the current value is kept.

.PARAMETER NetworkZone
    Optional. Zone this interface belongs to. If omitted, the current value is kept.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. If omitted, the current value is kept.

.PARAMETER MTU
    Optional. Maximum transmission unit. If omitted, the current value is kept.

.PARAMETER AutoNegotiation
    Optional. Link auto-negotiation: 'Enable' or 'Disable'. If omitted, the current value is
    kept.

.PARAMETER FEC
    Optional. Forward error correction: 'Off', 'Automatic', 'BaseR-encoding' or
    'RS-FEC-encoding'. If omitted, the current value is kept.

.PARAMETER InterfaceSpeed
    Optional. Link speed and duplex setting. If omitted, the current value is kept.

.PARAMETER MACAddress
    Optional. MAC address override, or 'Default'. If omitted, the current value is kept.

.PARAMETER DHCPRapidCommit
    Optional. DHCP rapid commit: 'Enable' or 'Disable'. If omitted, the current value is kept.

.PARAMETER DADAttempts
    Optional. Duplicate address detection attempts, 0-8. If omitted, the current value is kept.

.PARAMETER AllowedRAServers
    Optional. Allowed Router Advertisement server addresses. If omitted, the current value is
    kept.

.PARAMETER IPv4Configuration
    Optional. Complete IPv4Configuration object, typically built with
    New-SfosInterfaceIPv4Configuration -InputObject from the existing configuration so only the
    intended field changes. If omitted, the interface's current IPv4Configuration is resent
    unchanged.

.PARAMETER IPv6Configuration
    Optional. Complete IPv6Configuration object, typically built with
    New-SfosInterfaceIPv6Configuration -InputObject from the existing configuration. If
    omitted, the interface's current IPv6Configuration is resent unchanged.

.PARAMETER MSS
    Optional. Complete MSS object, typically built with New-SfosInterfaceMSSConfiguration
    -InputObject from the existing configuration. If omitted, the interface's current MSS is
    resent unchanged.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosInterface result can be piped in;
    Hardware, Name and NetworkZone bind by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosInterface -Hardware 'Port1' -MTU 9000 -WhatIf

    Shows what changing the MTU of Port1 would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosInterface -Hardware 'Port1' -MTU 9000

    Changes the MTU of Port1 to 9000. Zone, IP assignment and MSS are resent unchanged. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Interface/operations/Interface.html

.LINK
    Get-SfosInterface
#>
function Set-SfosInterface {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$NetworkZone,

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus,

        [int]$MTU,

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoNegotiation,

        [ValidateSet('Off', 'Automatic', 'BaseR-encoding', 'RS-FEC-encoding')]
        [string]$FEC,

        [string]$InterfaceSpeed,

        [string]$MACAddress,

        [ValidateSet('Enable', 'Disable')]
        [string]$DHCPRapidCommit,

        [ValidateRange(0, 8)]
        [int]$DADAttempts,

        [string]$AllowedRAServers,

        [PSCustomObject]$IPv4Configuration,
        [PSCustomObject]$IPv6Configuration,
        [PSCustomObject]$MSS,

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

        $existing = @(Get-SfosInterface -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -HardwareLike $Hardware `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Hardware -eq $Hardware })

        if ($existing.Count -eq 0) {
            throw "The Interface object '$Hardware' was not found."
        }
        $cur = $existing[0]

        $target = [PSCustomObject]@{
            Name              = if ($bp.ContainsKey('Name')) { $Name } else { $cur.Name }
            Hardware          = $Hardware
            NetworkZone       = if ($bp.ContainsKey('NetworkZone')) { $NetworkZone } else { $cur.NetworkZone }
            InterfaceStatus   = if ($bp.ContainsKey('InterfaceStatus')) { $InterfaceStatus } else { $cur.InterfaceStatus }
            MTU               = if ($bp.ContainsKey('MTU')) { $MTU } else { $cur.MTU }
            AutoNegotiation   = if ($bp.ContainsKey('AutoNegotiation')) { $AutoNegotiation } else { $cur.AutoNegotiation }
            FEC               = if ($bp.ContainsKey('FEC')) { $FEC } else { $cur.FEC }
            InterfaceSpeed    = if ($bp.ContainsKey('InterfaceSpeed')) { $InterfaceSpeed } else { $cur.InterfaceSpeed }
            MACAddress        = if ($bp.ContainsKey('MACAddress')) { $MACAddress } else { $cur.MACAddress }
            DHCPRapidCommit   = if ($bp.ContainsKey('DHCPRapidCommit')) { $DHCPRapidCommit } else { $cur.DHCPRapidCommit }
            BreakoutMembers   = $cur.BreakoutMembers
            BreakoutSource    = $cur.BreakoutSource
            DADAttempts       = if ($bp.ContainsKey('DADAttempts')) { $DADAttempts } else { $cur.DADAttempts }
            AllowedRAServers  = if ($bp.ContainsKey('AllowedRAServers')) { $AllowedRAServers } else { $cur.AllowedRAServers }
            IPv4Configuration = if ($bp.ContainsKey('IPv4Configuration')) { $IPv4Configuration } else { $cur.IPv4Configuration }
            IPv6Configuration = if ($bp.ContainsKey('IPv6Configuration')) { $IPv6Configuration } else { $cur.IPv6Configuration }
            MSS               = if ($bp.ContainsKey('MSS')) { $MSS } else { $cur.MSS }
        }

        if (-not $PSCmdlet.ShouldProcess("Interface '$Hardware' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosInterfaceXml -Interface $target

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update Interface object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Interface' -Action 'update' -Target $Hardware
    }
}

#endregion

#region VLAN

# --- VLAN ---
#
# VLANs are always sub-interfaces of a physical carrier port. Element names below come
# from the vendor operations page (operations/AddVLAN%26EditVLAN.html). Two points where
# the documented sample is wrong or misleading:
#
# 1. <Hardware> is not a client-settable field. The doc sample lists
#    <Hardware>interfacename</Hardware> and <Interface>interfacename</Interface> as if
#    both were inputs; in fact the firewall computes Hardware itself as
#    "<Interface>.<VLANID>" (Interface=Port1, VLANID=997 -> Hardware=Port1.997) and
#    returns it on Get only. New-/Set-SfosVLAN do not send it; ConvertTo-SfosVLANXml does
#    not emit it. Get-SfosVLAN still exposes it as a read-only property.
#
# 2. <IPv6Assignment> can never be sent empty, even when IPv6Configuration is 'Disable' and
#    the firewall's own Get response shows it empty. Sending Set operation="add" without
#    IPv6Assignment, or operation="update" with <IPv6Assignment></IPv6Assignment> exactly
#    as read back from Get, both answer Code 501 "Configuration parameters validation
#    failed." with <InvalidParams><Params>/VLAN/IPv6Assignment</Params></InvalidParams>.
#    New-/Set-SfosVLAN therefore always substitute 'Static' when the value to send would
#    otherwise be empty - a case the read-modify-write pattern does not by itself cover,
#    because here what Get returns is not valid to send back unchanged.
#
# A third, non-fatal point: <IPv4Configuration> defaults to 'Disable' when omitted even if
# IPv4Assignment is 'DHCP' - the two are independent flags, exactly as on Interface above.
# New-SfosVLAN defaults -IPv4Configuration to 'Enable' so a freshly created VLAN actually
# passes traffic; Set-SfosVLAN preserves whatever the firewall currently has.
#
# The PPPoE reconnect schedule is out of scope here for the same reason as Interface's - no
# nested sample exists to verify against.

<#
.SYNOPSIS
    Builds the create or update XML body for a VLAN entity.

.DESCRIPTION
    Turns a fully resolved VLAN object into the XML that New-SfosVLAN and Set-SfosVLAN send to
    the firewall, so both cmdlets send an identical, complete entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER VLAN
    Fully resolved VLAN object with Name, Interface, Zone, VLANID, IPv4Configuration,
    IPv4Assignment, IPAddress, Netmask, GatewayName, GatewayAddress, Username, Password,
    ServiceName, ServiceName2, PreferredIP, LCPEchoInterval, LCPFailure,
    SchedulTimeForReconnect, IPv6Configuration, IPv6Assignment, IPv6Address, IPv6Prefix,
    IPv6GatewayName, IPv6GatewayAddress, Mode, DhcpOnly, AcceptOtherConfigfromDHCP,
    DHCPRapidCommit, PrefixDelegation, PrefixPreference, PreferredPrefixAddress,
    PreferredPrefixLength, UpstreamInterface, EnableRA, EnableDHCPv6Server and
    InterfaceStatus properties. An optional Hardware property is included when present.
#>
function ConvertTo-SfosVLANXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$VLAN
    )

    $e = { param($v) ConvertTo-SfosXmlEscaped -Text ([string]$v) }

    # Identity for operation="update" is <Hardware>, NOT <Interface>+<VLANID>:
    # update-by-Interface+VLANID answers Code 547 "Operation failed"
    # with no field-level detail, while the identical body with <Hardware> added (computed by
    # the firewall as "<Interface>.<VLANID>" and read back via Get-SfosVLAN) succeeds. For
    # operation="add" there is no existing object yet, so Hardware is omitted - VLAN objects
    # without a Hardware property (as New-SfosVLAN builds) produce no <Hardware> element at all.
    $hardwareXml = ''
    if ($VLAN.PSObject.Properties.Match('Hardware').Count -gt 0 -and $VLAN.Hardware) {
        $hardwareXml = "<Hardware>$(& $e $VLAN.Hardware)</Hardware>"
    }

    return @"
<Set operation="$Operation">
  <VLAN>
    <Name>$(& $e $VLAN.Name)</Name>
    $hardwareXml
    <Interface>$(& $e $VLAN.Interface)</Interface>
    <Zone>$(& $e $VLAN.Zone)</Zone>
    <VLANID>$(& $e $VLAN.VLANID)</VLANID>
    <IPv4Configuration>$(& $e $VLAN.IPv4Configuration)</IPv4Configuration>
    <IPv4Assignment>$(& $e $VLAN.IPv4Assignment)</IPv4Assignment>
    <IPAddress>$(& $e $VLAN.IPAddress)</IPAddress>
    <Netmask>$(& $e $VLAN.Netmask)</Netmask>
    <GatewayName>$(& $e $VLAN.GatewayName)</GatewayName>
    <GatewayAddress>$(& $e $VLAN.GatewayAddress)</GatewayAddress>
    <Username>$(& $e $VLAN.Username)</Username>
    <Password>$(& $e $VLAN.Password)</Password>
    <ServiceName>$(& $e $VLAN.ServiceName)</ServiceName>
    <ServiceName2>$(& $e $VLAN.ServiceName2)</ServiceName2>
    <PreferredIP>$(& $e $VLAN.PreferredIP)</PreferredIP>
    <LCPEchoInterval>$(& $e $VLAN.LCPEchoInterval)</LCPEchoInterval>
    <LCPFailure>$(& $e $VLAN.LCPFailure)</LCPFailure>
    <SchedulTimeForReconnect>$(& $e $VLAN.SchedulTimeForReconnect)</SchedulTimeForReconnect>
    <IPv6Configuration>$(& $e $VLAN.IPv6Configuration)</IPv6Configuration>
    <IPv6Assignment>$(& $e $VLAN.IPv6Assignment)</IPv6Assignment>
    <IPv6Address>$(& $e $VLAN.IPv6Address)</IPv6Address>
    <IPv6Prefix>$(& $e $VLAN.IPv6Prefix)</IPv6Prefix>
    <IPv6GatewayName>$(& $e $VLAN.IPv6GatewayName)</IPv6GatewayName>
    <IPv6GatewayAddress>$(& $e $VLAN.IPv6GatewayAddress)</IPv6GatewayAddress>
    <Mode>$(& $e $VLAN.Mode)</Mode>
    <DhcpOnly>$(& $e $VLAN.DhcpOnly)</DhcpOnly>
    <AcceptOtherConfigfromDHCP>$(& $e $VLAN.AcceptOtherConfigfromDHCP)</AcceptOtherConfigfromDHCP>
    <DHCPRapidCommit>$(& $e $VLAN.DHCPRapidCommit)</DHCPRapidCommit>
    <PrefixDelegation>$(& $e $VLAN.PrefixDelegation)</PrefixDelegation>
    <PrefixPreference>$(& $e $VLAN.PrefixPreference)</PrefixPreference>
    <PreferredPrefixAddress>$(& $e $VLAN.PreferredPrefixAddress)</PreferredPrefixAddress>
    <PreferredPrefixLength>$(& $e $VLAN.PreferredPrefixLength)</PreferredPrefixLength>
    <UpstreamInterface>$(& $e $VLAN.UpstreamInterface)</UpstreamInterface>
    <EnableRA>$(& $e $VLAN.EnableRA)</EnableRA>
    <EnableDHCPv6Server>$(& $e $VLAN.EnableDHCPv6Server)</EnableDHCPv6Server>
    <InterfaceStatus>$(& $e $VLAN.InterfaceStatus)</InterfaceStatus>
  </VLAN>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves VLAN sub-interfaces from a Sophos Firewall.

.DESCRIPTION
    Returns the VLAN sub-interface objects that are defined on the firewall. The cmdlet only
    reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only VLANs whose name contains the given text anywhere. If omitted, the
    name is not used to filter.

.PARAMETER InterfaceLike
    Optional. Returns only VLANs whose carrier interface contains the given text anywhere.
    Applied on the client. If omitted, the interface is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per VLAN, with the properties Name,
    Hardware, Interface, Zone, VLANID, IPv4Assignment, IPAddress, Netmask, GatewayName,
    GatewayAddress, IPv6Configuration, IPv6Assignment, IPv6Address, IPv6Prefix,
    IPv6GatewayName, IPv6GatewayAddress, DHCPRapidCommit, InterfaceStatus and Status, plus the
    PPPoE and DHCPv6 fields listed on Set-SfosVLAN. Returns System.Xml.XmlElement when -AsXml
    is used, and an empty array when no VLAN matches.

.EXAMPLE
    Get-SfosVLAN -NameLike 'DMZ-VLAN'

    Returns the VLAN whose name contains 'DMZ-VLAN'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/VLAN/VLAN.html

.LINK
    New-SfosVLAN

.LINK
    Set-SfosVLAN
#>
function Get-SfosVLAN {
    [CmdletBinding()]
    param(
        [string]$NameLike,
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
  <VLAN>
    $filterXml
  </VLAN>
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
        throw "Error retrieving VLAN objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VLAN' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/VLAN[VLANID]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name                       = [string]$node.Name
            Hardware                   = [string]$node.Hardware
            Interface                  = [string]$node.Interface
            Zone                       = [string]$node.Zone
            VLANID                     = [string]$node.VLANID
            IPv4Configuration          = [string]$node.IPv4Configuration
            IPv4Assignment             = [string]$node.IPv4Assignment
            IPAddress                   = [string]$node.IPAddress
            Netmask                     = [string]$node.Netmask
            GatewayName                 = [string]$node.GatewayName
            GatewayAddress              = [string]$node.GatewayAddress
            Username                    = [string]$node.Username
            Password                    = [string]$node.Password
            ServiceName                 = [string]$node.ServiceName
            ServiceName2                = [string]$node.ServiceName2
            PreferredIP                 = [string]$node.PreferredIP
            LCPEchoInterval             = [string]$node.LCPEchoInterval
            LCPFailure                  = [string]$node.LCPFailure
            SchedulTimeForReconnect     = [string]$node.SchedulTimeForReconnect
            IPv6Configuration           = [string]$node.IPv6Configuration
            IPv6Assignment              = [string]$node.IPv6Assignment
            IPv6Address                 = [string]$node.IPv6Address
            IPv6Prefix                  = [string]$node.IPv6Prefix
            IPv6GatewayName             = [string]$node.IPv6GatewayName
            IPv6GatewayAddress          = [string]$node.IPv6GatewayAddress
            Mode                        = [string]$node.Mode
            DhcpOnly                    = [string]$node.DhcpOnly
            AcceptOtherConfigfromDHCP   = [string]$node.AcceptOtherConfigfromDHCP
            DHCPRapidCommit             = [string]$node.DHCPRapidCommit
            PrefixDelegation            = [string]$node.PrefixDelegation
            PrefixPreference            = [string]$node.PrefixPreference
            PreferredPrefixAddress      = [string]$node.PreferredPrefixAddress
            PreferredPrefixLength       = [string]$node.PreferredPrefixLength
            UpstreamInterface           = [string]$node.UpstreamInterface
            EnableRA                    = [string]$node.EnableRA
            EnableDHCPv6Server          = [string]$node.EnableDHCPv6Server
            InterfaceStatus             = [string]$node.InterfaceStatus
            Status                      = [string]$node.Status
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($InterfaceLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Interface -like "*$InterfaceLike*" })
    }

    if ($AsXml) {
        $keptIds = @($objects | ForEach-Object -Process { $_.VLANID })
        return @($nodes | Where-Object -FilterScript { $keptIds -contains $_.VLANID })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a VLAN sub-interface on a Sophos Firewall.

.DESCRIPTION
    Adds a VLAN sub-interface on a physical carrier port. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

    The firewall computes the interface's hardware name itself from the carrier port and the
    VLAN ID, for example 'Port1.100'; there is no parameter for it. Read it back with
    Get-SfosVLAN once the VLAN exists.

.PARAMETER Name
    Optional. Descriptive name for the VLAN.

.PARAMETER Interface
    Required. Physical carrier port the VLAN runs on, for example 'Port1'.

.PARAMETER Zone
    Required. Zone assigned to the VLAN sub-interface.

.PARAMETER VLANID
    Required. VLAN tag, 1-4094.

.PARAMETER IPv4Configuration
    Optional. Whether IPv4 is enabled on this VLAN: 'Enable' or 'Disable'. Default: 'Enable'.

.PARAMETER IPv4Assignment
    Optional. IPv4 assignment method: 'Static', 'PPPoE' or 'DHCP'. Default: 'Static'.

.PARAMETER IPAddress
    Optional. Static IPv4 address. Only meaningful when IPv4Assignment is 'Static'.

.PARAMETER Netmask
    Optional. Static IPv4 subnet mask. Only meaningful when IPv4Assignment is 'Static'.

.PARAMETER GatewayName
    Optional. Name of the gateway object routed through this VLAN.

.PARAMETER GatewayAddress
    Optional. Gateway IPv4 address.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. Default: 'ON'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosVLAN -Interface 'Port1' -Zone 'LAN' -VLANID 100 -IPv4Assignment Static -IPAddress '10.100.0.1' -Netmask '255.255.255.0' -WhatIf

    Shows what creating the VLAN would send, without sending it to the firewall.

.EXAMPLE
    New-SfosVLAN -Interface 'Port1' -Zone 'LAN' -VLANID 100 -IPv4Assignment Static -IPAddress '10.100.0.1' -Netmask '255.255.255.0'

    Creates a VLAN with tag 100 on Port1, in the LAN zone, with a static IPv4 address. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/VLAN/operations/AddVLAN%26EditVLAN.html

.LINK
    Get-SfosVLAN

.LINK
    Set-SfosVLAN
#>
function New-SfosVLAN {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Interface,

        [Parameter(Mandatory)]
        [string]$Zone,

        [Parameter(Mandatory)]
        [ValidateRange(1, 4094)]
        [int]$VLANID,

        [ValidateSet('Enable', 'Disable')]
        [string]$IPv4Configuration = 'Enable',

        [ValidateSet('Static', 'PPPoE', 'DHCP')]
        [string]$IPv4Assignment = 'Static',

        [string]$IPAddress = '',
        [string]$Netmask = '',
        [string]$GatewayName = '',
        [string]$GatewayAddress = '',

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus = 'ON',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("VLAN $VLANID on interface '$Interface' on $($params.Firewall)", 'Create')) {
        return
    }

    $vlanObject = [PSCustomObject]@{
        Name = $Name; Interface = $Interface; Zone = $Zone; VLANID = $VLANID
        IPv4Configuration = $IPv4Configuration
        IPv4Assignment = $IPv4Assignment; IPAddress = $IPAddress; Netmask = $Netmask
        GatewayName = $GatewayName; GatewayAddress = $GatewayAddress
        Username = ''; Password = ''; ServiceName = ''; ServiceName2 = ''; PreferredIP = ''
        LCPEchoInterval = ''; LCPFailure = ''; SchedulTimeForReconnect = ''
        # IPv6Assignment must never be sent empty even though IPv6Configuration is 'Disable' -
        # see the region header comment for the live 501/InvalidParams finding. 'Static' is an
        # inert placeholder here: it has no effect while IPv6Configuration stays 'Disable'.
        IPv6Configuration = 'Disable'; IPv6Assignment = 'Static'; IPv6Address = ''; IPv6Prefix = ''
        IPv6GatewayName = ''; IPv6GatewayAddress = ''; Mode = ''; DhcpOnly = ''
        AcceptOtherConfigfromDHCP = ''; DHCPRapidCommit = ''; PrefixDelegation = ''
        PrefixPreference = ''; PreferredPrefixAddress = ''; PreferredPrefixLength = ''
        UpstreamInterface = ''; EnableRA = ''; EnableDHCPv6Server = ''
        InterfaceStatus = $InterfaceStatus
    }

    $inner = ConvertTo-SfosVLANXml -Operation 'add' -VLAN $vlanObject

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create VLAN object '$VLANID' on '$Interface': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VLAN' -Action 'create' -Target "$Interface.$VLANID"
}

<#
.SYNOPSIS
    Updates a VLAN sub-interface on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing VLAN sub-interface. The cmdlet reads the current VLAN
    first and sends every field back; fields you do not pass keep their current value. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER Interface
    Required. Physical carrier port identifying the VLAN together with -VLANID, for example
    'Port1'. Accepts pipeline input by property name.

.PARAMETER VLANID
    Required. VLAN tag identifying the VLAN together with -Interface. Accepts pipeline input
    by property name.

.PARAMETER Name
    Optional. Descriptive VLAN name. If omitted, the current value is kept.

.PARAMETER Zone
    Optional. Zone assigned to the VLAN sub-interface. If omitted, the current value is kept.

.PARAMETER IPv4Configuration
    Optional. Whether IPv4 is enabled on this VLAN: 'Enable' or 'Disable'. If omitted, the
    current value is kept.

.PARAMETER IPv4Assignment
    Optional. IPv4 assignment method: 'Static', 'PPPoE' or 'DHCP'. If omitted, the current
    value is kept.

.PARAMETER IPAddress
    Optional. Static IPv4 address. If omitted, the current value is kept.

.PARAMETER Netmask
    Optional. Static IPv4 subnet mask. If omitted, the current value is kept.

.PARAMETER GatewayName
    Optional. Name of the gateway object routed through this VLAN. If omitted, the current
    value is kept.

.PARAMETER GatewayAddress
    Optional. Gateway IPv4 address. If omitted, the current value is kept.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosVLAN result can be piped in;
    Interface and VLANID bind by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosVLAN -Interface 'Port1' -VLANID 100 -Zone 'DMZ' -WhatIf

    Shows what moving the VLAN to the DMZ zone would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosVLAN -Interface 'Port1' -VLANID 100 -Zone 'DMZ'

    Moves the VLAN with tag 100 on Port1 to the DMZ zone. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/VLAN/operations/AddVLAN%26EditVLAN.html

.LINK
    Get-SfosVLAN

.LINK
    New-SfosVLAN
#>
function Set-SfosVLAN {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Interface,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [int]$VLANID,

        [string]$Name,
        [string]$Zone,

        [ValidateSet('Enable', 'Disable')]
        [string]$IPv4Configuration,

        [ValidateSet('Static', 'PPPoE', 'DHCP')]
        [string]$IPv4Assignment,

        [string]$IPAddress,
        [string]$Netmask,
        [string]$GatewayName,
        [string]$GatewayAddress,

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus,

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

        $existing = @(Get-SfosVLAN -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InterfaceLike $Interface `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Interface -eq $Interface -and [int]$_.VLANID -eq $VLANID })

        if ($existing.Count -eq 0) {
            throw "The VLAN object '$Interface.$VLANID' was not found."
        }
        $cur = $existing[0]

        # IPv6Assignment can never be sent empty (region header comment, live 501/InvalidParams
        # finding) - substitute the same inert 'Static' placeholder New-SfosVLAN uses whenever
        # the value read back from the firewall is blank, which is exactly what happens while
        # IPv6Configuration is 'Disable'.
        $ipv6AssignmentToSend = if ($cur.IPv6Assignment) { $cur.IPv6Assignment } else { 'Static' }

        $target = [PSCustomObject]@{
            Name = if ($bp.ContainsKey('Name')) { $Name } else { $cur.Name }
            # Identity for the update call - see the region header comment and
            # ConvertTo-SfosVLANXml: update-by-Interface+VLANID alone fails live with Code 547.
            Hardware = $cur.Hardware
            Interface = $Interface
            Zone = if ($bp.ContainsKey('Zone')) { $Zone } else { $cur.Zone }
            VLANID = $VLANID
            IPv4Configuration = if ($bp.ContainsKey('IPv4Configuration')) { $IPv4Configuration } else { $cur.IPv4Configuration }
            IPv4Assignment = if ($bp.ContainsKey('IPv4Assignment')) { $IPv4Assignment } else { $cur.IPv4Assignment }
            IPAddress = if ($bp.ContainsKey('IPAddress')) { $IPAddress } else { $cur.IPAddress }
            Netmask = if ($bp.ContainsKey('Netmask')) { $Netmask } else { $cur.Netmask }
            GatewayName = if ($bp.ContainsKey('GatewayName')) { $GatewayName } else { $cur.GatewayName }
            GatewayAddress = if ($bp.ContainsKey('GatewayAddress')) { $GatewayAddress } else { $cur.GatewayAddress }
            Username = $cur.Username; Password = $cur.Password; ServiceName = $cur.ServiceName
            ServiceName2 = $cur.ServiceName2; PreferredIP = $cur.PreferredIP
            LCPEchoInterval = $cur.LCPEchoInterval; LCPFailure = $cur.LCPFailure
            SchedulTimeForReconnect = $cur.SchedulTimeForReconnect
            IPv6Configuration = $cur.IPv6Configuration; IPv6Assignment = $ipv6AssignmentToSend
            IPv6Address = $cur.IPv6Address; IPv6Prefix = $cur.IPv6Prefix
            IPv6GatewayName = $cur.IPv6GatewayName; IPv6GatewayAddress = $cur.IPv6GatewayAddress
            Mode = $cur.Mode; DhcpOnly = $cur.DhcpOnly
            AcceptOtherConfigfromDHCP = $cur.AcceptOtherConfigfromDHCP; DHCPRapidCommit = $cur.DHCPRapidCommit
            PrefixDelegation = $cur.PrefixDelegation; PrefixPreference = $cur.PrefixPreference
            PreferredPrefixAddress = $cur.PreferredPrefixAddress; PreferredPrefixLength = $cur.PreferredPrefixLength
            UpstreamInterface = $cur.UpstreamInterface; EnableRA = $cur.EnableRA
            EnableDHCPv6Server = $cur.EnableDHCPv6Server
            InterfaceStatus = if ($bp.ContainsKey('InterfaceStatus')) { $InterfaceStatus } else { $cur.InterfaceStatus }
        }

        if (-not $PSCmdlet.ShouldProcess("VLAN '$Interface.$VLANID' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosVLANXml -Operation 'update' -VLAN $target

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update VLAN object '$Interface.$VLANID': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VLAN' -Action 'update' -Target "$Interface.$VLANID"
    }
}

<#
.SYNOPSIS
    Removes a VLAN sub-interface from a Sophos Firewall.

.DESCRIPTION
    Deletes a VLAN sub-interface. The firewall only accepts the computed hardware value
    (interface and VLAN ID combined, for example 'Port1.100') as the deletion key; addressing
    a VLAN by name, or by interface and VLAN ID as separate fields, answers success without
    deleting anything. This cmdlet resolves the hardware value through Get-SfosVLAN first,
    then re-reads the object after the removal and throws if it is still present, rather than
    trusting the response alone. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER Interface
    Required. Physical carrier port of the VLAN to remove, for example 'Port1'. Accepts
    pipeline input by value and by property name.

.PARAMETER VLANID
    Required. VLAN tag of the VLAN to remove. Accepts pipeline input by property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosVLAN result can be piped in;
    Interface binds by value or by property name, VLANID by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if removal fails, including when the
    firewall reports success but the object is still present.

.EXAMPLE
    Get-SfosVLAN -NameLike 'DMZ-VLAN' | Remove-SfosVLAN -WhatIf

    Shows what removing the matching VLAN would send, without sending it to the firewall.

.EXAMPLE
    Get-SfosVLAN -NameLike 'DMZ-VLAN' | Remove-SfosVLAN

    Removes the VLAN whose name contains 'DMZ-VLAN'. The cmdlet asks for confirmation before
    it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/VLAN/operations/AddVLAN%26EditVLAN.html

.LINK
    Get-SfosVLAN
#>
function Remove-SfosVLAN {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Interface,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [int]$VLANID,

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
        $target = "$Interface.$VLANID"

        $existing = @(Get-SfosVLAN -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InterfaceLike $Interface `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Interface -eq $Interface -and [int]$_.VLANID -eq $VLANID })

        if ($existing.Count -eq 0) {
            throw "The VLAN object '$target' was not found."
        }
        $hardware = $existing[0].Hardware

        if (-not $PSCmdlet.ShouldProcess("VLAN '$target' (Hardware '$hardware') on $($params.Firewall)", 'Remove')) {
            return
        }

        $hardwareEsc = ConvertTo-SfosXmlEscaped -Text $hardware

        $inner = @"
<Remove>
  <VLAN>
    <Hardware>$hardwareEsc</Hardware>
  </VLAN>
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
            throw "Failed to remove VLAN object '$target': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'VLAN' -Action 'remove' -Target $target

        # The status alone is not trustworthy for this entity - see the .DESCRIPTION. Confirm
        # the object is actually gone before returning success to the caller.
        $stillThere = @(Get-SfosVLAN -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InterfaceLike $Interface `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Interface -eq $Interface -and [int]$_.VLANID -eq $VLANID })

        if ($stillThere.Count -gt 0) {
            throw "Sophos API reported success removing VLAN object '$target', but the object is still present on the firewall."
        }
    }
}

#endregion

#region LAG

# --- LAG ---
#
# Creating a LAG absorbs a member port and dissolves its existing IP configuration -
# recovery means rebuilding the interface, not reverting a value.
#
# Element names follow the vendor documentation page (operations/AddLAG%26EditLAG.html).
# The documented sample lists <IPAssignment> twice - once at the top level and once inside
# an "IPv4Configuration" comment block with an inconsistent value set (Static/DHCP at top,
# Static/PPPoe/DHCP in the second). The attribute table is unambiguous and single-valued
# (Static/DHCP only, Mandatory: Yes), so this module sends exactly one <IPAssignment>
# element with that constraint - PPPoE is not offered for LAG.
#
# <Hardware> here is a client-supplied field (unlike VLAN, where the firewall computes it) -
# the attribute table marks "Hardware/LagInterface" Mandatory: Yes, max 10 characters, and
# the documented sample uses it as the top identity element, so Set-/Remove-SfosLAG identify
# by -Hardware directly, no separate lookup needed.

<#
.SYNOPSIS
    Builds an MSS override object for use with New-SfosLAG and Set-SfosLAG.

.DESCRIPTION
    Wraps the two fields of a LAG's MSS override, for use with the -MSS parameter of
    New-SfosLAG and Set-SfosLAG. This cmdlet makes no API call; it only builds an in-memory
    object.

    Pass the LAG's current MSS object through -InputObject to keep every field you do not
    explicitly override.

.PARAMETER InputObject
    Optional. Existing MSS object to use as a base. Accepts pipeline input. Fields you also
    pass as a parameter override the value from this object; every other field is copied
    unchanged.

.PARAMETER OverrideMSS
    Optional. Whether to override the default MSS: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER MSSValue
    Optional. MSS value in bytes, 536-8960. Default: 1460.

.INPUTS
    System.Management.Automation.PSCustomObject. An MSS object can be piped in as
    -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties OverrideMSS
    and MSSValue.

.EXAMPLE
    New-SfosLAGMSSConfiguration -OverrideMSS Enable -MSSValue 1400

    Builds an MSS override object with a custom value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/LAG/operations/AddLAG%26EditLAG.html

.LINK
    New-SfosLAG

.LINK
    Set-SfosLAG
#>
function New-SfosLAGMSSConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Enable', 'Disable')]
        [string]$OverrideMSS = 'Disable',

        [ValidateRange(536, 8960)]
        [int]$MSSValue = 1460
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject
        $targetOverride = if ($bp.ContainsKey('OverrideMSS')) { $OverrideMSS } elseif ($hasBase) { [string]$InputObject.OverrideMSS } else { $OverrideMSS }
        $targetValue = if ($bp.ContainsKey('MSSValue')) { $MSSValue } elseif ($hasBase) { [string]$InputObject.MSSValue } else { $MSSValue }

        return [PSCustomObject]@{
            OverrideMSS = $targetOverride
            MSSValue    = $targetValue
        }
    }
}

<#
.SYNOPSIS
    Builds the create or update XML body for a LAG entity.

.DESCRIPTION
    Turns a fully resolved LAG object into the XML that New-SfosLAG and Set-SfosLAG send to the
    firewall, so both cmdlets send an identical, complete entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER LAG
    Fully resolved LAG object with Name, Hardware, MemberInterface, Mode, NetworkZone,
    IPAssignment, IPv4Configuration, IPv4Address, Netmask, GatewayName, GatewayIP,
    IPv6Configuration, IPv6Address, Prefix, GatewayNameIpv6, GatewayIPv6, InterfaceSpeed,
    AutoNegotiation, FEC, MTU, MSS, XmitHashPolicy, PrimaryInterface, MACAddress and
    InterfaceStatus properties.
#>
function ConvertTo-SfosLAGXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$LAG
    )

    $e = { param($v) ConvertTo-SfosXmlEscaped -Text ([string]$v) }
    $mss = $LAG.MSS

    $memberXml = ''
    foreach ($member in @($LAG.MemberInterface)) {
        if (-not $member) { continue }
        $memberXml += "<Interface>$(& $e $member)</Interface>"
    }

    return @"
<Set operation="$Operation">
  <LAG>
    <Name>$(& $e $LAG.Name)</Name>
    <Hardware>$(& $e $LAG.Hardware)</Hardware>
    <MemberInterface>
      $memberXml
    </MemberInterface>
    <Mode>$(& $e $LAG.Mode)</Mode>
    <NetworkZone>$(& $e $LAG.NetworkZone)</NetworkZone>
    <IPAssignment>$(& $e $LAG.IPAssignment)</IPAssignment>
    <IPv4Configuration>$(& $e $LAG.IPv4Configuration)</IPv4Configuration>
    <IPv4Address>$(& $e $LAG.IPv4Address)</IPv4Address>
    <Netmask>$(& $e $LAG.Netmask)</Netmask>
    <GatewayName>$(& $e $LAG.GatewayName)</GatewayName>
    <GatewayIP>$(& $e $LAG.GatewayIP)</GatewayIP>
    <IPv6Configuration>$(& $e $LAG.IPv6Configuration)</IPv6Configuration>
    <IPv6Address>$(& $e $LAG.IPv6Address)</IPv6Address>
    <Prefix>$(& $e $LAG.Prefix)</Prefix>
    <GatewayNameIpv6>$(& $e $LAG.GatewayNameIpv6)</GatewayNameIpv6>
    <GatewayIPv6>$(& $e $LAG.GatewayIPv6)</GatewayIPv6>
    <InterfaceSpeed>$(& $e $LAG.InterfaceSpeed)</InterfaceSpeed>
    <AutoNegotiation>$(& $e $LAG.AutoNegotiation)</AutoNegotiation>
    <FEC>$(& $e $LAG.FEC)</FEC>
    <MTU>$(& $e $LAG.MTU)</MTU>
    <MSS>
      <OverrideMSS>$(& $e $mss.OverrideMSS)</OverrideMSS>
      <MSSValue>$(& $e $mss.MSSValue)</MSSValue>
    </MSS>
    <XmitHashPolicy>$(& $e $LAG.XmitHashPolicy)</XmitHashPolicy>
    <PrimaryInterface>$(& $e $LAG.PrimaryInterface)</PrimaryInterface>
    <MACAddress>$(& $e $LAG.MACAddress)</MACAddress>
    <InterfaceStatus>$(& $e $LAG.InterfaceStatus)</InterfaceStatus>
  </LAG>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves link aggregation groups from a Sophos Firewall.

.DESCRIPTION
    Returns the LAG (Link Aggregation Group) objects that are defined on the firewall. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only LAGs whose name contains the given text anywhere. If omitted, the
    name is not used to filter.

.PARAMETER HardwareLike
    Optional. Returns only LAGs whose hardware interface name contains the given text
    anywhere. Applied on the client. If omitted, the hardware name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per LAG, with the properties Name,
    Hardware, MemberInterface, Mode, NetworkZone, IPAssignment, IPv4Configuration,
    IPv4Address, Netmask, GatewayName, GatewayIP, IPv6Configuration, IPv6Address, Prefix,
    GatewayNameIpv6, GatewayIPv6, InterfaceSpeed, AutoNegotiation, FEC, MTU, MSS,
    XmitHashPolicy, PrimaryInterface, MACAddress and InterfaceStatus. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no LAG matches.

.EXAMPLE
    Get-SfosLAG

    Lists every link aggregation group on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/LAG/LAG.html

.LINK
    New-SfosLAG

.LINK
    Set-SfosLAG
#>
function Get-SfosLAG {
    [CmdletBinding()]
    param(
        [string]$NameLike,
        [string]$HardwareLike,

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
  <LAG>
    $filterXml
  </LAG>
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
        throw "Error retrieving LAG objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LAG' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/LAG[Hardware]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $members = [string[]]@($node.MemberInterface | Select-Object -ExpandProperty Interface -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })

        [PSCustomObject]@{
            Name              = [string]$node.Name
            Hardware          = [string]$node.Hardware
            MemberInterface   = $members
            Mode              = [string]$node.Mode
            NetworkZone       = [string]$node.NetworkZone
            IPAssignment      = [string]$node.IPAssignment
            IPv4Configuration = [string]$node.IPv4Configuration
            IPv4Address       = [string]$node.IPv4Address
            Netmask           = [string]$node.Netmask
            GatewayName       = [string]$node.GatewayName
            GatewayIP         = [string]$node.GatewayIP
            IPv6Configuration = [string]$node.IPv6Configuration
            IPv6Address       = [string]$node.IPv6Address
            Prefix            = [string]$node.Prefix
            GatewayNameIpv6   = [string]$node.GatewayNameIpv6
            GatewayIPv6       = [string]$node.GatewayIPv6
            InterfaceSpeed    = [string]$node.InterfaceSpeed
            AutoNegotiation   = [string]$node.AutoNegotiation
            FEC               = [string]$node.FEC
            MTU               = [string]$node.MTU
            MSS               = [PSCustomObject]@{
                OverrideMSS = [string]$node.MSS.OverrideMSS
                MSSValue    = [string]$node.MSS.MSSValue
            }
            XmitHashPolicy    = [string]$node.XmitHashPolicy
            PrimaryInterface  = [string]$node.PrimaryInterface
            MACAddress        = [string]$node.MACAddress
            InterfaceStatus   = [string]$node.InterfaceStatus
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($HardwareLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Hardware -like "*$HardwareLike*" })
    }

    if ($AsXml) {
        $keptHw = @($objects | ForEach-Object -Process { $_.Hardware })
        return @($nodes | Where-Object -FilterScript { $keptHw -contains $_.Hardware })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a link aggregation group on a Sophos Firewall.

.DESCRIPTION
    Adds a LAG (Link Aggregation Group) that bundles several physical ports into one logical
    interface. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with administrative permission.

    A physical port loses its own IP configuration as soon as it becomes a member of a LAG. If
    the port is currently carrying production traffic, including the management or API
    connection, that traffic is interrupted, and the port's previous configuration has to be
    rebuilt by hand afterward; it is not restored automatically when the port is removed from
    the LAG.

.PARAMETER Hardware
    Required. Name for the LAG interface, up to 10 characters.

.PARAMETER Name
    Optional. Descriptive name for the LAG.

.PARAMETER MemberInterface
    Required. Physical port names that become members of this LAG. At least one.

.PARAMETER Mode
    Required. LAG mode: 'ActiveBackup' or '802.3ad(LACP)'.

.PARAMETER NetworkZone
    Required. Zone assigned to the LAG.

.PARAMETER IPAssignment
    Optional. IP assignment method: 'Static' or 'DHCP'. Default: 'Static'.

.PARAMETER IPv4Configuration
    Optional. Whether IPv4 is enabled: 'Enable' or 'Disable'. Default: 'Enable'.

.PARAMETER IPv4Address
    Optional. Static IPv4 address. Only meaningful when IPAssignment is 'Static'.

.PARAMETER Netmask
    Optional. Static IPv4 subnet mask. Only meaningful when IPAssignment is 'Static'.

.PARAMETER GatewayName
    Optional. Name of the gateway object routed through this LAG.

.PARAMETER GatewayIP
    Optional. Gateway IPv4 address.

.PARAMETER XmitHashPolicy
    Optional. Load-balancing hash policy, only meaningful with -Mode '802.3ad(LACP)':
    'Layer2', 'Layer2+3' or 'Layer3+4'.

.PARAMETER MTU
    Optional. Maximum transmission unit, 576-9000. Default: 1500.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. Default: 'ON'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosLAG -Hardware 'LAG1' -MemberInterface 'Port4', 'Port5' -Mode 'ActiveBackup' -NetworkZone 'LAN' -WhatIf

    Shows what creating the LAG would send, without sending it to the firewall.

.EXAMPLE
    New-SfosLAG -Hardware 'LAG1' -MemberInterface 'Port4', 'Port5' -Mode 'ActiveBackup' -NetworkZone 'LAN'

    Creates a LAG named LAG1 from Port4 and Port5, in the LAN zone. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/LAG/operations/AddLAG%26EditLAG.html

.LINK
    Get-SfosLAG

.LINK
    Set-SfosLAG
#>
function New-SfosLAG {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 10)]
        [string]$Hardware,

        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$MemberInterface,

        [Parameter(Mandatory)]
        [ValidateSet('ActiveBackup', '802.3ad(LACP)')]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$NetworkZone,

        [ValidateSet('Static', 'DHCP')]
        [string]$IPAssignment = 'Static',

        [ValidateSet('Enable', 'Disable')]
        [string]$IPv4Configuration = 'Enable',

        [string]$IPv4Address = '',
        [string]$Netmask = '',
        [string]$GatewayName = '',
        [string]$GatewayIP = '',

        [ValidateSet('', 'Layer2', 'Layer2+3', 'Layer3+4')]
        [string]$XmitHashPolicy = '',

        [ValidateRange(576, 9000)]
        [int]$MTU = 1500,

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus = 'ON',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("LAG '$Hardware' on $($params.Firewall)", 'Create')) {
        return
    }

    $lagObject = [PSCustomObject]@{
        Name = $Name; Hardware = $Hardware; MemberInterface = $MemberInterface; Mode = $Mode
        NetworkZone = $NetworkZone; IPAssignment = $IPAssignment; IPv4Configuration = $IPv4Configuration
        IPv4Address = $IPv4Address; Netmask = $Netmask; GatewayName = $GatewayName; GatewayIP = $GatewayIP
        IPv6Configuration = 'Disable'; IPv6Address = ''; Prefix = ''; GatewayNameIpv6 = ''; GatewayIPv6 = ''
        InterfaceSpeed = ''; AutoNegotiation = 'Enable'; FEC = 'Off'; MTU = $MTU
        MSS = [PSCustomObject]@{ OverrideMSS = 'Disable'; MSSValue = 1460 }
        XmitHashPolicy = $XmitHashPolicy; PrimaryInterface = ''; MACAddress = 'Default'
        InterfaceStatus = $InterfaceStatus
    }

    $inner = ConvertTo-SfosLAGXml -Operation 'add' -LAG $lagObject

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create LAG object '$Hardware': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LAG' -Action 'create' -Target $Hardware
}

<#
.SYNOPSIS
    Updates a link aggregation group on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing LAG. The cmdlet reads the current LAG first and sends
    every field back; fields you do not pass keep their current value. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

    Adding a member port that is currently carrying production traffic, including the
    management or API connection, interrupts that traffic, because the port loses its own IP
    configuration once it joins the LAG.

.PARAMETER Hardware
    Required. Name of the LAG interface to update. Accepts pipeline input by property name.

.PARAMETER MemberInterface
    Optional. Physical port names that are members of this LAG. If omitted, the current value
    is kept.

.PARAMETER Mode
    Optional. LAG mode: 'ActiveBackup' or '802.3ad(LACP)'. If omitted, the current value is
    kept.

.PARAMETER NetworkZone
    Optional. Zone assigned to the LAG. If omitted, the current value is kept.

.PARAMETER IPv4Configuration
    Optional. Whether IPv4 is enabled: 'Enable' or 'Disable'. If omitted, the current value is
    kept.

.PARAMETER IPAssignment
    Optional. IP assignment method: 'Static' or 'DHCP'. If omitted, the current value is kept.

.PARAMETER IPv4Address
    Optional. Static IPv4 address. If omitted, the current value is kept.

.PARAMETER Netmask
    Optional. Static IPv4 subnet mask. If omitted, the current value is kept.

.PARAMETER GatewayName
    Optional. Name of the gateway object routed through this LAG. If omitted, the current
    value is kept.

.PARAMETER GatewayIP
    Optional. Gateway IPv4 address. If omitted, the current value is kept.

.PARAMETER MTU
    Optional. Maximum transmission unit. If omitted, the current value is kept.

.PARAMETER MSS
    Optional. Complete MSS object, typically built with New-SfosLAGMSSConfiguration
    -InputObject from the existing configuration. If omitted, the current MSS is resent
    unchanged.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosLAG result can be piped in;
    Hardware binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosLAG -Hardware 'LAG1' -NetworkZone 'DMZ' -WhatIf

    Shows what moving the LAG to the DMZ zone would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosLAG -Hardware 'LAG1' -NetworkZone 'DMZ'

    Moves the LAG named LAG1 to the DMZ zone. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/LAG/operations/AddLAG%26EditLAG.html

.LINK
    Get-SfosLAG

.LINK
    New-SfosLAG
#>
function Set-SfosLAG {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

        [string[]]$MemberInterface,

        [ValidateSet('ActiveBackup', '802.3ad(LACP)')]
        [string]$Mode,

        [string]$NetworkZone,

        [ValidateSet('Enable', 'Disable')]
        [string]$IPv4Configuration,

        [ValidateSet('Static', 'DHCP')]
        [string]$IPAssignment,

        [string]$IPv4Address,
        [string]$Netmask,
        [string]$GatewayName,
        [string]$GatewayIP,

        [int]$MTU,

        [PSCustomObject]$MSS,

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus,

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

        $existing = @(Get-SfosLAG -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -HardwareLike $Hardware `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Hardware -eq $Hardware })

        if ($existing.Count -eq 0) {
            throw "The LAG object '$Hardware' was not found."
        }
        $cur = $existing[0]

        $target = [PSCustomObject]@{
            Name = $cur.Name; Hardware = $Hardware
            MemberInterface = if ($bp.ContainsKey('MemberInterface')) { $MemberInterface } else { $cur.MemberInterface }
            Mode = if ($bp.ContainsKey('Mode')) { $Mode } else { $cur.Mode }
            NetworkZone = if ($bp.ContainsKey('NetworkZone')) { $NetworkZone } else { $cur.NetworkZone }
            IPAssignment = if ($bp.ContainsKey('IPAssignment')) { $IPAssignment } else { $cur.IPAssignment }
            IPv4Configuration = if ($bp.ContainsKey('IPv4Configuration')) { $IPv4Configuration } else { $cur.IPv4Configuration }
            IPv4Address = if ($bp.ContainsKey('IPv4Address')) { $IPv4Address } else { $cur.IPv4Address }
            Netmask = if ($bp.ContainsKey('Netmask')) { $Netmask } else { $cur.Netmask }
            GatewayName = if ($bp.ContainsKey('GatewayName')) { $GatewayName } else { $cur.GatewayName }
            GatewayIP = if ($bp.ContainsKey('GatewayIP')) { $GatewayIP } else { $cur.GatewayIP }
            IPv6Configuration = $cur.IPv6Configuration; IPv6Address = $cur.IPv6Address; Prefix = $cur.Prefix
            GatewayNameIpv6 = $cur.GatewayNameIpv6; GatewayIPv6 = $cur.GatewayIPv6
            InterfaceSpeed = $cur.InterfaceSpeed; AutoNegotiation = $cur.AutoNegotiation; FEC = $cur.FEC
            MTU = if ($bp.ContainsKey('MTU')) { $MTU } else { $cur.MTU }
            MSS = if ($bp.ContainsKey('MSS')) { $MSS } else { $cur.MSS }
            XmitHashPolicy = $cur.XmitHashPolicy; PrimaryInterface = $cur.PrimaryInterface
            MACAddress = $cur.MACAddress
            InterfaceStatus = if ($bp.ContainsKey('InterfaceStatus')) { $InterfaceStatus } else { $cur.InterfaceStatus }
        }

        if (-not $PSCmdlet.ShouldProcess("LAG '$Hardware' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosLAGXml -Operation 'update' -LAG $target

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update LAG object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LAG' -Action 'update' -Target $Hardware
    }
}

<#
.SYNOPSIS
    Removes a link aggregation group from a Sophos Firewall.

.DESCRIPTION
    Deletes a LAG. Its member ports become individual interfaces again but do not get their
    previous IP configuration back automatically; each one has to be reconfigured by hand
    before it carries traffic again. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Hardware
    Required. Name of the LAG interface to remove. Accepts pipeline input by property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosLAG result can be piped in;
    Hardware binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosLAG -Hardware 'LAG1' -WhatIf

    Shows what removing LAG1 would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosLAG -Hardware 'LAG1'

    Removes the LAG named LAG1. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/LAG/operations/AddLAG%26EditLAG.html

.LINK
    Get-SfosLAG
#>
function Remove-SfosLAG {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

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
        if (-not $PSCmdlet.ShouldProcess("LAG '$Hardware' on $($params.Firewall)", 'Remove')) {
            return
        }

        $hardwareEsc = ConvertTo-SfosXmlEscaped -Text $Hardware

        $inner = @"
<Remove>
  <LAG>
    <Hardware>$hardwareEsc</Hardware>
  </LAG>
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
            throw "Failed to remove LAG object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LAG' -Action 'remove' -Target $Hardware
    }
}

#endregion

#region BridgePair

# --- BridgePair ---
#
# A bridge pair needs two free interfaces to bind together.
#
# Element names follow the vendor documentation page
# (operations/AddBridge-Pair%26EditBridge-Pair.html). The MSS subtree here is spelled
# <MSS><Override>...</Override><MSSValue>...</MSSValue></MSS> - "Override", not
# "OverrideMSS" as on Interface/VLAN/LAG. This module follows the documented spelling for
# BridgePair rather than assuming the entities share a field name just because they share a
# concept. New-SfosBridgePairMSSConfiguration below is therefore a distinct function/object
# shape from New-SfosInterfaceMSSConfiguration and New-SfosLAGMSSConfiguration, not a shared
# one.

<#
.SYNOPSIS
    Builds an MSS override object for use with New-SfosBridgePair and Set-SfosBridgePair.

.DESCRIPTION
    Wraps the two fields of a bridge pair's MSS override, for use with the -MSS parameter of
    New-SfosBridgePair and Set-SfosBridgePair. This cmdlet makes no API call; it only builds an
    in-memory object.

    Pass the bridge pair's current MSS object through -InputObject to keep every field you do
    not explicitly override.

.PARAMETER InputObject
    Optional. Existing MSS object to use as a base. Accepts pipeline input. Fields you also
    pass as a parameter override the value from this object; every other field is copied
    unchanged.

.PARAMETER Override
    Optional. Whether to override the default MSS: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER MSSValue
    Optional. MSS value in bytes, 536-8960. Default: 1460.

.INPUTS
    System.Management.Automation.PSCustomObject. An MSS object can be piped in as
    -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties Override and
    MSSValue.

.EXAMPLE
    New-SfosBridgePairMSSConfiguration -Override Enable -MSSValue 1400

    Builds an MSS override object with a custom value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/BridgePair/operations/AddBridge-Pair%26EditBridge-Pair.html

.LINK
    New-SfosBridgePair

.LINK
    Set-SfosBridgePair
#>
function New-SfosBridgePairMSSConfiguration {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Enable', 'Disable')]
        [string]$Override = 'Disable',

        [ValidateRange(536, 8960)]
        [int]$MSSValue = 1460
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject
        $targetOverride = if ($bp.ContainsKey('Override')) { $Override } elseif ($hasBase) { [string]$InputObject.Override } else { $Override }
        $targetValue = if ($bp.ContainsKey('MSSValue')) { $MSSValue } elseif ($hasBase) { [string]$InputObject.MSSValue } else { $MSSValue }

        return [PSCustomObject]@{
            Override = $targetOverride
            MSSValue = $targetValue
        }
    }
}

<#
.SYNOPSIS
    Builds the create or update XML body for a BridgePair entity.

.DESCRIPTION
    Turns a fully resolved BridgePair object into the XML that New-SfosBridgePair and
    Set-SfosBridgePair send to the firewall, so both cmdlets send an identical, complete
    entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER BridgePair
    Fully resolved BridgePair object with Name, Hardware, Description, RoutingOnBridgePair,
    MemberInterface, MemberZone (parallel arrays forming the bridge member list),
    VLANFilteringOnBridge, PermittedVLAN, IPv4Configuration, IPv4Assignment, IPAddress,
    Netmask, GatewayName, GatewayIPAddress, IPv6Configuration, IPv6Assignment, IPv6Address,
    Prefix, IPv6GatewayName, IPv6GatewayIPAddress, ARPBroadcast, MTU, MSS, STP, MAXAge,
    MACAging, FilterEthernetFrames, EtherType (array), UpstreamInterface, EnableRA,
    EnableDHCPv6Server, DADAttempts, AllowedRAServers and InterfaceStatus properties.
#>
function ConvertTo-SfosBridgePairXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$BridgePair
    )

    $e = { param($v) ConvertTo-SfosXmlEscaped -Text ([string]$v) }
    $mss = $BridgePair.MSS

    $memberXml = ''
    $memberInterfaces = @($BridgePair.MemberInterface)
    $memberZones = @($BridgePair.MemberZone)
    for ($i = 0; $i -lt $memberInterfaces.Count; $i++) {
        $zoneValue = if ($i -lt $memberZones.Count) { $memberZones[$i] } else { '' }
        $memberXml += "<Member><Interface>$(& $e $memberInterfaces[$i])</Interface><Zone>$(& $e $zoneValue)</Zone></Member>"
    }

    $vlanXml = ''
    foreach ($vlan in @($BridgePair.PermittedVLAN)) {
        if (-not $vlan) { continue }
        $vlanXml += "<PermittedVLAN>$(& $e $vlan)</PermittedVLAN>"
    }

    $etherTypeXml = ''
    foreach ($et in @($BridgePair.EtherType)) {
        if (-not $et) { continue }
        $etherTypeXml += "<EtherType>$(& $e $et)</EtherType>"
    }

    return @"
<Set operation="$Operation">
  <BridgePair>
    <Name>$(& $e $BridgePair.Name)</Name>
    <Hardware>$(& $e $BridgePair.Hardware)</Hardware>
    <Description>$(& $e $BridgePair.Description)</Description>
    <RoutingOnBridgePair>$(& $e $BridgePair.RoutingOnBridgePair)</RoutingOnBridgePair>
    <BridgeMembers>
      $memberXml
    </BridgeMembers>
    <VLANFilteringOnBridge>$(& $e $BridgePair.VLANFilteringOnBridge)</VLANFilteringOnBridge>
    <PermittedVlansList>
      $vlanXml
    </PermittedVlansList>
    <IPv4Configuration>$(& $e $BridgePair.IPv4Configuration)</IPv4Configuration>
    <IPv4Assignment>$(& $e $BridgePair.IPv4Assignment)</IPv4Assignment>
    <IPAddress>$(& $e $BridgePair.IPAddress)</IPAddress>
    <Netmask>$(& $e $BridgePair.Netmask)</Netmask>
    <Gateway>
      <GatewayName>$(& $e $BridgePair.GatewayName)</GatewayName>
      <GatewayIPAddress>$(& $e $BridgePair.GatewayIPAddress)</GatewayIPAddress>
    </Gateway>
    <IPv6Configuration>$(& $e $BridgePair.IPv6Configuration)</IPv6Configuration>
    <IPv6Assignment>$(& $e $BridgePair.IPv6Assignment)</IPv6Assignment>
    <IPv6Address>$(& $e $BridgePair.IPv6Address)</IPv6Address>
    <Prefix>$(& $e $BridgePair.Prefix)</Prefix>
    <IPv6Gateway>
      <IPv6GatewayName>$(& $e $BridgePair.IPv6GatewayName)</IPv6GatewayName>
      <IPv6GatewayIPAddress>$(& $e $BridgePair.IPv6GatewayIPAddress)</IPv6GatewayIPAddress>
    </IPv6Gateway>
    <ARPBroadcast>$(& $e $BridgePair.ARPBroadcast)</ARPBroadcast>
    <MTU>$(& $e $BridgePair.MTU)</MTU>
    <MSS>
      <Override>$(& $e $mss.Override)</Override>
      <MSSValue>$(& $e $mss.MSSValue)</MSSValue>
    </MSS>
    <STP>$(& $e $BridgePair.STP)</STP>
    <MAXAge>$(& $e $BridgePair.MAXAge)</MAXAge>
    <MACAging>$(& $e $BridgePair.MACAging)</MACAging>
    <FilterEthernetFrames>$(& $e $BridgePair.FilterEthernetFrames)</FilterEthernetFrames>
    <EtherTypeList>
      $etherTypeXml
    </EtherTypeList>
    <UpstreamInterface>$(& $e $BridgePair.UpstreamInterface)</UpstreamInterface>
    <EnableRA>$(& $e $BridgePair.EnableRA)</EnableRA>
    <EnableDHCPv6Server>$(& $e $BridgePair.EnableDHCPv6Server)</EnableDHCPv6Server>
    <DADAttempts>$(& $e $BridgePair.DADAttempts)</DADAttempts>
    <AllowedRAServers>$(& $e $BridgePair.AllowedRAServers)</AllowedRAServers>
    <InterfaceStatus>$(& $e $BridgePair.InterfaceStatus)</InterfaceStatus>
  </BridgePair>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves bridge pairs from a Sophos Firewall.

.DESCRIPTION
    Returns the BridgePair objects that are defined on the firewall. The cmdlet only reads;
    nothing on the firewall is changed. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only bridge pairs whose name contains the given text anywhere. If
    omitted, the name is not used to filter.

.PARAMETER HardwareLike
    Optional. Returns only bridge pairs whose hardware interface name contains the given text
    anywhere. Applied on the client. If omitted, the hardware name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per bridge pair, with the
    properties Name, Hardware, Description, RoutingOnBridgePair, MemberInterface, MemberZone,
    VLANFilteringOnBridge, PermittedVLAN, IPv4Configuration, IPv4Assignment, IPAddress,
    Netmask, GatewayName, GatewayIPAddress, IPv6Configuration, IPv6Assignment, IPv6Address,
    Prefix, IPv6GatewayName, IPv6GatewayIPAddress, ARPBroadcast, MTU, MSS, STP, MAXAge,
    MACAging, FilterEthernetFrames, EtherType and InterfaceStatus. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no bridge pair matches.

.EXAMPLE
    Get-SfosBridgePair

    Lists every bridge pair on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/BridgePair/BridgePair.html

.LINK
    New-SfosBridgePair

.LINK
    Set-SfosBridgePair
#>
function Get-SfosBridgePair {
    [CmdletBinding()]
    param(
        [string]$NameLike,
        [string]$HardwareLike,

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
  <BridgePair>
    $filterXml
  </BridgePair>
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
        throw "Error retrieving BridgePair objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'BridgePair' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/BridgePair[Hardware]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $memberInterfaces = [string[]]@($node.BridgeMembers.Member | Select-Object -ExpandProperty Interface -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
        $memberZones = [string[]]@($node.BridgeMembers.Member | Select-Object -ExpandProperty Zone -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
        $permittedVlans = [string[]]@($node.PermittedVlansList | Select-Object -ExpandProperty PermittedVLAN -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
        $etherTypes = [string[]]@($node.EtherTypeList | Select-Object -ExpandProperty EtherType -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })

        [PSCustomObject]@{
            Name                   = [string]$node.Name
            Hardware               = [string]$node.Hardware
            Description            = [string]$node.Description
            RoutingOnBridgePair    = [string]$node.RoutingOnBridgePair
            MemberInterface        = $memberInterfaces
            MemberZone             = $memberZones
            VLANFilteringOnBridge  = [string]$node.VLANFilteringOnBridge
            PermittedVLAN          = $permittedVlans
            IPv4Configuration      = [string]$node.IPv4Configuration
            IPv4Assignment         = [string]$node.IPv4Assignment
            IPAddress               = [string]$node.IPAddress
            Netmask                 = [string]$node.Netmask
            GatewayName             = [string]$node.Gateway.GatewayName
            GatewayIPAddress        = [string]$node.Gateway.GatewayIPAddress
            IPv6Configuration       = [string]$node.IPv6Configuration
            IPv6Assignment          = [string]$node.IPv6Assignment
            IPv6Address             = [string]$node.IPv6Address
            Prefix                  = [string]$node.Prefix
            IPv6GatewayName         = [string]$node.IPv6Gateway.IPv6GatewayName
            IPv6GatewayIPAddress    = [string]$node.IPv6Gateway.IPv6GatewayIPAddress
            ARPBroadcast            = [string]$node.ARPBroadcast
            MTU                     = [string]$node.MTU
            MSS                     = [PSCustomObject]@{
                Override = [string]$node.MSS.Override
                MSSValue = [string]$node.MSS.MSSValue
            }
            STP                     = [string]$node.STP
            MAXAge                  = [string]$node.MAXAge
            MACAging                = [string]$node.MACAging
            FilterEthernetFrames    = [string]$node.FilterEthernetFrames
            EtherType               = $etherTypes
            UpstreamInterface       = [string]$node.UpstreamInterface
            EnableRA                = [string]$node.EnableRA
            EnableDHCPv6Server      = [string]$node.EnableDHCPv6Server
            DADAttempts             = [string]$node.DADAttempts
            AllowedRAServers        = [string]$node.AllowedRAServers
            InterfaceStatus         = [string]$node.InterfaceStatus
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($HardwareLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Hardware -like "*$HardwareLike*" })
    }

    if ($AsXml) {
        $keptHw = @($objects | ForEach-Object -Process { $_.Hardware })
        return @($nodes | Where-Object -FilterScript { $keptHw -contains $_.Hardware })
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a bridge pair on a Sophos Firewall.

.DESCRIPTION
    Adds a bridge pair that joins two or more physical ports at layer 2. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

    A bridge pair needs two or more free member ports. A member port loses its own IP
    configuration once it joins the bridge; if it is currently carrying production traffic,
    including the management or API connection, that traffic is interrupted, and the port's
    previous configuration has to be rebuilt by hand afterward.

.PARAMETER Hardware
    Required. Name for the bridge pair interface, up to 10 characters.

.PARAMETER Name
    Optional. Descriptive name for the bridge pair.

.PARAMETER Description
    Optional. Free-text description, up to 100 characters.

.PARAMETER MemberInterface
    Required. Physical port names that become members of this bridge, parallel to
    -MemberZone: entries at the same position form one member.

.PARAMETER MemberZone
    Required. Zone for each member interface, parallel to -MemberInterface. Must list the same
    number of entries as -MemberInterface.

.PARAMETER RoutingOnBridgePair
    Optional. Whether routing is enabled on the bridge pair: 'Enable' or 'Disable'. Default:
    'Disable'.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. Default: 'ON'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosBridgePair -Hardware 'Bridge1' -MemberInterface 'Port4', 'Port5' -MemberZone 'LAN', 'DMZ' -WhatIf

    Shows what creating the bridge pair would send, without sending it to the firewall.

.EXAMPLE
    New-SfosBridgePair -Hardware 'Bridge1' -MemberInterface 'Port4', 'Port5' -MemberZone 'LAN', 'DMZ'

    Creates a bridge pair named Bridge1 from Port4 in the LAN zone and Port5 in the DMZ zone.
    The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/BridgePair/operations/AddBridge-Pair%26EditBridge-Pair.html

.LINK
    Get-SfosBridgePair

.LINK
    Set-SfosBridgePair
#>
function New-SfosBridgePair {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 10)]
        [string]$Hardware,

        [string]$Name,
        [string]$Description = '',

        [Parameter(Mandatory)]
        [string[]]$MemberInterface,

        [Parameter(Mandatory)]
        [string[]]$MemberZone,

        [ValidateSet('Enable', 'Disable')]
        [string]$RoutingOnBridgePair = 'Disable',

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus = 'ON',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($MemberInterface.Count -ne $MemberZone.Count) {
        throw "The BridgePair object '$Hardware' cannot be created: -MemberInterface and -MemberZone must list the same number of entries (one zone per member interface)."
    }

    if (-not $PSCmdlet.ShouldProcess("BridgePair '$Hardware' on $($params.Firewall)", 'Create')) {
        return
    }

    $bridgeObject = [PSCustomObject]@{
        Name = $Name; Hardware = $Hardware; Description = $Description
        RoutingOnBridgePair = $RoutingOnBridgePair
        MemberInterface = $MemberInterface; MemberZone = $MemberZone
        VLANFilteringOnBridge = 'Disable'; PermittedVLAN = @()
        IPv4Configuration = 'Disable'; IPv4Assignment = ''; IPAddress = ''; Netmask = ''
        GatewayName = ''; GatewayIPAddress = ''
        IPv6Configuration = 'Disable'; IPv6Assignment = 'Static'; IPv6Address = ''; Prefix = ''
        IPv6GatewayName = ''; IPv6GatewayIPAddress = ''
        ARPBroadcast = ''; MTU = 1500
        MSS = [PSCustomObject]@{ Override = 'Disable'; MSSValue = 1460 }
        STP = ''; MAXAge = ''; MACAging = ''; FilterEthernetFrames = ''; EtherType = @()
        UpstreamInterface = ''; EnableRA = ''; EnableDHCPv6Server = ''
        DADAttempts = ''; AllowedRAServers = ''
        InterfaceStatus = $InterfaceStatus
    }

    $inner = ConvertTo-SfosBridgePairXml -Operation 'add' -BridgePair $bridgeObject

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create BridgePair object '$Hardware': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'BridgePair' -Action 'create' -Target $Hardware
}

<#
.SYNOPSIS
    Updates a bridge pair on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing bridge pair. The cmdlet reads the current object first
    and sends every field back; fields you do not pass keep their current value. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

    Adding a member port that is currently carrying production traffic, including the
    management or API connection, interrupts that traffic, because the port loses its own IP
    configuration once it joins the bridge.

.PARAMETER Hardware
    Required. Name of the bridge pair interface to update. Accepts pipeline input by property
    name.

.PARAMETER Description
    Optional. Free-text description. If omitted, the current value is kept.

.PARAMETER MemberInterface
    Optional. Physical port names that are members of this bridge, parallel to -MemberZone. If
    omitted, the current value is kept.

.PARAMETER MemberZone
    Optional. Zone for each member interface, parallel to -MemberInterface. If omitted, the
    current value is kept.

.PARAMETER RoutingOnBridgePair
    Optional. Whether routing is enabled: 'Enable' or 'Disable'. If omitted, the current value
    is kept.

.PARAMETER MTU
    Optional. Maximum transmission unit. If omitted, the current value is kept.

.PARAMETER MSS
    Optional. Complete MSS object, typically built with New-SfosBridgePairMSSConfiguration
    -InputObject from the existing configuration. If omitted, the current MSS is resent
    unchanged.

.PARAMETER InterfaceStatus
    Optional. Admin up/down state: 'ON' or 'OFF'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosBridgePair result can be piped in;
    Hardware binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosBridgePair -Hardware 'Bridge1' -RoutingOnBridgePair Enable -WhatIf

    Shows what enabling routing on the bridge pair would send, without sending it to the
    firewall.

.EXAMPLE
    Set-SfosBridgePair -Hardware 'Bridge1' -RoutingOnBridgePair Enable

    Enables routing on the bridge pair named Bridge1. The cmdlet asks for confirmation before
    it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/BridgePair/operations/AddBridge-Pair%26EditBridge-Pair.html

.LINK
    Get-SfosBridgePair

.LINK
    New-SfosBridgePair
#>
function Set-SfosBridgePair {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

        [string]$Description,
        [string[]]$MemberInterface,
        [string[]]$MemberZone,

        [ValidateSet('Enable', 'Disable')]
        [string]$RoutingOnBridgePair,

        [int]$MTU,

        [PSCustomObject]$MSS,

        [ValidateSet('ON', 'OFF')]
        [string]$InterfaceStatus,

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

        if ($bp.ContainsKey('MemberInterface') -and $bp.ContainsKey('MemberZone') -and $MemberInterface.Count -ne $MemberZone.Count) {
            throw "The BridgePair object '$Hardware' cannot be updated: -MemberInterface and -MemberZone must list the same number of entries."
        }

        $existing = @(Get-SfosBridgePair -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -HardwareLike $Hardware `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Hardware -eq $Hardware })

        if ($existing.Count -eq 0) {
            throw "The BridgePair object '$Hardware' was not found."
        }
        $cur = $existing[0]

        $target = [PSCustomObject]@{
            Name = $cur.Name; Hardware = $Hardware
            Description = if ($bp.ContainsKey('Description')) { $Description } else { $cur.Description }
            RoutingOnBridgePair = if ($bp.ContainsKey('RoutingOnBridgePair')) { $RoutingOnBridgePair } else { $cur.RoutingOnBridgePair }
            MemberInterface = if ($bp.ContainsKey('MemberInterface')) { $MemberInterface } else { $cur.MemberInterface }
            MemberZone = if ($bp.ContainsKey('MemberZone')) { $MemberZone } else { $cur.MemberZone }
            VLANFilteringOnBridge = $cur.VLANFilteringOnBridge; PermittedVLAN = $cur.PermittedVLAN
            IPv4Configuration = $cur.IPv4Configuration; IPv4Assignment = $cur.IPv4Assignment
            IPAddress = $cur.IPAddress; Netmask = $cur.Netmask
            GatewayName = $cur.GatewayName; GatewayIPAddress = $cur.GatewayIPAddress
            IPv6Configuration = $cur.IPv6Configuration; IPv6Assignment = $cur.IPv6Assignment
            IPv6Address = $cur.IPv6Address; Prefix = $cur.Prefix
            IPv6GatewayName = $cur.IPv6GatewayName; IPv6GatewayIPAddress = $cur.IPv6GatewayIPAddress
            ARPBroadcast = $cur.ARPBroadcast
            MTU = if ($bp.ContainsKey('MTU')) { $MTU } else { $cur.MTU }
            MSS = if ($bp.ContainsKey('MSS')) { $MSS } else { $cur.MSS }
            STP = $cur.STP; MAXAge = $cur.MAXAge; MACAging = $cur.MACAging
            FilterEthernetFrames = $cur.FilterEthernetFrames; EtherType = $cur.EtherType
            UpstreamInterface = $cur.UpstreamInterface; EnableRA = $cur.EnableRA
            EnableDHCPv6Server = $cur.EnableDHCPv6Server
            DADAttempts = $cur.DADAttempts; AllowedRAServers = $cur.AllowedRAServers
            InterfaceStatus = if ($bp.ContainsKey('InterfaceStatus')) { $InterfaceStatus } else { $cur.InterfaceStatus }
        }

        if (-not $PSCmdlet.ShouldProcess("BridgePair '$Hardware' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosBridgePairXml -Operation 'update' -BridgePair $target

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update BridgePair object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'BridgePair' -Action 'update' -Target $Hardware
    }
}

<#
.SYNOPSIS
    Removes a BridgePair from the Sophos Firewall.

.DESCRIPTION
    Deletes a bridge pair. Its member ports become individual interfaces again but do not get
    their previous IP configuration back automatically; each one has to be reconfigured by
    hand before it carries traffic again. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Hardware
    Required. Name of the bridge pair interface to remove. Accepts pipeline input by property
    name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosBridgePair result can be piped in;
    Hardware binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosBridgePair -Hardware 'Bridge1' -WhatIf

    Shows what removing Bridge1 would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosBridgePair -Hardware 'Bridge1'

    Removes the bridge pair named Bridge1. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/BridgePair/operations/AddBridge-Pair%26EditBridge-Pair.html

.LINK
    Get-SfosBridgePair
#>
function Remove-SfosBridgePair {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

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
        if (-not $PSCmdlet.ShouldProcess("BridgePair '$Hardware' on $($params.Firewall)", 'Remove')) {
            return
        }

        $hardwareEsc = ConvertTo-SfosXmlEscaped -Text $Hardware

        $inner = @"
<Remove>
  <BridgePair>
    <Hardware>$hardwareEsc</Hardware>
  </BridgePair>
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
            throw "Failed to remove BridgePair object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'BridgePair' -Action 'remove' -Target $Hardware
    }
}

#endregion

#region Alias

# --- Alias ---
#
# 1. <Name> is not a caller-settable label. It is computed by the firewall as
#    "<Interface>:<Index>" (0-based per interface, e.g. "Port1:0" for the first Alias on
#    Port1). New-SfosAlias does not expose a -Name parameter; Get-SfosAlias still returns
#    Name as a read-only property.
# 2. Unlike VLAN (where Hardware, not Name, is required for Set/Remove), Alias's Name is a
#    reliable identity key for every operation - <Get> filtered by
#    <key name="Name" criteria="like">, <Set operation="update"> and <Remove> keyed by
#    <Name> all work as expected.
#
#    <Interface> is not a usable server-side filter key, though - <Get> with
#    <key name="Interface" criteria="like"> does not return every object the way a
#    merely-ignored unsupported key normally does; it answers
#    <Status>Transaction fail</Status> instead, a harder failure than an ignored filter. The
#    server-side pre-filter here therefore uses "Name", not "Interface", and -InterfaceLike
#    is client-side only.
#
# The Alias element for the IPv6 address is <IPv6>, not <IPv6Address> as everywhere else in
# this module.

<#
.SYNOPSIS
    Builds the create or update XML body for an Alias entity.

.DESCRIPTION
    Turns a fully resolved Alias object into the XML that New-SfosAlias and Set-SfosAlias send
    to the firewall, so both cmdlets send an identical, complete entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER Alias
    Fully resolved Alias object with Name, Interface, IPFamily, IPAddress, Netmask, IPv6 and
    Prefix properties. Name identifies the object on update; the firewall computes and ignores
    it on create.
#>
function ConvertTo-SfosAliasXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Alias
    )

    $e = { param($v) ConvertTo-SfosXmlEscaped -Text ([string]$v) }

    $nameXml = ''
    if ($Alias.PSObject.Properties.Match('Name').Count -gt 0 -and $Alias.Name) {
        $nameXml = "<Name>$(& $e $Alias.Name)</Name>"
    }

    return @"
<Set operation="$Operation">
  <Alias>
    $nameXml
    <Interface>$(& $e $Alias.Interface)</Interface>
    <IPFamily>$(& $e $Alias.IPFamily)</IPFamily>
    <IPAddress>$(& $e $Alias.IPAddress)</IPAddress>
    <Netmask>$(& $e $Alias.Netmask)</Netmask>
    <IPv6>$(& $e $Alias.IPv6)</IPv6>
    <Prefix>$(& $e $Alias.Prefix)</Prefix>
  </Alias>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves interface aliases from a Sophos Firewall.

.DESCRIPTION
    Returns the Alias objects that are defined on the firewall: secondary IP addresses bound
    to a physical port. The cmdlet only reads; nothing on the firewall is changed. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only aliases whose name contains the given text anywhere. The name is
    computed by the firewall as "Interface:Index", so filtering by a port name such as 'Port1'
    matches every alias on that port. If omitted, the name is not used to filter.

.PARAMETER InterfaceLike
    Optional. Returns only aliases whose carrier interface contains the given text anywhere.
    Applied on the client. If omitted, the interface is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per alias, with the properties
    Name, Interface, IPFamily, IPAddress, Netmask, IPv6 and Prefix. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no alias matches.

.EXAMPLE
    Get-SfosAlias -NameLike 'Port1'

    Returns every alias defined on Port1.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Alias/Alias.html

.LINK
    New-SfosAlias

.LINK
    Set-SfosAlias
#>
function Get-SfosAlias {
    [CmdletBinding()]
    param(
        [string]$NameLike,
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
  <Alias>
    $filterXml
  </Alias>
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
        throw "Error retrieving Alias objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Alias' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/Alias[Interface]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name      = [string]$node.Name
            Interface = [string]$node.Interface
            IPFamily  = [string]$node.IPFamily
            IPAddress  = [string]$node.IPAddress
            Netmask    = [string]$node.Netmask
            IPv6       = [string]$node.IPv6
            Prefix     = [string]$node.Prefix
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
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
    Creates an interface alias on a Sophos Firewall.

.DESCRIPTION
    Adds a secondary IP address to a physical port. There is no -Name parameter: the firewall
    computes the name itself as "Interface:Index". Use Get-SfosAlias afterward to find out
    what name the new object was given. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Interface
    Required. Physical carrier port, for example 'Port1'.

.PARAMETER IPFamily
    Required. 'IPv4' or 'IPv6'. Selects which of the two address parameter pairs below is
    required.

.PARAMETER IPAddress
    Required when -IPFamily is 'IPv4'. IPv4 address.

.PARAMETER Netmask
    Required when -IPFamily is 'IPv4'. IPv4 subnet mask.

.PARAMETER IPv6
    Required when -IPFamily is 'IPv6'. IPv6 address.

.PARAMETER Prefix
    Required when -IPFamily is 'IPv6'. IPv6 prefix length, 1-128.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosAlias -Interface 'Port1' -IPFamily IPv4 -IPAddress '10.10.10.1' -Netmask '255.255.255.0' -WhatIf

    Shows what creating the alias would send, without sending it to the firewall.

.EXAMPLE
    New-SfosAlias -Interface 'Port1' -IPFamily IPv4 -IPAddress '10.10.10.1' -Netmask '255.255.255.0'

    Adds a secondary IPv4 address to Port1. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Alias/operations/AddAlias%26EditAlias.html

.LINK
    Get-SfosAlias

.LINK
    Set-SfosAlias
#>
function New-SfosAlias {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Interface,

        [Parameter(Mandatory)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string]$IPAddress = '',
        [string]$Netmask = '',
        [string]$IPv6 = '',

        [ValidateRange(0, 128)]
        [int]$Prefix = 0,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($IPFamily -eq 'IPv4' -and (-not $IPAddress -or -not $Netmask)) {
        throw "The Alias object on interface '$Interface' cannot be created: -IPAddress and -Netmask are required when -IPFamily is 'IPv4'."
    }
    if ($IPFamily -eq 'IPv6' -and (-not $IPv6 -or $Prefix -eq 0)) {
        throw "The Alias object on interface '$Interface' cannot be created: -IPv6 and -Prefix are required when -IPFamily is 'IPv6'."
    }

    if (-not $PSCmdlet.ShouldProcess("Alias on interface '$Interface' ($IPFamily) on $($params.Firewall)", 'Create')) {
        return
    }

    $aliasObject = [PSCustomObject]@{
        Interface = $Interface; IPFamily = $IPFamily
        IPAddress = $IPAddress; Netmask = $Netmask
        IPv6 = $IPv6; Prefix = if ($Prefix -gt 0) { $Prefix } else { '' }
    }

    $inner = ConvertTo-SfosAliasXml -Operation 'add' -Alias $aliasObject

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create Alias object on interface '$Interface': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Alias' -Action 'create' -Target $Interface
}

<#
.SYNOPSIS
    Updates an interface alias on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing alias. The cmdlet reads the current alias first,
    identified by -Name, and sends every field back; fields you do not pass keep their current
    value. It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER Name
    Required. The alias's name, for example 'Port1:0', as returned by Get-SfosAlias. Accepts
    pipeline input by value and by property name.

.PARAMETER Interface
    Optional. New carrier port. If omitted, the current value is kept.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'. If omitted, the current value is kept.

.PARAMETER IPAddress
    Optional. New IPv4 address. If omitted, the current value is kept.

.PARAMETER Netmask
    Optional. New IPv4 subnet mask. If omitted, the current value is kept.

.PARAMETER IPv6
    Optional. New IPv6 address. If omitted, the current value is kept.

.PARAMETER Prefix
    Optional. New IPv6 prefix length. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosAlias result can be piped in; Name
    binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Get-SfosAlias -NameLike 'Port1' | Set-SfosAlias -Netmask '255.255.0.0' -WhatIf

    Shows what changing the netmask of every alias on Port1 would send, without sending it to
    the firewall.

.EXAMPLE
    Get-SfosAlias -NameLike 'Port1' | Set-SfosAlias -Netmask '255.255.0.0'

    Changes the netmask of every alias on Port1. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Alias/operations/AddAlias%26EditAlias.html

.LINK
    Get-SfosAlias

.LINK
    New-SfosAlias
#>
function Set-SfosAlias {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Interface,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string]$IPAddress,
        [string]$Netmask,
        [string]$IPv6,
        [int]$Prefix,

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

        $existing = @(Get-SfosAlias -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The Alias object '$Name' was not found."
        }
        $cur = $existing[0]

        $target = [PSCustomObject]@{
            Name = $Name
            Interface = if ($bp.ContainsKey('Interface')) { $Interface } else { $cur.Interface }
            IPFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { $cur.IPFamily }
            IPAddress = if ($bp.ContainsKey('IPAddress')) { $IPAddress } else { $cur.IPAddress }
            Netmask = if ($bp.ContainsKey('Netmask')) { $Netmask } else { $cur.Netmask }
            IPv6 = if ($bp.ContainsKey('IPv6')) { $IPv6 } else { $cur.IPv6 }
            Prefix = if ($bp.ContainsKey('Prefix')) { $Prefix } else { $cur.Prefix }
        }

        if (-not $PSCmdlet.ShouldProcess("Alias '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosAliasXml -Operation 'update' -Alias $target

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update Alias object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Alias' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an interface alias from a Sophos Firewall.

.DESCRIPTION
    Deletes an alias, identified by its name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Name
    Required. The alias's name, for example 'Port1:0', as returned by Get-SfosAlias. Accepts
    pipeline input by value and by property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosAlias result can be piped in; Name
    binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Get-SfosAlias -NameLike 'Port1' | Remove-SfosAlias -WhatIf

    Shows what removing every alias on Port1 would send, without sending it to the firewall.

.EXAMPLE
    Get-SfosAlias -NameLike 'Port1' | Remove-SfosAlias

    Removes every alias on Port1. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Alias/operations/AddAlias%26EditAlias.html

.LINK
    Get-SfosAlias
#>
function Remove-SfosAlias {
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
        if (-not $PSCmdlet.ShouldProcess("Alias '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <Alias>
    <Name>$nameEsc</Name>
  </Alias>
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
            throw "Failed to remove Alias object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Alias' -Action 'remove' -Target $Name
    }
}

#endregion


#region CellularWAN

# --- CellularWAN ---
#
# Doc folder WWAN, wire element <CellularWAN>. The root element differs from the doc folder
# name - sending a <WWAN> root instead trips the API's usual "wrong root element" failure.
#
# Singleton: a Get returns exactly one <CellularWAN> node with no <Name>, the same shape as
# SSLTLSInspectionSettings in SophosFirewall.Firewall. There is no create or delete
# operation - only Get/Set are exported, matching the module-wide singleton pattern.
#
# Scope: the vendor sample XML additionally documents a much larger <CellularWANSettings>
# block (IPAssignment, Connect, ReconnectTries, ModemPort, PhoneNumber, UserName, Password,
# SIMCardPINCode, APN, DHCPConnectCommand/DisconnectCommand, InitializationStrings,
# GatewaySettings, AssignmentType, MTU, MSS, MACAddress, ConnectionStatus). Without a
# cellular modem attached, a Get returns only
# <CellularWAN><Action>...</Action><DisconnectOnSystemDown/></CellularWAN> - no
# <CellularWANSettings> node at all. Only the two fields present in that response, Action
# and DisconnectOnSystemDown, are implemented. CellularWANSettings is documented but not
# implemented; a Get-* that does not expose those fields could not preserve them on a
# Set-*, so leaving them out entirely (rather than guessing at their shape) is the safer
# choice than a half-built read-modify-write over a subtree whose shape is not established.

<#
.SYNOPSIS
    Retrieves the cellular WAN settings of a Sophos Firewall.

.DESCRIPTION
    Returns the CellularWAN singleton: the action state of the WWAN/cellular modem and the
    disconnect-on-system-down behaviour. There is exactly one instance of this object per
    firewall, and no name. The cmdlet only reads; nothing on the firewall is changed. It needs
    an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties Action and
    DisconnectOnSystemDown. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosCellularWAN

    Returns the current cellular WAN state.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/WWAN/WWAN.html

.LINK
    Set-SfosCellularWAN
#>
function Get-SfosCellularWAN {
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

    $inner = '<Get><CellularWAN></CellularWAN></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving CellularWAN: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CellularWAN' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/CellularWAN')
    if (-not $node) {
        throw 'CellularWAN could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        Action                 = [string]$node.Action
        DisconnectOnSystemDown = [string]$node.DisconnectOnSystemDown
    }
}

<#
.SYNOPSIS
    Updates the cellular WAN settings of a Sophos Firewall.

.DESCRIPTION
    Changes the action state and disconnect-on-system-down behaviour of the WWAN/cellular
    modem. The cmdlet reads the current settings first and sends both fields back; a field you
    do not pass keeps its current value. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly, and an account with administrative
    permission.

    Setting -Action to 'Enable' activates the cellular modem as a live WAN uplink. Set it back
    to 'Disable' to deactivate the modem again.

.PARAMETER Action
    Optional. Requested action for the cellular WAN interface: 'Enable', 'Disable', 'Query' or
    'Set'. If omitted, the current value is kept.

.PARAMETER DisconnectOnSystemDown
    Optional. Whether to disconnect the modem when the system goes down: 'on' or 'off'. If
    omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosCellularWAN -DisconnectOnSystemDown 'off' -WhatIf

    Shows what changing the disconnect-on-system-down behaviour would send, without sending it
    to the firewall.

.EXAMPLE
    Set-SfosCellularWAN -DisconnectOnSystemDown 'off'

    Sets the modem to stay connected when the system goes down. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/WWAN/operations/CellularWAN.html

.LINK
    Get-SfosCellularWAN
#>
function Set-SfosCellularWAN {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable', 'Query', 'Set')]
        [string]$Action,

        [ValidateSet('on', 'off')]
        [string]$DisconnectOnSystemDown,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosCellularWAN -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetAction = if ($bp.ContainsKey('Action')) { $Action } else { $existing.Action }
    $targetDisconnect = if ($bp.ContainsKey('DisconnectOnSystemDown')) { $DisconnectOnSystemDown } else { $existing.DisconnectOnSystemDown }

    if (-not $PSCmdlet.ShouldProcess("CellularWAN on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <CellularWAN>
    <Action>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetAction))</Action>
    <DisconnectOnSystemDown>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDisconnect))</DisconnectOnSystemDown>
  </CellularWAN>
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
        throw "Error updating CellularWAN: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CellularWAN' -Action 'update'
}

#endregion


#region IPTunnel

# --- IPTunnel ---
#
# Doc folder and wire element both <IPTunnel>.
#
# Two points where the documentation does not match the wire:
#
# 1. <Hardware> is documented "Mandatory: No", but an Add without it fails with
#    <Status code="501">Configuration parameters validation failed.</Status>
#    <InvalidParams><Params>/IPTunnel/Hardware</Params></InvalidParams>. It is the name of
#    the virtual tunnel interface created on the firewall (not a reference to an existing
#    physical port) - up to 10 characters, starting with a letter. New-SfosIPTunnel
#    therefore makes it mandatory in this module, against the documentation.
#
# 2. <Filter> does not filter this entity. Every combination tried - key name="Name"
#    criteria="like", criteria="=", with and without a matching object present - answers
#    <Status>Transaction fail</Status> instead of either the matching records or the
#    documented empty-result wording. That message has no 'code' attribute, so Core's
#    Assert-SfosApiReturnSuccess (by design, see its own comments) treats it as a genuine
#    failure and throws rather than returning an empty list - sending a Filter here would
#    make every Get-SfosIPTunnel call fail whenever a NameLike filter is used.
#    Get-SfosIPTunnel therefore never sends a <Filter> and does all matching client-side,
#    unconditionally.
#
# Remove requires both <Name> and <Hardware> - <Remove><IPTunnel><Name>...</Name>
# </IPTunnel></Remove> alone answers <Status code="500">Operation could not be performed on
# Entity.</Status> even though the object exists; adding <Hardware> makes the identical
# request succeed with code 200. Remove-SfosIPTunnel resolves Hardware via Get-SfosIPTunnel
# when the caller does not supply it, so Get-SfosIPTunnel | Remove-SfosIPTunnel and
# Remove-SfosIPTunnel -Name '...' both work.

<#
.SYNOPSIS
    Retrieves IP tunnels from a Sophos Firewall.

.DESCRIPTION
    Returns the IPTunnel objects that are defined on the firewall: 6in4, 6to4, 6rd and 4in6
    tunnels. Every object is always fetched from the firewall; -NameLike is applied on the
    client. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only tunnels whose name contains the given text anywhere. If omitted,
    the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per tunnel, with the properties
    Name, Hardware, TunnelType, Zone, LocalEndPoint, RemoteEndPoint, TTL, TOS and Prefix.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no tunnel
    matches.

.EXAMPLE
    Get-SfosIPTunnel

    Lists every IP tunnel on the firewall of the current connection.

.EXAMPLE
    Get-SfosIPTunnel -NameLike '6rd'

    Returns tunnels whose name contains '6rd'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/IPTunnel/IPTunnel.html

.LINK
    New-SfosIPTunnel

.LINK
    Set-SfosIPTunnel
#>
function Get-SfosIPTunnel {
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

    # No <Filter> - see the module-level comment on this region. <Filter> on IPTunnel answers
    # <Status>Transaction fail</Status> regardless of key/criteria, which Core's status check
    # treats as an error, not an empty result.
    $inner = '<Get><IPTunnel></IPTunnel></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving IPTunnel objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPTunnel' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPTunnel[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $tunnelObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name           = [string]$node.Name
            Hardware       = [string]$node.Hardware
            TunnelType     = [string]$node.TunnelType
            Zone           = [string]$node.Zone
            LocalEndPoint  = [string]$node.LocalEndPoint
            RemoteEndPoint = [string]$node.RemoteEndPoint
            TTL            = [string]$node.TTL
            TOS            = [string]$node.TOS
            Prefix         = [string]$node.Prefix
        }
    }

    return @($tunnelObjects)
}

<#
.SYNOPSIS
    Creates an IP tunnel on a Sophos Firewall.

.DESCRIPTION
    Adds an IPTunnel object: a 6in4, 6to4, 6rd or 4in6 tunnel. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

.PARAMETER Name
    Required. Descriptive name of the tunnel, up to 58 characters, no commas.

.PARAMETER Hardware
    Required. Name for the virtual tunnel interface created on the firewall, up to 10
    characters, must start with a letter, only letters, digits and underscore after that.

.PARAMETER TunnelType
    Required. Type of tunnel: '6in4', '6to4', '6rd' or '4in6'.

.PARAMETER Zone
    Required. Zone the tunnel belongs to, for example 'LAN', 'WAN' or 'DMZ'.

.PARAMETER LocalEndPoint
    Required. IP address of the local end point of the tunnel.

.PARAMETER RemoteEndPoint
    Required. IP address of the remote end point of the tunnel.

.PARAMETER TTL
    Optional. Time to live of tunnel traffic, 0-255. Default: 0.

.PARAMETER TOS
    Optional. Type of service, the priority of tunnel traffic, 0-99. Default: 0.

.PARAMETER Prefix
    Optional. IPv6 prefix, used when -TunnelType is '6rd'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosIPTunnel -Name 'Site-Tunnel' -Hardware 'tun0' -TunnelType 6in4 -Zone DMZ -LocalEndPoint 203.0.113.1 -RemoteEndPoint 203.0.113.2 -WhatIf

    Shows what creating the tunnel would send, without sending it to the firewall.

.EXAMPLE
    New-SfosIPTunnel -Name 'Site-Tunnel' -Hardware 'tun0' -TunnelType 6in4 -Zone DMZ -LocalEndPoint 203.0.113.1 -RemoteEndPoint 203.0.113.2

    Creates a 6in4 tunnel named Site-Tunnel between the two given endpoints. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/IPTunnel/operations/AddIPTunnel%26EditIPTunnel.html

.LINK
    Get-SfosIPTunnel

.LINK
    Set-SfosIPTunnel
#>
function New-SfosIPTunnel {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 58)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateLength(1, 10)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_]*$')]
        [string]$Hardware,

        [Parameter(Mandatory)]
        [ValidateSet('6in4', '6to4', '6rd', '4in6')]
        [string]$TunnelType,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Zone,

        [Parameter(Mandatory)]
        [string]$LocalEndPoint,

        [Parameter(Mandatory)]
        [string]$RemoteEndPoint,

        [ValidateRange(0, 255)]
        [int]$TTL = 0,

        [ValidateRange(0, 99)]
        [int]$TOS = 0,

        [string]$Prefix,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = @"
<Set operation="add">
  <IPTunnel>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $Name)</Name>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $Hardware)</Hardware>
    <TunnelType>$TunnelType</TunnelType>
    <Zone>$(ConvertTo-SfosXmlEscaped -Text $Zone)</Zone>
    <LocalEndPoint>$(ConvertTo-SfosXmlEscaped -Text $LocalEndPoint)</LocalEndPoint>
    <RemoteEndPoint>$(ConvertTo-SfosXmlEscaped -Text $RemoteEndPoint)</RemoteEndPoint>
    <TTL>$TTL</TTL>
    <TOS>$TOS</TOS>
    <Prefix>$(ConvertTo-SfosXmlEscaped -Text $Prefix)</Prefix>
  </IPTunnel>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("IPTunnel '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating IPTunnel object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPTunnel' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an IP tunnel on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing IP tunnel. The cmdlet reads the current object first
    and sends every field back; fields you do not pass keep their current value. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

.PARAMETER Name
    Required. Name of the tunnel to update. Accepts pipeline input by value and by property
    name.

.PARAMETER Hardware
    Optional. Name of the virtual tunnel interface. If omitted, the current value is kept.

.PARAMETER TunnelType
    Optional. Type of tunnel: '6in4', '6to4', '6rd' or '4in6'. If omitted, the current value
    is kept.

.PARAMETER Zone
    Optional. Zone the tunnel belongs to. If omitted, the current value is kept.

.PARAMETER LocalEndPoint
    Optional. IP address of the local end point. If omitted, the current value is kept.

.PARAMETER RemoteEndPoint
    Optional. IP address of the remote end point. If omitted, the current value is kept.

.PARAMETER TTL
    Optional. Time to live of tunnel traffic, 0-255. If omitted, the current value is kept.

.PARAMETER TOS
    Optional. Type of service, the priority of tunnel traffic, 0-99. If omitted, the current
    value is kept.

.PARAMETER Prefix
    Optional. IPv6 prefix, used when the effective -TunnelType is '6rd'. If omitted, the
    current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosIPTunnel result can be piped in;
    Name binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosIPTunnel -Name 'Site-Tunnel' -TTL 128 -TOS 5 -WhatIf

    Shows what changing the TTL and TOS would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosIPTunnel -Name 'Site-Tunnel' -TTL 128 -TOS 5

    Changes the TTL and TOS of the tunnel named Site-Tunnel; every other field is preserved.
    The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/IPTunnel/operations/AddIPTunnel%26EditIPTunnel.html

.LINK
    Get-SfosIPTunnel

.LINK
    New-SfosIPTunnel
#>
function Set-SfosIPTunnel {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 58)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(1, 10)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9_]*$')]
        [string]$Hardware,

        [ValidateSet('6in4', '6to4', '6rd', '4in6')]
        [string]$TunnelType,

        [string]$Zone,

        [string]$LocalEndPoint,

        [string]$RemoteEndPoint,

        [ValidateRange(0, 255)]
        [int]$TTL,

        [ValidateRange(0, 99)]
        [int]$TOS,

        [string]$Prefix,

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
        $existing = @(Get-SfosIPTunnel -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPTunnel object '$Name' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetHardware = if ($bp.ContainsKey('Hardware')) { $Hardware } else { [string]$current.Hardware }
        $targetTunnelType = if ($bp.ContainsKey('TunnelType')) { $TunnelType } else { [string]$current.TunnelType }
        $targetZone = if ($bp.ContainsKey('Zone')) { $Zone } else { [string]$current.Zone }
        $targetLocal = if ($bp.ContainsKey('LocalEndPoint')) { $LocalEndPoint } else { [string]$current.LocalEndPoint }
        $targetRemote = if ($bp.ContainsKey('RemoteEndPoint')) { $RemoteEndPoint } else { [string]$current.RemoteEndPoint }
        $targetTTL = if ($bp.ContainsKey('TTL')) { $TTL } else { [int]$current.TTL }
        $targetTOS = if ($bp.ContainsKey('TOS')) { $TOS } else { [int]$current.TOS }
        $targetPrefix = if ($bp.ContainsKey('Prefix')) { $Prefix } else { [string]$current.Prefix }

        if (-not $PSCmdlet.ShouldProcess("IPTunnel '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="update">
  <IPTunnel>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $Name)</Name>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $targetHardware)</Hardware>
    <TunnelType>$targetTunnelType</TunnelType>
    <Zone>$(ConvertTo-SfosXmlEscaped -Text $targetZone)</Zone>
    <LocalEndPoint>$(ConvertTo-SfosXmlEscaped -Text $targetLocal)</LocalEndPoint>
    <RemoteEndPoint>$(ConvertTo-SfosXmlEscaped -Text $targetRemote)</RemoteEndPoint>
    <TTL>$targetTTL</TTL>
    <TOS>$targetTOS</TOS>
    <Prefix>$(ConvertTo-SfosXmlEscaped -Text $targetPrefix)</Prefix>
  </IPTunnel>
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
            throw "Error updating IPTunnel object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPTunnel' -Action 'update' -Target $Name
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes an IP tunnel from a Sophos Firewall.

.DESCRIPTION
    Deletes an IPTunnel object. The firewall needs both the name and the hardware value of the
    virtual tunnel interface to identify it; the name alone is not enough. When -Hardware is
    not supplied, this cmdlet resolves it automatically with one extra read, and throws a
    clear "was not found" error if the object does not exist. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Name
    Required. Name of the tunnel to remove. Accepts pipeline input by property name.

.PARAMETER Hardware
    Optional. Name of the tunnel's virtual interface. If omitted, it is resolved automatically
    with Get-SfosIPTunnel. Accepts pipeline input by property name, so
    Get-SfosIPTunnel | Remove-SfosIPTunnel supplies it directly without an extra round trip.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosIPTunnel result can be piped in;
    Name and Hardware bind by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosIPTunnel -Name 'Site-Tunnel' -WhatIf

    Shows what removing the tunnel would send, without sending it to the firewall.

.EXAMPLE
    Get-SfosIPTunnel -NameLike 'Site-Tunnel' | Remove-SfosIPTunnel

    Removes the tunnel whose name contains 'Site-Tunnel'. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/IPTunnel/operations/Delete%20IP%20Tunnel.html

.LINK
    Get-SfosIPTunnel

.LINK
    New-SfosIPTunnel
#>
function Remove-SfosIPTunnel {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 58)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Hardware,

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
        $targetHardware = $Hardware
        if (-not $targetHardware) {
            $existing = @(Get-SfosIPTunnel -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.Name -eq $Name })

            if ($existing.Count -eq 0) {
                throw "The IPTunnel object '$Name' was not found."
            }
            $targetHardware = [string]$existing[0].Hardware
        }

        if (-not $PSCmdlet.ShouldProcess("IPTunnel '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Remove>
  <IPTunnel>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $Name)</Name>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $targetHardware)</Hardware>
  </IPTunnel>
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
            throw "Error removing IPTunnel object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPTunnel' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion


#region GreTunnel

# --- GreTunnel ---
#
# Doc folder GRETunnel, wire element <GreTunnel>.
#
# A GreTunnel needs a <LocalGateway> naming an existing local interface - with LocalGateway
# set to a name that does not exist, Add answers <Status code="500">Operation could not be
# performed on Entity.</Status> and creates nothing. The fields below (TunnelName,
# LocalGateway, RemoteGateway, LocalNet, RemoteNet, TTL, Dyndns, State) are implemented from
# the vendor sample XML.
#
# Deletion is not documented for this entity at all: the GRETunnel doc folder lists exactly
# one operation ("Add GRE tunnel / Show GRE tunnel / Set GRE tunnel option") and no delete
# operation page exists. Remove-SfosGreTunnel below uses the module's standard <Remove> tag
# as the best available default; whether the firewall accepts it for this entity is not
# established, flagged again in its own .NOTES.

<#
.SYNOPSIS
    Retrieves GRE tunnels from a Sophos Firewall.

.DESCRIPTION
    Returns the GreTunnel objects that are defined on the firewall. The cmdlet only reads;
    nothing on the firewall is changed. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only tunnels whose name contains the given text anywhere. If omitted,
    the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per tunnel, with the properties
    TunnelName, LocalGateway, RemoteGateway, LocalNet, RemoteNet, TTL, Dyndns and State.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no tunnel
    matches.

.EXAMPLE
    Get-SfosGreTunnel

    Lists every GRE tunnel on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRETunnel/GRETunnel.html

.LINK
    New-SfosGreTunnel

.LINK
    Set-SfosGreTunnel
#>
function Get-SfosGreTunnel {
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

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="TunnelName" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <GreTunnel>
    $filterXml
  </GreTunnel>
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
        throw "Error retrieving GreTunnel objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreTunnel' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/GreTunnel[TunnelName]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.TunnelName -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $tunnelObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            TunnelName    = [string]$node.TunnelName
            LocalGateway  = [string]$node.LocalGateway
            RemoteGateway = [string]$node.RemoteGateway
            LocalNet      = [string]$node.LocalNet
            RemoteNet     = [string]$node.RemoteNet
            TTL           = [string]$node.TTL
            Dyndns        = [string]$node.Dyndns
            State         = [string]$node.State
        }
    }

    return @($tunnelObjects)
}

<#
.SYNOPSIS
    Creates a GRE tunnel on a Sophos Firewall.

.DESCRIPTION
    Adds a GreTunnel object. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER TunnelName
    Required. Name of the tunnel, up to 15 characters.

.PARAMETER LocalGateway
    Required. Name of the local interface acting as the tunnel's gateway. Must name an
    existing interface.

.PARAMETER RemoteGateway
    Required. Remote WAN IP address or DDNS host name, up to 64 characters.

.PARAMETER LocalNet
    Required. Local IP address of the tunnel.

.PARAMETER RemoteNet
    Required. Remote IP address of the tunnel.

.PARAMETER TTL
    Optional. Time to live, 0-255.

.PARAMETER Dyndns
    Optional. Whether the remote gateway is a dynamic DNS name: 'On' or 'Off'.

.PARAMETER State
    Optional. Tunnel state: 'Enabled' or 'Disabled'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosGreTunnel -TunnelName 'gre-test' -LocalGateway 'Port1' -RemoteGateway '203.0.113.10' -LocalNet '198.51.100.1' -RemoteNet '198.51.100.2' -State Disabled -WhatIf

    Shows what creating the tunnel would send, without sending it to the firewall.

.EXAMPLE
    New-SfosGreTunnel -TunnelName 'gre-test' -LocalGateway 'Port1' -RemoteGateway '203.0.113.10' -LocalNet '198.51.100.1' -RemoteNet '198.51.100.2' -State Disabled

    Creates a disabled GRE tunnel named gre-test. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRETunnel/operations/AddGREtunnel%26ShowGREtunnel%26SetGREtunneloption.html

.LINK
    Get-SfosGreTunnel

.LINK
    Set-SfosGreTunnel
#>
function New-SfosGreTunnel {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$TunnelName,

        [Parameter(Mandatory)]
        [string]$LocalGateway,

        [Parameter(Mandatory)]
        [ValidateLength(1, 64)]
        [string]$RemoteGateway,

        [Parameter(Mandatory)]
        [string]$LocalNet,

        [Parameter(Mandatory)]
        [string]$RemoteNet,

        [ValidateRange(0, 255)]
        [int]$TTL = 0,

        [ValidateSet('On', 'Off')]
        [string]$Dyndns = 'Off',

        [ValidateSet('Enabled', 'Disabled')]
        [string]$State = 'Disabled',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = @"
<Set operation="add">
  <GreTunnel>
    <TunnelName>$(ConvertTo-SfosXmlEscaped -Text $TunnelName)</TunnelName>
    <LocalGateway>$(ConvertTo-SfosXmlEscaped -Text $LocalGateway)</LocalGateway>
    <RemoteGateway>$(ConvertTo-SfosXmlEscaped -Text $RemoteGateway)</RemoteGateway>
    <LocalNet>$(ConvertTo-SfosXmlEscaped -Text $LocalNet)</LocalNet>
    <RemoteNet>$(ConvertTo-SfosXmlEscaped -Text $RemoteNet)</RemoteNet>
    <TTL>$TTL</TTL>
    <Dyndns>$Dyndns</Dyndns>
    <State>$State</State>
  </GreTunnel>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("GreTunnel '$TunnelName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating GreTunnel object '$TunnelName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreTunnel' -Action 'create' -Target $TunnelName
}

<#
.SYNOPSIS
    Updates a GRE tunnel on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing GRE tunnel. The cmdlet reads the current object first
    and sends every field back; fields you do not pass keep their current value. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

.PARAMETER TunnelName
    Required. Name of the tunnel to update. Accepts pipeline input by property name.

.PARAMETER LocalGateway
    Optional. Name of the local interface acting as the tunnel's gateway. If omitted, the
    current value is kept.

.PARAMETER RemoteGateway
    Optional. Remote WAN IP address or DDNS host name. If omitted, the current value is kept.

.PARAMETER LocalNet
    Optional. Local IP address of the tunnel. If omitted, the current value is kept.

.PARAMETER RemoteNet
    Optional. Remote IP address of the tunnel. If omitted, the current value is kept.

.PARAMETER TTL
    Optional. Time to live, 0-255. If omitted, the current value is kept.

.PARAMETER Dyndns
    Optional. Whether the remote gateway is a dynamic DNS name: 'On' or 'Off'. If omitted, the
    current value is kept.

.PARAMETER State
    Optional. Tunnel state: 'Enabled' or 'Disabled'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosGreTunnel result can be piped in;
    TunnelName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosGreTunnel -TunnelName 'gre-test' -State Enabled -WhatIf

    Shows what enabling the tunnel would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosGreTunnel -TunnelName 'gre-test' -State Enabled

    Enables the GRE tunnel named gre-test; every other field is preserved. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRETunnel/operations/AddGREtunnel%26ShowGREtunnel%26SetGREtunneloption.html

.LINK
    Get-SfosGreTunnel

.LINK
    New-SfosGreTunnel
#>
function Set-SfosGreTunnel {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$TunnelName,

        [string]$LocalGateway,

        [ValidateLength(0, 64)]
        [string]$RemoteGateway,

        [string]$LocalNet,

        [string]$RemoteNet,

        [ValidateRange(0, 255)]
        [int]$TTL,

        [ValidateSet('On', 'Off')]
        [string]$Dyndns,

        [ValidateSet('Enabled', 'Disabled')]
        [string]$State,

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
        $existing = @(Get-SfosGreTunnel -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.TunnelName -eq $TunnelName })

        if ($existing.Count -eq 0) {
            throw "The GreTunnel object '$TunnelName' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetLocalGw = if ($bp.ContainsKey('LocalGateway')) { $LocalGateway } else { [string]$current.LocalGateway }
        $targetRemoteGw = if ($bp.ContainsKey('RemoteGateway')) { $RemoteGateway } else { [string]$current.RemoteGateway }
        $targetLocalNet = if ($bp.ContainsKey('LocalNet')) { $LocalNet } else { [string]$current.LocalNet }
        $targetRemoteNet = if ($bp.ContainsKey('RemoteNet')) { $RemoteNet } else { [string]$current.RemoteNet }
        $targetTTL = if ($bp.ContainsKey('TTL')) { $TTL } else { [int]$current.TTL }
        $targetDyndns = if ($bp.ContainsKey('Dyndns')) { $Dyndns } else { [string]$current.Dyndns }
        $targetState = if ($bp.ContainsKey('State')) { $State } else { [string]$current.State }

        if (-not $PSCmdlet.ShouldProcess("GreTunnel '$TunnelName' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="update">
  <GreTunnel>
    <TunnelName>$(ConvertTo-SfosXmlEscaped -Text $TunnelName)</TunnelName>
    <LocalGateway>$(ConvertTo-SfosXmlEscaped -Text $targetLocalGw)</LocalGateway>
    <RemoteGateway>$(ConvertTo-SfosXmlEscaped -Text $targetRemoteGw)</RemoteGateway>
    <LocalNet>$(ConvertTo-SfosXmlEscaped -Text $targetLocalNet)</LocalNet>
    <RemoteNet>$(ConvertTo-SfosXmlEscaped -Text $targetRemoteNet)</RemoteNet>
    <TTL>$targetTTL</TTL>
    <Dyndns>$targetDyndns</Dyndns>
    <State>$targetState</State>
  </GreTunnel>
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
            throw "Error updating GreTunnel object '$TunnelName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreTunnel' -Action 'update' -Target $TunnelName
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes a GRE tunnel from a Sophos Firewall.

.DESCRIPTION
    Deletes a GreTunnel object, identified by its name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER TunnelName
    Required. Name of the tunnel to remove. Accepts pipeline input by value and by property
    name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosGreTunnel result can be piped in;
    TunnelName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosGreTunnel -TunnelName 'gre-test' -WhatIf

    Shows what removing the tunnel would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosGreTunnel -TunnelName 'gre-test'

    Removes the GRE tunnel named gre-test. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRETunnel/GRETunnel.html

.LINK
    Get-SfosGreTunnel
#>
function Remove-SfosGreTunnel {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$TunnelName,

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
        if (-not $PSCmdlet.ShouldProcess("GreTunnel '$TunnelName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Remove>
  <GreTunnel>
    <TunnelName>$(ConvertTo-SfosXmlEscaped -Text $TunnelName)</TunnelName>
  </GreTunnel>
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
            throw "Error removing GreTunnel object '$TunnelName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreTunnel' -Action 'remove' -Target $TunnelName
    }
    end {
    }
}

#endregion


#region GreRoute

# --- GreRoute ---
#
# Doc folder GRERoute, wire element <GreRoute>.
#
# GreRoute depends on GreTunnel (a route needs a tunnel to route through). Referencing a
# TunnelName that does not exist answers <Status code="501">Configuration parameters
# validation failed.</Status> <InvalidParams><Params>/GreRoute/TunnelName</Params>
# </InvalidParams>.
#
# The vendor's own operation page documents this entity's <Set operation="..."> attribute
# as taking 'add' or 'del' - not this module's usual 'add'/'update' convention, and 'del'
# rather than the <Remove> tag used as the norm elsewhere. This is the same kind of
# exception as operation="edit" elsewhere in this API - the wire behaviour, not the
# module-wide convention, wins when the two disagree. Remove-SfosGreRoute therefore uses
# <Set operation="del"> rather than <Remove>. No 'update' operation is documented for this
# entity at all (route entries are conceptually add-or-remove, not edit-in-place), so
# Set-SfosGreRoute is implemented as a read, then a delete-and-recreate using only the two
# documented operations, rather than guessing at an undocumented update semantic.

<#
.SYNOPSIS
    Retrieves GRE tunnel routes from a Sophos Firewall.

.DESCRIPTION
    Returns the GreRoute objects that are defined on the firewall: routes for a destination
    host or network through a GRE tunnel. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER TunnelNameLike
    Optional. Returns only routes whose tunnel name contains the given text anywhere. If
    omitted, the tunnel name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per route, with the properties
    Host, Netmask and TunnelName. Returns System.Xml.XmlElement when -AsXml is used, and an
    empty array when no route matches.

.EXAMPLE
    Get-SfosGreRoute

    Lists every GRE tunnel route on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRERoute/GRERoute.html

.LINK
    New-SfosGreRoute

.LINK
    Set-SfosGreRoute
#>
function Get-SfosGreRoute {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$TunnelNameLike,

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
    if ($TunnelNameLike) {
        $tunnelLikeEsc = ConvertTo-SfosXmlEscaped -Text $TunnelNameLike
        $filterXml = ('<Filter><key name="TunnelName" criteria="like">{0}</key></Filter>' -f $tunnelLikeEsc)
    }

    $inner = @"
<Get>
  <GreRoute>
    $filterXml
  </GreRoute>
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
        throw "Error retrieving GreRoute objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreRoute' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/GreRoute[TunnelName]' | ForEach-Object -Process {
        $_.Node
    }

    if ($TunnelNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.TunnelName -like "*$TunnelNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $routeObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Host       = [string]$node.Host
            Netmask    = [string]$node.Netmask
            TunnelName = [string]$node.TunnelName
        }
    }

    return @($routeObjects)
}

<#
.SYNOPSIS
    Creates a GRE tunnel route on a Sophos Firewall.

.DESCRIPTION
    Adds a GreRoute object, routing traffic for a destination host or network through an
    existing GRE tunnel. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER HostAddress
    Required. Destination host or network IP address for the route. Aliased to -Host; the
    parameter cannot be named Host outright because that is an automatic PowerShell variable.

.PARAMETER Netmask
    Required. Netmask of the destination host or network.

.PARAMETER TunnelName
    Required. Name of the existing GRE tunnel this route uses. Must name an existing tunnel.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosGreRoute -HostAddress '198.51.100.0' -Netmask '255.255.255.0' -TunnelName 'gre-test' -WhatIf

    Shows what creating the route would send, without sending it to the firewall.

.EXAMPLE
    New-SfosGreRoute -HostAddress '198.51.100.0' -Netmask '255.255.255.0' -TunnelName 'gre-test'

    Routes the 198.51.100.0/24 network through the GRE tunnel named gre-test. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRERoute/operations/AddanddeleteGREroute.html

.LINK
    Get-SfosGreRoute

.LINK
    New-SfosGreTunnel
#>
function New-SfosGreRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Not -Host: $Host is an automatic PowerShell variable holding the console host, and a
        # parameter of that name shadows it inside the function. The wire element stays <Host>;
        # the alias keeps the Sophos spelling available to callers.
        [Parameter(Mandatory)]
        [Alias('Host')]
        [string]$HostAddress,

        [Parameter(Mandatory)]
        [string]$Netmask,

        [Parameter(Mandatory)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$TunnelName,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = @"
<Set operation="add">
  <GreRoute>
    <Host>$(ConvertTo-SfosXmlEscaped -Text $HostAddress)</Host>
    <Netmask>$(ConvertTo-SfosXmlEscaped -Text $Netmask)</Netmask>
    <TunnelName>$(ConvertTo-SfosXmlEscaped -Text $TunnelName)</TunnelName>
  </GreRoute>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("GreRoute for '$HostAddress/$Netmask' via '$TunnelName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating GreRoute object for '$HostAddress/$Netmask' via '$TunnelName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreRoute' -Action 'create' -Target "$HostAddress/$Netmask via $TunnelName"
}

<#
.SYNOPSIS
    Updates a GRE tunnel route on a Sophos Firewall.

.DESCRIPTION
    Changes an existing route by removing it and recreating it with the merged field values;
    the API for this entity has no in-place update operation. The cmdlet reads the current
    route first; fields you do not pass keep their current value. If the recreate step fails
    after the removal, the route is left removed rather than restored automatically. It needs
    an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER TunnelName
    Required. Name of the tunnel that identifies the route to update, since a GreRoute has no
    separate name of its own.

.PARAMETER HostAddress
    Optional. Destination host or network IP address for the route. Aliased to -Host. If
    omitted, the current value is kept.

.PARAMETER Netmask
    Optional. Netmask of the destination host or network. If omitted, the current value is
    kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosGreRoute result can be piped in;
    TunnelName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the removal or the recreate step
    fails.

.EXAMPLE
    Set-SfosGreRoute -TunnelName 'gre-test' -Netmask '255.255.255.128' -WhatIf

    Shows what changing the netmask of the route would send, without sending it to the
    firewall.

.EXAMPLE
    Set-SfosGreRoute -TunnelName 'gre-test' -Netmask '255.255.255.128'

    Changes the netmask of the route for tunnel gre-test. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRERoute/operations/AddanddeleteGREroute.html

.LINK
    Get-SfosGreRoute

.LINK
    New-SfosGreRoute
#>
function Set-SfosGreRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$TunnelName,

        # See New-SfosGreRoute: -Host would shadow the automatic $Host variable.
        [Alias('Host')]
        [string]$HostAddress,

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
        $existing = @(Get-SfosGreRoute -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.TunnelName -eq $TunnelName })

        if ($existing.Count -eq 0) {
            throw "The GreRoute object for tunnel '$TunnelName' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetHost = if ($bp.ContainsKey('HostAddress')) { $HostAddress } else { [string]$current.Host }
        $targetNetmask = if ($bp.ContainsKey('Netmask')) { $Netmask } else { [string]$current.Netmask }

        if (-not $PSCmdlet.ShouldProcess("GreRoute for tunnel '$TunnelName' on $($params.Firewall)", 'Replace (remove and recreate)')) {
            return
        }

        Remove-SfosGreRoute -TunnelName $TunnelName -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false

        New-SfosGreRoute -Host $targetHost -Netmask $targetNetmask -TunnelName $TunnelName `
            -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes a GRE tunnel route from a Sophos Firewall.

.DESCRIPTION
    Deletes a GreRoute object, identified by the name of the tunnel it belongs to, since a
    route has no separate name of its own. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER TunnelName
    Required. Name of the tunnel that identifies the route to remove. Accepts pipeline input
    by value and by property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosGreRoute result can be piped in;
    TunnelName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosGreRoute -TunnelName 'gre-test' -WhatIf

    Shows what removing the route would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosGreRoute -TunnelName 'gre-test'

    Removes the route for the GRE tunnel named gre-test. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/GRERoute/operations/AddanddeleteGREroute.html

.LINK
    Get-SfosGreRoute

.LINK
    New-SfosGreRoute
#>
function Remove-SfosGreRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$TunnelName,

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
        if (-not $PSCmdlet.ShouldProcess("GreRoute for tunnel '$TunnelName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Set operation="del">
  <GreRoute>
    <TunnelName>$(ConvertTo-SfosXmlEscaped -Text $TunnelName)</TunnelName>
  </GreRoute>
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
            throw "Error removing GreRoute object for tunnel '$TunnelName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GreRoute' -Action 'remove' -Target $TunnelName
    }
    end {
    }
}

#endregion


#region TAP

# --- TAP ---
#
# Doc folder TapInterfaceConfiguration, wire element <TAP>.
#
# TAP mode converts an existing physical Ethernet port into a promiscuous monitor-only
# interface - <Hardware> must name an existing physical interface. Converting a port to TAP
# mode strips its zone and IPv4 assignment.
#
# A <Set operation="add"><TAP><Hardware>...</Hardware>...</TAP></Set> with a Hardware value
# that does not resolve to a real interface answers <Status code="200">Configuration
# applied successfully.</Status>, but a follow-up Get still shows "No. of records Zero." -
# the firewall reports success while doing nothing for a Hardware value it cannot resolve.
# This is the same class of defect seen elsewhere in this API (a write reporting success
# while the firewall did nothing), so a 200 from this Add/Set call alone is not sufficient
# evidence of a real change - a caller should always re-Get to confirm.
#
# The vendor's operation page documents an ACTION enum of 'add'/'delete'/'show', not this
# module's usual 'add'/'update' pair, and 'delete' rather than the <Remove> tag - mirroring
# GreRoute's 'add'/'del' exception. New-SfosTAP therefore uses <Set operation="add">, and
# Remove-SfosTAP uses <Set operation="delete"> rather than <Remove>. No separate 'update'
# value is documented, so Set-SfosTAP re-sends <Set operation="add"> with the merged
# fields.

<#
.SYNOPSIS
    Retrieves TAP interface configurations from a Sophos Firewall.

.DESCRIPTION
    Returns the TAP objects that are defined on the firewall: physical interfaces configured
    for promiscuous monitor-mode capture. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER HardwareLike
    Optional. Returns only TAP interfaces whose hardware name contains the given text
    anywhere. If omitted, the hardware name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per TAP interface, with the
    properties Hardware, InterfaceSpeed, AutoNegotiation and FEC. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no TAP interface
    matches.

.EXAMPLE
    Get-SfosTAP

    Lists every TAP interface configuration on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/TapInterfaceConfiguration/TapInterfaceConfiguration.html

.LINK
    New-SfosTAP

.LINK
    Set-SfosTAP
#>
function Get-SfosTAP {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$HardwareLike,

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
    if ($HardwareLike) {
        $hwLikeEsc = ConvertTo-SfosXmlEscaped -Text $HardwareLike
        $filterXml = ('<Filter><key name="Hardware" criteria="like">{0}</key></Filter>' -f $hwLikeEsc)
    }

    $inner = @"
<Get>
  <TAP>
    $filterXml
  </TAP>
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
        throw "Error retrieving TAP objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TAP' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/TAP[Hardware]' | ForEach-Object -Process {
        $_.Node
    }

    if ($HardwareLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Hardware -like "*$HardwareLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $tapObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Hardware        = [string]$node.Hardware
            InterfaceSpeed  = [string]$node.InterfaceSpeed
            AutoNegotiation = [string]$node.AutoNegotiation
            FEC             = [string]$node.FEC
        }
    }

    return @($tapObjects)
}

<#
.SYNOPSIS
    Configures a physical interface as a TAP interface on a Sophos Firewall.

.DESCRIPTION
    Puts an existing physical interface into TAP (promiscuous monitor-mode) capture mode.
    -Hardware must name an existing physical interface. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission. Read the object back with Get-SfosTAP afterward to confirm the
    interface was actually reconfigured.

.PARAMETER Hardware
    Required. Name of the physical interface to configure as a TAP interface.

.PARAMETER InterfaceSpeed
    Optional. Interface speed. Default: 'Auto Negotiate'.

.PARAMETER AutoNegotiation
    Optional. Whether auto-negotiation is enabled: 'Enable' or 'Disable'. Default: 'Enable'.

.PARAMETER FEC
    Optional. Forward error correction mode: 'Off', 'Automatic', 'BaseR-encoding' or
    'RS-FEC-encoding'. Default: 'Off'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    configuration.

.EXAMPLE
    New-SfosTAP -Hardware 'PortX' -WhatIf

    Shows what configuring PortX as a TAP interface would send, without sending it to the
    firewall.

.EXAMPLE
    New-SfosTAP -Hardware 'PortX'

    Configures PortX as a TAP interface. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/TapInterfaceConfiguration/operations/ConfigureTAPinterface.html

.LINK
    Get-SfosTAP

.LINK
    Set-SfosTAP
#>
function New-SfosTAP {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Hardware,

        [string]$InterfaceSpeed = 'Auto Negotiate',

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoNegotiation = 'Enable',

        [ValidateSet('Off', 'Automatic', 'BaseR-encoding', 'RS-FEC-encoding')]
        [string]$FEC = 'Off',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = @"
<Set operation="add">
  <TAP>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $Hardware)</Hardware>
    <InterfaceSpeed>$(ConvertTo-SfosXmlEscaped -Text $InterfaceSpeed)</InterfaceSpeed>
    <AutoNegotiation>$AutoNegotiation</AutoNegotiation>
    <FEC>$FEC</FEC>
  </TAP>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("TAP '$Hardware' on $($params.Firewall)", 'Configure')) {
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
        throw "Error configuring TAP object '$Hardware': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TAP' -Action 'create' -Target $Hardware
}

<#
.SYNOPSIS
    Updates a TAP interface configuration on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing TAP interface. The cmdlet reads the current object
    first and sends every field back; fields you do not pass keep their current value. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER Hardware
    Required. Name of the physical interface to update. Accepts pipeline input by property
    name.

.PARAMETER InterfaceSpeed
    Optional. Interface speed. If omitted, the current value is kept.

.PARAMETER AutoNegotiation
    Optional. Whether auto-negotiation is enabled: 'Enable' or 'Disable'. If omitted, the
    current value is kept.

.PARAMETER FEC
    Optional. Forward error correction mode. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosTAP result can be piped in;
    Hardware binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosTAP -Hardware 'PortX' -FEC Automatic -WhatIf

    Shows what changing the FEC mode would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosTAP -Hardware 'PortX' -FEC Automatic

    Changes the FEC mode of PortX; every other field is preserved. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/TapInterfaceConfiguration/operations/ConfigureTAPinterface.html

.LINK
    Get-SfosTAP
#>
function Set-SfosTAP {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

        [string]$InterfaceSpeed,

        [ValidateSet('Enable', 'Disable')]
        [string]$AutoNegotiation,

        [ValidateSet('Off', 'Automatic', 'BaseR-encoding', 'RS-FEC-encoding')]
        [string]$FEC,

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
        $existing = @(Get-SfosTAP -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.Hardware -eq $Hardware })

        if ($existing.Count -eq 0) {
            throw "The TAP object '$Hardware' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetSpeed = if ($bp.ContainsKey('InterfaceSpeed')) { $InterfaceSpeed } else { [string]$current.InterfaceSpeed }
        $targetAutoNeg = if ($bp.ContainsKey('AutoNegotiation')) { $AutoNegotiation } else { [string]$current.AutoNegotiation }
        $targetFEC = if ($bp.ContainsKey('FEC')) { $FEC } else { [string]$current.FEC }

        if (-not $PSCmdlet.ShouldProcess("TAP '$Hardware' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="add">
  <TAP>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $Hardware)</Hardware>
    <InterfaceSpeed>$(ConvertTo-SfosXmlEscaped -Text $targetSpeed)</InterfaceSpeed>
    <AutoNegotiation>$targetAutoNeg</AutoNegotiation>
    <FEC>$targetFEC</FEC>
  </TAP>
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
            throw "Error updating TAP object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TAP' -Action 'update' -Target $Hardware
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes the TAP configuration from an interface on a Sophos Firewall.

.DESCRIPTION
    Reverts an interface from TAP capture mode back to normal operation. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

.PARAMETER Hardware
    Required. Name of the physical interface to revert. Accepts pipeline input by property
    name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosTAP result can be piped in;
    Hardware binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosTAP -Hardware 'PortX' -WhatIf

    Shows what reverting PortX to normal operation would send, without sending it to the
    firewall.

.EXAMPLE
    Remove-SfosTAP -Hardware 'PortX'

    Reverts PortX from TAP mode to normal operation. The cmdlet asks for confirmation before
    it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/TapInterfaceConfiguration/operations/ConfigureTAPinterface.html

.LINK
    Get-SfosTAP
#>
function Remove-SfosTAP {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Hardware,

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
        if (-not $PSCmdlet.ShouldProcess("TAP '$Hardware' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Set operation="delete">
  <TAP>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $Hardware)</Hardware>
  </TAP>
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
            throw "Error removing TAP object '$Hardware': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TAP' -Action 'remove' -Target $Hardware
    }
    end {
    }
}

#endregion


#region REDDevice

# --- REDDevice ---
#
# Doc folder and wire element both <REDDevice>.
#
# A RED device registration ties into Sophos's real provisioning infrastructure and a
# genuine RED appliance's device ID.
#
# REDMTU is documented "Mandatory: Yes, Default: 1500", but the "Default" column
# contradicts the "Mandatory" column: omitting it answers <Status code="501">
# Configuration parameters validation failed.</Status> naming /REDDevice/REDMTU and
# /REDDevice/REDDeviceID as invalid. Supplying REDMTU=1500 with a REDDeviceID formatted
# like a real Sophos RED serial answers <Status code="504">Operation failed. Deleting
# entity referred by another entity.</Status> - a message that reads oddly for an Add,
# likely a status-code/message-catalog mismatch rather than a literal description; the
# doc's own table maps 504 differently for Add vs. Update RED Device.
#
# This module implements the top-level fields plus the UplinkSettings/NetworkSetting/
# AdvancedSettings fields from the vendor sample XML. The following documented subtrees are
# explicitly not implemented (matching how FirewallRule leaves UserPolicy/HTTPBasedPolicy
# unimplemented rather than guessing at their shape): Certificate (Cert/Key/CA),
# SwitchSettings/LANPortSettings (RED50-specific port config), and NetworkSetting's
# StandardSplit/TransparentSplit network and domain lists. Get-SfosREDDevice would need to
# expose all of these for a Set-* to preserve them safely, so leaving them unimplemented is
# safer than a partial read-modify-write over nested lists whose populated shape has never
# been observed.

<#
.SYNOPSIS
    Retrieves RED devices from a Sophos Firewall.

.DESCRIPTION
    Returns the REDDevice objects (Remote Ethernet Devices) that are registered on the
    firewall. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER BranchNameLike
    Optional. Returns only RED devices whose branch name contains the given text anywhere. If
    omitted, the branch name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per RED device, with the
    properties BranchName, Device, REDDeviceID, TunnelID, UTMHostName, SecondUTMHostName,
    DeploymentMode, Status, Authorized, REDMTU, UplinkConnection, UplinkAddress,
    UplinkNetmask, UplinkDefaultGateway, UplinkDNS, UMTS3GFailover, OperationMode, IPAddress,
    NetMask, Zone, TunnelCompression, RemoteIPAssignment and RemoteTunnelIPv4Address. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no device matches.

.EXAMPLE
    Get-SfosREDDevice

    Lists every RED device registered on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/REDDevice/REDDevice.html

.LINK
    New-SfosREDDevice

.LINK
    Set-SfosREDDevice
#>
function Get-SfosREDDevice {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$BranchNameLike,

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
    if ($BranchNameLike) {
        $branchLikeEsc = ConvertTo-SfosXmlEscaped -Text $BranchNameLike
        $filterXml = ('<Filter><key name="BranchName" criteria="like">{0}</key></Filter>' -f $branchLikeEsc)
    }

    $inner = @"
<Get>
  <REDDevice>
    $filterXml
  </REDDevice>
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
        throw "Error retrieving REDDevice objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'REDDevice' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/REDDevice[BranchName]' | ForEach-Object -Process {
        $_.Node
    }

    if ($BranchNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.BranchName -like "*$BranchNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $deviceObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            BranchName             = [string]$node.BranchName
            Device                 = [string]$node.Device
            REDDeviceID            = [string]$node.REDDeviceID
            TunnelID               = [string]$node.TunnelID
            UTMHostName            = [string]$node.UTMHostName
            SecondUTMHostName      = [string]$node.SecondUTMHostName
            DeploymentMode         = [string]$node.DeploymentMode
            Status                 = [string]$node.Status
            Authorized             = [string]$node.Authorized
            REDMTU                 = [string]$node.REDMTU
            UplinkConnection       = [string]$node.UplinkSettings.Uplink.Connection
            UplinkAddress          = [string]$node.UplinkSettings.Uplink.Address
            UplinkNetmask          = [string]$node.UplinkSettings.Uplink.Netmask
            UplinkDefaultGateway   = [string]$node.UplinkSettings.Uplink.DefaultGateway
            UplinkDNS              = [string]$node.UplinkSettings.Uplink.DNS
            UMTS3GFailover         = [string]$node.UplinkSettings.UMTS3GFailover
            OperationMode          = [string]$node.NetworkSetting.OperationMode
            IPAddress              = [string]$node.NetworkSetting.IPAddress
            NetMask                = [string]$node.NetworkSetting.NetMask
            Zone                   = [string]$node.NetworkSetting.Zone
            TunnelCompression      = [string]$node.NetworkSetting.TunnelCompression
            RemoteIPAssignment     = [string]$node.AdvancedSettings.RemoteIPAssignment
            RemoteTunnelIPv4Address = [string]$node.AdvancedSettings.RemoteTunnelIPv4Address
        }
    }

    return @($deviceObjects)
}

<#
.SYNOPSIS
    Registers a RED device on a Sophos Firewall.

.DESCRIPTION
    Adds a REDDevice object (Remote Ethernet Device). A real device needs a genuine Sophos RED
    serial number and reachability to Sophos's provisioning service. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

.PARAMETER BranchName
    Required. Name for the remote location where the RED device will be set up.

.PARAMETER Device
    Optional. RED device model: 'RED15', 'RED15W', 'red20', 'RED50', 'red60',
    'RED_FIREWALL_SERVER', 'RED_FIREWALL_SERVER_LEGACY', 'RED_FIREWALL_CLIENT' or
    'RED_FIREWALL_CLIENT_LEGACY'.

.PARAMETER REDDeviceID
    Required. Serial or device ID of the physical RED device.

.PARAMETER TunnelID
    Optional. Tunnel ID for the RED connection.

.PARAMETER UnlockCode
    Optional. Unlock code for the RED device.

.PARAMETER UTMHostName
    Optional. Host name the RED device uses to reach this firewall.

.PARAMETER SecondUTMHostName
    Optional. Second host name the RED device uses to reach this firewall. RED15 and RED50
    only.

.PARAMETER DeploymentMode
    Optional. 'AutoDeployment', through the Sophos provisioning service, or
    'ManualDeployment', through a USB stick. Default: 'ManualDeployment'.

.PARAMETER UplinkConnection
    Optional. Primary uplink connection type: 'DHCP' or 'Static'. Default: 'DHCP'.

.PARAMETER UplinkAddress
    Optional. Primary uplink static IPv4 address. Only used when -UplinkConnection is
    'Static'.

.PARAMETER UplinkNetmask
    Optional. Primary uplink static netmask. Only used when -UplinkConnection is 'Static'.

.PARAMETER UplinkDefaultGateway
    Optional. Primary uplink static default gateway. Only used when -UplinkConnection is
    'Static'.

.PARAMETER UplinkDNS
    Optional. Primary uplink static DNS server. Only used when -UplinkConnection is 'Static'.

.PARAMETER UMTS3GFailover
    Optional. Enables 3G/UMTS failover: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER OperationMode
    Optional. How the remote network is integrated: 'Standard', 'Split' or 'Transparent'.

.PARAMETER IPAddress
    Optional. IP address of the RED device's local bridge interface.

.PARAMETER NetMask
    Optional. Netmask of the RED device's local bridge interface.

.PARAMETER Zone
    Optional. Zone the RED device's local interface belongs to.

.PARAMETER TunnelCompression
    Optional. Enables tunnel compression: 'Enable' or 'Disable'. Default: 'Disable'.

.PARAMETER RemoteIPAssignment
    Optional. Bridge IP assignment on the RED end: 'NoIPAddress', 'DHCP' or 'Static'. RED20
    and RED60 only. Default: 'NoIPAddress'.

.PARAMETER RemoteTunnelIPv4Address
    Optional. Static IPv4 address for the RED end of the tunnel. Only used when
    -RemoteIPAssignment is 'Static'.

.PARAMETER REDMTU
    Optional. MTU of the RED device, 576-1500. Default: 1500.

.PARAMETER Authorized
    Optional. Whether the device should be authorized: '0' or '1'. Default: '1'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosREDDevice -BranchName 'Branch Office' -Device red20 -REDDeviceID 'S0123456789' -UTMHostName 'vpn.example.invalid' -OperationMode Standard -IPAddress 198.51.100.50 -NetMask 255.255.255.0 -Zone DMZ -WhatIf

    Shows what registering the device would send, without sending it to the firewall.

.EXAMPLE
    New-SfosREDDevice -BranchName 'Branch Office' -Device red20 -REDDeviceID 'S0123456789' -UTMHostName 'vpn.example.invalid' -OperationMode Standard -IPAddress 198.51.100.50 -NetMask 255.255.255.0 -Zone DMZ

    Registers a RED20 device for the branch office, bridged into the DMZ zone. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/REDDevice/operations/AddREDDevice%26UpdateREDDevice.html

.LINK
    Get-SfosREDDevice

.LINK
    Set-SfosREDDevice
#>
function New-SfosREDDevice {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BranchName,

        [ValidateSet('RED15', 'RED15W', 'red20', 'RED50', 'red60', 'RED_FIREWALL_SERVER', 'RED_FIREWALL_SERVER_LEGACY', 'RED_FIREWALL_CLIENT', 'RED_FIREWALL_CLIENT_LEGACY')]
        [string]$Device,

        [Parameter(Mandatory)]
        [string]$REDDeviceID,

        [string]$TunnelID,

        [string]$UnlockCode,

        [Parameter(Mandatory)]
        [string]$UTMHostName,

        [string]$SecondUTMHostName,

        [ValidateSet('AutoDeployment', 'ManualDeployment')]
        [string]$DeploymentMode = 'ManualDeployment',

        [ValidateSet('DHCP', 'Static')]
        [string]$UplinkConnection = 'DHCP',

        [string]$UplinkAddress,

        [string]$UplinkNetmask,

        [string]$UplinkDefaultGateway,

        [string]$UplinkDNS,

        [ValidateSet('Enable', 'Disable')]
        [string]$UMTS3GFailover = 'Disable',

        [Parameter(Mandatory)]
        [ValidateSet('Standard', 'Split', 'Transparent')]
        [string]$OperationMode,

        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$NetMask,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Zone,

        [ValidateSet('Enable', 'Disable')]
        [string]$TunnelCompression = 'Disable',

        [ValidateSet('NoIPAddress', 'DHCP', 'Static')]
        [string]$RemoteIPAssignment = 'NoIPAddress',

        [string]$RemoteTunnelIPv4Address,

        [ValidateRange(576, 1500)]
        [int]$REDMTU = 1500,

        [ValidateSet('0', '1')]
        [string]$Authorized = '1',

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $deviceXml = ''
    if ($Device) {
        $deviceXml = "<Device>$(ConvertTo-SfosXmlEscaped -Text $Device)</Device>"
    }

    $uplinkStaticXml = ''
    if ($UplinkConnection -eq 'Static') {
        $uplinkStaticXml = "<Address>$(ConvertTo-SfosXmlEscaped -Text $UplinkAddress)</Address><Netmask>$(ConvertTo-SfosXmlEscaped -Text $UplinkNetmask)</Netmask><DefaultGateway>$(ConvertTo-SfosXmlEscaped -Text $UplinkDefaultGateway)</DefaultGateway><DNS>$(ConvertTo-SfosXmlEscaped -Text $UplinkDNS)</DNS>"
    }

    $remoteTunnelXml = ''
    if ($RemoteIPAssignment -eq 'Static') {
        $remoteTunnelXml = "<RemoteTunnelIPv4Address>$(ConvertTo-SfosXmlEscaped -Text $RemoteTunnelIPv4Address)</RemoteTunnelIPv4Address>"
    }

    $inner = @"
<Set operation="add">
  <REDDevice transactionid="">
    <BranchName>$(ConvertTo-SfosXmlEscaped -Text $BranchName)</BranchName>
    $deviceXml
    <REDDeviceID>$(ConvertTo-SfosXmlEscaped -Text $REDDeviceID)</REDDeviceID>
    <TunnelID>$(ConvertTo-SfosXmlEscaped -Text $TunnelID)</TunnelID>
    <UnlockCode>$(ConvertTo-SfosXmlEscaped -Text $UnlockCode)</UnlockCode>
    <UTMHostName>$(ConvertTo-SfosXmlEscaped -Text $UTMHostName)</UTMHostName>
    <SecondUTMHostName>$(ConvertTo-SfosXmlEscaped -Text $SecondUTMHostName)</SecondUTMHostName>
    <DeploymentMode>$DeploymentMode</DeploymentMode>
    <UplinkSettings>
      <Uplink>
        <Connection>$UplinkConnection</Connection>
        $uplinkStaticXml
      </Uplink>
      <UMTS3GFailover>$UMTS3GFailover</UMTS3GFailover>
    </UplinkSettings>
    <Authorized>$Authorized</Authorized>
    <NetworkSetting>
      <OperationMode>$OperationMode</OperationMode>
      <IPAddress>$(ConvertTo-SfosXmlEscaped -Text $IPAddress)</IPAddress>
      <NetMask>$(ConvertTo-SfosXmlEscaped -Text $NetMask)</NetMask>
      <Zone>$(ConvertTo-SfosXmlEscaped -Text $Zone)</Zone>
      <TunnelCompression>$TunnelCompression</TunnelCompression>
    </NetworkSetting>
    <REDMTU>$REDMTU</REDMTU>
    <AdvancedSettings>
      <RemoteIPAssignment>$RemoteIPAssignment</RemoteIPAssignment>
      $remoteTunnelXml
    </AdvancedSettings>
  </REDDevice>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("REDDevice '$BranchName' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating REDDevice object '$BranchName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'REDDevice' -Action 'create' -Target $BranchName
}

<#
.SYNOPSIS
    Updates a RED device on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing RED device. The cmdlet reads the current object first
    and sends every field this module exposes back; fields you do not pass keep their current
    value. It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER BranchName
    Required. Name of the RED device to update. Accepts pipeline input by property name.

.PARAMETER REDDeviceID
    Optional. Serial or device ID of the physical RED device. If omitted, the current value is
    kept.

.PARAMETER UTMHostName
    Optional. Host name the RED device uses to reach this firewall. If omitted, the current
    value is kept.

.PARAMETER DeploymentMode
    Optional. 'AutoDeployment' or 'ManualDeployment'. If omitted, the current value is kept.

.PARAMETER UplinkConnection
    Optional. Primary uplink connection type: 'DHCP' or 'Static'. If omitted, the current
    value is kept.

.PARAMETER UMTS3GFailover
    Optional. Enables 3G/UMTS failover. If omitted, the current value is kept.

.PARAMETER OperationMode
    Optional. 'Standard', 'Split' or 'Transparent'. If omitted, the current value is kept.

.PARAMETER IPAddress
    Optional. IP address of the RED device's local bridge interface. If omitted, the current
    value is kept.

.PARAMETER NetMask
    Optional. Netmask of the RED device's local bridge interface. If omitted, the current
    value is kept.

.PARAMETER Zone
    Optional. Zone the RED device's local interface belongs to. If omitted, the current value
    is kept.

.PARAMETER TunnelCompression
    Optional. Enables tunnel compression. If omitted, the current value is kept.

.PARAMETER REDMTU
    Optional. MTU of the RED device, 576-1500. If omitted, the current value is kept.

.PARAMETER Authorized
    Optional. Whether the device should be authorized: '0' or '1'. If omitted, the current
    value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosREDDevice result can be piped in;
    BranchName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosREDDevice -BranchName 'Branch Office' -Authorized 0 -WhatIf

    Shows what revoking authorization would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosREDDevice -BranchName 'Branch Office' -Authorized 0

    Revokes authorization for the RED device at Branch Office; every other field is preserved.
    The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/REDDevice/operations/AddREDDevice%26UpdateREDDevice.html

.LINK
    Get-SfosREDDevice

.LINK
    New-SfosREDDevice
#>
function Set-SfosREDDevice {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$BranchName,

        [string]$REDDeviceID,

        [string]$UTMHostName,

        [ValidateSet('AutoDeployment', 'ManualDeployment')]
        [string]$DeploymentMode,

        [ValidateSet('DHCP', 'Static')]
        [string]$UplinkConnection,

        [ValidateSet('Enable', 'Disable')]
        [string]$UMTS3GFailover,

        [ValidateSet('Standard', 'Split', 'Transparent')]
        [string]$OperationMode,

        [string]$IPAddress,

        [string]$NetMask,

        [string]$Zone,

        [ValidateSet('Enable', 'Disable')]
        [string]$TunnelCompression,

        [ValidateRange(576, 1500)]
        [int]$REDMTU,

        [ValidateSet('0', '1')]
        [string]$Authorized,

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
        $existing = @(Get-SfosREDDevice -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.BranchName -eq $BranchName })

        if ($existing.Count -eq 0) {
            throw "The REDDevice object '$BranchName' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetREDDeviceID = if ($bp.ContainsKey('REDDeviceID')) { $REDDeviceID } else { [string]$current.REDDeviceID }
        $targetUTMHostName = if ($bp.ContainsKey('UTMHostName')) { $UTMHostName } else { [string]$current.UTMHostName }
        $targetDeploymentMode = if ($bp.ContainsKey('DeploymentMode')) { $DeploymentMode } else { [string]$current.DeploymentMode }
        $targetUplinkConnection = if ($bp.ContainsKey('UplinkConnection')) { $UplinkConnection } else { [string]$current.UplinkConnection }
        $targetUMTS3G = if ($bp.ContainsKey('UMTS3GFailover')) { $UMTS3GFailover } else { [string]$current.UMTS3GFailover }
        $targetOperationMode = if ($bp.ContainsKey('OperationMode')) { $OperationMode } else { [string]$current.OperationMode }
        $targetIPAddress = if ($bp.ContainsKey('IPAddress')) { $IPAddress } else { [string]$current.IPAddress }
        $targetNetMask = if ($bp.ContainsKey('NetMask')) { $NetMask } else { [string]$current.NetMask }
        $targetZone = if ($bp.ContainsKey('Zone')) { $Zone } else { [string]$current.Zone }
        $targetTunnelCompression = if ($bp.ContainsKey('TunnelCompression')) { $TunnelCompression } else { [string]$current.TunnelCompression }
        $targetREDMTU = if ($bp.ContainsKey('REDMTU')) { $REDMTU } else { [int]$current.REDMTU }
        $targetAuthorized = if ($bp.ContainsKey('Authorized')) { $Authorized } else { [string]$current.Authorized }

        if (-not $PSCmdlet.ShouldProcess("REDDevice '$BranchName' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="update">
  <REDDevice transactionid="">
    <BranchName>$(ConvertTo-SfosXmlEscaped -Text $BranchName)</BranchName>
    <REDDeviceID>$(ConvertTo-SfosXmlEscaped -Text $targetREDDeviceID)</REDDeviceID>
    <UTMHostName>$(ConvertTo-SfosXmlEscaped -Text $targetUTMHostName)</UTMHostName>
    <DeploymentMode>$targetDeploymentMode</DeploymentMode>
    <UplinkSettings>
      <Uplink>
        <Connection>$targetUplinkConnection</Connection>
      </Uplink>
      <UMTS3GFailover>$targetUMTS3G</UMTS3GFailover>
    </UplinkSettings>
    <Authorized>$targetAuthorized</Authorized>
    <NetworkSetting>
      <OperationMode>$targetOperationMode</OperationMode>
      <IPAddress>$(ConvertTo-SfosXmlEscaped -Text $targetIPAddress)</IPAddress>
      <NetMask>$(ConvertTo-SfosXmlEscaped -Text $targetNetMask)</NetMask>
      <Zone>$(ConvertTo-SfosXmlEscaped -Text $targetZone)</Zone>
      <TunnelCompression>$targetTunnelCompression</TunnelCompression>
    </NetworkSetting>
    <REDMTU>$targetREDMTU</REDMTU>
  </REDDevice>
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
            throw "Error updating REDDevice object '$BranchName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'REDDevice' -Action 'update' -Target $BranchName
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes a RED device from a Sophos Firewall.

.DESCRIPTION
    Deletes a REDDevice object. The firewall identifies the device by its device ID, not by
    name; this cmdlet resolves the device ID through Get-SfosREDDevice when the caller
    supplies -BranchName instead. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER BranchName
    Optional. Name of the RED device to remove. Used to resolve -REDDeviceID through
    Get-SfosREDDevice when -REDDeviceID is not supplied directly.

.PARAMETER REDDeviceID
    Optional. Device ID of the RED device to remove. If omitted, it is resolved automatically
    with Get-SfosREDDevice using -BranchName. Accepts pipeline input by property name, so
    Get-SfosREDDevice | Remove-SfosREDDevice supplies it directly without an extra round trip.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosREDDevice result can be piped in;
    BranchName and REDDeviceID bind by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosREDDevice -BranchName 'Branch Office' -WhatIf

    Shows what removing the device would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosREDDevice -BranchName 'Branch Office'

    Removes the RED device registered for Branch Office. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/REDDevice/operations/Delete%20RED.html

.LINK
    Get-SfosREDDevice
#>
function Remove-SfosREDDevice {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$BranchName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$REDDeviceID,

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
        $targetDeviceID = $REDDeviceID
        if (-not $targetDeviceID) {
            $existing = @(Get-SfosREDDevice -Firewall $params.Firewall `
                    -Port $params.Port `
                    -Username $params.Username `
                    -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.BranchName -eq $BranchName })

            if ($existing.Count -eq 0) {
                throw "The REDDevice object '$BranchName' was not found."
            }
            $targetDeviceID = [string]$existing[0].REDDeviceID
        }

        if (-not $PSCmdlet.ShouldProcess("REDDevice '$BranchName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Remove>
  <REDDevice>
    <REDDeviceID>$(ConvertTo-SfosXmlEscaped -Text $targetDeviceID)</REDDeviceID>
  </REDDevice>
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
            throw "Error removing REDDevice object '$BranchName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'REDDevice' -Action 'remove' -Target $BranchName
    }
    end {
    }
}

#endregion


#region WiFi6Interface

# --- WiFi6Interface ---
#
# Doc folder and wire element both <WiFi6Interface>.
#
# The API response root carries the attribute IS_WIFI6="0" on an appliance without a WiFi6
# radio present or licensed. A <Set operation="add"> on such an appliance answers with only
# the <Login> block and no <WiFi6Interface> status element at all - the firewall silently
# drops the entire operation rather than validating or rejecting it. A follow-up Get still
# shows "No. of records Zero.".
#
# The functions below are implemented from the vendor sample XML and use this module's
# standard operation="add"/"update" and <Remove> conventions, since the doc for this
# entity - unlike GreRoute/TAP - does not document a divergent operation enum.

<#
.SYNOPSIS
    Retrieves local Wi-Fi 6 interfaces from a Sophos Firewall.

.DESCRIPTION
    Returns the WiFi6Interface objects that are defined on the firewall: local Wi-Fi 6 radio
    interfaces. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only interfaces whose name contains the given text anywhere. If omitted,
    the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per interface, with the properties
    Name, Hardware, Zone, IPv4Address and Netmask. Returns System.Xml.XmlElement when -AsXml
    is used, and an empty array when no interface matches.

.EXAMPLE
    Get-SfosWiFi6Interface

    Lists every local Wi-Fi 6 interface on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/WiFi6Interface/WiFi6Interface.html

.LINK
    New-SfosWiFi6Interface

.LINK
    Set-SfosWiFi6Interface
#>
function Get-SfosWiFi6Interface {
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

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <WiFi6Interface>
    $filterXml
  </WiFi6Interface>
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
        throw "Error retrieving WiFi6Interface objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WiFi6Interface' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/WiFi6Interface[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $interfaceObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name        = [string]$node.Name
            Hardware    = [string]$node.Hardware
            Zone        = [string]$node.Zone
            IPv4Address = [string]$node.IPv4Address
            Netmask     = [string]$node.Netmask
        }
    }

    return @($interfaceObjects)
}

<#
.SYNOPSIS
    Creates a local Wi-Fi 6 interface on a Sophos Firewall.

.DESCRIPTION
    Configures a local Wi-Fi 6 radio interface. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission. It applies only to appliances with built-in Wi-Fi 6 hardware.

.PARAMETER Name
    Required. Descriptive name of the interface, up to 58 characters.

.PARAMETER Hardware
    Required. Hardware name of the local Wi-Fi 6 interface.

.PARAMETER Zone
    Required. Zone the interface belongs to, for example 'LAN', 'WIFI' or 'None'.

.PARAMETER IPv4Address
    Optional. IPv4 address of the interface.

.PARAMETER Netmask
    Optional. IPv4 subnet mask of the interface, up to 15 characters.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosWiFi6Interface -Name 'Guest-WiFi6' -Hardware 'wifi0' -Zone WIFI -WhatIf

    Shows what creating the interface would send, without sending it to the firewall.

.EXAMPLE
    New-SfosWiFi6Interface -Name 'Guest-WiFi6' -Hardware 'wifi0' -Zone WIFI

    Creates a Wi-Fi 6 interface named Guest-WiFi6 in the WIFI zone. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/WiFi6Interface/operations/WiFi6Interface.html

.LINK
    Get-SfosWiFi6Interface

.LINK
    Set-SfosWiFi6Interface
#>
function New-SfosWiFi6Interface {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 58)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Hardware,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Zone,

        [string]$IPv4Address,

        [ValidateLength(0, 15)]
        [string]$Netmask,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = @"
<Set operation="add">
  <WiFi6Interface>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $Name)</Name>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $Hardware)</Hardware>
    <Zone>$(ConvertTo-SfosXmlEscaped -Text $Zone)</Zone>
    <IPv4Address>$(ConvertTo-SfosXmlEscaped -Text $IPv4Address)</IPv4Address>
    <Netmask>$(ConvertTo-SfosXmlEscaped -Text $Netmask)</Netmask>
  </WiFi6Interface>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("WiFi6Interface '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating WiFi6Interface object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WiFi6Interface' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates a local Wi-Fi 6 interface on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing local Wi-Fi 6 interface. The cmdlet reads the current
    object first and sends every field back; fields you do not pass keep their current value.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER Name
    Required. Name of the interface to update. Accepts pipeline input by property name.

.PARAMETER Hardware
    Optional. Hardware name of the local Wi-Fi 6 interface. If omitted, the current value is
    kept.

.PARAMETER Zone
    Optional. Zone the interface belongs to. If omitted, the current value is kept.

.PARAMETER IPv4Address
    Optional. IPv4 address of the interface. If omitted, the current value is kept.

.PARAMETER Netmask
    Optional. IPv4 subnet mask of the interface. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosWiFi6Interface result can be piped
    in; Name binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosWiFi6Interface -Name 'Guest-WiFi6' -Zone LAN -WhatIf

    Shows what moving the interface to the LAN zone would send, without sending it to the
    firewall.

.EXAMPLE
    Set-SfosWiFi6Interface -Name 'Guest-WiFi6' -Zone LAN

    Moves the interface named Guest-WiFi6 to the LAN zone; every other field is preserved. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/WiFi6Interface/operations/WiFi6Interface.html

.LINK
    Get-SfosWiFi6Interface

.LINK
    New-SfosWiFi6Interface
#>
function Set-SfosWiFi6Interface {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 58)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Hardware,

        [string]$Zone,

        [string]$IPv4Address,

        [ValidateLength(0, 15)]
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
        $existing = @(Get-SfosWiFi6Interface -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WiFi6Interface object '$Name' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetHardware = if ($bp.ContainsKey('Hardware')) { $Hardware } else { [string]$current.Hardware }
        $targetZone = if ($bp.ContainsKey('Zone')) { $Zone } else { [string]$current.Zone }
        $targetIPv4 = if ($bp.ContainsKey('IPv4Address')) { $IPv4Address } else { [string]$current.IPv4Address }
        $targetNetmask = if ($bp.ContainsKey('Netmask')) { $Netmask } else { [string]$current.Netmask }

        if (-not $PSCmdlet.ShouldProcess("WiFi6Interface '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="update">
  <WiFi6Interface>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $Name)</Name>
    <Hardware>$(ConvertTo-SfosXmlEscaped -Text $targetHardware)</Hardware>
    <Zone>$(ConvertTo-SfosXmlEscaped -Text $targetZone)</Zone>
    <IPv4Address>$(ConvertTo-SfosXmlEscaped -Text $targetIPv4)</IPv4Address>
    <Netmask>$(ConvertTo-SfosXmlEscaped -Text $targetNetmask)</Netmask>
  </WiFi6Interface>
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
            throw "Error updating WiFi6Interface object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WiFi6Interface' -Action 'update' -Target $Name
    }
    end {
    }
}

<#
.SYNOPSIS
    Removes a local Wi-Fi 6 interface from a Sophos Firewall.

.DESCRIPTION
    Deletes a WiFi6Interface object, identified by its name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Name
    Required. Name of the interface to remove. Accepts pipeline input by property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosWiFi6Interface result can be piped
    in; Name binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosWiFi6Interface -Name 'Guest-WiFi6' -WhatIf

    Shows what removing the interface would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosWiFi6Interface -Name 'Guest-WiFi6'

    Removes the interface named Guest-WiFi6. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/WiFi6Interface/operations/WiFi6Interface.html

.LINK
    Get-SfosWiFi6Interface
#>
function Remove-SfosWiFi6Interface {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 58)]
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
        if (-not $PSCmdlet.ShouldProcess("WiFi6Interface '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $inner = @"
<Remove>
  <WiFi6Interface>
    <Name>$(ConvertTo-SfosXmlEscaped -Text $Name)</Name>
  </WiFi6Interface>
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
            throw "Error removing WiFi6Interface object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WiFi6Interface' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion


#region Zone

<#
.SYNOPSIS
    Builds the ApplianceAccess XML fragment for a Zone entity.

.DESCRIPTION
    Turns the nested ApplianceAccess object, as returned by Get-SfosZone or built by hand with
    the same shape, into the XML fragment a Zone entity expects. Each of the five sub-groups
    (AdminServices, AuthenticationServices, NetworkServices, VPNServices, OtherServices) is
    only emitted when the corresponding sub-object is present, and each field within a group
    is only emitted when it has a value.

.PARAMETER ApplianceAccess
    PSCustomObject with optional AdminServices, AuthenticationServices, NetworkServices,
    VPNServices and OtherServices sub-objects, each holding Enable/Disable string fields.
#>
function ConvertTo-SfosZoneApplianceAccessXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [PSCustomObject]$ApplianceAccess
    )

    if (-not $ApplianceAccess) {
        return ''
    }

    $adminXml = ''
    if ($ApplianceAccess.AdminServices) {
        $a = $ApplianceAccess.AdminServices
        $f = ''
        if ($a.HTTPS) { $f += "<HTTPS>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.HTTPS))</HTTPS>" }
        if ($a.SSH) { $f += "<SSH>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.SSH))</SSH>" }
        $adminXml = "<AdminServices>$f</AdminServices>"
    }

    $authXml = ''
    if ($ApplianceAccess.AuthenticationServices) {
        $a = $ApplianceAccess.AuthenticationServices
        $f = ''
        if ($a.ClientAuthentication) { $f += "<ClientAuthentication>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.ClientAuthentication))</ClientAuthentication>" }
        if ($a.CaptivePortal) { $f += "<CaptivePortal>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.CaptivePortal))</CaptivePortal>" }
        if ($a.ADSSO) { $f += "<ADSSO>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.ADSSO))</ADSSO>" }
        if ($a.RadiusSSO) { $f += "<RadiusSSO>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.RadiusSSO))</RadiusSSO>" }
        if ($a.ChromebookSSO) { $f += "<ChromebookSSO>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.ChromebookSSO))</ChromebookSSO>" }
        $authXml = "<AuthenticationServices>$f</AuthenticationServices>"
    }

    $netXml = ''
    if ($ApplianceAccess.NetworkServices) {
        $a = $ApplianceAccess.NetworkServices
        $f = ''
        if ($a.DNS) { $f += "<DNS>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.DNS))</DNS>" }
        if ($a.Ping) { $f += "<Ping>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.Ping))</Ping>" }
        $netXml = "<NetworkServices>$f</NetworkServices>"
    }

    $vpnXml = ''
    if ($ApplianceAccess.VPNServices) {
        $a = $ApplianceAccess.VPNServices
        $f = ''
        if ($a.IPsec) { $f += "<IPsec>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.IPsec))</IPsec>" }
        if ($a.RED) { $f += "<RED>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.RED))</RED>" }
        if ($a.SSLVPN) { $f += "<SSLVPN>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.SSLVPN))</SSLVPN>" }
        if ($a.VPNPortal) { $f += "<VPNPortal>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.VPNPortal))</VPNPortal>" }
        $vpnXml = "<VPNServices>$f</VPNServices>"
    }

    $otherXml = ''
    if ($ApplianceAccess.OtherServices) {
        $a = $ApplianceAccess.OtherServices
        $f = ''
        if ($a.WebProxy) { $f += "<WebProxy>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.WebProxy))</WebProxy>" }
        if ($a.WirelessProtection) { $f += "<WirelessProtection>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.WirelessProtection))</WirelessProtection>" }
        if ($a.UserPortal) { $f += "<UserPortal>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.UserPortal))</UserPortal>" }
        if ($a.DynamicRouting) { $f += "<DynamicRouting>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.DynamicRouting))</DynamicRouting>" }
        if ($a.SMTPRelay) { $f += "<SMTPRelay>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.SMTPRelay))</SMTPRelay>" }
        if ($a.SNMP) { $f += "<SNMP>$(ConvertTo-SfosXmlEscaped -Text ([string]$a.SNMP))</SNMP>" }
        $otherXml = "<OtherServices>$f</OtherServices>"
    }

    if (-not ($adminXml -or $authXml -or $netXml -or $vpnXml -or $otherXml)) {
        return ''
    }

    return "<ApplianceAccess>$adminXml$authXml$netXml$vpnXml$otherXml</ApplianceAccess>"
}

<#
.SYNOPSIS
    Retrieves Zone objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for Zone objects. By default the cmdlet returns
    PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

.PARAMETER NameLike
    Optional. Returns only zones whose name contains the given text anywhere. If omitted, the
    name is not used to filter.

.PARAMETER TypeLike
    Optional. Returns only zones whose type contains the given text anywhere. Applied on the
    client. If omitted, the type is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per zone, with the properties
    Name, Type, Description, MemberPorts and ApplianceAccess, a nested object with the
    AdminServices, AuthenticationServices, NetworkServices, VPNServices and OtherServices
    groups. Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no zone
    matches.

.EXAMPLE
    Get-SfosZone

    Lists every zone on the firewall of the current connection.

.EXAMPLE
    (Get-SfosZone -NameLike 'LAN').ApplianceAccess.AdminServices

    Shows the admin access settings (HTTPS, SSH) of the LAN zone.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Zone/Zone.html

.LINK
    New-SfosZone

.LINK
    Set-SfosZone
#>
function Get-SfosZone {
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
  <Zone>
    $filterXml
  </Zone>
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
        throw "Error retrieving Zone objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Zone' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/Zone[Name]' | ForEach-Object -Process { $_.Node }

    $zoneObjects = foreach ($node in @($nodes)) {
        $memberPorts = [string[]]@()
        if ($node.MemberPorts) {
            $memberPorts = [string[]]@(([string]$node.MemberPorts) -split ',' | Where-Object -FilterScript { $_ })
        }

        $applianceAccess = $null
        $aaNode = $node.ApplianceAccess
        if ($aaNode) {
            $adminServices = $null
            if ($aaNode.AdminServices) {
                $adminServices = [PSCustomObject]@{
                    HTTPS = [string]$aaNode.AdminServices.HTTPS
                    SSH   = [string]$aaNode.AdminServices.SSH
                }
            }
            $authServices = $null
            if ($aaNode.AuthenticationServices) {
                $authServices = [PSCustomObject]@{
                    ClientAuthentication = [string]$aaNode.AuthenticationServices.ClientAuthentication
                    CaptivePortal        = [string]$aaNode.AuthenticationServices.CaptivePortal
                    ADSSO                = [string]$aaNode.AuthenticationServices.ADSSO
                    RadiusSSO            = [string]$aaNode.AuthenticationServices.RadiusSSO
                    ChromebookSSO        = [string]$aaNode.AuthenticationServices.ChromebookSSO
                }
            }
            $networkServices = $null
            if ($aaNode.NetworkServices) {
                $networkServices = [PSCustomObject]@{
                    DNS  = [string]$aaNode.NetworkServices.DNS
                    Ping = [string]$aaNode.NetworkServices.Ping
                }
            }
            $vpnServices = $null
            if ($aaNode.VPNServices) {
                $vpnServices = [PSCustomObject]@{
                    IPsec     = [string]$aaNode.VPNServices.IPsec
                    RED       = [string]$aaNode.VPNServices.RED
                    SSLVPN    = [string]$aaNode.VPNServices.SSLVPN
                    VPNPortal = [string]$aaNode.VPNServices.VPNPortal
                }
            }
            $otherServices = $null
            if ($aaNode.OtherServices) {
                $otherServices = [PSCustomObject]@{
                    WebProxy           = [string]$aaNode.OtherServices.WebProxy
                    WirelessProtection = [string]$aaNode.OtherServices.WirelessProtection
                    UserPortal         = [string]$aaNode.OtherServices.UserPortal
                    DynamicRouting     = [string]$aaNode.OtherServices.DynamicRouting
                    SMTPRelay          = [string]$aaNode.OtherServices.SMTPRelay
                    SNMP               = [string]$aaNode.OtherServices.SNMP
                }
            }

            $applianceAccess = [PSCustomObject]@{
                AdminServices          = $adminServices
                AuthenticationServices = $authServices
                NetworkServices        = $networkServices
                VPNServices            = $vpnServices
                OtherServices          = $otherServices
            }
        }

        [PSCustomObject]@{
            Name             = [string]$node.Name
            Type             = [string]$node.Type
            Description      = [string]$node.Description
            MemberPorts      = $memberPorts
            ApplianceAccess  = $applianceAccess
        }
    }

    $zoneObjects = @($zoneObjects)
    if ($NameLike) {
        $zoneObjects = @($zoneObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($TypeLike) {
        $zoneObjects = @($zoneObjects | Where-Object -FilterScript { $_.Type -like "*$TypeLike*" })
    }

    if ($AsXml) {
        $keptNames = @($zoneObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $zoneObjects
}

<#
.SYNOPSIS
    Creates a zone on a Sophos Firewall.

.DESCRIPTION
    Adds a Zone object: a logical grouping of physical interfaces and ports, with its own
    ApplianceAccess settings. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

    The zone that carries the current management or API connection also carries the
    ApplianceAccess flags that allow that connection to reach the firewall at all. Creating a
    zone itself does not change an existing zone, but reusing the same ApplianceAccess shape
    later in Set-SfosZone on that zone can remove the reachability of your own session; see
    Set-SfosZone before changing an existing zone's access.

.PARAMETER Name
    Required. Name to identify the zone. The first character must be alphanumeric and not a
    leading zero; the rest may be alphanumeric or underscore. Up to 60 characters.

.PARAMETER Type
    Required. Zone type: 'LAN', 'WAN', 'DMZ', 'LOCAL', 'VPN' or 'Discover'.

.PARAMETER Description
    Optional. Zone description, up to 60 characters.

.PARAMETER ApplianceAccess
    Optional. Nested object describing administrative, authentication, network, VPN and other
    service access on this zone, in the same shape as the ApplianceAccess property returned by
    Get-SfosZone.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosZone -Name 'Extranet' -Type DMZ -WhatIf

    Shows what creating the zone would send, without sending it to the firewall.

.EXAMPLE
    New-SfosZone -Name 'Extranet' -Type DMZ

    Creates a DMZ-type zone named Extranet with no special appliance access. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Zone/operations/AddZone%26EditZone%26EditZonefromAPI.html

.LINK
    Get-SfosZone

.LINK
    Set-SfosZone
#>
function New-SfosZone {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[A-Za-z1-9][A-Za-z0-9_]*$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('LAN', 'WAN', 'DMZ', 'LOCAL', 'VPN', 'Discover')]
        [string]$Type,

        [ValidateLength(0, 60)]
        [string]$Description,

        [PSCustomObject]$ApplianceAccess,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("Zone '$Name' on $($params.Firewall)", 'Create')) {
        return
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $typeEsc = ConvertTo-SfosXmlEscaped -Text $Type
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Description)
    $aaXml = ConvertTo-SfosZoneApplianceAccessXml -ApplianceAccess $ApplianceAccess

    $inner = @"
<Set operation="add">
  <Zone>
    <Name>$nameEsc</Name>
    <Type>$typeEsc</Type>
    <Description>$descEsc</Description>
    $aaXml
  </Zone>
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
        throw "Failed to create Zone object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Zone' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates a zone on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing zone. The cmdlet reads the current zone first and
    sends every field back; fields you do not pass keep their current value, including every
    sub-group of ApplianceAccess when you omit -ApplianceAccess entirely. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

    If the zone you update carries the current management or API connection, changing its
    ApplianceAccess settings, for example disabling HTTPS or SSH, can make the firewall
    unreachable over the network. There is then no way to undo the change remotely; recovery
    needs local access to the appliance. Check the current settings with Get-SfosZone first,
    and use -WhatIf to preview the call.

.PARAMETER Name
    Required. Name of the zone to update. Accepts pipeline input by property name.

.PARAMETER Type
    Optional. Zone type: 'LAN', 'WAN', 'DMZ', 'LOCAL', 'VPN' or 'Discover'. If omitted, the
    current value is kept.

.PARAMETER Description
    Optional. Zone description. If omitted, the current value is kept.

.PARAMETER ApplianceAccess
    Optional. Nested appliance access object, in the same shape as returned by Get-SfosZone.
    If omitted, the current value, all five sub-groups, is kept unchanged.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosZone result can be piped in; Name
    binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosZone -Name 'Extranet' -Description 'Partner extranet' -WhatIf

    Shows what changing the description would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosZone -Name 'Extranet' -Description 'Partner extranet'

    Changes the description of the Extranet zone; ApplianceAccess and every other field are
    preserved. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Zone/operations/AddZone%26EditZone%26EditZonefromAPI.html

.LINK
    Get-SfosZone

.LINK
    New-SfosZone
#>
function Set-SfosZone {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [string]$Name,

        [ValidateSet('LAN', 'WAN', 'DMZ', 'LOCAL', 'VPN', 'Discover')]
        [string]$Type,

        [string]$Description,

        [PSCustomObject]$ApplianceAccess,

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
        $existing = @(Get-SfosZone -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The Zone object '$Name' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $targetType = if ($bp.ContainsKey('Type')) { $Type } else { $existing.Type }
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { $existing.Description }
        $targetAppliance = if ($bp.ContainsKey('ApplianceAccess')) { $ApplianceAccess } else { $existing.ApplianceAccess }

        if (-not $PSCmdlet.ShouldProcess("Zone '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $typeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetType)
        $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetDescription)
        $aaXml = ConvertTo-SfosZoneApplianceAccessXml -ApplianceAccess $targetAppliance

        $inner = @"
<Set operation="update">
  <Zone>
    <Name>$nameEsc</Name>
    <Type>$typeEsc</Type>
    <Description>$descEsc</Description>
    $aaXml
  </Zone>
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
            throw "Failed to update Zone object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Zone' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a zone from a Sophos Firewall.

.DESCRIPTION
    Deletes a Zone object, identified by its name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

    Removing the zone that carries the current management or API connection, such as the
    factory LAN zone, makes the firewall unreachable over the network. There is then no way to
    undo the removal remotely; recovery needs local access to the appliance.

.PARAMETER Name
    Required. Name of the zone to remove. Accepts pipeline input by property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosZone result can be piped in; Name
    binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosZone -Name 'Extranet' -WhatIf

    Shows what removing the zone would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosZone -Name 'Extranet'

    Removes the zone named Extranet. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Zone/operations/Delete%20Zone.html

.LINK
    Get-SfosZone
#>
function Remove-SfosZone {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        if (-not $PSCmdlet.ShouldProcess("Zone '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <Zone>
    <Name>$nameEsc</Name>
  </Zone>
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
            throw "Failed to remove Zone object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Zone' -Action 'delete' -Target $Name
    }
}

#endregion

#region GatewayConfiguration

# --- GatewayConfiguration ---
#
# Root element is <GatewayConfiguration>, not <Gateway> - a folder/element name mismatch.
# The list entries inside it are named <Gateway>.
#
# The vendor operations page for this entity documents only "Update Gateway" - there is no
# Add/Delete Gateway operation, and its own sample XML says so explicitly: "Gateway cannot
# be added using this tag, it can only be updated" (operations/UpdateGateway.html).
# Consequently this module exposes no New-/Remove- cmdlets for GatewayConfiguration or for
# individual Gateway entries - there is nothing documented for them to call. Building an
# entry is instead a local, non-API builder, New-SfosGatewayConfigurationGateway, whose
# result is passed into Set-SfosGatewayConfiguration -Gateway. This matches the codebase's
# existing precedent of Get/Set-only cmdlets for singleton-shaped entities
# (SophosFirewall.Firewall's SSLTLSInspectionSettings).
#
# GatewayConfiguration is a container, not a plain singleton: besides GatewayFailoverTimeout
# it holds a whole Gateway list, and SFOS replaces the entire container on update - an
# update that resends GatewayFailoverTimeout but omits the Gateway list, or sends an
# incomplete Gateway entry missing Weight/Type/FailOverRules, deletes the default route.
# Set-SfosGatewayConfiguration therefore always reads the current configuration first and
# writes back the complete Gateway list (every field of every entry, including nested
# FailOverRules) unless the caller explicitly supplies a replacement.

<#
.SYNOPSIS
    Retrieves the gateway configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the GatewayConfiguration singleton: the failover timeout and the list of
    configured gateways. There is exactly one instance of this object per firewall, and no
    name. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties
    GatewayFailoverTimeout and GatewayList, an array of gateway objects with the properties
    Name, IPFamily, IPAddress, Type, Weight, ActivateGatewayOnFailureOf, ActionOnActivation,
    ActionOnFailback, CustomWeight and FailOverRuleList. Returns System.Xml.XmlElement when
    -AsXml is used.

.EXAMPLE
    Get-SfosGatewayConfiguration

    Returns the current gateway configuration.

.EXAMPLE
    (Get-SfosGatewayConfiguration).GatewayList[0].FailOverRuleList

    Shows the failover rules of the first configured gateway.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Gateway/Gateway.html

.LINK
    Set-SfosGatewayConfiguration
#>
function Get-SfosGatewayConfiguration {
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

    $inner = '<Get><GatewayConfiguration></GatewayConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving GatewayConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GatewayConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/GatewayConfiguration')
    if (-not $node) {
        throw 'GatewayConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $gatewayNodes = @($node.SelectNodes('Gateway'))
    $gatewayList = foreach ($gwNode in $gatewayNodes) {
        $ruleNodes = @($gwNode.SelectNodes('FailOverRules/Rule'))
        $ruleList = foreach ($ruleNode in $ruleNodes) {
            [PSCustomObject]@{
                Protocol  = [string]$ruleNode.Protocol
                IPAddress = [string]$ruleNode.IPAddress
                Port      = [string]$ruleNode.Port
                Condition = [string]$ruleNode.Condition
            }
        }

        [PSCustomObject]@{
            Name                       = [string]$gwNode.Name
            IPFamily                   = [string]$gwNode.IPFamily
            IPAddress                  = [string]$gwNode.IPAddress
            Type                       = [string]$gwNode.Type
            Weight                     = [string]$gwNode.Weight
            ActivateGatewayOnFailureOf = [string]$gwNode.ActivateGatewayOnFailureOf
            ActionOnActivation         = [string]$gwNode.ActionOnActivation
            ActionOnFailback           = [string]$gwNode.ActionOnFailback
            CustomWeight               = [string]$gwNode.CustomWeight
            FailOverRuleList           = [PSCustomObject[]]@($ruleList)
        }
    }

    return [PSCustomObject]@{
        GatewayFailoverTimeout = [string]$node.GatewayFailoverTimeout
        GatewayList            = [PSCustomObject[]]@($gatewayList)
    }
}

<#
.SYNOPSIS
    Resolves one Gateway field value between a caller-supplied parameter and a base object.

.DESCRIPTION
    Applies one precedence rule: an explicitly bound parameter always wins; otherwise, when a
    base object is available through -InputObject, that base's value is kept; otherwise the
    parameter's own default value is used.

.PARAMETER IsBound
    Whether the caller explicitly passed the parameter, from $PSBoundParameters.ContainsKey.

.PARAMETER Value
    The parameter's own value.

.PARAMETER BaseValue
    The corresponding value from -InputObject.

.PARAMETER HasBase
    Whether -InputObject was supplied at all.
#>
function Resolve-SfosGatewayFieldValue {
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
    Builds a gateway list entry for use with Set-SfosGatewayConfiguration.

.DESCRIPTION
    Builds one element of the gateway list for use with the -Gateway parameter of
    Set-SfosGatewayConfiguration. This cmdlet makes no API call; it only builds an in-memory
    object. Individual gateways cannot be created directly through the API, only through an
    update of the whole gateway list.

    Pass an existing entry, for example one element of
    (Get-SfosGatewayConfiguration).GatewayList, through -InputObject to keep every field you
    do not explicitly override, including the nested FailOverRuleList.

.PARAMETER InputObject
    Optional. Existing gateway object to use as a base. Accepts pipeline input. Fields you
    also pass as a parameter override the value from this object; every other field, including
    FailOverRuleList, is copied unchanged.

.PARAMETER Name
    Required. Name identifying the gateway. No comma allowed, up to 50 characters.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'. Default: 'IPv4'.

.PARAMETER IPAddress
    Optional. Gateway IP address.

.PARAMETER Type
    Optional. 'Active' or 'Backup'. Default: 'Active'.

.PARAMETER Weight
    Optional. Determines how much traffic passes through this link relative to another. Used
    for active IPv4 gateways.

.PARAMETER ActivateGatewayOnFailureOf
    Optional. Gateway activation condition for a backup gateway: 'Any', 'All', a specific
    gateway name, or 'Manual'.

.PARAMETER ActionOnActivation
    Optional. Action on activation of a backup gateway: 'InheritWeight' or 'UseCustomWeight'.

.PARAMETER ActionOnFailback
    Optional. Action for existing and new connections after failback:
    'ServeNewConnections' or 'ServeAllConnections'.

.PARAMETER CustomWeight
    Optional. Weight to use when -ActionOnActivation is 'UseCustomWeight'.

.PARAMETER FailOverRule
    Optional. Array of failover rule objects, each with Protocol ('PING' or 'TCP'), IPAddress,
    Port ('*' for any) and Condition ('AND' or 'OR') properties, the same shape as
    Get-SfosGatewayConfiguration's FailOverRuleList.

.INPUTS
    System.Management.Automation.PSCustomObject. A gateway object, for example one element of
    (Get-SfosGatewayConfiguration).GatewayList, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the same properties
    Get-SfosGatewayConfiguration returns for a GatewayList entry.

.EXAMPLE
    New-SfosGatewayConfigurationGateway -Name 'Backup-GW' -IPAddress '203.0.113.1' -Type Backup -Weight 1

    Builds a backup gateway entry from scratch, for use with Set-SfosGatewayConfiguration.

.EXAMPLE
    (Get-SfosGatewayConfiguration).GatewayList | New-SfosGatewayConfigurationGateway -Weight 5

    Takes every configured gateway and changes only the weight; every other field, including
    FailOverRuleList, keeps its current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Gateway/operations/UpdateGateway.html

.LINK
    Set-SfosGatewayConfiguration
#>
function New-SfosGatewayConfigurationGateway {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose - this function
    # builds an in-memory object and never calls the API, exactly like
    # New-SfosFirewallRuleNetworkPolicy in SophosFirewall.Firewall.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidatePattern('^[^,]+$')]
        [ValidateLength(1, 50)]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [string]$IPAddress,

        [ValidateSet('Active', 'Backup')]
        [string]$Type = 'Active',

        [string]$Weight,

        [string]$ActivateGatewayOnFailureOf,

        [ValidateSet('InheritWeight', 'UseCustomWeight')]
        [string]$ActionOnActivation,

        [ValidateSet('ServeNewConnections', 'ServeAllConnections')]
        [string]$ActionOnFailback,

        [string]$CustomWeight,

        [PSCustomObject[]]$FailOverRule
    )

    # process block, not a bare body: -InputObject takes pipeline input, and without it only
    # the last object of a multi-object pipeline would be built. Same shape as
    # New-SfosFirewallRuleNetworkPolicy in SophosFirewall.Firewall.
    process {
            $hasBase = [bool]$InputObject
            $bp = $PSBoundParameters

            $resolvedName = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('Name') -Value $Name -BaseValue $InputObject.Name -HasBase $hasBase
        $resolvedFamily = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('IPFamily') -Value $IPFamily -BaseValue $InputObject.IPFamily -HasBase $hasBase
        $resolvedAddress = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('IPAddress') -Value $IPAddress -BaseValue $InputObject.IPAddress -HasBase $hasBase
        $resolvedType = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('Type') -Value $Type -BaseValue $InputObject.Type -HasBase $hasBase
        $resolvedWeight = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('Weight') -Value $Weight -BaseValue $InputObject.Weight -HasBase $hasBase
        $resolvedActivate = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('ActivateGatewayOnFailureOf') -Value $ActivateGatewayOnFailureOf -BaseValue $InputObject.ActivateGatewayOnFailureOf -HasBase $hasBase
        $resolvedActionActivation = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('ActionOnActivation') -Value $ActionOnActivation -BaseValue $InputObject.ActionOnActivation -HasBase $hasBase
        $resolvedActionFailback = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('ActionOnFailback') -Value $ActionOnFailback -BaseValue $InputObject.ActionOnFailback -HasBase $hasBase
        $resolvedCustomWeight = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('CustomWeight') -Value $CustomWeight -BaseValue $InputObject.CustomWeight -HasBase $hasBase
        $resolvedRules = Resolve-SfosGatewayFieldValue -IsBound $bp.ContainsKey('FailOverRule') -Value $FailOverRule -BaseValue $InputObject.FailOverRuleList -HasBase $hasBase

        return [PSCustomObject]@{
            Name                       = $resolvedName
            IPFamily                   = $resolvedFamily
            IPAddress                  = $resolvedAddress
            Type                       = $resolvedType
            Weight                     = $resolvedWeight
            ActivateGatewayOnFailureOf = $resolvedActivate
            ActionOnActivation         = $resolvedActionActivation
            ActionOnFailback           = $resolvedActionFailback
            CustomWeight               = $resolvedCustomWeight
            FailOverRuleList           = [PSCustomObject[]]@($resolvedRules)
        }
    }
}

<#
.SYNOPSIS
    Builds the update XML body for the GatewayConfiguration entity.

.DESCRIPTION
    Turns a failover timeout and a full gateway list into the XML that
    Set-SfosGatewayConfiguration sends to the firewall. The caller is responsible for having
    already merged in every gateway entry it wants preserved; this function does not merge.

.PARAMETER GatewayFailoverTimeout
    Failover timeout in seconds.

.PARAMETER GatewayList
    Full list of gateway objects to write.
#>
function ConvertTo-SfosGatewayConfigurationXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$GatewayFailoverTimeout,

        [PSCustomObject[]]$GatewayList
    )

    $timeoutEsc = ConvertTo-SfosXmlEscaped -Text $GatewayFailoverTimeout

    $gatewaysXml = ''
    foreach ($gw in @($GatewayList)) {
        if (-not $gw) {
            continue
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.Name)
        $familyEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.IPFamily)
        $addressEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.IPAddress)
        $typeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.Type)
        $weightEsc = ConvertTo-SfosXmlEscaped -Text ([string]$gw.Weight)

        $activateXml = ''
        if ($gw.ActivateGatewayOnFailureOf) {
            $activateXml = "<ActivateGatewayOnFailureOf>$(ConvertTo-SfosXmlEscaped -Text ([string]$gw.ActivateGatewayOnFailureOf))</ActivateGatewayOnFailureOf>"
        }
        $actionActivationXml = ''
        if ($gw.ActionOnActivation) {
            $actionActivationXml = "<ActionOnActivation>$(ConvertTo-SfosXmlEscaped -Text ([string]$gw.ActionOnActivation))</ActionOnActivation>"
        }
        $actionFailbackXml = ''
        if ($gw.ActionOnFailback) {
            $actionFailbackXml = "<ActionOnFailback>$(ConvertTo-SfosXmlEscaped -Text ([string]$gw.ActionOnFailback))</ActionOnFailback>"
        }
        $customWeightXml = ''
        if ($gw.CustomWeight) {
            $customWeightXml = "<CustomWeight>$(ConvertTo-SfosXmlEscaped -Text ([string]$gw.CustomWeight))</CustomWeight>"
        }

        $rulesXml = ''
        foreach ($rule in @($gw.FailOverRuleList)) {
            if (-not $rule) {
                continue
            }
            $protocolEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Protocol)
            $ruleAddressEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.IPAddress)
            $portEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Port)
            $conditionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$rule.Condition)
            $rulesXml += "<Rule><Protocol>$protocolEsc</Protocol><IPAddress>$ruleAddressEsc</IPAddress><Port>$portEsc</Port><Condition>$conditionEsc</Condition></Rule>"
        }
        $failOverRulesXml = ''
        if ($rulesXml) {
            $failOverRulesXml = "<FailOverRules>$rulesXml</FailOverRules>"
        }

        $gatewaysXml += "<Gateway><Name>$nameEsc</Name><IPFamily>$familyEsc</IPFamily><IPAddress>$addressEsc</IPAddress><Type>$typeEsc</Type><Weight>$weightEsc</Weight>$activateXml$actionActivationXml$actionFailbackXml$customWeightXml$failOverRulesXml</Gateway>"
    }

    return "<Set operation=`"update`"><GatewayConfiguration><GatewayFailoverTimeout>$timeoutEsc</GatewayFailoverTimeout>$gatewaysXml</GatewayConfiguration></Set>"
}

<#
.SYNOPSIS
    Updates the gateway configuration of a Sophos Firewall.

.DESCRIPTION
    Changes the failover timeout, the gateway list, or both. The cmdlet reads the current
    configuration first and sends the complete gateway list back, every field of every entry
    including Weight, Type and the nested FailOverRules; entries you do not replace keep their
    current values. -GatewayFailoverTimeout and -Gateway are independent: passing one does not
    require passing the other. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER GatewayFailoverTimeout
    Optional. Failover timeout in seconds. If omitted, the current value is kept.

.PARAMETER Gateway
    Optional. Full replacement gateway list, typically built with
    New-SfosGatewayConfigurationGateway from the existing GatewayList so unrelated fields
    survive. If omitted, the current list is kept unchanged.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosGatewayConfiguration -GatewayFailoverTimeout 90 -WhatIf

    Shows what changing the failover timeout would send, without sending it to the firewall.
    The gateway list is resent unchanged.

.EXAMPLE
    Set-SfosGatewayConfiguration -GatewayFailoverTimeout 90

    Changes the failover timeout to 90 seconds; the gateway list is preserved. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/Gateway/operations/UpdateGateway.html

.LINK
    Get-SfosGatewayConfiguration
#>
function Set-SfosGatewayConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$GatewayFailoverTimeout,

        [PSCustomObject[]]$Gateway,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosGatewayConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetTimeout = if ($bp.ContainsKey('GatewayFailoverTimeout')) { $GatewayFailoverTimeout } else { $existing.GatewayFailoverTimeout }
    $targetGateways = if ($bp.ContainsKey('Gateway')) { $Gateway } else { $existing.GatewayList }

    if (-not $PSCmdlet.ShouldProcess("GatewayConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = ConvertTo-SfosGatewayConfigurationXml -GatewayFailoverTimeout ([string]$targetTimeout) -GatewayList $targetGateways

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating GatewayConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'GatewayConfiguration' -Action 'update'
}

#endregion

#region ARPConfiguration

# --- ARPConfiguration ---
#
# Singleton. Only Get/Set are exposed - there is one ARPConfiguration per firewall, with no
# Name and no create/delete operation, the same shape as SophosFirewall.Firewall's
# SSLTLSInspectionSettings.
#
# Root element is <ARPConfiguration> (folder ARPNeighbour, element ARPConfiguration). The
# whole-entity-replace rule applies even to this two-field singleton: an update carrying
# only ARPCacheEntryTimeOut with no Log element at all silently resets
# LogPossibleARPPoisoningAttempts to 'Disable'.

<#
.SYNOPSIS
    Retrieves the ARP configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the ARPConfiguration singleton: the device-wide ARP cache timeout and ARP
    poisoning logging setting. There is exactly one instance of this object per firewall, and
    no name. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties
    ARPCacheEntryTimeOut and LogPossibleARPPoisoningAttempts. Returns System.Xml.XmlElement
    when -AsXml is used.

.EXAMPLE
    Get-SfosARPConfiguration

    Returns the current ARP configuration.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/ARPNeighbour/ARPNeighbour.html

.LINK
    Set-SfosARPConfiguration
#>
function Get-SfosARPConfiguration {
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

    $inner = '<Get><ARPConfiguration></ARPConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ARPConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ARPConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/ARPConfiguration')
    if (-not $node) {
        throw 'ARPConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        ARPCacheEntryTimeOut             = [string]$node.ARPCacheEntryTimeOut
        LogPossibleARPPoisoningAttempts  = [string]$node.LogPossibleARPPoisoningAttempts
    }
}

<#
.SYNOPSIS
    Updates the ARP configuration of a Sophos Firewall.

.DESCRIPTION
    Changes the ARP cache timeout, the ARP poisoning logging setting, or both. The cmdlet
    reads the current settings first and sends both fields back; a field you do not pass keeps
    its current value. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER ARPCacheEntryTimeOut
    Optional. Minutes after which ARP cache entries are flushed, 1-500. If omitted, the
    current value is kept.

.PARAMETER LogPossibleARPPoisoningAttempts
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosARPConfiguration -ARPCacheEntryTimeOut 15 -WhatIf

    Shows what changing the cache timeout would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosARPConfiguration -ARPCacheEntryTimeOut 15

    Changes the ARP cache timeout to 15 minutes; the logging setting is preserved. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/ARPNeighbour/operations/ARPConfiguration.html

.LINK
    Get-SfosARPConfiguration
#>
function Set-SfosARPConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(1, 500)]
        [int]$ARPCacheEntryTimeOut,

        [ValidateSet('Enable', 'Disable')]
        [string]$LogPossibleARPPoisoningAttempts,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosARPConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetTimeout = if ($bp.ContainsKey('ARPCacheEntryTimeOut')) { $ARPCacheEntryTimeOut } else { $existing.ARPCacheEntryTimeOut }
    $targetLog = if ($bp.ContainsKey('LogPossibleARPPoisoningAttempts')) { $LogPossibleARPPoisoningAttempts } else { $existing.LogPossibleARPPoisoningAttempts }

    if (-not $PSCmdlet.ShouldProcess("ARPConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    $timeoutEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetTimeout)
    $logEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetLog)

    $inner = @"
<Set operation="update">
  <ARPConfiguration>
    <ARPCacheEntryTimeOut>$timeoutEsc</ARPCacheEntryTimeOut>
    <LogPossibleARPPoisoningAttempts>$logEsc</LogPossibleARPPoisoningAttempts>
  </ARPConfiguration>
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
        throw "Error updating ARPConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ARPConfiguration' -Action 'update'
}

#endregion

#region StaticARP

# --- StaticARP ---
#
# Root element is <StaticARP> (folder ARP, element StaticARP).
#
# The vendor documentation for Add/Edit Static Neighbour
# (operations/AddStaticNeighbour%26EditStaticNeighbour.html) is internally inconsistent
# with every other operations page in this API area: it is the only add/edit page with no
# <xmp> sample block at all, its field descriptions are literal placeholders ("Specify
# 'ipaddress'", "Specify 'neighname'") instead of prose, and it lists a mandatory
# 'neighname' field that does not appear anywhere on the wire.
#
#   - Interface is documented "Mandatory: No" but is enforced as mandatory and must be an
#     existing interface name - omitting it, sending it empty, or sending a name that does
#     not exist all answer the identical 501 "Configuration parameters validation failed",
#     InvalidParams=/StaticARP/Interface.
#   - A 'Name'/'neighname' element is accepted without complaint but never appears in the
#     Get response - entries created with no Name-like element at all succeed identically.
#     Since a field a Get-* does not expose is impossible to preserve on update, no Name
#     parameter is exposed by this module: the wire shape is
#     IPFamily/IPAddress/MACAddress/Interface/AddAsATrustedMACAddress only.
#   - AddAsATrustedMACAddress is documented "Only 'Enable' allowed", but a Get after
#     omitting it on Add returns 'Disable' - both values are real states.
#   - operation="update" answers 500 "Operation could not be performed on Entity" on every
#     attempt, regardless of which or how many fields are sent, including the identical
#     field set Get returned. operation="add" against an existing IPAddress answers 502
#     "Entity having same name already exists", confirming IPAddress is the effective
#     unique key. This firmware therefore does not support updating a StaticARP entry in
#     place at all - Set-SfosStaticARP below removes and recreates the entry, and says so.
#   - Filtering on IPAddress works server-side for both criteria="=" and criteria="like"
#     (substring); this is the only filter key this module relies on.

<#
.SYNOPSIS
    Retrieves static ARP entries from a Sophos Firewall.

.DESCRIPTION
    Returns the StaticARP objects that are defined on the firewall: static IP-to-MAC mappings.
    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER IPAddressLike
    Optional. Returns only entries whose IP address contains the given text anywhere. If
    omitted, the address is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per entry, with the properties
    IPFamily, IPAddress, MACAddress, Interface and AddAsATrustedMACAddress. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no entry matches.

.EXAMPLE
    Get-SfosStaticARP

    Lists every static ARP entry on the firewall of the current connection.

.EXAMPLE
    Get-SfosStaticARP -IPAddressLike '10.0.0.24'

    Returns entries whose IP address contains '10.0.0.24'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/ARP/ARP.html

.LINK
    New-SfosStaticARP

.LINK
    Set-SfosStaticARP
#>
function Get-SfosStaticARP {
    [CmdletBinding()]
    param(
        [string]$IPAddressLike,

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
    if ($IPAddressLike) {
        $ipLikeEsc = ConvertTo-SfosXmlEscaped -Text $IPAddressLike
        $filterXml = ('<Filter><key name="IPAddress" criteria="like">{0}</key></Filter>' -f $ipLikeEsc)
    }

    $inner = @"
<Get>
  <StaticARP>
    $filterXml
  </StaticARP>
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
        throw "Error retrieving StaticARP objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'StaticARP' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/StaticARP[IPAddress]' | ForEach-Object -Process { $_.Node }

    $entryObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            IPFamily                = [string]$node.IPFamily
            IPAddress                = [string]$node.IPAddress
            MACAddress               = [string]$node.MACAddress
            Interface                = [string]$node.Interface
            AddAsATrustedMACAddress  = [string]$node.AddAsATrustedMACAddress
        }
    }

    $entryObjects = @($entryObjects)
    if ($IPAddressLike) {
        $entryObjects = @($entryObjects | Where-Object -FilterScript { $_.IPAddress -like "*$IPAddressLike*" })
    }

    if ($AsXml) {
        $keptAddresses = @($entryObjects | ForEach-Object -Process { $_.IPAddress })
        return @($nodes | Where-Object -FilterScript { $keptAddresses -contains $_.IPAddress })
    }

    return $entryObjects
}

<#
.SYNOPSIS
    Creates a static ARP entry on a Sophos Firewall.

.DESCRIPTION
    Adds a static IP-to-MAC mapping. The IP address is the entry's effective unique key;
    adding an IP address that already has an entry fails. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER IPAddress
    Required. IP address for the static mapping.

.PARAMETER MACAddress
    Required. MAC address to map the IP address to.

.PARAMETER Interface
    Required. Interface the mapping applies to. Must be an existing interface name.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'. Default: 'IPv4'.

.PARAMETER AddAsATrustedMACAddress
    Optional. 'Enable' or 'Disable'. If omitted, the firewall defaults to 'Disable'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosStaticARP -IPAddress '192.0.2.10' -MACAddress '00:11:22:33:44:55' -Interface 'Port1' -WhatIf

    Shows what creating the mapping would send, without sending it to the firewall.

.EXAMPLE
    New-SfosStaticARP -IPAddress '192.0.2.10' -MACAddress '00:11:22:33:44:55' -Interface 'Port1'

    Maps 192.0.2.10 to the given MAC address on Port1. The cmdlet asks for confirmation before
    it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/ARP/operations/AddStaticNeighbour%26EditStaticNeighbour.html

.LINK
    Get-SfosStaticARP

.LINK
    Set-SfosStaticARP
#>
function New-SfosStaticARP {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [string]$MACAddress,

        [Parameter(Mandatory)]
        [string]$Interface,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [ValidateSet('Enable', 'Disable')]
        [string]$AddAsATrustedMACAddress,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("StaticARP '$IPAddress' on $($params.Firewall)", 'Create')) {
        return
    }

    $ipEsc = ConvertTo-SfosXmlEscaped -Text $IPAddress
    $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress
    $ifaceEsc = ConvertTo-SfosXmlEscaped -Text $Interface
    $familyEsc = ConvertTo-SfosXmlEscaped -Text $IPFamily

    $trustedXml = ''
    if ($AddAsATrustedMACAddress) {
        $trustedXml = "<AddAsATrustedMACAddress>$(ConvertTo-SfosXmlEscaped -Text $AddAsATrustedMACAddress)</AddAsATrustedMACAddress>"
    }

    $inner = @"
<Set operation="add">
  <StaticARP>
    <IPAddress>$ipEsc</IPAddress>
    <MACAddress>$macEsc</MACAddress>
    <IPFamily>$familyEsc</IPFamily>
    <Interface>$ifaceEsc</Interface>
    $trustedXml
  </StaticARP>
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
        throw "Failed to create StaticARP object '$IPAddress': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'StaticARP' -Action 'create' -Target $IPAddress
}

<#
.SYNOPSIS
    Updates a static ARP entry on a Sophos Firewall.

.DESCRIPTION
    Changes the MAC address, interface, IP family or trusted-MAC setting of an existing
    StaticARP entry, identified by its IP address. There is no in-place update for this
    entity, so the cmdlet removes the existing entry and recreates it with the merged field
    values; fields you do not pass keep their current value. The IP address itself, the
    entry's key, cannot be changed; remove the old entry and create a new one instead. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

    The entry does not exist for a brief moment between the removal and the recreate. If the
    recreate step fails after the removal succeeded, the mapping is gone until it is created
    again by hand.

.PARAMETER IPAddress
    Required. IP address identifying the entry to change. Accepts pipeline input by value and
    by property name. Cannot itself be changed by this cmdlet.

.PARAMETER MACAddress
    Optional. New MAC address. If omitted, the current value is kept.

.PARAMETER Interface
    Optional. New interface. If omitted, the current value is kept.

.PARAMETER IPFamily
    Optional. New IP family. If omitted, the current value is kept.

.PARAMETER AddAsATrustedMACAddress
    Optional. New trusted-MAC setting. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosStaticARP result can be piped in;
    IPAddress binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the removal or the recreate step
    fails.

.EXAMPLE
    Set-SfosStaticARP -IPAddress '192.0.2.10' -MACAddress '00:11:22:33:44:66' -WhatIf

    Shows what changing the MAC address would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosStaticARP -IPAddress '192.0.2.10' -MACAddress '00:11:22:33:44:66'

    Changes the MAC address of the entry for 192.0.2.10; interface and other fields are
    preserved. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/ARP/operations/AddStaticNeighbour%26EditStaticNeighbour.html

.LINK
    Get-SfosStaticARP

.LINK
    New-SfosStaticARP
#>
function Set-SfosStaticARP {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$IPAddress,

        [string]$MACAddress,

        [string]$Interface,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [ValidateSet('Enable', 'Disable')]
        [string]$AddAsATrustedMACAddress,

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
        $existing = @(Get-SfosStaticARP -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -IPAddressLike $IPAddress `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.IPAddress -eq $IPAddress })

        if ($existing.Count -eq 0) {
            throw "The StaticARP object '$IPAddress' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $targetMac = if ($bp.ContainsKey('MACAddress')) { $MACAddress } else { $existing.MACAddress }
        $targetIface = if ($bp.ContainsKey('Interface')) { $Interface } else { $existing.Interface }
        $targetFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { $existing.IPFamily }
        $targetTrusted = if ($bp.ContainsKey('AddAsATrustedMACAddress')) { $AddAsATrustedMACAddress } else { $existing.AddAsATrustedMACAddress }

        if (-not $PSCmdlet.ShouldProcess("StaticARP '$IPAddress' on $($params.Firewall)", 'Recreate (operation=update is not supported by this firmware for StaticARP)')) {
            return
        }

        $ipEsc = ConvertTo-SfosXmlEscaped -Text $IPAddress

        $innerRemove = @"
<Remove>
  <StaticARP>
    <IPAddress>$ipEsc</IPAddress>
  </StaticARP>
</Remove>
"@

        try {
            $responseRemove = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $innerRemove -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update StaticARP object '$IPAddress' (remove step): $($_.Exception.Message)"
        }
        $XmlRemove = [xml]$responseRemove.Content
        Assert-SfosApiReturnSuccess -Xml $XmlRemove -ObjectName 'StaticARP' -Action 'update (remove step)' -Target $IPAddress

        $macEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetMac)
        $ifaceEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetIface)
        $familyEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetFamily)
        $trustedXml = ''
        if ($targetTrusted) {
            $trustedXml = "<AddAsATrustedMACAddress>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetTrusted))</AddAsATrustedMACAddress>"
        }

        $innerAdd = @"
<Set operation="add">
  <StaticARP>
    <IPAddress>$ipEsc</IPAddress>
    <MACAddress>$macEsc</MACAddress>
    <IPFamily>$familyEsc</IPFamily>
    <Interface>$ifaceEsc</Interface>
    $trustedXml
  </StaticARP>
</Set>
"@

        try {
            $responseAdd = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $innerAdd -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update StaticARP object '$IPAddress' (recreate step) - the original entry was already removed and no longer exists: $($_.Exception.Message)"
        }
        $XmlAdd = [xml]$responseAdd.Content
        Assert-SfosApiReturnSuccess -Xml $XmlAdd -ObjectName 'StaticARP' -Action 'update (recreate step)' -Target $IPAddress
    }
}

<#
.SYNOPSIS
    Removes a static ARP entry from a Sophos Firewall.

.DESCRIPTION
    Deletes a StaticARP entry, identified by its IP address. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER IPAddress
    Required. IP address of the entry to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosStaticARP result can be piped in;
    IPAddress binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosStaticARP -IPAddress '192.0.2.10' -WhatIf

    Shows what removing the entry would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosStaticARP -IPAddress '192.0.2.10'

    Removes the static ARP entry for 192.0.2.10. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/ARP/operations/Delete%20Static%20ARP%20Entry.html

.LINK
    Get-SfosStaticARP
#>
function Remove-SfosStaticARP {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$IPAddress,

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
        if (-not $PSCmdlet.ShouldProcess("StaticARP '$IPAddress' on $($params.Firewall)", 'Remove')) {
            return
        }

        $ipEsc = ConvertTo-SfosXmlEscaped -Text $IPAddress

        $inner = @"
<Remove>
  <StaticARP>
    <IPAddress>$ipEsc</IPAddress>
  </StaticARP>
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
            throw "Failed to remove StaticARP object '$IPAddress': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'StaticARP' -Action 'delete' -Target $IPAddress
    }
}

#endregion

#region RouterAdvertisement

# --- RouterAdvertisement ---
#
# IPv6 router advertisement acts on a live segment.
#
# Root element is <RouterAdvertisement>, matching the doc folder name. The wire element for
# the "on-link" flag is spelled with a hyphen, <On-link>, which is legal XML but not a legal
# bare PowerShell property/parameter name; this module exposes it as -OnLink and maps it
# explicitly during XML build/parse.

<#
.SYNOPSIS
    Retrieves router advertisement configurations from a Sophos Firewall.

.DESCRIPTION
    Returns the RouterAdvertisement objects that are defined on the firewall: the IPv6 SLAAC
    and RA configuration per interface. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER InterfaceLike
    Optional. Returns only configurations whose interface contains the given text anywhere.
    Applied on the client. If omitted, the interface is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per interface, with the
    properties Interface, Description, MinAdvertisementInterval, MaxAdvertisementInterval,
    ManageIPAddressfromDHCPv6, ManageOtherParametersfromDHCPv6, DefaultGateway,
    DefaultGatewayLifeTime, PrefixList (an array of objects with Prefix64, OnLink, Autonomous,
    PreferredLifeTime and ValidLifeTime), LinkMTU, ReachableTime, RetransmitTime and HopLimit.
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no
    configuration matches.

.EXAMPLE
    Get-SfosRouterAdvertisement

    Lists every router advertisement configuration on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/RouterAdvertisement/RouterAdvertisement.html

.LINK
    New-SfosRouterAdvertisement

.LINK
    Set-SfosRouterAdvertisement
#>
function Get-SfosRouterAdvertisement {
    [CmdletBinding()]
    param(
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

    $inner = '<Get><RouterAdvertisement></RouterAdvertisement></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving RouterAdvertisement objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RouterAdvertisement' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/RouterAdvertisement[Interface]' | ForEach-Object -Process { $_.Node }

    $raObjects = foreach ($node in @($nodes)) {
        $prefixNodes = @($node.SelectNodes('PrefixAdvertisementConfiguration/PrefixAdvertisementConfigurationDetail'))
        $prefixList = foreach ($pNode in $prefixNodes) {
            $onLinkNode = $pNode.SelectSingleNode('On-link')
            [PSCustomObject]@{
                Prefix64          = [string]$pNode.Prefix64
                OnLink            = if ($onLinkNode) { [string]$onLinkNode.InnerText } else { '' }
                Autonomous        = [string]$pNode.Autonomous
                PreferredLifeTime = [string]$pNode.PreferredLifeTime
                ValidLifeTime     = [string]$pNode.ValidLifeTime
            }
        }

        [PSCustomObject]@{
            Interface                       = [string]$node.Interface
            Description                     = [string]$node.Description
            MinAdvertisementInterval        = [string]$node.MinAdvertisementInterval
            MaxAdvertisementInterval        = [string]$node.MaxAdvertisementInterval
            ManageIPAddressfromDHCPv6       = [string]$node.ManageIPAddressfromDHCPv6
            ManageOtherParametersfromDHCPv6 = [string]$node.ManageOtherParametersfromDHCPv6
            DefaultGateway                  = [string]$node.DefaultGateway
            DefaultGatewayLifeTime          = [string]$node.DefaultGatewayLifeTime
            PrefixList                      = [PSCustomObject[]]@($prefixList)
            LinkMTU                         = [string]$node.LinkMTU
            ReachableTime                   = [string]$node.ReachableTime
            RetransmitTime                  = [string]$node.RetransmitTime
            HopLimit                        = [string]$node.HopLimit
        }
    }

    $raObjects = @($raObjects)
    if ($InterfaceLike) {
        $raObjects = @($raObjects | Where-Object -FilterScript { $_.Interface -like "*$InterfaceLike*" })
    }

    if ($AsXml) {
        $keptInterfaces = @($raObjects | ForEach-Object -Process { $_.Interface })
        return @($nodes | Where-Object -FilterScript { $keptInterfaces -contains $_.Interface })
    }

    return $raObjects
}

<#
.SYNOPSIS
    Builds the create or update XML body for a RouterAdvertisement entity.

.DESCRIPTION
    Turns a fully resolved RouterAdvertisement object into the XML that
    New-SfosRouterAdvertisement and Set-SfosRouterAdvertisement send to the firewall, so both
    cmdlets send an identical, complete entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER RouterAdvertisement
    Fully resolved object with the same property shape Get-SfosRouterAdvertisement returns.
#>
function ConvertTo-SfosRouterAdvertisementXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$RouterAdvertisement
    )

    $ifaceEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.Interface)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.Description)
    $minIntEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.MinAdvertisementInterval)
    $maxIntEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.MaxAdvertisementInterval)
    $manageIpEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.ManageIPAddressfromDHCPv6)
    $manageOtherEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.ManageOtherParametersfromDHCPv6)
    $defGwEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.DefaultGateway)
    $defGwLifeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.DefaultGatewayLifeTime)
    $linkMtuEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.LinkMTU)
    $reachableEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.ReachableTime)
    $retransmitEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.RetransmitTime)
    $hopLimitEsc = ConvertTo-SfosXmlEscaped -Text ([string]$RouterAdvertisement.HopLimit)

    $defGwXml = ''
    if ($defGwEsc) {
        $defGwXml = "<DefaultGateway>$defGwEsc</DefaultGateway>"
    }

    $prefixXml = ''
    foreach ($prefix in @($RouterAdvertisement.PrefixList)) {
        if (-not $prefix) {
            continue
        }
        $prefix64Esc = ConvertTo-SfosXmlEscaped -Text ([string]$prefix.Prefix64)
        $onLinkEsc = ConvertTo-SfosXmlEscaped -Text ([string]$prefix.OnLink)
        $autonomousEsc = ConvertTo-SfosXmlEscaped -Text ([string]$prefix.Autonomous)
        $preferredEsc = ConvertTo-SfosXmlEscaped -Text ([string]$prefix.PreferredLifeTime)
        $validEsc = ConvertTo-SfosXmlEscaped -Text ([string]$prefix.ValidLifeTime)
        $prefixXml += "<PrefixAdvertisementConfigurationDetail><Prefix64>$prefix64Esc</Prefix64><On-link>$onLinkEsc</On-link><Autonomous>$autonomousEsc</Autonomous><PreferredLifeTime>$preferredEsc</PreferredLifeTime><ValidLifeTime>$validEsc</ValidLifeTime></PrefixAdvertisementConfigurationDetail>"
    }
    $prefixWrapperXml = ''
    if ($prefixXml) {
        $prefixWrapperXml = "<PrefixAdvertisementConfiguration>$prefixXml</PrefixAdvertisementConfiguration>"
    }

    return "<Set operation=`"$Operation`"><RouterAdvertisement><Interface>$ifaceEsc</Interface><Description>$descEsc</Description><MinAdvertisementInterval>$minIntEsc</MinAdvertisementInterval><MaxAdvertisementInterval>$maxIntEsc</MaxAdvertisementInterval><ManageIPAddressfromDHCPv6>$manageIpEsc</ManageIPAddressfromDHCPv6><ManageOtherParametersfromDHCPv6>$manageOtherEsc</ManageOtherParametersfromDHCPv6>$defGwXml<DefaultGatewayLifeTime>$defGwLifeEsc</DefaultGatewayLifeTime>$prefixWrapperXml<LinkMTU>$linkMtuEsc</LinkMTU><ReachableTime>$reachableEsc</ReachableTime><RetransmitTime>$retransmitEsc</RetransmitTime><HopLimit>$hopLimitEsc</HopLimit></RouterAdvertisement></Set>"
}

<#
.SYNOPSIS
    Creates a router advertisement configuration on a Sophos Firewall.

.DESCRIPTION
    Adds an IPv6 Router Advertisement (SLAAC) configuration for an interface. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission. Because it acts on a live IPv6
    segment, review the values carefully before writing.

.PARAMETER Interface
    Required. Interface to configure Router Advertisement on.

.PARAMETER Description
    Optional. Description of the configuration.

.PARAMETER MinAdvertisementInterval
    Optional. Minimum seconds between advertisements, from 3 up to the firewall's configured
    maximum. Default: 198.

.PARAMETER MaxAdvertisementInterval
    Optional. Maximum seconds between advertisements, 4-1800. Default: 600.

.PARAMETER ManageIPAddressfromDHCPv6
    Optional. Manages IPv6 address autoconfiguration from a DHCPv6 server: 'Enable' or
    'Disable'. Default: 'Disable'.

.PARAMETER ManageOtherParametersfromDHCPv6
    Optional. Manages other parameters, such as DNS and default router, from a DHCPv6 server:
    'Enable' or 'Disable'.

.PARAMETER DefaultGateway
    Optional. Advertises this appliance as the default gateway: 'Enable' or 'Disable'.

.PARAMETER DefaultGatewayLifeTime
    Optional. Seconds this appliance is advertised as usable as a default gateway.

.PARAMETER PrefixList
    Optional. Array of prefix advertisement objects, each with Prefix64, OnLink ('Enable' or
    'Disable'), Autonomous ('Enable' or 'Disable'), PreferredLifeTime and ValidLifeTime
    properties. ValidLifeTime must be greater than or equal to PreferredLifeTime.

.PARAMETER LinkMTU
    Optional. MTU in bytes for packets sent on the interface, 1280-1500.

.PARAMETER ReachableTime
    Optional. Seconds a neighbor is assumed reachable after a reachability confirmation,
    0-3600.

.PARAMETER RetransmitTime
    Optional. Seconds to wait before retransmitting neighbor solicitations, 0-4294968.

.PARAMETER HopLimit
    Optional. Hop limit advertised to clients, 0-255. Default: 64.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosRouterAdvertisement -Interface 'VLAN20' -ManageOtherParametersfromDHCPv6 Disable -DefaultGatewayLifeTime 1800 -LinkMTU 1500 -ReachableTime 0 -RetransmitTime 0 -WhatIf

    Shows what creating the configuration would send, without sending it to the firewall.

.EXAMPLE
    New-SfosRouterAdvertisement -Interface 'VLAN20' -ManageOtherParametersfromDHCPv6 Disable -DefaultGatewayLifeTime 1800 -LinkMTU 1500 -ReachableTime 0 -RetransmitTime 0

    Creates a router advertisement configuration on VLAN20. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/RouterAdvertisement/operations/AddRouterAdvertisement%26UpdateRouterAdvertisement.html

.LINK
    Get-SfosRouterAdvertisement

.LINK
    Set-SfosRouterAdvertisement
#>
function New-SfosRouterAdvertisement {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Interface,

        [string]$Description,

        [ValidateRange(3, 1800)]
        [int]$MinAdvertisementInterval = 198,

        [ValidateRange(4, 1800)]
        [int]$MaxAdvertisementInterval = 600,

        [ValidateSet('Enable', 'Disable')]
        [string]$ManageIPAddressfromDHCPv6 = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ManageOtherParametersfromDHCPv6,

        [ValidateSet('Enable', 'Disable')]
        [string]$DefaultGateway,

        [int]$DefaultGatewayLifeTime,

        [PSCustomObject[]]$PrefixList,

        [ValidateRange(1280, 1500)]
        [int]$LinkMTU,

        [ValidateRange(0, 3600)]
        [int]$ReachableTime,

        [ValidateRange(0, 4294968)]
        [int]$RetransmitTime,

        [ValidateRange(0, 255)]
        [int]$HopLimit = 64,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("RouterAdvertisement '$Interface' on $($params.Firewall)", 'Create')) {
        return
    }

    $raObject = [PSCustomObject]@{
        Interface                       = $Interface
        Description                     = $Description
        MinAdvertisementInterval        = $MinAdvertisementInterval
        MaxAdvertisementInterval        = $MaxAdvertisementInterval
        ManageIPAddressfromDHCPv6       = $ManageIPAddressfromDHCPv6
        ManageOtherParametersfromDHCPv6 = $ManageOtherParametersfromDHCPv6
        DefaultGateway                  = $DefaultGateway
        DefaultGatewayLifeTime          = $DefaultGatewayLifeTime
        PrefixList                      = $PrefixList
        LinkMTU                         = $LinkMTU
        ReachableTime                   = $ReachableTime
        RetransmitTime                  = $RetransmitTime
        HopLimit                        = $HopLimit
    }
    $inner = ConvertTo-SfosRouterAdvertisementXml -Operation 'add' -RouterAdvertisement $raObject

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to create RouterAdvertisement object '$Interface': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RouterAdvertisement' -Action 'create' -Target $Interface
}

<#
.SYNOPSIS
    Updates a router advertisement configuration on a Sophos Firewall.

.DESCRIPTION
    Changes the Router Advertisement configuration of an interface. The cmdlet reads the
    current configuration first and sends every field back; fields you do not pass keep their
    current value, including the whole PrefixList. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Interface
    Required. Interface identifying the configuration to change. Accepts pipeline input by
    value and by property name.

.PARAMETER Description
    Optional. New description. If omitted, the current value is kept.

.PARAMETER MinAdvertisementInterval
    Optional. New minimum advertisement interval. If omitted, the current value is kept.

.PARAMETER MaxAdvertisementInterval
    Optional. New maximum advertisement interval. If omitted, the current value is kept.

.PARAMETER ManageIPAddressfromDHCPv6
    Optional. New DHCPv6 address management setting. If omitted, the current value is kept.

.PARAMETER ManageOtherParametersfromDHCPv6
    Optional. New DHCPv6 other-parameters management setting. If omitted, the current value
    is kept.

.PARAMETER DefaultGateway
    Optional. New default-gateway advertisement setting. If omitted, the current value is
    kept.

.PARAMETER DefaultGatewayLifeTime
    Optional. New default gateway lifetime. If omitted, the current value is kept.

.PARAMETER PrefixList
    Optional. New full prefix list, replacing the existing one entirely. If omitted, the
    current list is kept.

.PARAMETER LinkMTU
    Optional. New link MTU. If omitted, the current value is kept.

.PARAMETER ReachableTime
    Optional. New reachable time. If omitted, the current value is kept.

.PARAMETER RetransmitTime
    Optional. New retransmit time. If omitted, the current value is kept.

.PARAMETER HopLimit
    Optional. New hop limit. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosRouterAdvertisement result can be
    piped in; Interface binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosRouterAdvertisement -Interface 'VLAN20' -HopLimit 32 -WhatIf

    Shows what changing the hop limit would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosRouterAdvertisement -Interface 'VLAN20' -HopLimit 32

    Changes the hop limit on VLAN20; the prefix list and every other field are preserved. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/RouterAdvertisement/operations/AddRouterAdvertisement%26UpdateRouterAdvertisement.html

.LINK
    Get-SfosRouterAdvertisement

.LINK
    New-SfosRouterAdvertisement
#>
function Set-SfosRouterAdvertisement {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Interface,

        [string]$Description,
        [int]$MinAdvertisementInterval,
        [int]$MaxAdvertisementInterval,

        [ValidateSet('Enable', 'Disable')]
        [string]$ManageIPAddressfromDHCPv6,

        [ValidateSet('Enable', 'Disable')]
        [string]$ManageOtherParametersfromDHCPv6,

        [ValidateSet('Enable', 'Disable')]
        [string]$DefaultGateway,

        [int]$DefaultGatewayLifeTime,

        [PSCustomObject[]]$PrefixList,

        [int]$LinkMTU,
        [int]$ReachableTime,
        [int]$RetransmitTime,
        [int]$HopLimit,

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
        $existing = @(Get-SfosRouterAdvertisement -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InterfaceLike $Interface `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Interface -eq $Interface })

        if ($existing.Count -eq 0) {
            throw "The RouterAdvertisement object '$Interface' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $merged = [PSCustomObject]@{
            Interface                       = $Interface
            Description                     = if ($bp.ContainsKey('Description')) { $Description } else { $existing.Description }
            MinAdvertisementInterval        = if ($bp.ContainsKey('MinAdvertisementInterval')) { $MinAdvertisementInterval } else { $existing.MinAdvertisementInterval }
            MaxAdvertisementInterval        = if ($bp.ContainsKey('MaxAdvertisementInterval')) { $MaxAdvertisementInterval } else { $existing.MaxAdvertisementInterval }
            ManageIPAddressfromDHCPv6       = if ($bp.ContainsKey('ManageIPAddressfromDHCPv6')) { $ManageIPAddressfromDHCPv6 } else { $existing.ManageIPAddressfromDHCPv6 }
            ManageOtherParametersfromDHCPv6 = if ($bp.ContainsKey('ManageOtherParametersfromDHCPv6')) { $ManageOtherParametersfromDHCPv6 } else { $existing.ManageOtherParametersfromDHCPv6 }
            DefaultGateway                  = if ($bp.ContainsKey('DefaultGateway')) { $DefaultGateway } else { $existing.DefaultGateway }
            DefaultGatewayLifeTime          = if ($bp.ContainsKey('DefaultGatewayLifeTime')) { $DefaultGatewayLifeTime } else { $existing.DefaultGatewayLifeTime }
            PrefixList                      = if ($bp.ContainsKey('PrefixList')) { $PrefixList } else { $existing.PrefixList }
            LinkMTU                         = if ($bp.ContainsKey('LinkMTU')) { $LinkMTU } else { $existing.LinkMTU }
            ReachableTime                   = if ($bp.ContainsKey('ReachableTime')) { $ReachableTime } else { $existing.ReachableTime }
            RetransmitTime                  = if ($bp.ContainsKey('RetransmitTime')) { $RetransmitTime } else { $existing.RetransmitTime }
            HopLimit                        = if ($bp.ContainsKey('HopLimit')) { $HopLimit } else { $existing.HopLimit }
        }

        if (-not $PSCmdlet.ShouldProcess("RouterAdvertisement '$Interface' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosRouterAdvertisementXml -Operation 'update' -RouterAdvertisement $merged

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update RouterAdvertisement object '$Interface': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RouterAdvertisement' -Action 'update' -Target $Interface
    }
}

<#
.SYNOPSIS
    Removes a router advertisement configuration from a Sophos Firewall.

.DESCRIPTION
    Deletes the Router Advertisement configuration of an interface. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

.PARAMETER Interface
    Required. Interface whose configuration is removed. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosRouterAdvertisement result can be
    piped in; Interface binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosRouterAdvertisement -Interface 'VLAN20' -WhatIf

    Shows what removing the configuration would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosRouterAdvertisement -Interface 'VLAN20'

    Removes the Router Advertisement configuration from VLAN20. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/RouterAdvertisement/operations/Delete%20Router%20Advertisement.html

.LINK
    Get-SfosRouterAdvertisement
#>
function Remove-SfosRouterAdvertisement {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Interface,

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
        if (-not $PSCmdlet.ShouldProcess("RouterAdvertisement '$Interface' on $($params.Firewall)", 'Remove')) {
            return
        }

        $ifaceEsc = ConvertTo-SfosXmlEscaped -Text $Interface

        $inner = @"
<Remove>
  <RouterAdvertisement>
    <Interface>$ifaceEsc</Interface>
  </RouterAdvertisement>
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
            throw "Failed to remove RouterAdvertisement object '$Interface': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RouterAdvertisement' -Action 'delete' -Target $Interface
    }
}

#endregion


#region DNS

# --- DNS ---
#
# Singleton. The doc folder and the wire element both read <DNS>. There is exactly one
# instance; Get returns it without a filter and Set always updates it - there is no
# add/remove for this entity.
#
# This entity controls name resolution for the whole appliance, so a Set-SfosDNS that
# drops a field silently changes how the appliance resolves names.
#
# The entity has three independent subtrees (IPv4Settings, IPv6Settings,
# DNSQueryConfiguration). SFOS replaces the whole entity on <Set operation="update">, so
# Set-SfosDNS reads the current object first and always re-sends all three subtrees
# complete - never a partial IPv4Settings or IPv6Settings, because a partial subtree would
# clear whatever field it omits. Two small builders (New-SfosDNSIPv4Settings,
# New-SfosDNSIPv6Settings) exist for the same reason ConvertTo-SfosFirewallRuleNetworkPolicyXml's
# sibling builder exists in SophosFirewall.Firewall: a subtree has several fields, an
# -InputObject plus ValueFromPipeline lets a caller change one field of an existing subtree
# (for example (Get-SfosDNS).IPv4Settings | New-SfosDNSIPv4Settings -ObtainDNSFrom Static)
# without having to restate the other fields, and the merge logic (bound parameter wins,
# otherwise -InputObject, otherwise the parameter default) is centralised there instead of
# being duplicated in Set-SfosDNS.
#
# DNSIPList is present under IPv4Settings even when ObtainDNSFrom=DHCP - the doc sample's
# comment ("This tag should be used only when ObtainDNSFrom has value Static") does not
# match what the appliance sends back on a Get. This module always emits DNSIPList on Set,
# matching the observed shape rather than the doc comment.

<#
.SYNOPSIS
    Builds an IPv4Settings sub-object for use with Set-SfosDNS.

.DESCRIPTION
    Builds the object Set-SfosDNS expects for its -IPv4Settings parameter: ObtainDNSFrom plus
    up to three static DNS server addresses. This cmdlet makes no API call; it only builds an
    in-memory object.

    Pass the current IPv4Settings, for example (Get-SfosDNS).IPv4Settings, through
    -InputObject to keep every field you do not explicitly override.

.PARAMETER InputObject
    Optional. Existing IPv4Settings object to use as a base, typically
    (Get-SfosDNS).IPv4Settings. Accepts pipeline input. Fields you also pass as a parameter
    override the value from this object; every other field is copied unchanged.

.PARAMETER ObtainDNSFrom
    Optional. Where the appliance obtains its IPv4 DNS servers from: 'DHCP', 'PPPoE' or
    'Static'. Default: 'DHCP'.

.PARAMETER DNS1
    Optional. Static primary DNS server IPv4 address. Only meaningful when ObtainDNSFrom is
    'Static'.

.PARAMETER DNS2
    Optional. Static secondary DNS server IPv4 address.

.PARAMETER DNS3
    Optional. Static tertiary DNS server IPv4 address.

.INPUTS
    System.Management.Automation.PSCustomObject. An IPv4Settings object, for example
    (Get-SfosDNS).IPv4Settings, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties
    ObtainDNSFrom, DNS1, DNS2 and DNS3, the same shape Get-SfosDNS returns for its
    IPv4Settings property.

.EXAMPLE
    New-SfosDNSIPv4Settings

    Builds an IPv4Settings object that uses DHCP, the default.

.EXAMPLE
    (Get-SfosDNS).IPv4Settings | New-SfosDNSIPv4Settings -ObtainDNSFrom Static

    Takes the current IPv4 DNS settings and switches to static resolution; DNS1-3 keep their
    current values.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNS/operations/DNSList.html

.LINK
    Get-SfosDNS

.LINK
    Set-SfosDNS
#>
function New-SfosDNSIPv4Settings {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose - this function
    # builds an in-memory object and never calls the API. See the identical reasoning on
    # New-SfosFirewallRuleNetworkPolicy in SophosFirewall.Firewall.
    #
    # PSUseSingularNouns is suppressed on purpose. 'IPv4Settings' is not a plural container
    # here but the name of the wire subtree itself (<IPv4Settings> under <DNS>) - the same
    # reasoning Get-SfosSSLTLSInspectionSettings uses in SophosFirewall.Firewall for
    # 'SSLTLSInspectionSettings': it is one configuration object, not a plural container, so the
    # Sophos spelling wins over PowerShell's singular-noun habit.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('DHCP', 'PPPoE', 'Static')]
        [string]$ObtainDNSFrom = 'DHCP',

        [string]$DNS1 = '',

        [string]$DNS2 = '',

        [string]$DNS3 = ''
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject

        $targetObtain = if ($bp.ContainsKey('ObtainDNSFrom')) { $ObtainDNSFrom } elseif ($hasBase) { $InputObject.ObtainDNSFrom } else { $ObtainDNSFrom }
        $targetDns1 = if ($bp.ContainsKey('DNS1')) { $DNS1 } elseif ($hasBase) { $InputObject.DNS1 } else { $DNS1 }
        $targetDns2 = if ($bp.ContainsKey('DNS2')) { $DNS2 } elseif ($hasBase) { $InputObject.DNS2 } else { $DNS2 }
        $targetDns3 = if ($bp.ContainsKey('DNS3')) { $DNS3 } elseif ($hasBase) { $InputObject.DNS3 } else { $DNS3 }

        return [PSCustomObject]@{
            ObtainDNSFrom = $targetObtain
            DNS1          = [string]$targetDns1
            DNS2          = [string]$targetDns2
            DNS3          = [string]$targetDns3
        }
    }
}

<#
.SYNOPSIS
    Builds an IPv6Settings sub-object for use with Set-SfosDNS.

.DESCRIPTION
    Builds the object Set-SfosDNS expects for its -IPv6Settings parameter: ObtainDNSFrom plus
    up to three static DNS server addresses. This cmdlet makes no API call; it only builds an
    in-memory object.

    Pass the current IPv6Settings, for example (Get-SfosDNS).IPv6Settings, through
    -InputObject to keep every field you do not explicitly override.

.PARAMETER InputObject
    Optional. Existing IPv6Settings object to use as a base, typically
    (Get-SfosDNS).IPv6Settings. Accepts pipeline input. Fields you also pass as a parameter
    override the value from this object; every other field is copied unchanged.

.PARAMETER ObtainDNSFrom
    Optional. Where the appliance obtains its IPv6 DNS servers from: 'DHCP' or 'Static'.
    Default: 'DHCP'.

.PARAMETER DNS1
    Optional. Static primary DNS server IPv6 address.

.PARAMETER DNS2
    Optional. Static secondary DNS server IPv6 address.

.PARAMETER DNS3
    Optional. Static tertiary DNS server IPv6 address.

.INPUTS
    System.Management.Automation.PSCustomObject. An IPv6Settings object, for example
    (Get-SfosDNS).IPv6Settings, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties
    ObtainDNSFrom, DNS1, DNS2 and DNS3, the same shape Get-SfosDNS returns for its
    IPv6Settings property.

.EXAMPLE
    New-SfosDNSIPv6Settings

    Builds an IPv6Settings object that uses DHCP, the default.

.EXAMPLE
    (Get-SfosDNS).IPv6Settings | New-SfosDNSIPv6Settings -DNS1 '2001:db8::1'

    Takes the current IPv6 DNS settings and changes only the primary server.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNS/operations/DNSList.html

.LINK
    Get-SfosDNS

.LINK
    Set-SfosDNS
#>
function New-SfosDNSIPv6Settings {
    # See New-SfosDNSIPv4Settings for the reasoning behind both suppressions below.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('DHCP', 'Static')]
        [string]$ObtainDNSFrom = 'DHCP',

        [string]$DNS1 = '',

        [string]$DNS2 = '',

        [string]$DNS3 = ''
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject

        $targetObtain = if ($bp.ContainsKey('ObtainDNSFrom')) { $ObtainDNSFrom } elseif ($hasBase) { $InputObject.ObtainDNSFrom } else { $ObtainDNSFrom }
        $targetDns1 = if ($bp.ContainsKey('DNS1')) { $DNS1 } elseif ($hasBase) { $InputObject.DNS1 } else { $DNS1 }
        $targetDns2 = if ($bp.ContainsKey('DNS2')) { $DNS2 } elseif ($hasBase) { $InputObject.DNS2 } else { $DNS2 }
        $targetDns3 = if ($bp.ContainsKey('DNS3')) { $DNS3 } elseif ($hasBase) { $InputObject.DNS3 } else { $DNS3 }

        return [PSCustomObject]@{
            ObtainDNSFrom = $targetObtain
            DNS1          = [string]$targetDns1
            DNS2          = [string]$targetDns2
            DNS3          = [string]$targetDns3
        }
    }
}

<#
.SYNOPSIS
    Retrieves the DNS settings of a Sophos Firewall.

.DESCRIPTION
    Returns the DNS singleton: the appliance-wide IPv4 and IPv6 DNS resolver configuration.
    There is exactly one instance of this object per firewall, and no name. The cmdlet only
    reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties IPv4Settings
    (ObtainDNSFrom, DNS1, DNS2, DNS3), IPv6Settings (ObtainDNSFrom, DNS1, DNS2, DNS3) and
    DNSQueryConfiguration. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosDNS

    Returns the current DNS settings.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNS/DNS.html

.LINK
    Set-SfosDNS
#>
function Get-SfosDNS {
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

    $inner = '<Get><DNS></DNS></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DNS settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNS' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/DNS')
    if (-not $node) {
        throw 'DNS settings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $ipv4 = [PSCustomObject]@{
        ObtainDNSFrom = [string]$node.IPv4Settings.ObtainDNSFrom
        DNS1          = [string]$node.IPv4Settings.DNSIPList.DNS1
        DNS2          = [string]$node.IPv4Settings.DNSIPList.DNS2
        DNS3          = [string]$node.IPv4Settings.DNSIPList.DNS3
    }
    $ipv6 = [PSCustomObject]@{
        ObtainDNSFrom = [string]$node.IPv6Settings.ObtainDNSFrom
        DNS1          = [string]$node.IPv6Settings.DNSIPList.DNS1
        DNS2          = [string]$node.IPv6Settings.DNSIPList.DNS2
        DNS3          = [string]$node.IPv6Settings.DNSIPList.DNS3
    }

    return [PSCustomObject]@{
        IPv4Settings          = $ipv4
        IPv6Settings          = $ipv6
        DNSQueryConfiguration = [string]$node.DNSQueryConfiguration
    }
}

<#
.SYNOPSIS
    Builds the update XML body for the DNS singleton.

.DESCRIPTION
    Turns fully resolved IPv4Settings, IPv6Settings and DNSQueryConfiguration values into the
    XML that Set-SfosDNS sends to the firewall. Always emits all three subtrees complete; the
    caller is responsible for merging in every field it wants preserved before calling this
    function.

.PARAMETER IPv4Settings
    Fully resolved IPv4Settings object with ObtainDNSFrom, DNS1, DNS2 and DNS3 properties.

.PARAMETER IPv6Settings
    Fully resolved IPv6Settings object with ObtainDNSFrom, DNS1, DNS2 and DNS3 properties.

.PARAMETER DNSQueryConfiguration
    Fully resolved DNSQueryConfiguration value.
#>
function ConvertTo-SfosDNSXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$IPv4Settings,

        [Parameter(Mandatory)]
        [PSCustomObject]$IPv6Settings,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$DNSQueryConfiguration
    )

    $ipv4ObtainEsc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv4Settings.ObtainDNSFrom)
    $ipv4Dns1Esc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv4Settings.DNS1)
    $ipv4Dns2Esc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv4Settings.DNS2)
    $ipv4Dns3Esc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv4Settings.DNS3)
    $ipv6ObtainEsc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv6Settings.ObtainDNSFrom)
    $ipv6Dns1Esc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv6Settings.DNS1)
    $ipv6Dns2Esc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv6Settings.DNS2)
    $ipv6Dns3Esc = ConvertTo-SfosXmlEscaped -Text ([string]$IPv6Settings.DNS3)
    $queryEsc = ConvertTo-SfosXmlEscaped -Text $DNSQueryConfiguration

    return @"
<Set operation="update">
  <DNS>
    <IPv4Settings>
      <ObtainDNSFrom>$ipv4ObtainEsc</ObtainDNSFrom>
      <DNSIPList>
        <DNS1>$ipv4Dns1Esc</DNS1>
        <DNS2>$ipv4Dns2Esc</DNS2>
        <DNS3>$ipv4Dns3Esc</DNS3>
      </DNSIPList>
    </IPv4Settings>
    <IPv6Settings>
      <ObtainDNSFrom>$ipv6ObtainEsc</ObtainDNSFrom>
      <DNSIPList>
        <DNS1>$ipv6Dns1Esc</DNS1>
        <DNS2>$ipv6Dns2Esc</DNS2>
        <DNS3>$ipv6Dns3Esc</DNS3>
      </DNSIPList>
    </IPv6Settings>
    <DNSQueryConfiguration>$queryEsc</DNSQueryConfiguration>
  </DNS>
</Set>
"@
}

<#
        .SYNOPSIS
        Updates the DNS resolver settings of a Sophos Firewall.

        .DESCRIPTION
        Changes the device-wide DNS configuration: the IPv4 resolver settings, the IPv6
        resolver settings, the query strategy, or any combination of the three. The cmdlet
        reads the current settings first and sends all three subtrees back complete; a
        subtree you do not pass is carried forward unchanged. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with administrative permission.

        A wrong value leaves the firewall unable to resolve host names, which affects
        firmware updates, licensing and any host-name-based rule, including the connection
        this module itself uses if it addresses the firewall by name. Check the current
        settings with Get-SfosDNS first, and use -WhatIf to preview the call.

        .PARAMETER IPv4Settings
        Optional. The IPv4 resolver settings, as returned by Get-SfosDNS or built with
        New-SfosDNSIPv4Settings. If omitted, the current settings are kept.

        .PARAMETER IPv6Settings
        Optional. The IPv6 resolver settings, as returned by Get-SfosDNS or built with
        New-SfosDNSIPv6Settings. If omitted, the current settings are kept.

        .PARAMETER DNSQueryConfiguration
        Optional. Query strategy, for example
        'ChooseServerBasedOnIncomingRequestsRecordType'. If omitted, the current value is
        kept.

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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosDNS -DNSQueryConfiguration 'ChooseIPv4DNSServerOverIPv6' -WhatIf

        Shows what changing the query strategy would send, without sending it to the
        firewall. Both resolver lists are resent unchanged.

        .EXAMPLE
        $ipv4 = New-SfosDNSIPv4Settings -ObtainDNSFrom Static -DNS1 '10.0.0.53' -DNS2 '10.0.0.54'
        Set-SfosDNS -IPv4Settings $ipv4

        Points IPv4 resolution at two static servers. The cmdlet asks for confirmation before
        it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDNS

        .LINK
        New-SfosDNSIPv4Settings

        .LINK
        New-SfosDNSIPv6Settings
#>
function Set-SfosDNS {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [PSCustomObject]$IPv4Settings,

        [PSCustomObject]$IPv6Settings,

        [ValidateSet('ChooseServerBasedOnIncomingRequestsRecordType', 'ChooseIPv6DNSServerOverIPv4', 'ChooseIPv4DNSServerOverIPv6', 'ChooseIPv6IfRequestOriginatorAddressIsIPv6,ElseIPv4')]
        [string]$DNSQueryConfiguration,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDNS -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetIPv4 = if ($bp.ContainsKey('IPv4Settings')) { $IPv4Settings } else { $existing.IPv4Settings }
    $targetIPv6 = if ($bp.ContainsKey('IPv6Settings')) { $IPv6Settings } else { $existing.IPv6Settings }
    $targetQuery = if ($bp.ContainsKey('DNSQueryConfiguration')) { $DNSQueryConfiguration } else { $existing.DNSQueryConfiguration }

    if (-not $PSCmdlet.ShouldProcess("DNS settings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = ConvertTo-SfosDNSXml -IPv4Settings $targetIPv4 -IPv6Settings $targetIPv6 -DNSQueryConfiguration $targetQuery

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating DNS settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNS' -Action 'update'
}

#endregion

#region DNSHostEntry

# --- DNSHostEntry ---
#
# Wire shape:
#   <DNSHostEntry>
#     <HostName>...</HostName>
#     <AddressList><Address><EntryType>.../EntryType><IPFamily>.../IPFamily>
#       <IPAddress>...</IPAddress><TTL>.../TTL><Weight>.../Weight>
#       <PublishOnWAN>.../PublishOnWAN></Address>...</AddressList>
#     <AddReverseDNSLookUp>.../AddReverseDNSLookUp>
#   </DNSHostEntry>
# Up to 8 Address entries per host.

<#
.SYNOPSIS
    Builds an address entry for use with New-SfosDNSHostEntry, Set-SfosDNSHostEntry and
    Add-SfosDNSHostEntryMember.

.DESCRIPTION
    Builds one entry of the address list a DNS host entry holds, up to 8 per host. This cmdlet
    makes no API call; it only builds an in-memory object.

    Pass an existing address, for example one element of the AddressList property returned by
    Get-SfosDNSHostEntry, through -InputObject to keep every field you do not explicitly
    override.

.PARAMETER InputObject
    Optional. Existing address object to use as a base. Accepts pipeline input. Fields you
    also pass as a parameter override the value from this object; every other field is copied
    unchanged.

.PARAMETER EntryType
    Optional. How the address was entered: 'Manual' or 'InterfaceIP'. Default: 'Manual'.

.PARAMETER IPFamily
    Optional. Address family: 'IPv4' or 'IPv6'. Default: 'IPv4'.

.PARAMETER IPAddress
    Required, unless supplied through -InputObject. The IPv4 or IPv6 address mapped to the
    host name.

.PARAMETER TTL
    Optional. Time to live in seconds, 1-604800. Default: 3600.

.PARAMETER Weight
    Optional. Load-balancing weight, 0-255. Default: 0.

.PARAMETER PublishOnWAN
    Optional. Whether to publish this DNS host entry on the WAN: 'Enable' or 'Disable'.
    Default: 'Disable'.

.INPUTS
    System.Management.Automation.PSCustomObject. An address object, for example one element
    of a Get-SfosDNSHostEntry result's AddressList, can be piped in as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties EntryType,
    IPFamily, IPAddress, TTL, Weight and PublishOnWAN, the same shape Get-SfosDNSHostEntry
    returns for each AddressList entry.

.EXAMPLE
    New-SfosDNSHostEntryAddress -IPAddress '203.0.113.10'

    Builds one manual IPv4 address entry.

.EXAMPLE
    (Get-SfosDNSHostEntry -HostNameLike 'host.example.invalid').AddressList[0] | New-SfosDNSHostEntryAddress -TTL 7200

    Takes the first address of an existing host entry and changes only the TTL.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/operations/AddDNSHostEntry%26EditDNSHostEntry.html

.LINK
    New-SfosDNSHostEntry

.LINK
    Add-SfosDNSHostEntryMember
#>
function New-SfosDNSHostEntryAddress {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Manual', 'InterfaceIP')]
        [string]$EntryType = 'Manual',

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [string]$IPAddress,

        [ValidateRange(1, 604800)]
        [int]$TTL = 3600,

        [ValidateRange(0, 255)]
        [int]$Weight = 0,

        [ValidateSet('Enable', 'Disable')]
        [string]$PublishOnWAN = 'Disable'
    )

    process {
        $bp = $PSBoundParameters
        $hasBase = $null -ne $InputObject

        $targetEntryType = if ($bp.ContainsKey('EntryType')) { $EntryType } elseif ($hasBase) { $InputObject.EntryType } else { $EntryType }
        $targetIPFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } elseif ($hasBase) { $InputObject.IPFamily } else { $IPFamily }
        $targetIPAddress = if ($bp.ContainsKey('IPAddress')) { $IPAddress } elseif ($hasBase) { $InputObject.IPAddress } else { $IPAddress }
        $targetTTL = if ($bp.ContainsKey('TTL')) { $TTL } elseif ($hasBase) { $InputObject.TTL } else { $TTL }
        $targetWeight = if ($bp.ContainsKey('Weight')) { $Weight } elseif ($hasBase) { $InputObject.Weight } else { $Weight }
        $targetPublishOnWAN = if ($bp.ContainsKey('PublishOnWAN')) { $PublishOnWAN } elseif ($hasBase) { $InputObject.PublishOnWAN } else { $PublishOnWAN }

        return [PSCustomObject]@{
            EntryType    = $targetEntryType
            IPFamily     = $targetIPFamily
            IPAddress    = [string]$targetIPAddress
            TTL          = [string]$targetTTL
            Weight       = [string]$targetWeight
            PublishOnWAN = $targetPublishOnWAN
        }
    }
}

<#
.SYNOPSIS
    Builds the create or update XML body for a DNSHostEntry entity.

.DESCRIPTION
    Turns a host name, an address list and the reverse-lookup flag into the XML that
    New-SfosDNSHostEntry, Set-SfosDNSHostEntry, Add-SfosDNSHostEntryMember and
    Remove-SfosDNSHostEntryMember send to the firewall, so all four cmdlets send an identical,
    complete entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER HostName
    Required. The host name that identifies the entry.

.PARAMETER Address
    Array of address objects, built with New-SfosDNSHostEntryAddress.

.PARAMETER AddReverseDNSLookUp
    'Enable' or 'Disable'.
#>
function ConvertTo-SfosDNSHostEntryXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$HostName,

        [object[]]$Address,

        [string]$AddReverseDNSLookUp
    )

    $hostNameEsc = ConvertTo-SfosXmlEscaped -Text $HostName
    $reverseEsc = ConvertTo-SfosXmlEscaped -Text ([string]$AddReverseDNSLookUp)

    $addressXml = ''
    foreach ($addr in @($Address)) {
        if (-not $addr) {
            continue
        }
        if (-not [string]$addr.IPAddress) {
            throw "DNSHostEntry '$HostName': every Address entry requires a non-empty IPAddress."
        }
        $entryTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$addr.EntryType)
        $ipFamilyEsc = ConvertTo-SfosXmlEscaped -Text ([string]$addr.IPFamily)
        $ipAddressEsc = ConvertTo-SfosXmlEscaped -Text ([string]$addr.IPAddress)
        $ttlEsc = ConvertTo-SfosXmlEscaped -Text ([string]$addr.TTL)
        $weightEsc = ConvertTo-SfosXmlEscaped -Text ([string]$addr.Weight)
        $publishEsc = ConvertTo-SfosXmlEscaped -Text ([string]$addr.PublishOnWAN)
        $addressXml += "<Address><EntryType>$entryTypeEsc</EntryType><IPFamily>$ipFamilyEsc</IPFamily><IPAddress>$ipAddressEsc</IPAddress><TTL>$ttlEsc</TTL><Weight>$weightEsc</Weight><PublishOnWAN>$publishEsc</PublishOnWAN></Address>"
    }

    return @"
<Set operation="$Operation">
  <DNSHostEntry>
    <HostName>$hostNameEsc</HostName>
    <AddressList>$addressXml</AddressList>
    <AddReverseDNSLookUp>$reverseEsc</AddReverseDNSLookUp>
  </DNSHostEntry>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves DNS host entries from a Sophos Firewall.

.DESCRIPTION
    Returns the DNSHostEntry objects that are defined on the firewall: static DNS mappings.
    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER HostNameLike
    Optional. Returns only entries whose host name contains the given text anywhere. If
    omitted, the host name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per entry, with the properties
    HostName, AddressList, an array of objects with EntryType, IPFamily, IPAddress, TTL,
    Weight and PublishOnWAN, and AddReverseDNSLookUp. Returns System.Xml.XmlElement when
    -AsXml is used, and an empty array when no entry matches.

.EXAMPLE
    Get-SfosDNSHostEntry

    Lists every DNS host entry on the firewall of the current connection.

.EXAMPLE
    Get-SfosDNSHostEntry -HostNameLike 'example.invalid'

    Returns entries whose host name contains 'example.invalid'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/DNSHostEntry.html

.LINK
    New-SfosDNSHostEntry

.LINK
    Set-SfosDNSHostEntry
#>
function Get-SfosDNSHostEntry {
    [CmdletBinding()]
    param(
        [string]$HostNameLike,

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
    if ($HostNameLike) {
        $hostNameLikeEsc = ConvertTo-SfosXmlEscaped -Text $HostNameLike
        $filterXml = ('<Filter><key name="HostName" criteria="like">{0}</key></Filter>' -f $hostNameLikeEsc)
    }

    $inner = @"
<Get>
  <DNSHostEntry>
    $filterXml
  </DNSHostEntry>
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
        throw "Error retrieving DNSHostEntry objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Without this check a firewall-side error would be read as an empty result instead of
    # being reported. This also affects Set-/Add-/Remove-SfosDNSHostEntryMember, which call
    # back into this function to read the current object before every write.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSHostEntry' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DNSHostEntry[HostName]' | ForEach-Object -Process { $_.Node }

    $nodes = @($nodes)
    if ($HostNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.HostName -like "*$HostNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $entryObjects = foreach ($node in $nodes) {
        $addresses = foreach ($addrNode in @($node.AddressList.Address)) {
            if (-not $addrNode) {
                continue
            }
            [PSCustomObject]@{
                EntryType    = [string]$addrNode.EntryType
                IPFamily     = [string]$addrNode.IPFamily
                IPAddress    = [string]$addrNode.IPAddress
                TTL          = [string]$addrNode.TTL
                Weight       = [string]$addrNode.Weight
                PublishOnWAN = [string]$addrNode.PublishOnWAN
            }
        }

        [PSCustomObject]@{
            HostName            = [string]$node.HostName
            AddressList         = [object[]]@($addresses)
            AddReverseDNSLookUp = [string]$node.AddReverseDNSLookUp
        }
    }

    return @($entryObjects)
}

<#
.SYNOPSIS
    Creates a DNS host entry on a Sophos Firewall.

.DESCRIPTION
    Adds a static DNS host-to-address mapping. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER HostName
    Required. Fully qualified domain name for the mapping, up to 253 characters. Accepts
    pipeline input by property name.

.PARAMETER Address
    Required. One to eight address objects, built with New-SfosDNSHostEntryAddress.

.PARAMETER AddReverseDNSLookUp
    Optional. Whether to add a reverse DNS lookup entry: 'Enable' or 'Disable'. Default:
    'Disable'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. HostName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    $addr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.10'
    New-SfosDNSHostEntry -HostName 'host.example.invalid' -Address $addr -WhatIf

    Shows what creating the entry would send, without sending it to the firewall.

.EXAMPLE
    $addr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.10'
    New-SfosDNSHostEntry -HostName 'host.example.invalid' -Address $addr

    Creates a DNS host entry mapping host.example.invalid to 203.0.113.10. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/operations/AddDNSHostEntry%26EditDNSHostEntry.html

.LINK
    Get-SfosDNSHostEntry

.LINK
    New-SfosDNSHostEntryAddress
#>
function New-SfosDNSHostEntry {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [ValidateCount(1, 8)]
        [object[]]$Address,

        [ValidateSet('Enable', 'Disable')]
        [string]$AddReverseDNSLookUp = 'Disable',

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
        if (-not $PSCmdlet.ShouldProcess("DNSHostEntry '$HostName' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosDNSHostEntryXml -Operation 'add' -HostName $HostName -Address $Address -AddReverseDNSLookUp $AddReverseDNSLookUp

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DNSHostEntry object '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSHostEntry' -Action 'create' -Target $HostName
    }
}

<#
.SYNOPSIS
    Updates a DNS host entry on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing DNS host entry. The cmdlet reads the current object
    first and sends every field back; fields you do not pass keep their current value. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER HostName
    Required. Host name identifying the entry to update. Accepts pipeline input by value and
    by property name.

.PARAMETER Address
    Optional. Replacement address list, one to eight entries. If omitted, the current
    AddressList is kept unchanged.

.PARAMETER AddReverseDNSLookUp
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDNSHostEntry result can be piped
    in; HostName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosDNSHostEntry -HostName 'host.example.invalid' -AddReverseDNSLookUp Enable -WhatIf

    Shows what enabling reverse DNS lookup would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosDNSHostEntry -HostName 'host.example.invalid' -AddReverseDNSLookUp Enable

    Enables reverse DNS lookup for the entry; the existing addresses are kept. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/operations/AddDNSHostEntry%26EditDNSHostEntry.html

.LINK
    Get-SfosDNSHostEntry

.LINK
    New-SfosDNSHostEntry
#>
function Set-SfosDNSHostEntry {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

        [object[]]$Address,

        [ValidateSet('Enable', 'Disable')]
        [string]$AddReverseDNSLookUp,

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
        $existing = @(Get-SfosDNSHostEntry -HostNameLike $HostName @params | Where-Object -FilterScript { $_.HostName -eq $HostName })
        if ($existing.Count -eq 0) {
            throw "The DNSHostEntry object '$HostName' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $targetAddress = if ($bp.ContainsKey('Address')) { $Address } else { $existing.AddressList }
        $targetReverse = if ($bp.ContainsKey('AddReverseDNSLookUp')) { $AddReverseDNSLookUp } else { $existing.AddReverseDNSLookUp }

        if (-not $PSCmdlet.ShouldProcess("DNSHostEntry '$HostName' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosDNSHostEntryXml -Operation 'update' -HostName $HostName -Address $targetAddress -AddReverseDNSLookUp $targetReverse

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DNSHostEntry object '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSHostEntry' -Action 'update' -Target $HostName
    }
}

<#
.SYNOPSIS
    Removes a DNS host entry from a Sophos Firewall.

.DESCRIPTION
    Deletes a DNSHostEntry, identified by its host name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER HostName
    Required. Host name of the entry to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDNSHostEntry result can be piped
    in; HostName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosDNSHostEntry -HostName 'host.example.invalid' -WhatIf

    Shows what removing the entry would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDNSHostEntry -HostName 'host.example.invalid'

    Removes the DNS host entry for host.example.invalid. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/operations/Delete%20DNS%20Host%20Entry.html

.LINK
    Get-SfosDNSHostEntry
#>
function Remove-SfosDNSHostEntry {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

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
        if (-not $PSCmdlet.ShouldProcess("DNSHostEntry '$HostName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $hostNameEsc = ConvertTo-SfosXmlEscaped -Text $HostName

        $inner = @"
<Remove>
  <DNSHostEntry>
    <HostName>$hostNameEsc</HostName>
  </DNSHostEntry>
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
            throw "Error removing DNSHostEntry object '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSHostEntry' -Action 'remove' -Target $HostName
    }
}

<#
.SYNOPSIS
    Adds addresses to an existing DNS host entry on a Sophos Firewall.

.DESCRIPTION
    Adds one or more addresses to the address list of a DNS host entry, preserving the
    addresses already present, and throws if the resulting list would exceed the maximum of 8
    addresses. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly, and an account with administrative permission.

.PARAMETER HostName
    Required. Host name of the entry to add addresses to. Accepts pipeline input by property
    name.

.PARAMETER Address
    Required. One or more address objects, built with New-SfosDNSHostEntryAddress, to add.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. HostName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    $addr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.20'
    Add-SfosDNSHostEntryMember -HostName 'host.example.invalid' -Address $addr -WhatIf

    Shows what adding the address would send, without sending it to the firewall.

.EXAMPLE
    $addr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.20'
    Add-SfosDNSHostEntryMember -HostName 'host.example.invalid' -Address $addr

    Adds 203.0.113.20 to the address list of host.example.invalid. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/operations/AddDNSHostEntry%26EditDNSHostEntry.html

.LINK
    Get-SfosDNSHostEntry

.LINK
    Remove-SfosDNSHostEntryMember
#>
function Add-SfosDNSHostEntryMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Address,

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
        $existing = @(Get-SfosDNSHostEntry -HostNameLike $HostName @params | Where-Object -FilterScript { $_.HostName -eq $HostName })
        if ($existing.Count -eq 0) {
            throw "The DNSHostEntry object '$HostName' was not found."
        }
        $existing = $existing[0]

        $combined = @()
        $combined += $existing.AddressList
        $combined += $Address
        $combined = @($combined | Where-Object -FilterScript { $_ } | Sort-Object -Property IPAddress -Unique)

        if ($combined.Count -gt 8) {
            throw "DNSHostEntry '$HostName' would end up with $($combined.Count) addresses; the firewall supports at most 8."
        }

        if (-not $PSCmdlet.ShouldProcess("DNSHostEntry '$HostName' on $($params.Firewall)", 'Add members')) {
            return
        }

        $inner = ConvertTo-SfosDNSHostEntryXml -Operation 'update' -HostName $HostName -Address $combined -AddReverseDNSLookUp $existing.AddReverseDNSLookUp

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error adding members to DNSHostEntry '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSHostEntry' -Action 'add members' -Target $HostName
    }
}

<#
.SYNOPSIS
    Removes addresses from an existing DNS host entry on a Sophos Firewall.

.DESCRIPTION
    Removes the addresses matching the given IP addresses from a DNS host entry's address
    list, keeping every other address in place. The cmdlet reads the object back afterward and
    throws if any requested address is still present, rather than reporting success for a
    change that did not take effect. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER HostName
    Required. Host name of the entry to remove addresses from. Accepts pipeline input by
    property name.

.PARAMETER IPAddress
    Required. One or more IP addresses identifying the addresses to remove.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. HostName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the removal fails or does not
    take effect.

.EXAMPLE
    Remove-SfosDNSHostEntryMember -HostName 'host.example.invalid' -IPAddress '203.0.113.20' -WhatIf

    Shows what removing the address would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDNSHostEntryMember -HostName 'host.example.invalid' -IPAddress '203.0.113.20'

    Removes 203.0.113.20 from the address list of host.example.invalid. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSHostEntry/operations/AddDNSHostEntry%26EditDNSHostEntry.html

.LINK
    Get-SfosDNSHostEntry

.LINK
    Add-SfosDNSHostEntryMember
#>
function Remove-SfosDNSHostEntryMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$IPAddress,

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
        $existing = @(Get-SfosDNSHostEntry -HostNameLike $HostName @params | Where-Object -FilterScript { $_.HostName -eq $HostName })
        if ($existing.Count -eq 0) {
            throw "The DNSHostEntry object '$HostName' was not found."
        }
        $existing = $existing[0]

        $remaining = @($existing.AddressList | Where-Object -FilterScript { $IPAddress -notcontains $_.IPAddress })

        if (-not $PSCmdlet.ShouldProcess("DNSHostEntry '$HostName' on $($params.Firewall)", 'Remove members')) {
            return
        }

        $inner = ConvertTo-SfosDNSHostEntryXml -Operation 'update' -HostName $HostName -Address $remaining -AddReverseDNSLookUp $existing.AddReverseDNSLookUp

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing members from DNSHostEntry '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSHostEntry' -Action 'remove members' -Target $HostName

        $after = @(Get-SfosDNSHostEntry -HostNameLike $HostName @params | Where-Object -FilterScript { $_.HostName -eq $HostName })
        if ($after.Count -gt 0) {
            $stillPresent = @($after[0].AddressList | Where-Object -FilterScript { $IPAddress -contains $_.IPAddress })
            if ($stillPresent.Count -gt 0) {
                throw "DNSHostEntry '$HostName': the firewall reported success but $($stillPresent.Count) of the requested address(es) are still present. This firmware may treat the AddressList as append-only on update."
            }
        }
    }
}

#endregion

#region DNSRequestRoute

# --- DNSRequestRoute ---
#
# Wire shape:
#   <DNSRequestRoute>
#     <DomainName>...</DomainName>
#     <TargetServers><Host>...</Host><Host>...</Host>...</TargetServers>
#   </DNSRequestRoute>
# Up to 8 target servers per route.
#
# TargetServers/Host must be the name of an existing IPHost object, not a raw IP address
# string. The documentation says of the Host field: "Select DNS Server to resolve the
# domain specified above. You can also add IP Address from this page" - which reads as "a
# raw IP address is accepted directly". It is not: a raw IP address, a system host-group
# name and a plain resolvable-looking host name are all rejected with the identical error -
# 501 "Configuration parameters validation failed", <InvalidParams><Params>
# /DNSRequestRoute/TargetServers/Host</Params></InvalidParams> - regardless of the XML
# structure used to send them (with or without the <TargetServers> wrapper, one Host or
# two). The name of an existing IPHost object is accepted with code 200. "You can also add
# IP Address from this page" almost certainly describes a SFOS WebAdmin UI convenience -
# typing a raw IP into that picker creates an IPHost object behind the scenes and then
# references it - which the XML API does not do on the caller's behalf. This module does
# not silently create an IPHost object for a caller who passes a raw IP; TargetServer
# values are sent to the firewall exactly as given, and the firewall's own error names the
# object that was not found.
#
# The IPHost object must additionally have HostType 'IP' (a single address). An IPHost of
# HostType 'Network' (for example a subnet object) is rejected with the same 501 error as a
# raw IP address - only single-host IPHost objects are accepted.

<#
.SYNOPSIS
    Builds the create or update XML body for a DNSRequestRoute entity.

.DESCRIPTION
    Turns a domain name and a target server list into the XML that New-SfosDNSRequestRoute,
    Set-SfosDNSRequestRoute, Add-SfosDNSRequestRouteMember and Remove-SfosDNSRequestRouteMember
    send to the firewall, so all four cmdlets send an identical, complete entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER DomainName
    Required. The domain name that identifies the route.

.PARAMETER TargetServer
    Array of target server name strings.
#>
function ConvertTo-SfosDNSRequestRouteXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [string[]]$TargetServer
    )

    $domainEsc = ConvertTo-SfosXmlEscaped -Text $DomainName

    $hostsXml = ''
    foreach ($target in @($TargetServer)) {
        if (-not $target) {
            continue
        }
        $hostsXml += "<Host>$(ConvertTo-SfosXmlEscaped -Text $target)</Host>"
    }

    return @"
<Set operation="$Operation">
  <DNSRequestRoute>
    <DomainName>$domainEsc</DomainName>
    <TargetServers>$hostsXml</TargetServers>
  </DNSRequestRoute>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves DNS request routes from a Sophos Firewall.

.DESCRIPTION
    Returns the DNSRequestRoute objects that are defined on the firewall: domains routed to
    specific internal DNS servers. Each target server is the name of an existing IPHost
    object, not a raw IP address. The cmdlet only reads; nothing on the firewall is changed.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

.PARAMETER DomainNameLike
    Optional. Returns only routes whose domain name contains the given text anywhere. If
    omitted, the domain name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per route, with the properties
    DomainName and TargetServers, an array of IPHost object names. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no route matches.

.EXAMPLE
    Get-SfosDNSRequestRoute

    Lists every DNS request route on the firewall of the current connection.

.EXAMPLE
    Get-SfosDNSRequestRoute -DomainNameLike 'example.invalid'

    Returns routes whose domain name contains 'example.invalid'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSRequestRoute/DNSRequestRoute.html

.LINK
    New-SfosDNSRequestRoute

.LINK
    Set-SfosDNSRequestRoute
#>
function Get-SfosDNSRequestRoute {
    [CmdletBinding()]
    param(
        [string]$DomainNameLike,

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
    if ($DomainNameLike) {
        $domainLikeEsc = ConvertTo-SfosXmlEscaped -Text $DomainNameLike
        $filterXml = ('<Filter><key name="DomainName" criteria="like">{0}</key></Filter>' -f $domainLikeEsc)
    }

    $inner = @"
<Get>
  <DNSRequestRoute>
    $filterXml
  </DNSRequestRoute>
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
        throw "Error retrieving DNSRequestRoute objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSRequestRoute' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DNSRequestRoute[DomainName]' | ForEach-Object -Process { $_.Node }

    $nodes = @($nodes)
    if ($DomainNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.DomainName -like "*$DomainNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $routeObjects = foreach ($node in $nodes) {
        [PSCustomObject]@{
            DomainName    = [string]$node.DomainName
            TargetServers = [string[]]@($node.TargetServers | Select-Object -ExpandProperty Host -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
        }
    }

    return @($routeObjects)
}

<#
.SYNOPSIS
    Creates a DNS request route on a Sophos Firewall.

.DESCRIPTION
    Adds an internal DNS request route: a domain routed to specific DNS servers. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

.PARAMETER DomainName
    Required. Domain for which the target servers should be used, up to 255 characters.

.PARAMETER TargetServer
    Required. One to eight names of existing IPHost objects, of type IP, to use as DNS
    servers. A raw IP address is not accepted; the object must already exist on the firewall.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. DomainName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosDNSRequestRoute -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server' -WhatIf

    Shows what creating the route would send, without sending it to the firewall.

.EXAMPLE
    New-SfosDNSRequestRoute -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server'

    Routes example.invalid through the IPHost object named Internal-DNS-Server. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSRequestRoute/operations/AddDNSRequestRoute%26EditDNSRequestRoute.html

.LINK
    Get-SfosDNSRequestRoute

.LINK
    Set-SfosDNSRequestRoute
#>
function New-SfosDNSRequestRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [ValidateCount(1, 8)]
        [string[]]$TargetServer,

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
        if (-not $PSCmdlet.ShouldProcess("DNSRequestRoute '$DomainName' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosDNSRequestRouteXml -Operation 'add' -DomainName $DomainName -TargetServer $TargetServer

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DNSRequestRoute object '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSRequestRoute' -Action 'create' -Target $DomainName
    }
}

<#
.SYNOPSIS
    Updates a DNS request route on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing DNS request route. The cmdlet reads the current
    object first and sends every field back; fields you do not pass keep their current value.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER DomainName
    Required. Domain name identifying the route to update. Accepts pipeline input by value and
    by property name.

.PARAMETER TargetServer
    Optional. Replacement target server list, one to eight names of existing IPHost objects of
    type IP. If omitted, the current TargetServers list is kept unchanged.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDNSRequestRoute result can be
    piped in; DomainName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosDNSRequestRoute -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server', 'Internal-DNS-Server-2' -WhatIf

    Shows what replacing the target server list would send, without sending it to the
    firewall.

.EXAMPLE
    Set-SfosDNSRequestRoute -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server', 'Internal-DNS-Server-2'

    Replaces the target servers for example.invalid with the two given IPHost objects. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSRequestRoute/operations/AddDNSRequestRoute%26EditDNSRequestRoute.html

.LINK
    Get-SfosDNSRequestRoute

.LINK
    New-SfosDNSRequestRoute
#>
function Set-SfosDNSRequestRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

        [string[]]$TargetServer,

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
        $existing = @(Get-SfosDNSRequestRoute -DomainNameLike $DomainName @params | Where-Object -FilterScript { $_.DomainName -eq $DomainName })
        if ($existing.Count -eq 0) {
            throw "The DNSRequestRoute object '$DomainName' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $targetServers = if ($bp.ContainsKey('TargetServer')) { $TargetServer } else { $existing.TargetServers }

        if (-not $PSCmdlet.ShouldProcess("DNSRequestRoute '$DomainName' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosDNSRequestRouteXml -Operation 'update' -DomainName $DomainName -TargetServer $targetServers

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DNSRequestRoute object '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSRequestRoute' -Action 'update' -Target $DomainName
    }
}

<#
.SYNOPSIS
    Removes a DNS request route from a Sophos Firewall.

.DESCRIPTION
    Deletes a DNSRequestRoute, identified by its domain name. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

.PARAMETER DomainName
    Required. Domain name of the route to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDNSRequestRoute result can be
    piped in; DomainName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosDNSRequestRoute -DomainName 'example.invalid' -WhatIf

    Shows what removing the route would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDNSRequestRoute -DomainName 'example.invalid'

    Removes the DNS request route for example.invalid. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSRequestRoute/operations/Delete%20DNS%20Request%20Route.html

.LINK
    Get-SfosDNSRequestRoute
#>
function Remove-SfosDNSRequestRoute {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

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
        if (-not $PSCmdlet.ShouldProcess("DNSRequestRoute '$DomainName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $domainEsc = ConvertTo-SfosXmlEscaped -Text $DomainName

        $inner = @"
<Remove>
  <DNSRequestRoute>
    <DomainName>$domainEsc</DomainName>
  </DNSRequestRoute>
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
            throw "Error removing DNSRequestRoute object '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSRequestRoute' -Action 'remove' -Target $DomainName
    }
}

<#
.SYNOPSIS
    Adds target servers to an existing DNS request route on a Sophos Firewall.

.DESCRIPTION
    Adds one or more target servers to the target server list of a DNS request route,
    preserving the servers already present, and throws if the resulting list would exceed the
    maximum of 8 servers. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER DomainName
    Required. Domain name of the route to add target servers to. Accepts pipeline input by
    property name.

.PARAMETER TargetServer
    Required. One or more names of existing IPHost objects to add as target servers.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. DomainName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Add-SfosDNSRequestRouteMember -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server-2' -WhatIf

    Shows what adding the target server would send, without sending it to the firewall.

.EXAMPLE
    Add-SfosDNSRequestRouteMember -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server-2'

    Adds Internal-DNS-Server-2 to the target server list of example.invalid. The cmdlet asks
    for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSRequestRoute/operations/AddDNSRequestRoute%26EditDNSRequestRoute.html

.LINK
    Get-SfosDNSRequestRoute

.LINK
    Remove-SfosDNSRequestRouteMember
#>
function Add-SfosDNSRequestRouteMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TargetServer,

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
        $existing = @(Get-SfosDNSRequestRoute -DomainNameLike $DomainName @params | Where-Object -FilterScript { $_.DomainName -eq $DomainName })
        if ($existing.Count -eq 0) {
            throw "The DNSRequestRoute object '$DomainName' was not found."
        }
        $existing = $existing[0]

        $combined = @()
        $combined += $existing.TargetServers
        $combined += $TargetServer
        $combined = @($combined | Where-Object -FilterScript { $_ } | Select-Object -Unique)

        if ($combined.Count -gt 8) {
            throw "DNSRequestRoute '$DomainName' would end up with $($combined.Count) target servers; the firewall supports at most 8."
        }

        if (-not $PSCmdlet.ShouldProcess("DNSRequestRoute '$DomainName' on $($params.Firewall)", 'Add members')) {
            return
        }

        $inner = ConvertTo-SfosDNSRequestRouteXml -Operation 'update' -DomainName $DomainName -TargetServer $combined

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error adding members to DNSRequestRoute '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSRequestRoute' -Action 'add members' -Target $DomainName
    }
}

<#
.SYNOPSIS
    Removes target servers from an existing DNS request route on a Sophos Firewall.

.DESCRIPTION
    Removes the target servers matching the given names from a DNS request route's target
    server list, keeping every other server in place. The cmdlet reads the object back
    afterward and throws if any requested server is still present, rather than reporting
    success for a change that did not take effect. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER DomainName
    Required. Domain name of the route to remove target servers from. Accepts pipeline input
    by property name.

.PARAMETER TargetServer
    Required. One or more IPHost object names to remove from the target server list.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. DomainName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the removal fails or does not
    take effect.

.EXAMPLE
    Remove-SfosDNSRequestRouteMember -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server-2' -WhatIf

    Shows what removing the target server would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDNSRequestRouteMember -DomainName 'example.invalid' -TargetServer 'Internal-DNS-Server-2'

    Removes Internal-DNS-Server-2 from the target server list of example.invalid. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DNSRequestRoute/operations/AddDNSRequestRoute%26EditDNSRequestRoute.html

.LINK
    Get-SfosDNSRequestRoute

.LINK
    Add-SfosDNSRequestRouteMember
#>
function Remove-SfosDNSRequestRouteMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TargetServer,

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
        $existing = @(Get-SfosDNSRequestRoute -DomainNameLike $DomainName @params | Where-Object -FilterScript { $_.DomainName -eq $DomainName })
        if ($existing.Count -eq 0) {
            throw "The DNSRequestRoute object '$DomainName' was not found."
        }
        $existing = $existing[0]

        $remaining = @($existing.TargetServers | Where-Object -FilterScript { $TargetServer -notcontains $_ })

        if (-not $PSCmdlet.ShouldProcess("DNSRequestRoute '$DomainName' on $($params.Firewall)", 'Remove members')) {
            return
        }

        $inner = ConvertTo-SfosDNSRequestRouteXml -Operation 'update' -DomainName $DomainName -TargetServer $remaining

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing members from DNSRequestRoute '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DNSRequestRoute' -Action 'remove members' -Target $DomainName

        $after = @(Get-SfosDNSRequestRoute -DomainNameLike $DomainName @params | Where-Object -FilterScript { $_.DomainName -eq $DomainName })
        if ($after.Count -gt 0) {
            $stillPresent = @($after[0].TargetServers | Where-Object -FilterScript { $TargetServer -contains $_ })
            if ($stillPresent.Count -gt 0) {
                throw "DNSRequestRoute '$DomainName': the firewall reported success but $($stillPresent.Count) of the requested target server(s) are still present. This firmware may treat TargetServers as append-only on update."
            }
        }
    }
}

#endregion

#region DynamicDNS

# --- DynamicDNS ---
#
# DynamicDNS calls out to an external DDNS provider (DynDNS, ZoneEdit, EasyDNS,
# DynAccess) with real credentials on every add/edit.
#
# Wire shape:
#   <DynamicDNS>
#     <HostName>...</HostName><Interface>...</Interface><IPv4Address>.../IPv4Address>
#     <ServiceProvider>...</ServiceProvider><LoginName>...</LoginName><Password>...</Password>
#   </DynamicDNS>

<#
.SYNOPSIS
    Builds the create or update XML body for a DynamicDNS entity.

.DESCRIPTION
    Turns a fully resolved DynamicDNS object into the XML that New-SfosDynamicDNS and
    Set-SfosDynamicDNS send to the firewall, so both cmdlets send an identical, complete
    entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER DynamicDNS
    Fully resolved DynamicDNS object with HostName, Interface, IPv4Address, ServiceProvider,
    LoginName and Password properties.
#>
function ConvertTo-SfosDynamicDNSXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$DynamicDNS
    )

    $hostNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DynamicDNS.HostName)
    $interfaceEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DynamicDNS.Interface)
    $ipv4Esc = ConvertTo-SfosXmlEscaped -Text ([string]$DynamicDNS.IPv4Address)
    $providerEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DynamicDNS.ServiceProvider)
    $loginEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DynamicDNS.LoginName)
    $passwordEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DynamicDNS.Password)

    return @"
<Set operation="$Operation">
  <DynamicDNS>
    <HostName>$hostNameEsc</HostName>
    <Interface>$interfaceEsc</Interface>
    <IPv4Address>$ipv4Esc</IPv4Address>
    <ServiceProvider>$providerEsc</ServiceProvider>
    <LoginName>$loginEsc</LoginName>
    <Password>$passwordEsc</Password>
  </DynamicDNS>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves dynamic DNS bindings from a Sophos Firewall.

.DESCRIPTION
    Returns the DynamicDNS objects that are defined on the firewall. The cmdlet only reads;
    nothing on the firewall is changed. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly.

.PARAMETER HostNameLike
    Optional. Returns only bindings whose host name contains the given text anywhere. If
    omitted, the host name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per binding, with the properties
    HostName, Interface, IPv4Address, ServiceProvider, LoginName and Password. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no binding matches.

.EXAMPLE
    Get-SfosDynamicDNS

    Lists every dynamic DNS binding on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DynamicDNS/DynamicDNS.html

.LINK
    New-SfosDynamicDNS

.LINK
    Set-SfosDynamicDNS
#>
function Get-SfosDynamicDNS {
    [CmdletBinding()]
    param(
        [string]$HostNameLike,

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
    if ($HostNameLike) {
        $hostNameLikeEsc = ConvertTo-SfosXmlEscaped -Text $HostNameLike
        $filterXml = ('<Filter><key name="HostName" criteria="like">{0}</key></Filter>' -f $hostNameLikeEsc)
    }

    $inner = @"
<Get>
  <DynamicDNS>
    $filterXml
  </DynamicDNS>
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
        throw "Error retrieving DynamicDNS objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DynamicDNS' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DynamicDNS[HostName]' | ForEach-Object -Process { $_.Node }

    $nodes = @($nodes)
    if ($HostNameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.HostName -like "*$HostNameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $ddnsObjects = foreach ($node in $nodes) {
        [PSCustomObject]@{
            HostName        = [string]$node.HostName
            Interface       = [string]$node.Interface
            IPv4Address     = [string]$node.IPv4Address
            ServiceProvider = [string]$node.ServiceProvider
            LoginName       = [string]$node.LoginName
            Password        = [string]$node.Password
        }
    }

    return @($ddnsObjects)
}

<#
.SYNOPSIS
    Creates a dynamic DNS binding on a Sophos Firewall.

.DESCRIPTION
    Registers a dynamic DNS (DDNS) binding. This contacts the chosen external DDNS provider
    with the given account credentials. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER HostName
    Required. Host name registered with the DDNS provider, up to 253 characters.

.PARAMETER Interface
    Required. Name of the interface whose IP address is bound to HostName.

.PARAMETER IPv4Address
    Required. Which IPv4 address to publish: 'UsePortIP' or 'NATedPublicIP'.

.PARAMETER ServiceProvider
    Required. DDNS provider name, for example 'DynDNS', 'ZoneEdit', 'EasyDNS' or 'DynAccess'.

.PARAMETER LoginName
    Required. DDNS account login name, up to 50 characters.

.PARAMETER DDNSPassword
    Required. DDNS account password, up to 120 characters. Sent as plain text like every
    other field of this request; there is no separate credential channel for this operation.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. HostName binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosDynamicDNS -HostName 'example.invalid' -Interface 'PortB' -IPv4Address UsePortIP -ServiceProvider DynDNS -LoginName 'ddnsuser' -DDNSPassword 'ddnspass' -WhatIf

    Shows what registering the binding would send, without sending it to the firewall. The
    provider account password is -DDNSPassword; -Password is this module's own connection
    parameter and expects a SecureString, so it cannot stand in for it.

.EXAMPLE
    New-SfosDynamicDNS -HostName 'example.invalid' -Interface 'PortB' -IPv4Address UsePortIP -ServiceProvider DynDNS -LoginName 'ddnsuser' -DDNSPassword 'ddnspass'

    Registers example.invalid with DynDNS, bound to PortB. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DynamicDNS/operations/AddDynamicDNS%26EditDynamicDNS.html

.LINK
    Get-SfosDynamicDNS

.LINK
    Set-SfosDynamicDNS
#>
function New-SfosDynamicDNS {
    # PSAvoidUsingUsernameAndPasswordParams and PSAvoidUsingPlainTextForPassword are
    # suppressed on purpose. -DDNSPassword is not this module's own authentication - it is the
    # DDNS provider account password the Sophos API documents as a plain <Password> element
    # inside the request body (everything in this API travels as XML
    # field text, there is no separate secure-credential channel for this operation). It is
    # deliberately named DDNSPassword, not Password, so it can never be confused with - or
    # collide with - this module's connection -Password parameter, which stays SecureString.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

        [Parameter(Mandatory)]
        [string]$Interface,

        [Parameter(Mandatory)]
        [ValidateSet('UsePortIP', 'NATedPublicIP')]
        [string]$IPv4Address,

        [Parameter(Mandatory)]
        [string]$ServiceProvider,

        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [string]$LoginName,

        [Parameter(Mandatory)]
        [ValidateLength(1, 120)]
        [string]$DDNSPassword,

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
        if (-not $PSCmdlet.ShouldProcess("DynamicDNS '$HostName' on $($params.Firewall)", 'Create')) {
            return
        }

        $ddns = [PSCustomObject]@{
            HostName        = $HostName
            Interface       = $Interface
            IPv4Address     = $IPv4Address
            ServiceProvider = $ServiceProvider
            LoginName       = $LoginName
            Password        = $DDNSPassword
        }
        $inner = ConvertTo-SfosDynamicDNSXml -Operation 'add' -DynamicDNS $ddns

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DynamicDNS object '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DynamicDNS' -Action 'create' -Target $HostName
    }
}

<#
.SYNOPSIS
    Updates a dynamic DNS binding on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing dynamic DNS binding. The cmdlet reads the current
    object first and sends every field back; fields you do not pass keep their current value.
    This contacts the external DDNS provider. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER HostName
    Required. Host name identifying the binding to update. Accepts pipeline input by value and
    by property name.

.PARAMETER Interface
    Optional. Replacement interface name. If omitted, the current value is kept.

.PARAMETER IPv4Address
    Optional. Replacement IPv4 address source: 'UsePortIP' or 'NATedPublicIP'. If omitted, the
    current value is kept.

.PARAMETER ServiceProvider
    Optional. Replacement DDNS provider name. If omitted, the current value is kept.

.PARAMETER LoginName
    Optional. Replacement DDNS account login name. If omitted, the current value is kept.

.PARAMETER DDNSPassword
    Optional. Replacement DDNS account password. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDynamicDNS result can be piped in;
    HostName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosDynamicDNS -HostName 'example.invalid' -IPv4Address NATedPublicIP -WhatIf

    Shows what switching to the NATed public IP would send, without sending it to the
    firewall.

.EXAMPLE
    Set-SfosDynamicDNS -HostName 'example.invalid' -IPv4Address NATedPublicIP

    Switches example.invalid to publish the NATed public IP. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DynamicDNS/operations/AddDynamicDNS%26EditDynamicDNS.html

.LINK
    Get-SfosDynamicDNS

.LINK
    New-SfosDynamicDNS
#>
function Set-SfosDynamicDNS {
    # See New-SfosDynamicDNS for the reasoning behind both suppressions below.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

        [string]$Interface,

        [ValidateSet('UsePortIP', 'NATedPublicIP')]
        [string]$IPv4Address,

        [string]$ServiceProvider,

        [string]$LoginName,

        [string]$DDNSPassword,

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
        $existing = @(Get-SfosDynamicDNS -HostNameLike $HostName @params | Where-Object -FilterScript { $_.HostName -eq $HostName })
        if ($existing.Count -eq 0) {
            throw "The DynamicDNS object '$HostName' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $targetInterface = if ($bp.ContainsKey('Interface')) { $Interface } else { $existing.Interface }
        $targetIPv4 = if ($bp.ContainsKey('IPv4Address')) { $IPv4Address } else { $existing.IPv4Address }
        $targetProvider = if ($bp.ContainsKey('ServiceProvider')) { $ServiceProvider } else { $existing.ServiceProvider }
        $targetLogin = if ($bp.ContainsKey('LoginName')) { $LoginName } else { $existing.LoginName }
        $targetPassword = if ($bp.ContainsKey('DDNSPassword')) { $DDNSPassword } else { $existing.Password }

        if (-not $PSCmdlet.ShouldProcess("DynamicDNS '$HostName' on $($params.Firewall)", 'Update')) {
            return
        }

        $ddns = [PSCustomObject]@{
            HostName        = $HostName
            Interface       = $targetInterface
            IPv4Address     = $targetIPv4
            ServiceProvider = $targetProvider
            LoginName       = $targetLogin
            Password        = $targetPassword
        }
        $inner = ConvertTo-SfosDynamicDNSXml -Operation 'update' -DynamicDNS $ddns

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DynamicDNS object '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DynamicDNS' -Action 'update' -Target $HostName
    }
}

<#
.SYNOPSIS
    Removes a dynamic DNS binding from a Sophos Firewall.

.DESCRIPTION
    Deletes a DynamicDNS binding, identified by its host name. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

.PARAMETER HostName
    Required. Host name of the binding to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDynamicDNS result can be piped in;
    HostName binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosDynamicDNS -HostName 'example.invalid' -WhatIf

    Shows what removing the binding would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDynamicDNS -HostName 'example.invalid'

    Removes the dynamic DNS binding for example.invalid. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DynamicDNS/operations/Delete%20Dynamic%20DNS.html

.LINK
    Get-SfosDynamicDNS
#>
function Remove-SfosDynamicDNS {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 253)]
        [string]$HostName,

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
        if (-not $PSCmdlet.ShouldProcess("DynamicDNS '$HostName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $hostNameEsc = ConvertTo-SfosXmlEscaped -Text $HostName

        $inner = @"
<Remove>
  <DynamicDNS>
    <HostName>$hostNameEsc</HostName>
  </DynamicDNS>
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
            throw "Error removing DynamicDNS object '$HostName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DynamicDNS' -Action 'remove' -Target $HostName
    }
}

#endregion

#region DHCPServer

# --- DHCPServer ---
#
# A second DHCP server on a segment that already has one can cause address conflicts, so a
# new scope needs a segment of its own.
#
# Wire shape:
#   <DHCPServer><Name>...</Name><Status>...</Status><Interface>...</Interface>
#     <IPLease><IP>start-end</IP>...</IPLease><ConflictDetection>.../ConflictDetection>
#     <LeaseForRelay>...</LeaseForRelay><SubnetMask>...</SubnetMask><DomainName>.../DomainName>
#     <DefaultLeaseTime>...</DefaultLeaseTime><MaxLeaseTime>...</MaxLeaseTime>
#     <UseApplianceDNSSettings>...</UseApplianceDNSSettings>
#     <PrimaryDNSServer>...</PrimaryDNSServer><SecondaryDNSServer>.../SecondaryDNSServer>
#     <PrimaryWINSServer>...</PrimaryWINSServer><SecondaryWINSServer>.../SecondaryWINSServer>
#     <BootServer/><BootFile/><Gateway>...</Gateway>
#     <UseInterfaceIPasGateway>...</UseInterfaceIPasGateway></DHCPServer>
# StaticLease/Lease (HostName/MACAddress/IPAddress) and DHCPOption/Options
# (OptionName/OptionType/OptionCode/OptionValue) are documented but do not appear on a
# scope that uses a dynamic range only.
#
# <Status> here is the enabled/disabled data field, not an API status - same class of field
# as <Status> on FirewallRule/NATRule in SophosFirewall.Firewall. It is read-only through
# this entity: the Add/Edit operation documentation does not list Status as a settable
# parameter, and enabling/disabling a DHCP server is a dedicated endpoint - see
# Set-SfosDHCPServerStatus below. New-/Set-SfosDHCPServer therefore do not expose -Status.
#
# UseApplianceDNSSettings is documented as accepting only 'Enable', but a scope with it set
# to 'Disable' is accepted by the appliance - the observed value wins over the doc's
# incomplete enum.

<#
.SYNOPSIS
    Builds the <Set> inner XML for a DHCPServer entity. Internal helper, not exported.

.DESCRIPTION
    Centralizes the DHCPServer XML shape so New- and Set-SfosDHCPServer send an identical,
    complete entity body. SFOS replaces the whole entity on <Set operation="update">; the
    caller is responsible for merging in every field it wants preserved before calling this
    function. Does not emit <Status> - see the region header for why that field is not settable
    here.

.PARAMETER Operation
    'add' or 'update', passed straight to <Set operation="...">.

.PARAMETER DHCPServer
    Fully resolved DHCPServer object - same property shape Get-SfosDHCPServer returns, minus
    Status.
#>
function ConvertTo-SfosDHCPServerXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$DHCPServer
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.Name)
    $interfaceEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.Interface)
    $useIfGwEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.UseInterfaceIPasGateway)
    $conflictEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.ConflictDetection)
    $leaseRelayEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.LeaseForRelay)
    $subnetEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.SubnetMask)
    $domainEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.DomainName)
    $gatewayEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.Gateway)
    $defaultLeaseEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.DefaultLeaseTime)
    $maxLeaseEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.MaxLeaseTime)
    $useApplianceDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.UseApplianceDNSSettings)
    $primaryDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.PrimaryDNSServer)
    $secondaryDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.SecondaryDNSServer)
    $primaryWinsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.PrimaryWINSServer)
    $secondaryWinsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.SecondaryWINSServer)
    $bootServerEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.BootServer)
    $bootFileEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServer.BootFile)

    $ipLeaseXml = ''
    foreach ($range in @($DHCPServer.IPLease)) {
        if (-not $range) {
            continue
        }
        $ipLeaseXml += "<IP>$(ConvertTo-SfosXmlEscaped -Text $range)</IP>"
    }

    $staticLeaseXml = ''
    foreach ($lease in @($DHCPServer.StaticLease)) {
        if (-not $lease) {
            continue
        }
        $hostEsc = ConvertTo-SfosXmlEscaped -Text ([string]$lease.HostName)
        $macEsc = ConvertTo-SfosXmlEscaped -Text ([string]$lease.MACAddress)
        $ipEsc = ConvertTo-SfosXmlEscaped -Text ([string]$lease.IPAddress)
        $staticLeaseXml += "<Lease><HostName>$hostEsc</HostName><MACAddress>$macEsc</MACAddress><IPAddress>$ipEsc</IPAddress></Lease>"
    }
    if ($staticLeaseXml) {
        $staticLeaseXml = "<StaticLease>$staticLeaseXml</StaticLease>"
    }

    $dhcpOptionXml = ''
    foreach ($opt in @($DHCPServer.DHCPOption)) {
        if (-not $opt) {
            continue
        }
        $optNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionName)
        $optTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionType)
        $optCodeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionCode)
        $optValueEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionValue)
        $dhcpOptionXml += "<Options><OptionName>$optNameEsc</OptionName><OptionType>$optTypeEsc</OptionType><OptionCode>$optCodeEsc</OptionCode><OptionValue>$optValueEsc</OptionValue></Options>"
    }
    if ($dhcpOptionXml) {
        $dhcpOptionXml = "<DHCPOption>$dhcpOptionXml</DHCPOption>"
    }

    return @"
<Set operation="$Operation">
  <DHCPServer>
    <Name>$nameEsc</Name>
    <Interface>$interfaceEsc</Interface>
    <UseInterfaceIPasGateway>$useIfGwEsc</UseInterfaceIPasGateway>
    <IPLease>$ipLeaseXml</IPLease>
    <ConflictDetection>$conflictEsc</ConflictDetection>
    $staticLeaseXml
    <SubnetMask>$subnetEsc</SubnetMask>
    <DomainName>$domainEsc</DomainName>
    <Gateway>$gatewayEsc</Gateway>
    <DefaultLeaseTime>$defaultLeaseEsc</DefaultLeaseTime>
    <MaxLeaseTime>$maxLeaseEsc</MaxLeaseTime>
    <LeaseForRelay>$leaseRelayEsc</LeaseForRelay>
    <UseApplianceDNSSettings>$useApplianceDnsEsc</UseApplianceDNSSettings>
    <PrimaryDNSServer>$primaryDnsEsc</PrimaryDNSServer>
    <SecondaryDNSServer>$secondaryDnsEsc</SecondaryDNSServer>
    <PrimaryWINSServer>$primaryWinsEsc</PrimaryWINSServer>
    <SecondaryWINSServer>$secondaryWinsEsc</SecondaryWINSServer>
    <BootServer>$bootServerEsc</BootServer>
    <BootFile>$bootFileEsc</BootFile>
    $dhcpOptionXml
  </DHCPServer>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves DHCP servers from a Sophos Firewall.

.DESCRIPTION
    Returns the DHCPServer objects (IPv4 DHCP scopes) that are defined on the firewall. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only DHCP servers whose name contains the given text anywhere. If
    omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per DHCP server, with the
    properties Name, Status, Interface, IPLease, ConflictDetection, LeaseForRelay,
    SubnetMask, DomainName, DefaultLeaseTime, MaxLeaseTime, UseApplianceDNSSettings,
    PrimaryDNSServer, SecondaryDNSServer, PrimaryWINSServer, SecondaryWINSServer, BootServer,
    BootFile, Gateway, UseInterfaceIPasGateway, StaticLease (an array of objects with
    HostName, MACAddress and IPAddress) and DHCPOption (an array of objects with OptionName,
    OptionType, OptionCode and OptionValue). Returns System.Xml.XmlElement when -AsXml is
    used, and an empty array when no DHCP server matches.

.EXAMPLE
    Get-SfosDHCPServer

    Lists every DHCP server on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPServer/DHCPServer.html

.LINK
    New-SfosDHCPServer

.LINK
    Set-SfosDHCPServer
#>
function Get-SfosDHCPServer {
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
  <DHCPServer>
    $filterXml
  </DHCPServer>
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
        throw "Error retrieving DHCPServer objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServer' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DHCPServer[Name]' | ForEach-Object -Process { $_.Node }

    $nodes = @($nodes)
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $serverObjects = foreach ($node in $nodes) {
        $staticLease = foreach ($leaseNode in @($node.StaticLease.Lease)) {
            if (-not $leaseNode) {
                continue
            }
            [PSCustomObject]@{
                HostName   = [string]$leaseNode.HostName
                MACAddress = [string]$leaseNode.MACAddress
                IPAddress  = [string]$leaseNode.IPAddress
            }
        }

        $dhcpOption = foreach ($optNode in @($node.DHCPOption.Options)) {
            if (-not $optNode) {
                continue
            }
            [PSCustomObject]@{
                OptionName  = [string]$optNode.OptionName
                OptionType  = [string]$optNode.OptionType
                OptionCode  = [string]$optNode.OptionCode
                OptionValue = [string]$optNode.OptionValue
            }
        }

        [PSCustomObject]@{
            Name                    = [string]$node.Name
            Status                  = [string]$node.Status
            Interface               = [string]$node.Interface
            IPLease                 = [string[]]@($node.IPLease | Select-Object -ExpandProperty IP -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            ConflictDetection       = [string]$node.ConflictDetection
            LeaseForRelay           = [string]$node.LeaseForRelay
            SubnetMask              = [string]$node.SubnetMask
            DomainName              = [string]$node.DomainName
            DefaultLeaseTime        = [string]$node.DefaultLeaseTime
            MaxLeaseTime            = [string]$node.MaxLeaseTime
            UseApplianceDNSSettings = [string]$node.UseApplianceDNSSettings
            PrimaryDNSServer        = [string]$node.PrimaryDNSServer
            SecondaryDNSServer      = [string]$node.SecondaryDNSServer
            PrimaryWINSServer       = [string]$node.PrimaryWINSServer
            SecondaryWINSServer     = [string]$node.SecondaryWINSServer
            BootServer              = [string]$node.BootServer
            BootFile                = [string]$node.BootFile
            Gateway                 = [string]$node.Gateway
            UseInterfaceIPasGateway = [string]$node.UseInterfaceIPasGateway
            StaticLease             = [object[]]@($staticLease)
            DHCPOption              = [object[]]@($dhcpOption)
        }
    }

    return @($serverObjects)
}

<#
.SYNOPSIS
    Creates a DHCP server on a Sophos Firewall.

.DESCRIPTION
    Adds an IPv4 DHCP server scope. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

    Adding a second DHCP server for a segment that already has one active hands out
    conflicting addresses to clients on that network. Check the existing scopes with
    Get-SfosDHCPServer before creating a new one on a live segment.

.PARAMETER Name
    Required. Name for the DHCP server, up to 50 characters, no commas.

.PARAMETER Interface
    Required. Interface on which the DHCP service is configured.

.PARAMETER IPLease
    Required. One or more IP address ranges, in the form "start-end", from which the server
    assigns addresses.

.PARAMETER UseInterfaceIPasGateway
    Optional. Whether to use the interface's own IP as the gateway handed to clients:
    'UseInterfaceIPAsGateway' or 'ANY'. Default: 'UseInterfaceIPAsGateway'.

.PARAMETER Gateway
    Optional. Default gateway IP address handed to clients, used when
    UseInterfaceIPasGateway is not 'UseInterfaceIPAsGateway'.

.PARAMETER SubnetMask
    Required. Subnet mask for the scope.

.PARAMETER DomainName
    Optional. Domain name handed to clients. Default: empty string.

.PARAMETER DefaultLeaseTime
    Optional. Default lease time in minutes, 1-43200. Default: 1440.

.PARAMETER MaxLeaseTime
    Optional. Maximum lease time in minutes, 1-43200. Default: 2880.

.PARAMETER ConflictDetection
    Optional. Whether to probe an address before leasing it: 'Enable' or 'Disable'. Default:
    'Disable'.

.PARAMETER LeaseForRelay
    Optional. Whether the server accepts requests forwarded by a DHCP relay: 'Enable' or
    'Disable'. Default: 'Disable'.

.PARAMETER UseApplianceDNSSettings
    Optional. Whether to hand out the appliance's own DNS settings to clients: 'Enable' or
    'Disable'. Default: 'Enable'.

.PARAMETER PrimaryDNSServer
    Optional. Primary DNS server IP handed to clients when UseApplianceDNSSettings is
    'Disable'. Default: empty string.

.PARAMETER SecondaryDNSServer
    Optional. Secondary DNS server IP. Default: empty string.

.PARAMETER PrimaryWINSServer
    Optional. Primary WINS server IP. Default: empty string.

.PARAMETER SecondaryWINSServer
    Optional. Secondary WINS server IP. Default: empty string.

.PARAMETER BootServer
    Optional. IP address of the server holding the boot file. Default: empty string.

.PARAMETER BootFile
    Optional. Full path of the boot file. Default: empty string.

.PARAMETER StaticLease
    Optional. Array of objects with HostName, MACAddress and IPAddress properties, for static
    MAC-to-IP mappings.

.PARAMETER DHCPOption
    Optional. Array of objects with OptionName, OptionType, OptionCode and OptionValue
    properties, for custom DHCP options.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Name binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.
    This cmdlet does not expose -Status; use Set-SfosDHCPServerStatus to enable or disable a
    scope.

.EXAMPLE
    New-SfosDHCPServer -Name 'Branch-Scope' -Interface 'PortC' -IPLease '10.10.10.10-10.10.10.200' -SubnetMask '255.255.255.0' -Gateway '10.10.10.1' -WhatIf

    Shows what creating the scope would send, without sending it to the firewall.

.EXAMPLE
    New-SfosDHCPServer -Name 'Branch-Scope' -Interface 'PortC' -IPLease '10.10.10.10-10.10.10.200' -SubnetMask '255.255.255.0' -Gateway '10.10.10.1'

    Creates a DHCP scope named Branch-Scope on PortC. The cmdlet asks for confirmation before
    it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPServer/operations/AddIPv4DHCPServer%26EditIPv4DHCPServer.html

.LINK
    Get-SfosDHCPServer

.LINK
    Set-SfosDHCPServerStatus
#>
function New-SfosDHCPServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Interface,

        [Parameter(Mandatory)]
        [string[]]$IPLease,

        [Parameter(Mandatory)]
        [string]$SubnetMask,

        [Parameter(Mandatory)]
        [string]$Gateway,

        [ValidateSet('UseInterfaceIPAsGateway', 'ANY')]
        [string]$UseInterfaceIPasGateway = 'UseInterfaceIPAsGateway',

        [string]$DomainName = '',

        [ValidateRange(1, 43200)]
        [int]$DefaultLeaseTime = 1440,

        [ValidateRange(1, 43200)]
        [int]$MaxLeaseTime = 2880,

        [ValidateSet('Enable', 'Disable')]
        [string]$ConflictDetection = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$LeaseForRelay = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$UseApplianceDNSSettings = 'Enable',

        [string]$PrimaryDNSServer = '',
        [string]$SecondaryDNSServer = '',
        [string]$PrimaryWINSServer = '',
        [string]$SecondaryWINSServer = '',
        [string]$BootServer = '',
        [string]$BootFile = '',

        [object[]]$StaticLease = @(),
        [object[]]$DHCPOption = @(),

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
        if (-not $PSCmdlet.ShouldProcess("DHCPServer '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $dhcpServer = [PSCustomObject]@{
            Name                    = $Name
            Interface               = $Interface
            IPLease                 = $IPLease
            UseInterfaceIPasGateway = $UseInterfaceIPasGateway
            Gateway                 = $Gateway
            SubnetMask              = $SubnetMask
            DomainName              = $DomainName
            DefaultLeaseTime        = $DefaultLeaseTime
            MaxLeaseTime            = $MaxLeaseTime
            ConflictDetection       = $ConflictDetection
            LeaseForRelay           = $LeaseForRelay
            UseApplianceDNSSettings = $UseApplianceDNSSettings
            PrimaryDNSServer        = $PrimaryDNSServer
            SecondaryDNSServer      = $SecondaryDNSServer
            PrimaryWINSServer       = $PrimaryWINSServer
            SecondaryWINSServer     = $SecondaryWINSServer
            BootServer              = $BootServer
            BootFile                = $BootFile
            StaticLease             = $StaticLease
            DHCPOption              = $DHCPOption
        }
        $inner = ConvertTo-SfosDHCPServerXml -Operation 'add' -DHCPServer $dhcpServer

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DHCPServer object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServer' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a DHCP server on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing DHCP scope. The cmdlet reads the current object first
    and sends every field back; fields you do not pass keep their current value. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

    Changing a scope that is currently serving addresses on a live segment, for example its
    lease range or gateway, changes address assignment for every client on that segment.
    Clients keep an already-issued lease until it expires, so the effect can appear only
    gradually and be easy to miss.

.PARAMETER Name
    Required. Name identifying the scope to update. Accepts pipeline input by value and by
    property name.

.PARAMETER Interface
    Optional. Replacement interface name. If omitted, the current value is kept.

.PARAMETER IPLease
    Optional. Replacement IP lease ranges. If omitted, the current value is kept.

.PARAMETER UseInterfaceIPasGateway
    Optional. 'UseInterfaceIPAsGateway' or 'ANY'. If omitted, the current value is kept.

.PARAMETER Gateway
    Optional. Replacement gateway IP. If omitted, the current value is kept.

.PARAMETER SubnetMask
    Optional. Replacement subnet mask. If omitted, the current value is kept.

.PARAMETER DomainName
    Optional. Replacement domain name. If omitted, the current value is kept.

.PARAMETER DefaultLeaseTime
    Optional. Replacement default lease time in minutes. If omitted, the current value is
    kept.

.PARAMETER MaxLeaseTime
    Optional. Replacement maximum lease time in minutes. If omitted, the current value is
    kept.

.PARAMETER ConflictDetection
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

.PARAMETER LeaseForRelay
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

.PARAMETER UseApplianceDNSSettings
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

.PARAMETER PrimaryDNSServer
    Optional. Replacement primary DNS server IP. If omitted, the current value is kept.

.PARAMETER SecondaryDNSServer
    Optional. Replacement secondary DNS server IP. If omitted, the current value is kept.

.PARAMETER PrimaryWINSServer
    Optional. Replacement primary WINS server IP. If omitted, the current value is kept.

.PARAMETER SecondaryWINSServer
    Optional. Replacement secondary WINS server IP. If omitted, the current value is kept.

.PARAMETER BootServer
    Optional. Replacement boot server IP. If omitted, the current value is kept.

.PARAMETER BootFile
    Optional. Replacement boot file path. If omitted, the current value is kept.

.PARAMETER StaticLease
    Optional. Replacement static lease list. If omitted, the current value is kept.

.PARAMETER DHCPOption
    Optional. Replacement DHCP option list. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDHCPServer result can be piped in;
    Name binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.
    This cmdlet does not expose -Status; use Set-SfosDHCPServerStatus to enable or disable a
    scope.

.EXAMPLE
    Set-SfosDHCPServer -Name 'Branch-Scope' -MaxLeaseTime 4320 -WhatIf

    Shows what changing the maximum lease time would send, without sending it to the
    firewall.

.EXAMPLE
    Set-SfosDHCPServer -Name 'Branch-Scope' -MaxLeaseTime 4320

    Changes the maximum lease time of Branch-Scope; every other field is preserved. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPServer/operations/AddIPv4DHCPServer%26EditIPv4DHCPServer.html

.LINK
    Get-SfosDHCPServer

.LINK
    New-SfosDHCPServer
#>
function Set-SfosDHCPServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Interface,
        [string[]]$IPLease,

        [ValidateSet('UseInterfaceIPAsGateway', 'ANY')]
        [string]$UseInterfaceIPasGateway,

        [string]$Gateway,
        [string]$SubnetMask,
        [string]$DomainName,

        [ValidateRange(1, 43200)]
        [int]$DefaultLeaseTime,

        [ValidateRange(1, 43200)]
        [int]$MaxLeaseTime,

        [ValidateSet('Enable', 'Disable')]
        [string]$ConflictDetection,

        [ValidateSet('Enable', 'Disable')]
        [string]$LeaseForRelay,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseApplianceDNSSettings,

        [string]$PrimaryDNSServer,
        [string]$SecondaryDNSServer,
        [string]$PrimaryWINSServer,
        [string]$SecondaryWINSServer,
        [string]$BootServer,
        [string]$BootFile,

        [object[]]$StaticLease,
        [object[]]$DHCPOption,

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
        $existing = @(Get-SfosDHCPServer -NameLike $Name @params | Where-Object -FilterScript { $_.Name -eq $Name })
        if ($existing.Count -eq 0) {
            throw "The DHCPServer object '$Name' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $dhcpServer = [PSCustomObject]@{
            Name                    = $Name
            Interface               = if ($bp.ContainsKey('Interface')) { $Interface } else { $existing.Interface }
            IPLease                 = if ($bp.ContainsKey('IPLease')) { $IPLease } else { $existing.IPLease }
            UseInterfaceIPasGateway = if ($bp.ContainsKey('UseInterfaceIPasGateway')) { $UseInterfaceIPasGateway } else { $existing.UseInterfaceIPasGateway }
            Gateway                 = if ($bp.ContainsKey('Gateway')) { $Gateway } else { $existing.Gateway }
            SubnetMask              = if ($bp.ContainsKey('SubnetMask')) { $SubnetMask } else { $existing.SubnetMask }
            DomainName              = if ($bp.ContainsKey('DomainName')) { $DomainName } else { $existing.DomainName }
            DefaultLeaseTime        = if ($bp.ContainsKey('DefaultLeaseTime')) { $DefaultLeaseTime } else { $existing.DefaultLeaseTime }
            MaxLeaseTime            = if ($bp.ContainsKey('MaxLeaseTime')) { $MaxLeaseTime } else { $existing.MaxLeaseTime }
            ConflictDetection       = if ($bp.ContainsKey('ConflictDetection')) { $ConflictDetection } else { $existing.ConflictDetection }
            LeaseForRelay           = if ($bp.ContainsKey('LeaseForRelay')) { $LeaseForRelay } else { $existing.LeaseForRelay }
            UseApplianceDNSSettings = if ($bp.ContainsKey('UseApplianceDNSSettings')) { $UseApplianceDNSSettings } else { $existing.UseApplianceDNSSettings }
            PrimaryDNSServer        = if ($bp.ContainsKey('PrimaryDNSServer')) { $PrimaryDNSServer } else { $existing.PrimaryDNSServer }
            SecondaryDNSServer      = if ($bp.ContainsKey('SecondaryDNSServer')) { $SecondaryDNSServer } else { $existing.SecondaryDNSServer }
            PrimaryWINSServer       = if ($bp.ContainsKey('PrimaryWINSServer')) { $PrimaryWINSServer } else { $existing.PrimaryWINSServer }
            SecondaryWINSServer     = if ($bp.ContainsKey('SecondaryWINSServer')) { $SecondaryWINSServer } else { $existing.SecondaryWINSServer }
            BootServer              = if ($bp.ContainsKey('BootServer')) { $BootServer } else { $existing.BootServer }
            BootFile                = if ($bp.ContainsKey('BootFile')) { $BootFile } else { $existing.BootFile }
            StaticLease             = if ($bp.ContainsKey('StaticLease')) { $StaticLease } else { $existing.StaticLease }
            DHCPOption              = if ($bp.ContainsKey('DHCPOption')) { $DHCPOption } else { $existing.DHCPOption }
        }

        if (-not $PSCmdlet.ShouldProcess("DHCPServer '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosDHCPServerXml -Operation 'update' -DHCPServer $dhcpServer

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DHCPServer object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServer' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a DHCP server from a Sophos Firewall.

.DESCRIPTION
    Deletes a DHCP scope, identified by its name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

    Removing a scope that is currently serving a live segment stops address assignment for
    that segment. Existing clients keep their current lease until it expires, so the effect
    is not immediate and is easy to overlook until leases start failing to renew.

.PARAMETER Name
    Required. Name of the DHCP scope to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDHCPServer result can be piped in;
    Name binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosDHCPServer -Name 'Branch-Scope' -WhatIf

    Shows what removing the scope would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDHCPServer -Name 'Branch-Scope'

    Removes the DHCP scope named Branch-Scope. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPServer/operations/Delete%20DHCP%20Server.html

.LINK
    Get-SfosDHCPServer
#>
function Remove-SfosDHCPServer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
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
        if (-not $PSCmdlet.ShouldProcess("DHCPServer '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <DHCPServer>
    <Name>$nameEsc</Name>
  </DHCPServer>
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
            throw "Error removing DHCPServer object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServer' -Action 'remove' -Target $Name
    }
}

#endregion

#region DHCPServerStatus

# --- DHCPServerStatus ---
#
# One call switches DHCP off for a whole segment, so this endpoint deserves care. It has no
# corresponding <Get> element - only one operation, "DHCP Server status change", exists
# under this folder.
#
# Function name: Set-SfosDHCPServerStatus, following the Verb-Sfos<Entity> pattern with the
# entity token taken verbatim from the Sophos documentation folder name (DHCPServerStatus) -
# not a purpose-derived name like "Enable-SfosDHCPServer", because this entity is a status
# toggle rather than a lifecycle verb pair.
#
# Wire shape:
#   <DHCPServerStatus>
#     <DHCPServerNamedhcpname>{DHCPServerName}</DHCPServerNamedhcpname>
#     <Status>ON/OFF</Status>
#   </DHCPServerStatus>
# The element name <DHCPServerNamedhcpname> is exactly as documented - both the sample XML
# and the attribute/parameter table (which lists the parameter as "DHCPServerNamedhcpname",
# not "Name") agree on this spelling. It looks like the vendor's own documentation
# generator concatenated a placeholder ("DHCPServerName") into the element name
# ("dhcpname") by mistake, the same class of error as <CountryHostGroup> elsewhere in this
# project. Inventing a "corrected" element name (<Name> or <DHCPServerName>) is exactly
# what should not be done: this module sends the literal documented element name and flags
# it clearly here and in the cmdlet's own .NOTES.
#
# Read-modify-write does not apply here: there is no Get to read from. This is a
# deliberate, API-enforced exception, not an oversight - documented in .NOTES below.

<#
.SYNOPSIS
    Builds the update XML body for a DHCPServerStatus request.

.DESCRIPTION
    Turns a scope name and the desired status into the XML that Set-SfosDHCPServerStatus
    sends to the firewall.

.PARAMETER Name
    Value sent as the wire element that identifies the DHCP scope.

.PARAMETER Status
    'ON' or 'OFF'.
#>
function ConvertTo-SfosDHCPServerStatusXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$Status
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $statusEsc = ConvertTo-SfosXmlEscaped -Text $Status

    return @"
<Set operation="update">
  <DHCPServerStatus>
    <DHCPServerNamedhcpname>$nameEsc</DHCPServerNamedhcpname>
    <Status>$statusEsc</Status>
  </DHCPServerStatus>
</Set>
"@
}

<#
        .SYNOPSIS
        Switches an existing DHCP server on a Sophos Firewall on or off.

        .DESCRIPTION
        Enables or disables a DHCP scope that already exists on the appliance. The API
        exposes this as a write-only endpoint: there is no matching read operation, so the
        current state cannot be checked first and no read-modify-write is possible here,
        unlike every other Set-* cmdlet in this module.

        Turning off a DHCP server stops address assignment for every client on that segment.
        Existing leases keep working until they expire, so the effect is delayed and easy to
        miss. Check the scope name with Get-SfosDHCPServer first, and use -WhatIf to preview
        the call.

        .PARAMETER Name
        Required. Name of the existing DHCP server to switch, as shown by Get-SfosDHCPServer.
        Accepts pipeline input by property name.

        .PARAMETER Status
        Required. 'ON' to enable the server, 'OFF' to disable it.

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
        was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
        when you work with more than one at a time. Any connection parameter you pass
        explicitly still takes precedence. If omitted, the stored default connection is used.

        .INPUTS
        System.Management.Automation.PSCustomObject. A Get-SfosDHCPServer result can be piped
        in; Name binds by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        request.

        .EXAMPLE
        Set-SfosDHCPServerStatus -Name 'Lab-Scope' -Status OFF -WhatIf

        Shows what disabling the scope would send, without sending it to the firewall.

        .EXAMPLE
        Set-SfosDHCPServerStatus -Name 'Lab-Scope' -Status ON

        Enables the DHCP scope named Lab-Scope. The cmdlet asks for confirmation before it
        writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPServerStatus/operations/DHCPServerstatuschange.html

        .LINK
        Get-SfosDHCPServer
#>
function Set-SfosDHCPServerStatus {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
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
        if (-not $PSCmdlet.ShouldProcess("DHCPServer '$Name' on $($params.Firewall)", "Set status to $Status")) {
            return
        }

        $inner = ConvertTo-SfosDHCPServerStatusXml -Name $Name -Status $Status

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to set DHCPServerStatus for '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServerStatus' -Action 'set status' -Target $Name
    }
}

#endregion

#region DHCPServerIpv6

# --- DHCPServerIpv6 ---
#
# Doc folder is 'DHCPIPV6Server', wire element is 'DHCPServerIpv6'. A <DHCPIPV6Server> root
# would answer 529 'Input request module is Invalid', the same failure class as
# <CountryHostGroup>. Cmdlet nouns follow the wire element - the Sophos spelling wins.
#
# Creating an IPv6 DHCP scope acts on a live segment, just like its IPv4 sibling.
#
# Wire shape:
#   <DHCPServerIpv6><Name>...</Name><Interface>...</Interface>
#     <IPLease><IP>start-end</IP>...</IPLease>
#     <StaticLease><Lease><HostName>...<DUID>...<IPAddress>...</Lease>...</StaticLease>
#     <UseApplianceDNSSettings>...</UseApplianceDNSSettings><PreferredTime>.../PreferredTime>
#     <ValidTime>...</ValidTime><PrimaryDNSServer>.../PrimaryDNSServer>
#     <SecondaryDNSServer>...</SecondaryDNSServer>
#     <DHCPOption><Options>...</Options></DHCPOption></DHCPServerIpv6>
# The StaticLease entry uses <DUID> where the IPv4 sibling (DHCPServer) uses <MACAddress>,
# per the sample XML for AddIPv6DHCPServer&EditIPv6DHCPServer. LeaseForRelay is documented
# in the attribute table but absent from the sample XML; it is still emitted here
# (defaulting to empty/unset) for parity with DHCPServer.

<#
.SYNOPSIS
    Builds the create or update XML body for a DHCPServerIpv6 entity.

.DESCRIPTION
    Turns a fully resolved DHCPServerIpv6 object into the XML that New-SfosDHCPServerIpv6 and
    Set-SfosDHCPServerIpv6 send to the firewall, so both cmdlets send an identical, complete
    entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER DHCPServerIpv6
    Fully resolved object with the same property shape Get-SfosDHCPServerIpv6 returns.
#>
function ConvertTo-SfosDHCPServerIpv6Xml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$DHCPServerIpv6
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.Name)
    $interfaceEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.Interface)
    $useApplianceDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.UseApplianceDNSSettings)
    $preferredEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.PreferredTime)
    $validEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.ValidTime)
    $primaryDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.PrimaryDNSServer)
    $secondaryDnsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.SecondaryDNSServer)
    $leaseRelayEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPServerIpv6.LeaseForRelay)

    $ipLeaseXml = ''
    foreach ($range in @($DHCPServerIpv6.IPLease)) {
        if (-not $range) {
            continue
        }
        $ipLeaseXml += "<IP>$(ConvertTo-SfosXmlEscaped -Text $range)</IP>"
    }

    $staticLeaseXml = ''
    foreach ($lease in @($DHCPServerIpv6.StaticLease)) {
        if (-not $lease) {
            continue
        }
        $hostEsc = ConvertTo-SfosXmlEscaped -Text ([string]$lease.HostName)
        $duidEsc = ConvertTo-SfosXmlEscaped -Text ([string]$lease.DUID)
        $ipEsc = ConvertTo-SfosXmlEscaped -Text ([string]$lease.IPAddress)
        $staticLeaseXml += "<Lease><HostName>$hostEsc</HostName><DUID>$duidEsc</DUID><IPAddress>$ipEsc</IPAddress></Lease>"
    }
    if ($staticLeaseXml) {
        $staticLeaseXml = "<StaticLease>$staticLeaseXml</StaticLease>"
    }

    $dhcpOptionXml = ''
    foreach ($opt in @($DHCPServerIpv6.DHCPOption)) {
        if (-not $opt) {
            continue
        }
        $optNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionName)
        $optTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionType)
        $optCodeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionCode)
        $optValueEsc = ConvertTo-SfosXmlEscaped -Text ([string]$opt.OptionValue)
        $dhcpOptionXml += "<Options><OptionName>$optNameEsc</OptionName><OptionType>$optTypeEsc</OptionType><OptionCode>$optCodeEsc</OptionCode><OptionValue>$optValueEsc</OptionValue></Options>"
    }
    if ($dhcpOptionXml) {
        $dhcpOptionXml = "<DHCPOption>$dhcpOptionXml</DHCPOption>"
    }

    return @"
<Set operation="$Operation">
  <DHCPServerIpv6>
    <Name>$nameEsc</Name>
    <Interface>$interfaceEsc</Interface>
    <IPLease>$ipLeaseXml</IPLease>
    $staticLeaseXml
    <UseApplianceDNSSettings>$useApplianceDnsEsc</UseApplianceDNSSettings>
    <PreferredTime>$preferredEsc</PreferredTime>
    <ValidTime>$validEsc</ValidTime>
    <PrimaryDNSServer>$primaryDnsEsc</PrimaryDNSServer>
    <SecondaryDNSServer>$secondaryDnsEsc</SecondaryDNSServer>
    <LeaseForRelay>$leaseRelayEsc</LeaseForRelay>
    $dhcpOptionXml
  </DHCPServerIpv6>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves IPv6 DHCP servers from a Sophos Firewall.

.DESCRIPTION
    Returns the DHCPServerIpv6 objects that are defined on the firewall. The cmdlet only
    reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only DHCP servers whose name contains the given text anywhere. If
    omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per DHCP server, with the
    properties Name, Interface, IPLease, StaticLease (an array of objects with HostName,
    DUID and IPAddress), UseApplianceDNSSettings, PreferredTime, ValidTime, PrimaryDNSServer,
    SecondaryDNSServer, LeaseForRelay and DHCPOption (an array of objects with OptionName,
    OptionType, OptionCode and OptionValue). Returns System.Xml.XmlElement when -AsXml is
    used, and an empty array when no DHCP server matches.

.EXAMPLE
    Get-SfosDHCPServerIpv6

    Lists every IPv6 DHCP server on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPIPV6Server/DHCPIPV6Server.html

.LINK
    New-SfosDHCPServerIpv6

.LINK
    Set-SfosDHCPServerIpv6
#>
function Get-SfosDHCPServerIpv6 {
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
  <DHCPServerIpv6>
    $filterXml
  </DHCPServerIpv6>
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
        throw "Error retrieving DHCPServerIpv6 objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServerIpv6' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DHCPServerIpv6[Name]' | ForEach-Object -Process { $_.Node }

    $nodes = @($nodes)
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $serverObjects = foreach ($node in $nodes) {
        $staticLease = foreach ($leaseNode in @($node.StaticLease.Lease)) {
            if (-not $leaseNode) {
                continue
            }
            [PSCustomObject]@{
                HostName  = [string]$leaseNode.HostName
                DUID      = [string]$leaseNode.DUID
                IPAddress = [string]$leaseNode.IPAddress
            }
        }

        $dhcpOption = foreach ($optNode in @($node.DHCPOption.Options)) {
            if (-not $optNode) {
                continue
            }
            [PSCustomObject]@{
                OptionName  = [string]$optNode.OptionName
                OptionType  = [string]$optNode.OptionType
                OptionCode  = [string]$optNode.OptionCode
                OptionValue = [string]$optNode.OptionValue
            }
        }

        [PSCustomObject]@{
            Name                    = [string]$node.Name
            Interface               = [string]$node.Interface
            IPLease                 = [string[]]@($node.IPLease | Select-Object -ExpandProperty IP -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_ })
            StaticLease             = [object[]]@($staticLease)
            UseApplianceDNSSettings = [string]$node.UseApplianceDNSSettings
            PreferredTime           = [string]$node.PreferredTime
            ValidTime               = [string]$node.ValidTime
            PrimaryDNSServer        = [string]$node.PrimaryDNSServer
            SecondaryDNSServer      = [string]$node.SecondaryDNSServer
            LeaseForRelay           = [string]$node.LeaseForRelay
            DHCPOption              = [object[]]@($dhcpOption)
        }
    }

    return @($serverObjects)
}

<#
.SYNOPSIS
    Creates an IPv6 DHCP server on a Sophos Firewall.

.DESCRIPTION
    Adds an IPv6 DHCP server scope. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

    Adding a second DHCP server for a segment that already has one active hands out
    conflicting addresses to clients on that network. Check the existing scopes with
    Get-SfosDHCPServerIpv6 before creating a new one on a live segment.

.PARAMETER Name
    Required. Name for the DHCP server, up to 50 characters, no commas.

.PARAMETER Interface
    Required. Interface on which the DHCP service is configured.

.PARAMETER IPLease
    Required. One or more IPv6 address ranges, in the form "start-end", from which the server
    assigns addresses.

.PARAMETER PreferredTime
    Required. Preferred lifetime in minutes, 1-43200.

.PARAMETER ValidTime
    Required. Valid lifetime in minutes, 1-43200.

.PARAMETER UseApplianceDNSSettings
    Optional. Whether to hand out the appliance's own DNS settings to clients: 'Enable' or
    'Disable'. Default: 'Enable'.

.PARAMETER PrimaryDNSServer
    Optional. Primary IPv6 DNS server address handed to clients when
    UseApplianceDNSSettings is 'Disable'. Default: empty string.

.PARAMETER SecondaryDNSServer
    Optional. Secondary IPv6 DNS server address. Default: empty string.

.PARAMETER LeaseForRelay
    Optional. Whether the server accepts requests forwarded by a DHCP relay: 'Enable' or
    'Disable'. Default: 'Disable'.

.PARAMETER StaticLease
    Optional. Array of objects with HostName, DUID and IPAddress properties, for static
    DUID-to-IP mappings.

.PARAMETER DHCPOption
    Optional. Array of objects with OptionName, OptionType, OptionCode and OptionValue
    properties, for custom DHCP options.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Name binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosDHCPServerIpv6 -Name 'Branch-Scope-v6' -Interface 'PortC' -IPLease '2001:db8::10-2001:db8::200' -PreferredTime 540 -ValidTime 720 -WhatIf

    Shows what creating the scope would send, without sending it to the firewall.

.EXAMPLE
    New-SfosDHCPServerIpv6 -Name 'Branch-Scope-v6' -Interface 'PortC' -IPLease '2001:db8::10-2001:db8::200' -PreferredTime 540 -ValidTime 720

    Creates an IPv6 DHCP scope named Branch-Scope-v6 on PortC. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPIPV6Server/operations/AddIPv6DHCPServer%26EditIPv6DHCPServer.html

.LINK
    Get-SfosDHCPServerIpv6

.LINK
    Set-SfosDHCPServerIpv6
#>
function New-SfosDHCPServerIpv6 {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Interface,

        [Parameter(Mandatory)]
        [string[]]$IPLease,

        [Parameter(Mandatory)]
        [ValidateRange(1, 43200)]
        [int]$PreferredTime,

        [Parameter(Mandatory)]
        [ValidateRange(1, 43200)]
        [int]$ValidTime,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseApplianceDNSSettings = 'Enable',

        [string]$PrimaryDNSServer = '',
        [string]$SecondaryDNSServer = '',

        [ValidateSet('Enable', 'Disable')]
        [string]$LeaseForRelay = 'Disable',

        [object[]]$StaticLease = @(),
        [object[]]$DHCPOption = @(),

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
        if (-not $PSCmdlet.ShouldProcess("DHCPServerIpv6 '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $dhcpServer = [PSCustomObject]@{
            Name                    = $Name
            Interface               = $Interface
            IPLease                 = $IPLease
            PreferredTime           = $PreferredTime
            ValidTime               = $ValidTime
            UseApplianceDNSSettings = $UseApplianceDNSSettings
            PrimaryDNSServer        = $PrimaryDNSServer
            SecondaryDNSServer      = $SecondaryDNSServer
            LeaseForRelay           = $LeaseForRelay
            StaticLease             = $StaticLease
            DHCPOption              = $DHCPOption
        }
        $inner = ConvertTo-SfosDHCPServerIpv6Xml -Operation 'add' -DHCPServerIpv6 $dhcpServer

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DHCPServerIpv6 object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServerIpv6' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an IPv6 DHCP server on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing IPv6 DHCP scope. The cmdlet reads the current object
    first and sends every field back; fields you do not pass keep their current value. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER Name
    Required. Name identifying the scope to update. Accepts pipeline input by property name.

.PARAMETER Interface
    Optional. Replacement interface name. If omitted, the current value is kept.

.PARAMETER IPLease
    Optional. Replacement IPv6 lease ranges. If omitted, the current value is kept.

.PARAMETER PreferredTime
    Optional. Replacement preferred lifetime in minutes. If omitted, the current value is
    kept.

.PARAMETER ValidTime
    Optional. Replacement valid lifetime in minutes. If omitted, the current value is kept.

.PARAMETER UseApplianceDNSSettings
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

.PARAMETER PrimaryDNSServer
    Optional. Replacement primary DNS server address. If omitted, the current value is kept.

.PARAMETER SecondaryDNSServer
    Optional. Replacement secondary DNS server address. If omitted, the current value is
    kept.

.PARAMETER LeaseForRelay
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

.PARAMETER StaticLease
    Optional. Replacement static lease list. If omitted, the current value is kept.

.PARAMETER DHCPOption
    Optional. Replacement DHCP option list. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDHCPServerIpv6 result can be piped
    in; Name binds by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosDHCPServerIpv6 -Name 'Branch-Scope-v6' -ValidTime 1440 -WhatIf

    Shows what changing the valid lifetime would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosDHCPServerIpv6 -Name 'Branch-Scope-v6' -ValidTime 1440

    Changes the valid lifetime of Branch-Scope-v6; every other field is preserved. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPIPV6Server/operations/AddIPv6DHCPServer%26EditIPv6DHCPServer.html

.LINK
    Get-SfosDHCPServerIpv6

.LINK
    New-SfosDHCPServerIpv6
#>
function Set-SfosDHCPServerIpv6 {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Interface,
        [string[]]$IPLease,

        [ValidateRange(1, 43200)]
        [int]$PreferredTime,

        [ValidateRange(1, 43200)]
        [int]$ValidTime,

        [ValidateSet('Enable', 'Disable')]
        [string]$UseApplianceDNSSettings,

        [string]$PrimaryDNSServer,
        [string]$SecondaryDNSServer,

        [ValidateSet('Enable', 'Disable')]
        [string]$LeaseForRelay,

        [object[]]$StaticLease,
        [object[]]$DHCPOption,

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
        $existing = @(Get-SfosDHCPServerIpv6 -NameLike $Name @params | Where-Object -FilterScript { $_.Name -eq $Name })
        if ($existing.Count -eq 0) {
            throw "The DHCPServerIpv6 object '$Name' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $dhcpServer = [PSCustomObject]@{
            Name                    = $Name
            Interface               = if ($bp.ContainsKey('Interface')) { $Interface } else { $existing.Interface }
            IPLease                 = if ($bp.ContainsKey('IPLease')) { $IPLease } else { $existing.IPLease }
            PreferredTime           = if ($bp.ContainsKey('PreferredTime')) { $PreferredTime } else { $existing.PreferredTime }
            ValidTime               = if ($bp.ContainsKey('ValidTime')) { $ValidTime } else { $existing.ValidTime }
            UseApplianceDNSSettings = if ($bp.ContainsKey('UseApplianceDNSSettings')) { $UseApplianceDNSSettings } else { $existing.UseApplianceDNSSettings }
            PrimaryDNSServer        = if ($bp.ContainsKey('PrimaryDNSServer')) { $PrimaryDNSServer } else { $existing.PrimaryDNSServer }
            SecondaryDNSServer      = if ($bp.ContainsKey('SecondaryDNSServer')) { $SecondaryDNSServer } else { $existing.SecondaryDNSServer }
            LeaseForRelay           = if ($bp.ContainsKey('LeaseForRelay')) { $LeaseForRelay } else { $existing.LeaseForRelay }
            StaticLease             = if ($bp.ContainsKey('StaticLease')) { $StaticLease } else { $existing.StaticLease }
            DHCPOption              = if ($bp.ContainsKey('DHCPOption')) { $DHCPOption } else { $existing.DHCPOption }
        }

        if (-not $PSCmdlet.ShouldProcess("DHCPServerIpv6 '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosDHCPServerIpv6Xml -Operation 'update' -DHCPServerIpv6 $dhcpServer

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DHCPServerIpv6 object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServerIpv6' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an IPv6 DHCP server from a Sophos Firewall.

.DESCRIPTION
    Deletes an IPv6 DHCP scope, identified by its name. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Name
    Required. Name of the DHCP scope to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDHCPServerIpv6 result can be piped
    in; Name binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosDHCPServerIpv6 -Name 'Branch-Scope-v6' -WhatIf

    Shows what removing the scope would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDHCPServerIpv6 -Name 'Branch-Scope-v6'

    Removes the IPv6 DHCP scope named Branch-Scope-v6. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPIPV6Server/operations/Delete%20IPv6%20DHCP%20Server.html

.LINK
    Get-SfosDHCPServerIpv6
#>
function Remove-SfosDHCPServerIpv6 {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
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
        if (-not $PSCmdlet.ShouldProcess("DHCPServerIpv6 '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <DHCPServerIpv6>
    <Name>$nameEsc</Name>
  </DHCPServerIpv6>
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
            throw "Error removing DHCPServerIpv6 object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPServerIpv6' -Action 'remove' -Target $Name
    }
}

#endregion

#region DHCPRelay

# --- DHCPRelay ---
#
# A relay configuration acts on a live segment.
#
# Wire shape:
#   <DHCPRelay><Name>...</Name><IPFamily>IPv4/IPv6</IPFamily><Interface>...</Interface>
#     <DHCPServerIP>...</DHCPServerIP><RelaythroughIPSec>.../RelaythroughIPSec></DHCPRelay>
# DHCPServerIP is documented as an array, so multiple <DHCPServerIP> siblings are emitted
# for more than one target server, matching the repeated-element style used elsewhere in
# this module (IPLease/IP, TargetServers/Host).

<#
.SYNOPSIS
    Builds the create or update XML body for a DHCPRelay entity.

.DESCRIPTION
    Turns a fully resolved DHCPRelay object into the XML that New-SfosDHCPRelay and
    Set-SfosDHCPRelay send to the firewall, so both cmdlets send an identical, complete
    entity body.

.PARAMETER Operation
    Required. 'add' or 'update', passed straight to the Set operation attribute.

.PARAMETER DHCPRelay
    Fully resolved DHCPRelay object with Name, IPFamily, Interface, DHCPServerIP and
    RelaythroughIPSec properties.
#>
function ConvertTo-SfosDHCPRelayXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$DHCPRelay
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPRelay.Name)
    $ipFamilyEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPRelay.IPFamily)
    $interfaceEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPRelay.Interface)
    $relaySecEsc = ConvertTo-SfosXmlEscaped -Text ([string]$DHCPRelay.RelaythroughIPSec)

    $serverIpXml = ''
    foreach ($ip in @($DHCPRelay.DHCPServerIP)) {
        if (-not $ip) {
            continue
        }
        $serverIpXml += "<DHCPServerIP>$(ConvertTo-SfosXmlEscaped -Text $ip)</DHCPServerIP>"
    }

    return @"
<Set operation="$Operation">
  <DHCPRelay>
    <Name>$nameEsc</Name>
    <IPFamily>$ipFamilyEsc</IPFamily>
    <Interface>$interfaceEsc</Interface>
    $serverIpXml
    <RelaythroughIPSec>$relaySecEsc</RelaythroughIPSec>
  </DHCPRelay>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves DHCP relay agents from a Sophos Firewall.

.DESCRIPTION
    Returns the DHCPRelay objects that are defined on the firewall. The cmdlet only reads;
    nothing on the firewall is changed. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only relay agents whose name contains the given text anywhere. If
    omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the network
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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per relay agent, with the
    properties Name, IPFamily, Interface, DHCPServerIP and RelaythroughIPSec. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no relay agent matches.

.EXAMPLE
    Get-SfosDHCPRelay

    Lists every DHCP relay agent on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPRelay/DHCPRelay.html

.LINK
    New-SfosDHCPRelay

.LINK
    Set-SfosDHCPRelay
#>
function Get-SfosDHCPRelay {
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
  <DHCPRelay>
    $filterXml
  </DHCPRelay>
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
        throw "Error retrieving DHCPRelay objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPRelay' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/DHCPRelay[Name]' | ForEach-Object -Process { $_.Node }

    $nodes = @($nodes)
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $relayObjects = foreach ($node in $nodes) {
        [PSCustomObject]@{
            Name              = [string]$node.Name
            IPFamily          = [string]$node.IPFamily
            Interface         = [string]$node.Interface
            DHCPServerIP      = [string[]]@($node.DHCPServerIP | Where-Object -FilterScript { $_ })
            RelaythroughIPSec = [string]$node.RelaythroughIPSec
        }
    }

    return @($relayObjects)
}

<#
.SYNOPSIS
    Creates a DHCP relay agent on a Sophos Firewall.

.DESCRIPTION
    Adds a DHCP relay agent configuration. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

.PARAMETER Name
    Required. Name for the DHCP relay agent, up to 60 characters, no commas.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'. Default: 'IPv4'.

.PARAMETER Interface
    Required. Interface on which the relay agent is configured.

.PARAMETER DHCPServerIP
    Required. One or more target DHCP server IP addresses to relay requests to, given as
    literal IP addresses.

.PARAMETER RelaythroughIPSec
    Optional. Whether to relay through an IPsec tunnel: 'Enable' or 'Disable'. Default:
    'Disable'.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosDHCPRelay -Name 'Branch-Relay' -Interface 'PortC' -DHCPServerIP '203.0.113.53' -WhatIf

    Shows what creating the relay agent would send, without sending it to the firewall.

.EXAMPLE
    New-SfosDHCPRelay -Name 'Branch-Relay' -Interface 'PortC' -DHCPServerIP '203.0.113.53'

    Creates a DHCP relay agent named Branch-Relay on PortC, forwarding to 203.0.113.53. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPRelay/operations/AddDHCPRelayConfiguration%26EditDHCPRelayConfiguration.html

.LINK
    Get-SfosDHCPRelay
#>
function New-SfosDHCPRelay {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily = 'IPv4',

        [Parameter(Mandatory)]
        [string]$Interface,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$DHCPServerIP,

        [ValidateSet('Enable', 'Disable')]
        [string]$RelaythroughIPSec = 'Disable',

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
        if (-not $PSCmdlet.ShouldProcess("DHCPRelay '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $relay = [PSCustomObject]@{
            Name              = $Name
            IPFamily          = $IPFamily
            Interface         = $Interface
            DHCPServerIP      = $DHCPServerIP
            RelaythroughIPSec = $RelaythroughIPSec
        }
        $inner = ConvertTo-SfosDHCPRelayXml -Operation 'add' -DHCPRelay $relay

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DHCPRelay object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPRelay' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a DHCP relay agent on a Sophos Firewall.

.DESCRIPTION
    Changes the settings of an existing DHCP relay agent. The cmdlet reads the current object
    first and sends every field back; fields you do not pass keep their current value. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER Name
    Required. Name identifying the relay agent to update. Accepts pipeline input by value and
    by property name.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'. If omitted, the current value is kept.

.PARAMETER Interface
    Optional. Replacement interface name. If omitted, the current value is kept.

.PARAMETER DHCPServerIP
    Optional. Replacement target DHCP server IP list. If omitted, the current value is kept.

.PARAMETER RelaythroughIPSec
    Optional. 'Enable' or 'Disable'. If omitted, the current value is kept.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDHCPRelay result can be piped in;
    Name binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosDHCPRelay -Name 'Branch-Relay' -RelaythroughIPSec Enable -WhatIf

    Shows what enabling relay through IPsec would send, without sending it to the firewall.

.EXAMPLE
    Set-SfosDHCPRelay -Name 'Branch-Relay' -RelaythroughIPSec Enable

    Enables relay through IPsec for Branch-Relay; every other field is preserved. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPRelay/operations/AddDHCPRelayConfiguration%26EditDHCPRelayConfiguration.html

.LINK
    Get-SfosDHCPRelay

.LINK
    New-SfosDHCPRelay
#>
function Set-SfosDHCPRelay {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string]$Interface,
        [string[]]$DHCPServerIP,

        [ValidateSet('Enable', 'Disable')]
        [string]$RelaythroughIPSec,

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
        $existing = @(Get-SfosDHCPRelay -NameLike $Name @params | Where-Object -FilterScript { $_.Name -eq $Name })
        if ($existing.Count -eq 0) {
            throw "The DHCPRelay object '$Name' was not found."
        }
        $existing = $existing[0]

        $bp = $PSBoundParameters
        $relay = [PSCustomObject]@{
            Name              = $Name
            IPFamily          = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { $existing.IPFamily }
            Interface         = if ($bp.ContainsKey('Interface')) { $Interface } else { $existing.Interface }
            DHCPServerIP      = if ($bp.ContainsKey('DHCPServerIP')) { $DHCPServerIP } else { $existing.DHCPServerIP }
            RelaythroughIPSec = if ($bp.ContainsKey('RelaythroughIPSec')) { $RelaythroughIPSec } else { $existing.RelaythroughIPSec }
        }

        if (-not $PSCmdlet.ShouldProcess("DHCPRelay '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosDHCPRelayXml -Operation 'update' -DHCPRelay $relay

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DHCPRelay object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPRelay' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a DHCP relay agent from a Sophos Firewall.

.DESCRIPTION
    Deletes a DHCP relay agent configuration, identified by its name. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly, and
    an account with administrative permission.

.PARAMETER Name
    Required. Name of the DHCP relay agent to remove. Accepts pipeline input by value and by
    property name.

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
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. A Get-SfosDHCPRelay result can be piped in;
    Name binds by value or by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal.

.EXAMPLE
    Remove-SfosDHCPRelay -Name 'Branch-Relay' -WhatIf

    Shows what removing the relay agent would send, without sending it to the firewall.

.EXAMPLE
    Remove-SfosDHCPRelay -Name 'Branch-Relay'

    Removes the DHCP relay agent named Branch-Relay. The cmdlet asks for confirmation before
    it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/CONFIGURE/Network/DHCPRelay/operations/Delete%20DHCP%20Relay%20Configuration.html

.LINK
    Get-SfosDHCPRelay
#>
function Remove-SfosDHCPRelay {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        if (-not $PSCmdlet.ShouldProcess("DHCPRelay '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <DHCPRelay>
    <Name>$nameEsc</Name>
  </DHCPRelay>
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
            throw "Error removing DHCPRelay object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DHCPRelay' -Action 'remove' -Target $Name
    }
}

#endregion

