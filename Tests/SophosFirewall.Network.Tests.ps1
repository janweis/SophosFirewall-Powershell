#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Network module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    With 100 exported functions, exhaustive per-cmdlet coverage is neither achievable nor
    useful. Coverage here is weighted towards the failure modes the project build rules and the module's own
    .NOTES call out as measured, expensive defects: the eight wire element names that differ
    from their documentation folder (a wrong root element answers 529 and fails silently for
    every caller who does not inspect the raw response), the read-modify-write cmdlets whose
    omitted fields are silently cleared by the firewall (Interface, Zone, GatewayConfiguration,
    DNS), and Remove-SfosVLAN's Hardware-vs-Name defect, where the wrong key reports success
    while deleting nothing.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

# Get module path - use relative paths that work in any environment
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Network\SophosFirewall.Network.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $ModulePath)) {
    Write-Error "Module manifest not found: $ModulePath"
    exit 1
}

# Import modules
Import-Module $CoreModulePath -Force
Import-Module $ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Network module should load' {
        Get-Module SophosFirewall.Network | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 100 functions' {
        (Get-Module SophosFirewall.Network).ExportedFunctions.Count | Should -Be 100
    }

    Context 'Private helpers are not exported' {
        # These build entity XML internally (ConvertTo-Sfos*Xml) or resolve one Gateway field's
        # merge precedence (Resolve-SfosGatewayFieldValue). If FunctionsToExport ever grew to
        # include one of these by accident, a caller could bypass the read-modify-write logic
        # in the matching Set-* and send an incomplete entity that silently drops fields
        # (the project build rules, section 5).
        It 'None of the 17 private helpers should be visible' {
            $privateHelpers = @(
                'ConvertTo-SfosInterfaceXml',
                'ConvertTo-SfosVLANXml',
                'ConvertTo-SfosLAGXml',
                'ConvertTo-SfosBridgePairXml',
                'ConvertTo-SfosAliasXml',
                'ConvertTo-SfosZoneApplianceAccessXml',
                'Resolve-SfosGatewayFieldValue',
                'ConvertTo-SfosGatewayConfigurationXml',
                'ConvertTo-SfosRouterAdvertisementXml',
                'ConvertTo-SfosDNSXml',
                'ConvertTo-SfosDNSHostEntryXml',
                'ConvertTo-SfosDNSRequestRouteXml',
                'ConvertTo-SfosDynamicDNSXml',
                'ConvertTo-SfosDHCPServerXml',
                'ConvertTo-SfosDHCPServerStatusXml',
                'ConvertTo-SfosDHCPServerIpv6Xml',
                'ConvertTo-SfosDHCPRelayXml'
            )
            foreach ($name in $privateHelpers) {
                Get-Command $name -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$name must stay private"
            }
        }
    }
}

Describe 'Wire Element Names (doc folder differs from API element)' {
    # the project build rules, section 3 / module header: eight documentation folders carry a different name
    # than the XML element they describe. A wrong root element answers 529 "Input request
    # module is Invalid" - or, for GreTunnel/GreRoute, silently hits a same-named-but-wrong-case
    # element instead, since the two only differ in capitalisation from their doc folders
    # (GRETunnel/GreTunnel, GRERoute/GreRoute).

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'CellularWAN (doc folder: WWAN)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CellularWAN><Action>Disable</Action><DisconnectOnSystemDown></DisconnectOnSystemDown></CellularWAN></Response>' }
            }
        }

        It 'Get-SfosCellularWAN should send element CellularWAN, never WWAN' {
            Get-SfosCellularWAN @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<CellularWAN>' -and $InnerXml -cnotmatch '<WWAN>'
            }
        }
    }

    Context 'ARPConfiguration (doc folder: ARPNeighbour)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ARPConfiguration><ARPCacheEntryTimeOut>10</ARPCacheEntryTimeOut><LogPossibleARPPoisoningAttempts>Disable</LogPossibleARPPoisoningAttempts></ARPConfiguration></Response>' }
            }
        }

        It 'Get-SfosARPConfiguration should send element ARPConfiguration, never ARPNeighbour' {
            Get-SfosARPConfiguration @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ARPConfiguration>' -and $InnerXml -cnotmatch '<ARPNeighbour>'
            }
        }
    }

    Context 'StaticARP (doc folder: ARP)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><StaticARP><Status>No. of records Zero.</Status></StaticARP></Response>' }
            }
        }

        It 'Get-SfosStaticARP should send element StaticARP, never the bare ARP' {
            Get-SfosStaticARP @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<StaticARP>' -and $InnerXml -cnotmatch '<ARP>'
            }
        }
    }

    Context 'GatewayConfiguration (doc folder: Gateway)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayConfiguration><GatewayFailoverTimeout>60</GatewayFailoverTimeout></GatewayConfiguration></Response>' }
            }
        }

        It 'Get-SfosGatewayConfiguration should send element GatewayConfiguration, never the bare Gateway' {
            Get-SfosGatewayConfiguration @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<GatewayConfiguration>' -and $InnerXml -cnotmatch '<Gateway>'
            }
        }
    }

    Context 'DHCPServerIpv6 (doc folder: DHCPIPV6Server)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServerIpv6><Status>No. of records Zero.</Status></DHCPServerIpv6></Response>' }
            }
        }

        It 'Get-SfosDHCPServerIpv6 should send element DHCPServerIpv6, never DHCPIPV6Server' {
            Get-SfosDHCPServerIpv6 @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<DHCPServerIpv6>' -and $InnerXml -cnotmatch '<DHCPIPV6Server>'
            }
        }
    }

    Context 'TAP (doc folder: TapInterfaceConfiguration)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><TAP><Status>No. of records Zero.</Status></TAP></Response>' }
            }
        }

        It 'Get-SfosTAP should send element TAP, never TapInterfaceConfiguration' {
            Get-SfosTAP @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<TAP>' -and $InnerXml -cnotmatch '<TapInterfaceConfiguration>'
            }
        }
    }

    Context 'GreTunnel (doc folder: GRETunnel - differs only in capitalisation)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreTunnel><Status>No. of records Zero.</Status></GreTunnel></Response>' }
            }
        }

        It 'Get-SfosGreTunnel should send element GreTunnel, never the all-caps GRETunnel' {
            Get-SfosGreTunnel @conn | Out-Null

            # -cnotmatch, not -notmatch: the two spellings differ only by case, and PowerShell's
            # default -match/-notmatch is case-insensitive, so a case-insensitive check here
            # would pass even if the module sent the wrong-case element.
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<GreTunnel>' -and $InnerXml -cnotmatch '<GRETunnel>'
            }
        }
    }

    Context 'GreRoute (doc folder: GRERoute - differs only in capitalisation)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreRoute><Status>No. of records Zero.</Status></GreRoute></Response>' }
            }
        }

        It 'Get-SfosGreRoute should send element GreRoute, never the all-caps GRERoute' {
            Get-SfosGreRoute @conn | Out-Null

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<GreRoute>' -and $InnerXml -cnotmatch '<GRERoute>'
            }
        }
    }
}

Describe 'Read-Modify-Write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosInterface' {
        BeforeEach {
            # Set-SfosInterface reads the current interface first (the project build rules, section 5). The
            # mocked Get answers with a fully populated interface so a partial -MTU-only update
            # can be checked against it: IPAddress/Netmask/NetworkZone/IPv4Assignment are the
            # fields whose loss would be most expensive (dropping the session's own IP or zone).
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <Interface>
    <Name>Uplink9</Name>
    <Hardware>Port9</Hardware>
    <NetworkZone>LAN</NetworkZone>
    <IPv4Configuration>Enable</IPv4Configuration>
    <IPv4Assignment>Static</IPv4Assignment>
    <IPAddress>10.0.0.5</IPAddress>
    <Netmask>255.255.255.0</Netmask>
    <GatewayName></GatewayName>
    <GatewayIP></GatewayIP>
    <IPv6Configuration>Disable</IPv6Configuration>
    <DHCPRapidCommit>Disable</DHCPRapidCommit>
    <InterfaceSpeed>Auto Negotiate</InterfaceSpeed>
    <AutoNegotiation>Enable</AutoNegotiation>
    <FEC>Off</FEC>
    <MTU>1500</MTU>
    <MSS><OverrideMSS>Disable</OverrideMSS><MSSValue>1460</MSSValue></MSS>
    <MACAddress>Default</MACAddress>
    <DADAttempts>1</DADAttempts>
    <AllowedRAServers></AllowedRAServers>
    <InterfaceStatus>ON</InterfaceStatus>
  </Interface>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Interface><Status code="200">OK</Status></Interface></Response>' }
                }
            }
        }

        It 'Should resend IPAddress, Netmask, NetworkZone and IPv4Assignment unchanged on an MTU-only update' {
            # Omitting any of these on a live update would silently clear the field
            # (the project build rules, section 5) - on a physical port this can drop the session's own IP.
            Set-SfosInterface -Hardware 'Port9' -MTU 9000 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<IPAddress>10\.0\.0\.5</IPAddress>' -and
                $InnerXml -match '<Netmask>255\.255\.255\.0</Netmask>' -and
                $InnerXml -match '<NetworkZone>LAN</NetworkZone>' -and
                $InnerXml -match '<IPv4Assignment>Static</IPv4Assignment>' -and
                $InnerXml -match '<MTU>9000</MTU>'
            }
        }
    }

    Context 'Set-SfosZone' {
        BeforeEach {
            # All five ApplianceAccess groups populated with distinct values, so a partial
            # update dropping any one group would be visible in the assertion below.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <Zone>
    <Name>DMZ9</Name>
    <Type>DMZ</Type>
    <Description>Original description</Description>
    <MemberPorts>Port9</MemberPorts>
    <ApplianceAccess>
      <AdminServices><HTTPS>Enable</HTTPS><SSH>Enable</SSH></AdminServices>
      <AuthenticationServices><ClientAuthentication>Enable</ClientAuthentication><CaptivePortal>Disable</CaptivePortal><ADSSO>Disable</ADSSO><RadiusSSO>Disable</RadiusSSO><ChromebookSSO>Disable</ChromebookSSO></AuthenticationServices>
      <NetworkServices><DNS>Enable</DNS><Ping>Enable</Ping></NetworkServices>
      <VPNServices><IPsec>Enable</IPsec><RED>Disable</RED><SSLVPN>Enable</SSLVPN><VPNPortal>Disable</VPNPortal></VPNServices>
      <OtherServices><WebProxy>Disable</WebProxy><WirelessProtection>Disable</WirelessProtection><UserPortal>Enable</UserPortal><DynamicRouting>Disable</DynamicRouting><SMTPRelay>Disable</SMTPRelay><SNMP>Disable</SNMP></OtherServices>
    </ApplianceAccess>
  </Zone>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Zone><Status code="200">OK</Status></Zone></Response>' }
                }
            }
        }

        It 'Should resend all five ApplianceAccess groups unchanged on a description-only update' {
            Set-SfosZone -Name 'DMZ9' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<AdminServices><HTTPS>Enable</HTTPS><SSH>Enable</SSH></AdminServices>' -and
                $InnerXml -match '<AuthenticationServices><ClientAuthentication>Enable</ClientAuthentication><CaptivePortal>Disable</CaptivePortal><ADSSO>Disable</ADSSO><RadiusSSO>Disable</RadiusSSO><ChromebookSSO>Disable</ChromebookSSO></AuthenticationServices>' -and
                $InnerXml -match '<NetworkServices><DNS>Enable</DNS><Ping>Enable</Ping></NetworkServices>' -and
                $InnerXml -match '<VPNServices><IPsec>Enable</IPsec><RED>Disable</RED><SSLVPN>Enable</SSLVPN><VPNPortal>Disable</VPNPortal></VPNServices>' -and
                $InnerXml -match '<OtherServices><WebProxy>Disable</WebProxy><WirelessProtection>Disable</WirelessProtection><UserPortal>Enable</UserPortal><DynamicRouting>Disable</DynamicRouting><SMTPRelay>Disable</SMTPRelay><SNMP>Disable</SNMP></OtherServices>'
            }
        }
    }

    Context 'Set-SfosGatewayConfiguration' {
        BeforeEach {
            # One Gateway entry carrying Weight, a non-default Type and a FailOverRule - the
            # three sub-fields most likely to be silently dropped by a naive timeout-only update.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <GatewayConfiguration>
    <GatewayFailoverTimeout>60</GatewayFailoverTimeout>
    <Gateway>
      <Name>WAN-GW9</Name>
      <IPFamily>IPv4</IPFamily>
      <IPAddress>10.0.9.1</IPAddress>
      <Type>Active</Type>
      <Weight>8</Weight>
      <ActivateGatewayOnFailureOf>Any</ActivateGatewayOnFailureOf>
      <ActionOnActivation>InheritWeight</ActionOnActivation>
      <ActionOnFailback>ServeNewConnections</ActionOnFailback>
      <CustomWeight>5</CustomWeight>
      <FailOverRules>
        <Rule><Protocol>PING</Protocol><IPAddress>198.51.100.9</IPAddress><Port>*</Port><Condition>AND</Condition></Rule>
      </FailOverRules>
    </Gateway>
  </GatewayConfiguration>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GatewayConfiguration><Status code="200">OK</Status></GatewayConfiguration></Response>' }
                }
            }
        }

        It 'Should resend the full Gateway list, including Weight, Type and FailOverRules, on a timeout-only update' {
            Set-SfosGatewayConfiguration -GatewayFailoverTimeout 90 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<GatewayFailoverTimeout>90</GatewayFailoverTimeout>' -and
                $InnerXml -match '<Name>WAN-GW9</Name>' -and
                $InnerXml -match '<Weight>8</Weight>' -and
                $InnerXml -match '<Type>Active</Type>' -and
                $InnerXml -match '<FailOverRules><Rule><Protocol>PING</Protocol><IPAddress>198\.51\.100\.9</IPAddress><Port>\*</Port><Condition>AND</Condition></Rule></FailOverRules>'
            }
        }
    }

    Context 'Set-SfosDNS' {
        BeforeEach {
            # All three subtrees (IPv4Settings, IPv6Settings, DNSQueryConfiguration) populated
            # with distinct values, so a query-configuration-only update dropping either address
            # subtree would be visible below.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <DNS>
    <IPv4Settings>
      <ObtainDNSFrom>Static</ObtainDNSFrom>
      <DNSIPList><DNS1>10.0.0.53</DNS1><DNS2>10.0.0.54</DNS2><DNS3></DNS3></DNSIPList>
    </IPv4Settings>
    <IPv6Settings>
      <ObtainDNSFrom>Static</ObtainDNSFrom>
      <DNSIPList><DNS1>2001:db8::53</DNS1><DNS2></DNS2><DNS3></DNS3></DNSIPList>
    </IPv6Settings>
    <DNSQueryConfiguration>ChooseIPv4DNSServerOverIPv6</DNSQueryConfiguration>
  </DNS>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNS><Status code="200">OK</Status></DNS></Response>' }
                }
            }
        }

        It 'Should resend both IPv4Settings and IPv6Settings unchanged on a query-configuration-only update' {
            Set-SfosDNS -DNSQueryConfiguration 'ChooseIPv6DNSServerOverIPv4' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<DNSQueryConfiguration>ChooseIPv6DNSServerOverIPv4</DNSQueryConfiguration>' -and
                $InnerXml -match '<IPv4Settings>\s*<ObtainDNSFrom>Static</ObtainDNSFrom>' -and
                $InnerXml -match '<DNS1>10\.0\.0\.53</DNS1>' -and
                $InnerXml -match '<DNS2>10\.0\.0\.54</DNS2>' -and
                $InnerXml -match '<DNS1>2001:db8::53</DNS1>'
            }
        }
    }
}

Describe 'Remove-SfosVLAN resolves Hardware before deleting' {
    # A remove keyed on Name/Interface+VLANID answers 200 on real hardware and deletes nothing
    # (module region header). Remove-SfosVLAN resolves the server-computed Hardware value first,
    # then re-Gets after the remove call rather than trusting the response status alone.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'the object is actually gone after the remove call' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>' -and $script:sfosTestVlanRemoved) {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VLAN><Status>No. of records Zero.</Status></VLAN></Response>' }
                }
                elseif ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VLAN><Name>Guest9</Name><Hardware>Port9.997</Hardware><Interface>Port9</Interface><Zone>DMZ</Zone><VLANID>997</VLANID></VLAN></Response>' }
                }
                else {
                    $script:sfosTestVlanRemoved = $true
                    [PSCustomObject]@{ Content = '<Response><VLAN><Status code="200">Configuration applied successfully.</Status></VLAN></Response>' }
                }
            }
            $script:sfosTestVlanRemoved = $false
        }

        It 'Should send the resolved Hardware value in the Remove request, not Interface/VLANID' {
            Remove-SfosVLAN -Interface 'Port9' -VLANID 997 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Hardware>Port9\.997</Hardware>'
            } -Times 1 -Exactly
        }
    }

    Context 'the object is still present after a false-success remove' {
        BeforeEach {
            # Every Get, before and after the remove, answers with the same still-present
            # object - simulating the measured defect where a wrong remove key reports success
            # (code 200) while deleting nothing.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VLAN><Name>Guest9</Name><Hardware>Port9.997</Hardware><Interface>Port9</Interface><Zone>DMZ</Zone><VLANID>997</VLANID></VLAN></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VLAN><Status code="200">Configuration applied successfully.</Status></VLAN></Response>' }
                }
            }
        }

        It 'Should throw, not report success, when the object is still present after a 200 remove response' {
            { Remove-SfosVLAN -Interface 'Port9' -VLANID 997 @conn -Confirm:$false } |
                Should -Throw '*still present*'
        }
    }
}

Describe 'New-SfosAlias has no -Name parameter' {
    # The firewall computes the Alias name as "<Interface>:<Index>" itself; a caller-supplied
    # value was silently ignored in live testing (region header comment), so this module does
    # not expose one at all.
    It '(Get-Command New-SfosAlias).Parameters should not contain a Name key' {
        (Get-Command New-SfosAlias).Parameters.ContainsKey('Name') | Should -BeFalse
    }
}

Describe 'New-SfosGatewayConfigurationGateway -InputObject' {

    Context 'overriding only the bound field' {
        It 'Should override only Weight and inherit every other field, including FailOverRuleList' {
            $base = [PSCustomObject]@{
                Name                       = 'GW9'
                IPFamily                   = 'IPv4'
                IPAddress                  = '10.0.9.1'
                Type                       = 'Backup'
                Weight                     = '5'
                ActivateGatewayOnFailureOf = 'Any'
                ActionOnActivation         = 'InheritWeight'
                ActionOnFailback           = 'ServeNewConnections'
                CustomWeight               = '3'
                FailOverRuleList           = @([PSCustomObject]@{ Protocol = 'PING'; IPAddress = '198.51.100.9'; Port = '*'; Condition = 'AND' })
            }

            $result = $base | New-SfosGatewayConfigurationGateway -Weight '9'

            $result.Weight | Should -Be '9'
            $result.Name | Should -Be 'GW9'
            $result.Type | Should -Be 'Backup'
            $result.ActivateGatewayOnFailureOf | Should -Be 'Any'
            @($result.FailOverRuleList)[0].Protocol | Should -Be 'PING'
        }
    }

    Context 'multiple pipeline objects' {
        It 'Should process every object of the pipeline, not just the last' {
            $bases = @(
                [PSCustomObject]@{ Name = 'GW9-a'; IPFamily = 'IPv4'; IPAddress = '10.0.9.1'; Type = 'Active'; Weight = '5'; FailOverRuleList = @() }
                [PSCustomObject]@{ Name = 'GW9-b'; IPFamily = 'IPv4'; IPAddress = '10.0.9.2'; Type = 'Backup'; Weight = '1'; FailOverRuleList = @() }
            )

            $results = @($bases | New-SfosGatewayConfigurationGateway -CustomWeight '7')

            $results.Count | Should -Be 2
            $results[0].Name | Should -Be 'GW9-a'
            $results[1].Name | Should -Be 'GW9-b'
            $results[0].CustomWeight | Should -Be '7'
            $results[1].CustomWeight | Should -Be '7'
        }
    }
}

Describe 'GreRoute Host parameter alias' {
    # -HostAddress is aliased to -Host because $Host is an automatic PowerShell variable; the
    # wire element still has to be <Host>, not <HostAddress>.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosGreRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><GreRoute><Status code="200">OK</Status></GreRoute></Response>' }
            }
        }

        It 'Should emit the Host element, not HostAddress, when called via the -Host alias' {
            New-SfosGreRoute -Host '10.0.9.0' -Netmask '255.255.255.0' -TunnelName 'gre-test9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Host>10\.0\.9\.0</Host>' -and $InnerXml -notmatch '<HostAddress>'
            }
        }
    }

    Context 'Set-SfosGreRoute (delete-and-recreate)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreRoute><Host>10.0.9.0</Host><Netmask>255.255.255.0</Netmask><TunnelName>gre-test9</TunnelName></GreRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GreRoute><Status code="200">OK</Status></GreRoute></Response>' }
                }
            }
        }

        It 'Should emit the Host element, not HostAddress, when called via the -HostAddress parameter directly' {
            Set-SfosGreRoute -TunnelName 'gre-test9' -HostAddress '10.0.9.128' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
                $InnerXml -match '<Host>10\.0\.9\.128</Host>' -and $InnerXml -notmatch '<HostAddress>'
            } -Times 1 -Exactly
        }
    }
}

Describe 'Error Paths' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-* on a non-existent object' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Interface><Status>No. of records Zero.</Status></Interface></Response>' }
            }
        }

        It 'Should throw naming the entity type and the object name' {
            { Set-SfosInterface -Hardware 'Port9-Missing' -MTU 9000 @conn -Confirm:$false } |
                Should -Throw '*Interface*Port9-Missing*'
        }
    }

    Context 'A firewall error response' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><StaticARP><Status code="500">Operation could not be performed on Entity.</Status></StaticARP></Response>' }
            }
        }

        It 'Should throw for New-SfosStaticARP on a code 500 response' {
            { New-SfosStaticARP -IPAddress '198.51.100.9' -MACAddress '00:11:22:33:44:55' -Interface 'Port9' @conn -Confirm:$false } |
                Should -Throw
        }
    }
}

Describe 'Empty Lists' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosZone without a MemberPorts element' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Zone><Name>NoPorts9</Name><Type>DMZ</Type><Description>none</Description></Zone></Response>' }
            }
        }

        It 'Should return MemberPorts as an empty array, not @('''')' {
            $result = @(Get-SfosZone @conn)

            $result.Count | Should -Be 1
            , $result[0].MemberPorts | Should -BeOfType [string[]]
            $result[0].MemberPorts.Count | Should -Be 0
        }
    }

    Context 'Get-SfosGatewayConfiguration without any Gateway node' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayConfiguration><GatewayFailoverTimeout>60</GatewayFailoverTimeout></GatewayConfiguration></Response>' }
            }
        }

        It 'Should return GatewayList as an empty array' {
            $result = Get-SfosGatewayConfiguration @conn

            $result.GatewayFailoverTimeout | Should -Be '60'
            , $result.GatewayList | Should -BeOfType [PSCustomObject[]]
            $result.GatewayList.Count | Should -Be 0
        }
    }
}

Describe 'XML Escaping' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
            [PSCustomObject]@{ Content = '<Response><GreTunnel><Status code="200">OK</Status></GreTunnel></Response>' }
        }
    }

    It 'Should escape ampersand and angle brackets in TunnelName' {
        New-SfosGreTunnel -TunnelName 'A&B<C>' -LocalGateway 'GW9' -RemoteGateway '203.0.113.9' -LocalNet '198.51.100.1' -RemoteNet '198.51.100.2' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<TunnelName>A&amp;B&lt;C&gt;</TunnelName>'
        }
    }
}

Describe 'WhatIf' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
            [PSCustomObject]@{ Content = '<Response><DHCPServerStatus><Status code="200">OK</Status></DHCPServerStatus></Response>' }
        }
    }

    It 'Set-SfosDHCPServerStatus should never call the API with -WhatIf' {
        # This cmdlet has no Get and no read-modify-write - on real hardware it would disable a
        # productive DHCP scope outright. It must never be exercised for real by this suite.
        Set-SfosDHCPServerStatus -Name 'Scope9' -Status OFF @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 0 -Exactly
    }

    It 'New-SfosZone should never call the API with -WhatIf' {
        New-SfosZone -Name 'Extranet9' -Type DMZ @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 0 -Exactly
    }
}
