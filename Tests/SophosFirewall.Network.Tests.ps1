#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Network module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    With 100 exported functions, exhaustive per-cmdlet coverage is neither achievable nor
    useful. Coverage here is weighted towards the failure modes the module's own .NOTES call
    out as measured, expensive defects: the eight wire element names that differ
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
        # in the matching Set-* and send an incomplete entity that silently drops fields.
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
    # Eight documentation folders carry a different name than the XML element they describe.
    # A wrong root element answers 529 "Input request
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
            # Set-SfosInterface reads the current interface first. The mocked Get answers with
            # a fully populated interface so a partial -MTU-only update
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
            # Omitting any of these on a live update would silently clear the field - on a
            # physical port this can drop the session's own IP.
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

# ---------------------------------------------------------------------------
# Section: Interface / VLAN / LAG / BridgePair
# ---------------------------------------------------------------------------

Describe 'Interface builders and Get' {

    Context 'New-SfosInterfaceIPv4Configuration -InputObject merge' {
        It 'Should override only GatewayName and keep every other field from InputObject' {
            $base = [PSCustomObject]@{
                Configuration = 'Enable'; Assignment = 'Static'; IPAddress = '10.0.0.5'; Netmask = '255.255.255.0'
                GatewayName   = 'OldGW'; GatewayIP = '10.0.0.1'; Username = ''; Password = ''; ServiceName = ''
                ServiceName2  = ''; PreferredIP = ''; LocalIP = ''; LCPEchoInterval = ''; LCPFailure = ''
                SchedulTimeForReconnect = ''; DSLSetting = ''; VLANTag = ''
            }
            $result = $base | New-SfosInterfaceIPv4Configuration -GatewayName 'NewGW'

            $result.GatewayName | Should -Be 'NewGW'
            $result.IPAddress | Should -Be '10.0.0.5'
            $result.Netmask | Should -Be '255.255.255.0'
            $result.Assignment | Should -Be 'Static'
        }
    }

    Context 'New-SfosInterfaceIPv6Configuration -InputObject merge' {
        It 'Should override only Configuration and keep every other field from InputObject' {
            $base = [PSCustomObject]@{
                Configuration = 'Disable'; Assignment = 'Static'; IPv6Address = '2001:db8::1'; Prefix = '64'
                GatewayNameIpv6 = ''; GatewayIPv6 = ''; Mode = ''; DhcpOnly = ''; AcceptOtherConfigfromDHCP = ''
                PrefixDelegation = 'Disable'; PrefixPreference = 'Disable'; PreferredPrefixAddress = ''
                PreferredPrefixLength = ''; UpstreamInterface = ''; EnableRA = ''; EnableDHCPv6Server = ''
            }
            $result = $base | New-SfosInterfaceIPv6Configuration -Configuration Enable

            $result.Configuration | Should -Be 'Enable'
            $result.IPv6Address | Should -Be '2001:db8::1'
            $result.Prefix | Should -Be '64'
        }
    }

    Context 'New-SfosInterfaceMSSConfiguration -InputObject merge' {
        It 'Should override only MSSValue and keep OverrideMSS from InputObject' {
            $base = [PSCustomObject]@{ OverrideMSS = 'Enable'; MSSValue = '1400' }
            $result = $base | New-SfosInterfaceMSSConfiguration -MSSValue 1300

            $result.MSSValue | Should -Be 1300
            $result.OverrideMSS | Should -Be 'Enable'
        }
    }

    Context 'Get-SfosInterface parsing' {
        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <Interface>
    <Name>Uplink9</Name>
    <Hardware>Port9</Hardware>
    <NetworkZone>LAN</NetworkZone>
    <InterfaceStatus>ON</InterfaceStatus>
    <Status>Connected, 1000 Mbps - Full Duplex</Status>
    <MTU>1500</MTU>
    <IPv4Configuration>Enable</IPv4Configuration>
    <IPv4Assignment>Static</IPv4Assignment>
    <IPAddress>10.0.0.5</IPAddress>
    <Netmask>255.255.255.0</Netmask>
    <IPv6Configuration>Disable</IPv6Configuration>
    <MSS><OverrideMSS>Disable</OverrideMSS><MSSValue>1460</MSSValue></MSS>
  </Interface>
</Response>
'@
                }
            }
        }

        It 'Should parse Name, Hardware, InterfaceStatus, Status and nested IPv4Configuration/MSS' {
            $result = @(Get-SfosInterface @conn)

            $result.Count | Should -Be 1
            $result[0].Hardware | Should -Be 'Port9'
            $result[0].InterfaceStatus | Should -Be 'ON'
            $result[0].Status | Should -Be 'Connected, 1000 Mbps - Full Duplex'
            $result[0].IPv4Configuration.IPAddress | Should -Be '10.0.0.5'
            $result[0].MSS.MSSValue | Should -Be '1460'
        }
    }
}

Describe 'VLAN Get/New/Set' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosVLAN parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VLAN><Name>Guest9</Name><Hardware>Port9.997</Hardware><Interface>Port9</Interface><Zone>DMZ</Zone><VLANID>997</VLANID><IPv4Assignment>Static</IPv4Assignment><IPAddress>10.250.98.1</IPAddress><Netmask>255.255.255.0</Netmask><IPv6Assignment></IPv6Assignment></VLAN></Response>' }
            }
        }
        It 'Should parse VLAN fields including the server-computed Hardware' {
            $result = @(Get-SfosVLAN @conn)
            $result.Count | Should -Be 1
            $result[0].Hardware | Should -Be 'Port9.997'
            $result[0].VLANID | Should -Be '997'
            $result[0].IPAddress | Should -Be '10.250.98.1'
        }
    }

    Context 'New-SfosVLAN XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><VLAN><Status code="200">OK</Status></VLAN></Response>' }
            }
        }
        It 'Should send operation=add, no Hardware element, and IPv6Assignment=Static as an inert placeholder' {
            # IPv6Assignment can never be sent empty even while IPv6Configuration stays Disable -
            # see the module region header (live 501/InvalidParams finding).
            New-SfosVLAN -Interface 'Port9' -Zone 'DMZ' -VLANID 997 -IPv4Assignment Static -IPAddress '10.250.98.1' -Netmask '255.255.255.0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<VLANID>997</VLANID>' -and
                $InnerXml -match '<IPv6Assignment>Static</IPv6Assignment>' -and
                $InnerXml -notmatch '<Hardware>'
            }
        }
    }

    Context 'Set-SfosVLAN read-modify-write and the IPv6Assignment placeholder' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VLAN><Name>Guest9</Name><Hardware>Port9.997</Hardware><Interface>Port9</Interface><Zone>DMZ</Zone><VLANID>997</VLANID><IPv4Configuration>Enable</IPv4Configuration><IPv4Assignment>Static</IPv4Assignment><IPAddress>10.250.98.1</IPAddress><Netmask>255.255.255.0</Netmask><IPv6Configuration>Disable</IPv6Configuration><IPv6Assignment></IPv6Assignment></VLAN></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VLAN><Status code="200">OK</Status></VLAN></Response>' }
                }
            }
        }
        It 'Should resend IPAddress/Netmask unchanged, the resolved Hardware, and substitute Static for the blank IPv6Assignment on a Zone-only update' {
            Set-SfosVLAN -Interface 'Port9' -VLANID 997 -Zone 'LAN' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Hardware>Port9\.997</Hardware>' -and
                $InnerXml -match '<Zone>LAN</Zone>' -and
                $InnerXml -match '<IPAddress>10\.250\.98\.1</IPAddress>' -and
                $InnerXml -match '<Netmask>255\.255\.255\.0</Netmask>' -and
                $InnerXml -match '<IPv6Assignment>Static</IPv6Assignment>'
            }
        }
    }
}

Describe 'LAG builder, Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosLAGMSSConfiguration -InputObject merge' {
        It 'Should override only MSSValue and keep OverrideMSS from InputObject' {
            $base = [PSCustomObject]@{ OverrideMSS = 'Enable'; MSSValue = '1400' }
            $result = $base | New-SfosLAGMSSConfiguration -MSSValue 1300
            $result.MSSValue | Should -Be 1300
            $result.OverrideMSS | Should -Be 'Enable'
        }
    }

    Context 'Get-SfosLAG parsing with a single member interface' {
        # A LAG with exactly one member must still come back as a one-element array, not an
        # unrolled bare string.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><LAG><Name>Bond9</Name><Hardware>LAG9</Hardware><MemberInterface><Interface>Port4</Interface></MemberInterface><Mode>ActiveBackup</Mode><NetworkZone>LAN</NetworkZone></LAG></Response>' }
            }
        }
        It 'Should return MemberInterface as a one-element array, not an unrolled string' {
            $result = @(Get-SfosLAG @conn)
            $result.Count | Should -Be 1
            , $result[0].MemberInterface | Should -BeOfType [string[]]
            $result[0].MemberInterface.Count | Should -Be 1
            $result[0].MemberInterface[0] | Should -Be 'Port4'
        }
    }

    Context 'New-SfosLAG XML generation with a single member interface' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><LAG><Status code="200">OK</Status></LAG></Response>' }
            }
        }
        It 'Should emit exactly one Interface element inside MemberInterface for a single-port LAG' {
            New-SfosLAG -Hardware 'LAG9' -MemberInterface 'Port4' -Mode ActiveBackup -NetworkZone 'LAN' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                ([regex]::Matches($InnerXml, '<Interface>Port4</Interface>').Count -eq 1)
            }
        }
    }

    Context 'Set-SfosLAG read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><LAG><Name>Bond9</Name><Hardware>LAG9</Hardware><MemberInterface><Interface>Port4</Interface></MemberInterface><Mode>ActiveBackup</Mode><NetworkZone>LAN</NetworkZone><IPAssignment>Static</IPAssignment><IPv4Configuration>Enable</IPv4Configuration><IPv4Address>10.0.9.1</IPv4Address><Netmask>255.255.255.0</Netmask></LAG></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><LAG><Status code="200">OK</Status></LAG></Response>' }
                }
            }
        }
        It 'Should resend IPv4Address/Netmask/MemberInterface unchanged on a NetworkZone-only update' {
            Set-SfosLAG -Hardware 'LAG9' -NetworkZone 'DMZ' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<NetworkZone>DMZ</NetworkZone>' -and
                $InnerXml -match '<IPv4Address>10\.0\.9\.1</IPv4Address>' -and
                $InnerXml -match '<Netmask>255\.255\.255\.0</Netmask>' -and
                $InnerXml -match '<Interface>Port4</Interface>'
            }
        }

        It 'Should throw naming the entity type and object name when the LAG does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><LAG><Status>No. of records Zero.</Status></LAG></Response>' }
            }
            { Set-SfosLAG -Hardware 'LAG-Missing' -NetworkZone 'DMZ' @conn -Confirm:$false } |
                Should -Throw '*LAG*LAG-Missing*'
        }
    }

    Context 'Remove-SfosLAG XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><LAG><Status code="200">OK</Status></LAG></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Hardware' {
            Remove-SfosLAG -Hardware 'LAG9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Hardware>LAG9</Hardware>'
            }
        }
    }
}

Describe 'BridgePair builder, Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosBridgePairMSSConfiguration uses Override, not OverrideMSS' {
        It 'Should expose an Override property - BridgePair spells the field differently than Interface/VLAN/LAG' {
            $result = New-SfosBridgePairMSSConfiguration -Override Enable -MSSValue 1400
            $result.Override | Should -Be 'Enable'
            $result.PSObject.Properties.Match('OverrideMSS').Count | Should -Be 0
        }

        It 'Should override only MSSValue and keep Override from InputObject' {
            $base = [PSCustomObject]@{ Override = 'Enable'; MSSValue = '1400' }
            $result = $base | New-SfosBridgePairMSSConfiguration -MSSValue 1300
            $result.MSSValue | Should -Be 1300
            $result.Override | Should -Be 'Enable'
        }
    }

    Context 'Get-SfosBridgePair parsing with a single member/VLAN/EtherType' {
        # A single member/VLAN/EtherType must still come back as a one-element array.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><BridgePair><Name>Br9</Name><Hardware>Bridge9</Hardware><BridgeMembers><Member><Interface>Port4</Interface><Zone>LAN</Zone></Member></BridgeMembers><PermittedVlansList><PermittedVLAN>100</PermittedVLAN></PermittedVlansList><EtherTypeList><EtherType>0x0800</EtherType></EtherTypeList></BridgePair></Response>' }
            }
        }
        It 'Should return MemberInterface, MemberZone, PermittedVLAN and EtherType as one-element arrays' {
            $result = @(Get-SfosBridgePair @conn)
            $result.Count | Should -Be 1
            , $result[0].MemberInterface | Should -BeOfType [string[]]
            $result[0].MemberInterface.Count | Should -Be 1
            $result[0].MemberInterface[0] | Should -Be 'Port4'
            $result[0].MemberZone[0] | Should -Be 'LAN'
            $result[0].PermittedVLAN.Count | Should -Be 1
            $result[0].EtherType.Count | Should -Be 1
        }
    }

    Context 'New-SfosBridgePair XML generation and validation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><BridgePair><Status code="200">OK</Status></BridgePair></Response>' }
            }
        }
        It 'Should pair MemberInterface with MemberZone by index inside Member elements' {
            New-SfosBridgePair -Hardware 'Bridge9' -MemberInterface 'Port4', 'Port5' -MemberZone 'LAN', 'DMZ' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Member><Interface>Port4</Interface><Zone>LAN</Zone></Member>' -and
                $InnerXml -match '<Member><Interface>Port5</Interface><Zone>DMZ</Zone></Member>'
            }
        }

        It 'Should throw client-side when MemberInterface and MemberZone counts differ' {
            { New-SfosBridgePair -Hardware 'Bridge9' -MemberInterface 'Port4', 'Port5' -MemberZone 'LAN' @conn -Confirm:$false } |
                Should -Throw '*same number*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 0 -Exactly
        }
    }

    Context 'Set-SfosBridgePair read-modify-write and validation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><BridgePair><Name>Br9</Name><Hardware>Bridge9</Hardware><Description>Original</Description><BridgeMembers><Member><Interface>Port4</Interface><Zone>LAN</Zone></Member></BridgeMembers><MTU>1500</MTU></BridgePair></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><BridgePair><Status code="200">OK</Status></BridgePair></Response>' }
                }
            }
        }
        It 'Should resend Description and MemberInterface/MemberZone unchanged on an MTU-only update' {
            Set-SfosBridgePair -Hardware 'Bridge9' -MTU 9000 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<MTU>9000</MTU>' -and
                $InnerXml -match '<Description>Original</Description>' -and
                $InnerXml -match '<Member><Interface>Port4</Interface><Zone>LAN</Zone></Member>'
            }
        }

        It 'Should throw client-side when MemberInterface and MemberZone counts differ' {
            { Set-SfosBridgePair -Hardware 'Bridge9' -MemberInterface 'Port4', 'Port5' -MemberZone 'LAN' @conn -Confirm:$false } |
                Should -Throw '*same number*'
        }
    }

    Context 'Remove-SfosBridgePair XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><BridgePair><Status code="200">OK</Status></BridgePair></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Hardware' {
            Remove-SfosBridgePair -Hardware 'Bridge9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Hardware>Bridge9</Hardware>'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Section: Alias / CellularWAN / IPTunnel / GreTunnel / GreRoute / TAP
# ---------------------------------------------------------------------------

Describe 'Alias Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosAlias parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Alias><Name>Port9:0</Name><Interface>Port9</Interface><IPFamily>IPv4</IPFamily><IPAddress>10.250.98.1</IPAddress><Netmask>255.255.255.0</Netmask></Alias></Response>' }
            }
        }
        It 'Should parse the firewall-computed Name and the address fields' {
            $result = @(Get-SfosAlias @conn)
            $result.Count | Should -Be 1
            $result[0].Name | Should -Be 'Port9:0'
            $result[0].IPAddress | Should -Be '10.250.98.1'
        }
    }

    Context 'New-SfosAlias XML generation and validation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Alias><Status code="200">OK</Status></Alias></Response>' }
            }
        }
        It 'Should send no Name element - the firewall computes Interface:Index itself' {
            New-SfosAlias -Interface 'Port9' -IPFamily IPv4 -IPAddress '10.250.98.1' -Netmask '255.255.255.0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -notmatch '<Name>'
            }
        }

        It 'Should throw client-side when IPFamily is IPv4 but IPAddress/Netmask are missing' {
            { New-SfosAlias -Interface 'Port9' -IPFamily IPv4 @conn -Confirm:$false } | Should -Throw '*IPAddress*Netmask*'
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 0 -Exactly
        }

        It 'Should throw client-side when IPFamily is IPv6 but IPv6/Prefix are missing' {
            { New-SfosAlias -Interface 'Port9' -IPFamily IPv6 @conn -Confirm:$false } | Should -Throw '*IPv6*Prefix*'
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 0 -Exactly
        }
    }

    Context 'Set-SfosAlias read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Alias><Name>Port9:0</Name><Interface>Port9</Interface><IPFamily>IPv4</IPFamily><IPAddress>10.250.98.1</IPAddress><Netmask>255.255.255.0</Netmask></Alias></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Alias><Status code="200">OK</Status></Alias></Response>' }
                }
            }
        }
        It 'Should resend IPAddress and Interface unchanged on a Netmask-only update' {
            Set-SfosAlias -Name 'Port9:0' -Netmask '255.255.0.0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Netmask>255\.255\.0\.0</Netmask>' -and
                $InnerXml -match '<IPAddress>10\.250\.98\.1</IPAddress>' -and
                $InnerXml -match '<Interface>Port9</Interface>' -and
                $InnerXml -match '<Name>Port9:0</Name>'
            }
        }

        It 'Should throw naming the entity type and object name when the Alias does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Alias><Status>No. of records Zero.</Status></Alias></Response>' }
            }
            { Set-SfosAlias -Name 'Port9:9' -Netmask '255.255.0.0' @conn -Confirm:$false } |
                Should -Throw '*Alias*Port9:9*'
        }
    }

    Context 'Remove-SfosAlias XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Alias><Status code="200">OK</Status></Alias></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Name' {
            Remove-SfosAlias -Name 'Port9:0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Port9:0</Name>'
            }
        }
    }
}

Describe 'CellularWAN Get/Set' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosCellularWAN parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CellularWAN><Action>Disable</Action><DisconnectOnSystemDown></DisconnectOnSystemDown></CellularWAN></Response>' }
            }
        }
        It 'Should return a singleton with Action and DisconnectOnSystemDown' {
            $result = Get-SfosCellularWAN @conn
            $result.Action | Should -Be 'Disable'
            $result.DisconnectOnSystemDown | Should -Be ''
        }
    }

    Context 'Set-SfosCellularWAN read-modify-write' {
        # Never exercised against a real firewall: -Action Enable would activate the cellular
        # modem. Mocked only.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CellularWAN><Action>Disable</Action><DisconnectOnSystemDown>off</DisconnectOnSystemDown></CellularWAN></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><CellularWAN><Status code="200">OK</Status></CellularWAN></Response>' }
                }
            }
        }
        It 'Should resend the existing Action unchanged on a DisconnectOnSystemDown-only update' {
            Set-SfosCellularWAN -DisconnectOnSystemDown 'on' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Action>Disable</Action>' -and
                $InnerXml -match '<DisconnectOnSystemDown>on</DisconnectOnSystemDown>'
            }
        }
    }
}

Describe 'IPTunnel Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosIPTunnel parsing and no server-side Filter' {
        # <Filter> answers Transaction fail for this entity (region header) - Get-SfosIPTunnel
        # must never send one, even when -NameLike is supplied.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPTunnel><Name>zznetB-iptun1</Name><Hardware>tun0hw1</Hardware><TunnelType>6in4</TunnelType><Zone>DMZ</Zone><LocalEndPoint>203.0.113.10</LocalEndPoint><RemoteEndPoint>203.0.113.20</RemoteEndPoint><TTL>64</TTL><TOS>0</TOS></IPTunnel></Response>' }
            }
        }
        It 'Should parse tunnel fields and never send a Filter element' {
            $result = @(Get-SfosIPTunnel -NameLike 'iptun1' @conn)
            $result.Count | Should -Be 1
            $result[0].Hardware | Should -Be 'tun0hw1'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch '<Filter>'
            }
        }
    }

    Context 'New-SfosIPTunnel XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><IPTunnel><Status code="200">OK</Status></IPTunnel></Response>' }
            }
        }
        It 'Should send Hardware as a mandatory element, against the (incorrect) documentation' {
            New-SfosIPTunnel -Name 'zznetB-iptun1' -Hardware 'tun0hw1' -TunnelType 6in4 -Zone 'DMZ' -LocalEndPoint '203.0.113.10' -RemoteEndPoint '203.0.113.20' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<Hardware>tun0hw1</Hardware>'
            }
        }
    }

    Context 'Set-SfosIPTunnel read-modify-write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPTunnel><Name>zznetB-iptun1</Name><Hardware>tun0hw1</Hardware><TunnelType>6in4</TunnelType><Zone>DMZ</Zone><LocalEndPoint>203.0.113.10</LocalEndPoint><RemoteEndPoint>203.0.113.20</RemoteEndPoint><TTL>64</TTL><TOS>0</TOS></IPTunnel></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><IPTunnel><Status code="200">OK</Status></IPTunnel></Response>' }
                }
            }
        }
        It 'Should resend Hardware/Zone/endpoints unchanged on a TTL/TOS-only update' {
            Set-SfosIPTunnel -Name 'zznetB-iptun1' -TTL 128 -TOS 5 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<TTL>128</TTL>' -and $InnerXml -match '<TOS>5</TOS>' -and
                $InnerXml -match '<Hardware>tun0hw1</Hardware>' -and
                $InnerXml -match '<Zone>DMZ</Zone>' -and
                $InnerXml -match '<LocalEndPoint>203\.0\.113\.10</LocalEndPoint>'
            }
        }
    }

    Context 'Remove-SfosIPTunnel Hardware resolution' {
        It 'Should send the piped Hardware directly, without an extra Get' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><IPTunnel><Status code="200">OK</Status></IPTunnel></Response>' }
            }

            [PSCustomObject]@{ Name = 'zznetB-iptun1'; Hardware = 'tun0hw1' } | Remove-SfosIPTunnel @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>zznetB-iptun1</Name>' -and $InnerXml -match '<Hardware>tun0hw1</Hardware>'
            }
        }

        It 'Should resolve Hardware via an extra Get when called with -Name alone' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPTunnel><Name>zznetB-iptun1</Name><Hardware>tun0hw1</Hardware></IPTunnel></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><IPTunnel><Status code="200">OK</Status></IPTunnel></Response>' }
                }
            }

            Remove-SfosIPTunnel -Name 'zznetB-iptun1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Hardware>tun0hw1</Hardware>'
            } -Times 1 -Exactly
        }

        It 'Should throw naming the entity type and object name when Hardware cannot be resolved' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPTunnel><Status>No. of records Zero.</Status></IPTunnel></Response>' }
            }
            { Remove-SfosIPTunnel -Name 'zznetB-missing' @conn -Confirm:$false } |
                Should -Throw '*IPTunnel*zznetB-missing*'
        }
    }
}

Describe 'GreTunnel Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosGreTunnel parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreTunnel><TunnelName>gre-test9</TunnelName><LocalGateway>GW9</LocalGateway><RemoteGateway>203.0.113.9</RemoteGateway><LocalNet>198.51.100.1</LocalNet><RemoteNet>198.51.100.2</RemoteNet><TTL>0</TTL><Dyndns>Off</Dyndns><State>Disabled</State></GreTunnel></Response>' }
            }
        }
        It 'Should parse every documented field' {
            $result = @(Get-SfosGreTunnel @conn)
            $result.Count | Should -Be 1
            $result[0].TunnelName | Should -Be 'gre-test9'
            $result[0].State | Should -Be 'Disabled'
        }
    }

    Context 'New-SfosGreTunnel XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><GreTunnel><Status code="200">OK</Status></GreTunnel></Response>' }
            }
        }
        It 'Should send operation=add with the documented fields' {
            New-SfosGreTunnel -TunnelName 'gre-test9' -LocalGateway 'GW9' -RemoteGateway '203.0.113.9' -LocalNet '198.51.100.1' -RemoteNet '198.51.100.2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<LocalGateway>GW9</LocalGateway>' -and
                $InnerXml -match '<State>Disabled</State>'
            }
        }
    }

    Context 'Set-SfosGreTunnel read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreTunnel><TunnelName>gre-test9</TunnelName><LocalGateway>GW9</LocalGateway><RemoteGateway>203.0.113.9</RemoteGateway><LocalNet>198.51.100.1</LocalNet><RemoteNet>198.51.100.2</RemoteNet><TTL>0</TTL><Dyndns>Off</Dyndns><State>Disabled</State></GreTunnel></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GreTunnel><Status code="200">OK</Status></GreTunnel></Response>' }
                }
            }
        }
        It 'Should resend LocalGateway/RemoteGateway unchanged on a State-only update' {
            Set-SfosGreTunnel -TunnelName 'gre-test9' -State Enabled @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<State>Enabled</State>' -and
                $InnerXml -match '<LocalGateway>GW9</LocalGateway>' -and
                $InnerXml -match '<RemoteGateway>203\.0\.113\.9</RemoteGateway>'
            }
        }

        It 'Should throw naming the entity type and object name when the GreTunnel does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreTunnel><Status>No. of records Zero.</Status></GreTunnel></Response>' }
            }
            { Set-SfosGreTunnel -TunnelName 'gre-missing' -State Enabled @conn -Confirm:$false } |
                Should -Throw '*GreTunnel*gre-missing*'
        }
    }

    Context 'Remove-SfosGreTunnel XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><GreTunnel><Status code="200">OK</Status></GreTunnel></Response>' }
            }
        }
        It 'Should use the module-standard Remove tag, even though the vendor doc page documents no delete operation for this entity' {
            Remove-SfosGreTunnel -TunnelName 'gre-test9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<TunnelName>gre-test9</TunnelName>'
            }
        }
    }
}

Describe 'GreRoute Get and the Set operation="del" exception' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosGreRoute parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GreRoute><Host>198.51.100.0</Host><Netmask>255.255.255.0</Netmask><TunnelName>gre-test9</TunnelName></GreRoute></Response>' }
            }
        }
        It 'Should parse Host, Netmask and TunnelName' {
            $result = @(Get-SfosGreRoute @conn)
            $result.Count | Should -Be 1
            $result[0].Host | Should -Be '198.51.100.0'
            $result[0].TunnelName | Should -Be 'gre-test9'
        }
    }

    Context 'Remove-SfosGreRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><GreRoute><Status code="200">OK</Status></GreRoute></Response>' }
            }
        }
        It 'Should send Set operation="del", not the module-standard Remove tag - the vendor doc documents only add/del for this entity' {
            Remove-SfosGreRoute -TunnelName 'gre-test9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="del">' -and
                $InnerXml -match '<TunnelName>gre-test9</TunnelName>' -and
                $InnerXml -notmatch '<Remove>'
            }
        }
    }
}

Describe 'TAP Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosTAP parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><TAP><Hardware>tap0hwfake</Hardware><InterfaceSpeed>Auto Negotiate</InterfaceSpeed><AutoNegotiation>Enable</AutoNegotiation><FEC>Off</FEC></TAP></Response>' }
            }
        }
        It 'Should parse Hardware/InterfaceSpeed/AutoNegotiation/FEC' {
            $result = @(Get-SfosTAP @conn)
            $result.Count | Should -Be 1
            $result[0].Hardware | Should -Be 'tap0hwfake'
        }
    }

    Context 'New-SfosTAP XML generation and the 200-without-effect defect' {
        BeforeEach {
            # Live-measured: an unresolvable Hardware value answers code 200 while creating
            # nothing (region header comment). Unlike Remove-SfosVLAN, this cmdlet has no
            # post-write re-Get/throw guard - the module's own .NOTES tells callers to re-Get.
            # This test documents that current (unconfirmed-safe) behaviour, it does not assert
            # it is correct.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><TAP><Status code="200">Configuration applied successfully.</Status></TAP></Response>' }
            }
        }
        It 'Should send operation=add and not throw on a 200 response, even for an unresolvable Hardware value' {
            { New-SfosTAP -Hardware 'tap0hwfake' @conn -Confirm:$false } | Should -Not -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<Hardware>tap0hwfake</Hardware>'
            }
        }
    }

    Context 'Set-SfosTAP read-modify-write, the add-not-update exception, and the not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><TAP><Hardware>tap0hwfake</Hardware><InterfaceSpeed>Auto Negotiate</InterfaceSpeed><AutoNegotiation>Enable</AutoNegotiation><FEC>Off</FEC></TAP></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><TAP><Status code="200">OK</Status></TAP></Response>' }
                }
            }
        }
        It 'Should resend InterfaceSpeed/AutoNegotiation unchanged and use operation=add, not update, on an FEC-only change' {
            Set-SfosTAP -Hardware 'tap0hwfake' -FEC Automatic @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<FEC>Automatic</FEC>' -and
                $InnerXml -match '<InterfaceSpeed>Auto Negotiate</InterfaceSpeed>' -and
                $InnerXml -match '<AutoNegotiation>Enable</AutoNegotiation>'
            }
        }

        It 'Should throw naming the entity type and object name when the TAP object does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><TAP><Status>No. of records Zero.</Status></TAP></Response>' }
            }
            { Set-SfosTAP -Hardware 'tap0hwfake' @conn -Confirm:$false } |
                Should -Throw "*The TAP object 'tap0hwfake' was not found.*"
        }
    }

    Context 'Remove-SfosTAP XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><TAP><Status code="200">OK</Status></TAP></Response>' }
            }
        }
        It 'Should send Set operation="delete", not the module-standard Remove tag' {
            Remove-SfosTAP -Hardware 'tap0hwfake' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="delete">' -and
                $InnerXml -match '<Hardware>tap0hwfake</Hardware>' -and
                $InnerXml -notmatch '<Remove>'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Section: REDDevice / WiFi6Interface / Zone / GatewayConfiguration /
#          ARPConfiguration / StaticARP / RouterAdvertisement
# ---------------------------------------------------------------------------

Describe 'REDDevice Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosREDDevice parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><REDDevice><BranchName>Branch9</BranchName><Device>red20</Device><REDDeviceID>S0000000009</REDDeviceID><UplinkSettings><Uplink><Connection>DHCP</Connection></Uplink><UMTS3GFailover>Disable</UMTS3GFailover></UplinkSettings><NetworkSetting><OperationMode>Standard</OperationMode><IPAddress>198.51.100.9</IPAddress><NetMask>255.255.255.0</NetMask><Zone>DMZ</Zone></NetworkSetting><AdvancedSettings><RemoteIPAssignment>NoIPAddress</RemoteIPAssignment></AdvancedSettings></REDDevice></Response>' }
            }
        }
        It 'Should parse top-level and nested Uplink/NetworkSetting/AdvancedSettings fields' {
            $result = @(Get-SfosREDDevice @conn)
            $result.Count | Should -Be 1
            $result[0].BranchName | Should -Be 'Branch9'
            $result[0].UplinkConnection | Should -Be 'DHCP'
            $result[0].OperationMode | Should -Be 'Standard'
            $result[0].IPAddress | Should -Be '198.51.100.9'
            $result[0].RemoteIPAssignment | Should -Be 'NoIPAddress'
        }
    }

    Context 'New-SfosREDDevice XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><REDDevice><Status code="200">OK</Status></REDDevice></Response>' }
            }
        }
        It 'Should include the Static uplink fields only when UplinkConnection is Static' {
            New-SfosREDDevice -BranchName 'Branch9' -Device red20 -REDDeviceID 'S0000000009' -UTMHostName 'vpn.example.invalid' -UplinkConnection Static -UplinkAddress '198.51.100.1' -UplinkNetmask '255.255.255.0' -OperationMode Standard -IPAddress '198.51.100.9' -NetMask '255.255.255.0' -Zone DMZ @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Connection>Static</Connection>' -and
                $InnerXml -match '<Address>198\.51\.100\.1</Address>'
            }
        }

        It 'Should omit the Static uplink fields when UplinkConnection is DHCP' {
            New-SfosREDDevice -BranchName 'Branch9' -REDDeviceID 'S0000000009' -UTMHostName 'vpn.example.invalid' -OperationMode Standard -IPAddress '198.51.100.9' -NetMask '255.255.255.0' -Zone DMZ @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Connection>DHCP</Connection>' -and $InnerXml -notmatch '<Address>'
            }
        }
    }

    Context 'Set-SfosREDDevice read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><REDDevice><BranchName>Branch9</BranchName><REDDeviceID>S0000000009</REDDeviceID><UTMHostName>vpn.example.invalid</UTMHostName><UplinkSettings><Uplink><Connection>DHCP</Connection></Uplink><UMTS3GFailover>Disable</UMTS3GFailover></UplinkSettings><NetworkSetting><OperationMode>Standard</OperationMode><IPAddress>198.51.100.9</IPAddress><NetMask>255.255.255.0</NetMask><Zone>DMZ</Zone></NetworkSetting><REDMTU>1500</REDMTU></REDDevice></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><REDDevice><Status code="200">OK</Status></REDDevice></Response>' }
                }
            }
        }
        It 'Should resend UTMHostName and NetworkSetting unchanged on an Authorized-only update' {
            Set-SfosREDDevice -BranchName 'Branch9' -Authorized 0 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Authorized>0</Authorized>' -and
                $InnerXml -match '<UTMHostName>vpn\.example\.invalid</UTMHostName>' -and
                $InnerXml -match '<Zone>DMZ</Zone>'
            }
        }

        It 'Should throw naming the entity type and object name when the REDDevice does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><REDDevice><Status>No. of records Zero.</Status></REDDevice></Response>' }
            }
            { Set-SfosREDDevice -BranchName 'Branch-Missing' -Authorized 0 @conn -Confirm:$false } |
                Should -Throw '*REDDevice*Branch-Missing*'
        }
    }

    Context 'Remove-SfosREDDevice REDDeviceID resolution' {
        It 'Should send the piped REDDeviceID directly, without an extra Get' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><REDDevice><Status code="200">OK</Status></REDDevice></Response>' }
            }

            [PSCustomObject]@{ BranchName = 'Branch9'; REDDeviceID = 'S0000000009' } | Remove-SfosREDDevice @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<REDDeviceID>S0000000009</REDDeviceID>'
            }
        }

        It 'Should resolve REDDeviceID via an extra Get when called with -BranchName alone' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><REDDevice><BranchName>Branch9</BranchName><REDDeviceID>S0000000009</REDDeviceID></REDDevice></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><REDDevice><Status code="200">OK</Status></REDDevice></Response>' }
                }
            }

            Remove-SfosREDDevice -BranchName 'Branch9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<REDDeviceID>S0000000009</REDDeviceID>'
            } -Times 1 -Exactly
        }
    }
}

Describe 'WiFi6Interface Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosWiFi6Interface parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WiFi6Interface><Name>Guest-WiFi9</Name><Hardware>wifi0</Hardware><Zone>WIFI</Zone><IPv4Address>10.20.30.1</IPv4Address><Netmask>255.255.255.0</Netmask></WiFi6Interface></Response>' }
            }
        }
        It 'Should parse Name/Hardware/Zone/IPv4Address/Netmask' {
            $result = @(Get-SfosWiFi6Interface @conn)
            $result.Count | Should -Be 1
            $result[0].Zone | Should -Be 'WIFI'
        }
    }

    Context 'New-SfosWiFi6Interface XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><WiFi6Interface><Status code="200">OK</Status></WiFi6Interface></Response>' }
            }
        }
        It 'Should send operation=add with the documented fields' {
            New-SfosWiFi6Interface -Name 'Guest-WiFi9' -Hardware 'wifi0' -Zone WIFI @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<Hardware>wifi0</Hardware>'
            }
        }
    }

    Context 'Set-SfosWiFi6Interface read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WiFi6Interface><Name>Guest-WiFi9</Name><Hardware>wifi0</Hardware><Zone>WIFI</Zone><IPv4Address>10.20.30.1</IPv4Address><Netmask>255.255.255.0</Netmask></WiFi6Interface></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WiFi6Interface><Status code="200">OK</Status></WiFi6Interface></Response>' }
                }
            }
        }
        It 'Should resend Hardware/IPv4Address unchanged on a Zone-only update' {
            Set-SfosWiFi6Interface -Name 'Guest-WiFi9' -Zone LAN @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Zone>LAN</Zone>' -and
                $InnerXml -match '<Hardware>wifi0</Hardware>' -and
                $InnerXml -match '<IPv4Address>10\.20\.30\.1</IPv4Address>'
            }
        }

        It 'Should throw naming the entity type and object name when the WiFi6Interface does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WiFi6Interface><Status>No. of records Zero.</Status></WiFi6Interface></Response>' }
            }
            { Set-SfosWiFi6Interface -Name 'Guest-Missing' -Zone LAN @conn -Confirm:$false } |
                Should -Throw '*WiFi6Interface*Guest-Missing*'
        }
    }

    Context 'Remove-SfosWiFi6Interface XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><WiFi6Interface><Status code="200">OK</Status></WiFi6Interface></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Name' {
            Remove-SfosWiFi6Interface -Name 'Guest-WiFi9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Guest-WiFi9</Name>'
            }
        }
    }
}

Describe 'Zone Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosZone parsing with MemberPorts and ApplianceAccess' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Zone><Name>DMZ9</Name><Type>DMZ</Type><Description>test</Description><MemberPorts>Port9,Port10</MemberPorts><ApplianceAccess><AdminServices><HTTPS>Enable</HTTPS><SSH>Disable</SSH></AdminServices></ApplianceAccess></Zone></Response>' }
            }
        }
        It 'Should split MemberPorts on comma and parse ApplianceAccess.AdminServices' {
            $result = @(Get-SfosZone @conn)
            $result.Count | Should -Be 1
            $result[0].MemberPorts.Count | Should -Be 2
            $result[0].MemberPorts[1] | Should -Be 'Port10'
            $result[0].ApplianceAccess.AdminServices.HTTPS | Should -Be 'Enable'
        }
    }

    Context 'New-SfosZone XML generation and the Type=LOCAL mock error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Zone><Status code="200">OK</Status></Zone></Response>' }
            }
        }
        It 'Should send operation=add with Name/Type/Description' {
            New-SfosZone -Name 'Extranet9' -Type DMZ -Description 'partner net' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Type>DMZ</Type>' -and
                $InnerXml -match '<Description>partner net</Description>'
            }
        }

        It 'Should throw when the firewall rejects Type LOCAL - live-measured 501 (Type LOCAL is the reserved system zone, not creatable via the API), reproduced here as a mocked error path' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Zone><Status code="501">Configuration parameters validation failed.</Status></Zone></Response>' }
            }

            { New-SfosZone -Name 'zzLocalTest9' -Type LOCAL @conn -Confirm:$false } | Should -Throw
        }
    }

    Context 'Set-SfosZone not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Zone><Status>No. of records Zero.</Status></Zone></Response>' }
            }
        }
        It 'Should throw naming the entity type and object name when the Zone does not exist' {
            { Set-SfosZone -Name 'Zone-Missing9' -Description 'x' @conn -Confirm:$false } |
                Should -Throw '*Zone*Zone-Missing9*'
        }
    }

    Context 'Remove-SfosZone XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Zone><Status code="200">OK</Status></Zone></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Name' {
            Remove-SfosZone -Name 'Extranet9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Extranet9</Name>'
            }
        }
    }
}

Describe 'GatewayConfiguration Get with a single-entry Gateway/FailOverRule list' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosGatewayConfiguration parsing' {
        # One Gateway with one FailOverRule must still come back as a one-element array.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayConfiguration><GatewayFailoverTimeout>60</GatewayFailoverTimeout><Gateway><Name>WAN-GW9</Name><IPFamily>IPv4</IPFamily><IPAddress>10.0.9.1</IPAddress><Type>Active</Type><Weight>8</Weight><FailOverRules><Rule><Protocol>PING</Protocol><IPAddress>198.51.100.9</IPAddress><Port>*</Port><Condition>AND</Condition></Rule></FailOverRules></Gateway></GatewayConfiguration></Response>' }
            }
        }
        It 'Should return GatewayList and FailOverRuleList as one-element arrays, not unrolled objects' {
            $result = Get-SfosGatewayConfiguration @conn
            , $result.GatewayList | Should -BeOfType [PSCustomObject[]]
            $result.GatewayList.Count | Should -Be 1
            , $result.GatewayList[0].FailOverRuleList | Should -BeOfType [PSCustomObject[]]
            $result.GatewayList[0].FailOverRuleList.Count | Should -Be 1
            $result.GatewayList[0].FailOverRuleList[0].Protocol | Should -Be 'PING'
        }
    }
}

Describe 'ARPConfiguration Get/Set' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosARPConfiguration parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ARPConfiguration><ARPCacheEntryTimeOut>10</ARPCacheEntryTimeOut><LogPossibleARPPoisoningAttempts>Disable</LogPossibleARPPoisoningAttempts></ARPConfiguration></Response>' }
            }
        }
        It 'Should return a singleton with both fields' {
            $result = Get-SfosARPConfiguration @conn
            $result.ARPCacheEntryTimeOut | Should -Be '10'
            $result.LogPossibleARPPoisoningAttempts | Should -Be 'Disable'
        }
    }

    Context 'Set-SfosARPConfiguration read-modify-write' {
        # Live-measured necessity (region header): an update omitting
        # LogPossibleARPPoisoningAttempts silently resets it to Disable.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ARPConfiguration><ARPCacheEntryTimeOut>10</ARPCacheEntryTimeOut><LogPossibleARPPoisoningAttempts>Enable</LogPossibleARPPoisoningAttempts></ARPConfiguration></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ARPConfiguration><Status code="200">OK</Status></ARPConfiguration></Response>' }
                }
            }
        }
        It 'Should resend the existing LogPossibleARPPoisoningAttempts unchanged on a timeout-only update' {
            Set-SfosARPConfiguration -ARPCacheEntryTimeOut 15 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ARPCacheEntryTimeOut>15</ARPCacheEntryTimeOut>' -and
                $InnerXml -match '<LogPossibleARPPoisoningAttempts>Enable</LogPossibleARPPoisoningAttempts>'
            }
        }
    }
}

Describe 'StaticARP Get/New/Set/Remove' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosStaticARP parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><StaticARP><IPFamily>IPv4</IPFamily><IPAddress>198.51.100.243</IPAddress><MACAddress>00:11:22:33:44:01</MACAddress><Interface>Port9</Interface><AddAsATrustedMACAddress>Disable</AddAsATrustedMACAddress></StaticARP></Response>' }
            }
        }
        It 'Should parse IPAddress, MACAddress and Interface' {
            $result = @(Get-SfosStaticARP @conn)
            $result.Count | Should -Be 1
            $result[0].MACAddress | Should -Be '00:11:22:33:44:01'
        }
    }

    Context 'New-SfosStaticARP XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><StaticARP><Status code="200">OK</Status></StaticARP></Response>' }
            }
        }
        It 'Should send operation=add with IPAddress/MACAddress/Interface' {
            New-SfosStaticARP -IPAddress '198.51.100.243' -MACAddress '00:11:22:33:44:01' -Interface 'Port9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<IPAddress>198\.51\.100\.243</IPAddress>' -and
                $InnerXml -match '<Interface>Port9</Interface>'
            }
        }
    }

    Context 'Set-SfosStaticARP performs Remove then Set operation=add, in that order' {
        # This firmware answers 500 on every operation="update" for StaticARP (region header) -
        # Set-SfosStaticARP therefore removes the existing entry and recreates it. Mandatory
        # test per the module's own documented Remove+Recreate sequence.
        BeforeEach {
            $script:sfosStaticArpCallOrder = [System.Collections.Generic.List[string]]::new()
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><StaticARP><IPFamily>IPv4</IPFamily><IPAddress>198.51.100.243</IPAddress><MACAddress>00:11:22:33:44:01</MACAddress><Interface>Port9</Interface><AddAsATrustedMACAddress>Disable</AddAsATrustedMACAddress></StaticARP></Response>' }
                }
                elseif ($InnerXml -match '<Remove>') {
                    $script:sfosStaticArpCallOrder.Add('remove')
                    [PSCustomObject]@{ Content = '<Response><StaticARP><Status code="200">OK</Status></StaticARP></Response>' }
                }
                else {
                    $script:sfosStaticArpCallOrder.Add('add')
                    [PSCustomObject]@{ Content = '<Response><StaticARP><Status code="200">OK</Status></StaticARP></Response>' }
                }
            }
        }
        It 'Should call Remove before Set operation=add, and resend the unchanged Interface' {
            Set-SfosStaticARP -IPAddress '198.51.100.243' -MACAddress '00:11:22:33:44:02' @conn -Confirm:$false

            @($script:sfosStaticArpCallOrder) | Should -Be @('remove', 'add')

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<MACAddress>00:11:22:33:44:02</MACAddress>' -and
                $InnerXml -match '<Interface>Port9</Interface>'
            }
        }
    }

    Context 'Remove-SfosStaticARP XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><StaticARP><Status code="200">OK</Status></StaticARP></Response>' }
            }
        }
        It 'Should send a Remove request keyed on IPAddress' {
            Remove-SfosStaticARP -IPAddress '198.51.100.243' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<IPAddress>198\.51\.100\.243</IPAddress>'
            }
        }
    }
}

Describe 'RouterAdvertisement Get/New/Set/Remove and the On-link hyphen mapping' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosRouterAdvertisement parsing with a single PrefixList entry' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RouterAdvertisement><Interface>VLAN20</Interface><Description>test</Description><PrefixAdvertisementConfiguration><PrefixAdvertisementConfigurationDetail><Prefix64>2001:db8:20::</Prefix64><On-link>Enable</On-link><Autonomous>Enable</Autonomous><PreferredLifeTime>3600</PreferredLifeTime><ValidLifeTime>7200</ValidLifeTime></PrefixAdvertisementConfigurationDetail></PrefixAdvertisementConfiguration></RouterAdvertisement></Response>' }
            }
        }
        It 'Should map the hyphenated On-link element to the OnLink property, as a one-element PrefixList array' {
            $result = @(Get-SfosRouterAdvertisement @conn)
            $result.Count | Should -Be 1
            , $result[0].PrefixList | Should -BeOfType [PSCustomObject[]]
            $result[0].PrefixList.Count | Should -Be 1
            $result[0].PrefixList[0].OnLink | Should -Be 'Enable'
            $result[0].PrefixList[0].Prefix64 | Should -Be '2001:db8:20::'
        }
    }

    Context 'New-SfosRouterAdvertisement XML generation emits the hyphenated On-link element' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><RouterAdvertisement><Status code="200">OK</Status></RouterAdvertisement></Response>' }
            }
        }
        It 'Should send On-link, not OnLink, inside the PrefixAdvertisementConfigurationDetail' {
            $prefix = [PSCustomObject]@{ Prefix64 = '2001:db8:20::'; OnLink = 'Enable'; Autonomous = 'Enable'; PreferredLifeTime = 3600; ValidLifeTime = 7200 }
            New-SfosRouterAdvertisement -Interface 'VLAN20' -PrefixList @($prefix) @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<On-link>Enable</On-link>' -and
                $InnerXml -notmatch '<OnLink>'
            }
        }
    }

    Context 'Set-SfosRouterAdvertisement read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RouterAdvertisement><Interface>VLAN20</Interface><Description>original</Description><HopLimit>64</HopLimit><PrefixAdvertisementConfiguration><PrefixAdvertisementConfigurationDetail><Prefix64>2001:db8:20::</Prefix64><On-link>Enable</On-link><Autonomous>Enable</Autonomous><PreferredLifeTime>3600</PreferredLifeTime><ValidLifeTime>7200</ValidLifeTime></PrefixAdvertisementConfigurationDetail></PrefixAdvertisementConfiguration></RouterAdvertisement></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><RouterAdvertisement><Status code="200">OK</Status></RouterAdvertisement></Response>' }
                }
            }
        }
        It 'Should resend Description and the whole PrefixList unchanged on a HopLimit-only update' {
            Set-SfosRouterAdvertisement -Interface 'VLAN20' -HopLimit 32 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<HopLimit>32</HopLimit>' -and
                $InnerXml -match '<Description>original</Description>' -and
                $InnerXml -match '<On-link>Enable</On-link>'
            }
        }

        It 'Should throw naming the entity type and object name when the RouterAdvertisement does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RouterAdvertisement><Status>No. of records Zero.</Status></RouterAdvertisement></Response>' }
            }
            { Set-SfosRouterAdvertisement -Interface 'VLAN-Missing' -HopLimit 32 @conn -Confirm:$false } |
                Should -Throw '*RouterAdvertisement*VLAN-Missing*'
        }
    }

    Context 'Remove-SfosRouterAdvertisement XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><RouterAdvertisement><Status code="200">OK</Status></RouterAdvertisement></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Interface' {
            Remove-SfosRouterAdvertisement -Interface 'VLAN20' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Interface>VLAN20</Interface>'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Section: DNS / DNSHostEntry / DNSRequestRoute / DynamicDNS
# ---------------------------------------------------------------------------

Describe 'DNS builders and Get' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosDNSIPv4Settings -InputObject merge' {
        It 'Should override only ObtainDNSFrom and keep DNS1-3 from InputObject' {
            $base = [PSCustomObject]@{ ObtainDNSFrom = 'DHCP'; DNS1 = '10.0.0.53'; DNS2 = '10.0.0.54'; DNS3 = '' }
            $result = $base | New-SfosDNSIPv4Settings -ObtainDNSFrom Static
            $result.ObtainDNSFrom | Should -Be 'Static'
            $result.DNS1 | Should -Be '10.0.0.53'
            $result.DNS2 | Should -Be '10.0.0.54'
        }
    }

    Context 'New-SfosDNSIPv6Settings -InputObject merge' {
        It 'Should override only DNS1 and keep ObtainDNSFrom from InputObject' {
            $base = [PSCustomObject]@{ ObtainDNSFrom = 'Static'; DNS1 = '2001:db8::53'; DNS2 = ''; DNS3 = '' }
            $result = $base | New-SfosDNSIPv6Settings -DNS1 '2001:db8::99'
            $result.DNS1 | Should -Be '2001:db8::99'
            $result.ObtainDNSFrom | Should -Be 'Static'
        }
    }

    Context 'Get-SfosDNS parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNS><IPv4Settings><ObtainDNSFrom>DHCP</ObtainDNSFrom><DNSIPList><DNS1>10.0.0.254</DNS1><DNS2></DNS2><DNS3></DNS3></DNSIPList></IPv4Settings><IPv6Settings><ObtainDNSFrom>DHCP</ObtainDNSFrom><DNSIPList><DNS1></DNS1><DNS2></DNS2><DNS3></DNS3></DNSIPList></IPv6Settings><DNSQueryConfiguration>ChooseIPv4DNSServerOverIPv6</DNSQueryConfiguration></DNS></Response>' }
            }
        }
        It 'Should return a singleton with nested IPv4Settings/IPv6Settings' {
            $result = Get-SfosDNS @conn
            $result.IPv4Settings.DNS1 | Should -Be '10.0.0.254'
            $result.DNSQueryConfiguration | Should -Be 'ChooseIPv4DNSServerOverIPv6'
        }
    }
}

Describe 'DNSHostEntry builder, Get/New/Set/Remove/Members' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosDNSHostEntryAddress -InputObject merge' {
        It 'Should override only TTL and keep IPAddress from InputObject' {
            $base = [PSCustomObject]@{ EntryType = 'Manual'; IPFamily = 'IPv4'; IPAddress = '203.0.113.10'; TTL = '3600'; Weight = '0'; PublishOnWAN = 'Disable' }
            $result = $base | New-SfosDNSHostEntryAddress -TTL 7200
            $result.TTL | Should -Be '7200'
            $result.IPAddress | Should -Be '203.0.113.10'
        }
    }

    Context 'Get-SfosDNSHostEntry parsing with a single AddressList entry' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.10</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address></AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>' }
            }
        }
        It 'Should return AddressList as a one-element array, not an unrolled object' {
            $result = @(Get-SfosDNSHostEntry @conn)
            $result.Count | Should -Be 1
            , $result[0].AddressList | Should -BeOfType [object[]]
            $result[0].AddressList.Count | Should -Be 1
            $result[0].AddressList[0].IPAddress | Should -Be '203.0.113.10'
        }
    }

    Context 'New-SfosDNSHostEntry XML generation and validation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
            }
        }
        It 'Should send operation=add with the AddressList entries' {
            $addr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.10'
            New-SfosDNSHostEntry -HostName 'host01.example.invalid' -Address $addr @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<IPAddress>203\.0\.113\.10</IPAddress>'
            }
        }

        It 'Should throw client-side when an Address entry has no IPAddress' {
            $addr = New-SfosDNSHostEntryAddress
            { New-SfosDNSHostEntry -HostName 'host01.example.invalid' -Address $addr @conn -Confirm:$false } |
                Should -Throw '*IPAddress*'
        }
    }

    Context 'Set-SfosDNSHostEntry read-modify-write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.10</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address></AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
                }
            }
        }
        It 'Should resend the existing AddressList unchanged on an AddReverseDNSLookUp-only update' {
            Set-SfosDNSHostEntry -HostName 'host01.example.invalid' -AddReverseDNSLookUp Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<AddReverseDNSLookUp>Enable</AddReverseDNSLookUp>' -and
                $InnerXml -match '<IPAddress>203\.0\.113\.10</IPAddress>'
            }
        }
    }

    Context 'Remove-SfosDNSHostEntry XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
            }
        }
        It 'Should send a Remove request keyed on HostName' {
            Remove-SfosDNSHostEntry -HostName 'host01.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<HostName>host01\.example\.invalid</HostName>'
            }
        }
    }

    Context 'Add-SfosDNSHostEntryMember grows the AddressList (1 -> 2) and enforces the 8-address maximum' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.10</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address></AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
                }
            }
        }
        It 'Should send both the existing and the new address (1 -> 2)' {
            $newAddr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.20'
            Add-SfosDNSHostEntryMember -HostName 'host01.example.invalid' -Address $newAddr @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<IPAddress>203\.0\.113\.10</IPAddress>' -and
                $InnerXml -match '<IPAddress>203\.0\.113\.20</IPAddress>'
            }
        }

        It 'Should throw client-side, without calling the API, when the result would exceed 8 addresses' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                $addrXml = (1..8 | ForEach-Object { "<Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.$_</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address>" }) -join ''
                [PSCustomObject]@{ Content = "<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList>$addrXml</AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>" }
            }

            $newAddr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.99'
            { Add-SfosDNSHostEntryMember -HostName 'host01.example.invalid' -Address $newAddr @conn -Confirm:$false } |
                Should -Throw '*8*'
        }
    }

    Context 'Remove-SfosDNSHostEntryMember shrinks the AddressList (2 -> 1) and detects an append-only firmware' {
        It 'Should send the AddressList without the removed address (2 -> 1)' {
            # Two Get calls happen here: one before the update (still 2 addresses) and one
            # afterwards to verify the removal actually took effect (must show only 1, or the
            # cmdlet's own append-only defence throws). The mock has to answer them differently.
            $script:sfosDnsHostEntryMemberGetCount = 0
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    $script:sfosDnsHostEntryMemberGetCount++
                    if ($script:sfosDnsHostEntryMemberGetCount -eq 1) {
                        [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.10</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.20</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address></AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>' }
                    }
                    else {
                        [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.10</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address></AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>' }
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
                }
            }

            Remove-SfosDNSHostEntryMember -HostName 'host01.example.invalid' -IPAddress '203.0.113.20' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<IPAddress>203\.0\.113\.10</IPAddress>' -and
                $InnerXml -notmatch '<IPAddress>203\.0\.113\.20</IPAddress>'
            } -Times 1 -Exactly
        }

        It 'Should throw when the requested address is still present after a 200 remove response (append-only firmware defence)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSHostEntry><HostName>host01.example.invalid</HostName><AddressList><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.10</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address><Address><EntryType>Manual</EntryType><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.20</IPAddress><TTL>3600</TTL><Weight>0</Weight><PublishOnWAN>Disable</PublishOnWAN></Address></AddressList><AddReverseDNSLookUp>Disable</AddReverseDNSLookUp></DNSHostEntry></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
                }
            }

            { Remove-SfosDNSHostEntryMember -HostName 'host01.example.invalid' -IPAddress '203.0.113.20' @conn -Confirm:$false } |
                Should -Throw '*still present*'
        }
    }
}

Describe 'DNSRequestRoute Get/New/Set/Remove/Members' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosDNSRequestRoute parsing with a single TargetServers entry' {
        # A single TargetServers entry must still come back as a one-element array.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers><Host>DnsForwarder</Host></TargetServers></DNSRequestRoute></Response>' }
            }
        }
        It 'Should return TargetServers as a one-element array of IPHost names' {
            $result = @(Get-SfosDNSRequestRoute @conn)
            $result.Count | Should -Be 1
            , $result[0].TargetServers | Should -BeOfType [string[]]
            $result[0].TargetServers.Count | Should -Be 1
            $result[0].TargetServers[0] | Should -Be 'DnsForwarder'
        }
    }

    Context 'New-SfosDNSRequestRoute XML generation' {
        # TargetServer must name an existing IPHost object of HostType IP - live-measured, see
        # the region header comment. Not enforced client-side (the firewall's own error names
        # the missing object), so only the wire shape is asserted here.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DNSRequestRoute><Status code="200">OK</Status></DNSRequestRoute></Response>' }
            }
        }
        It 'Should send operation=add with the TargetServer entries as Host elements' {
            New-SfosDNSRequestRoute -DomainName 'corp.example.invalid' -TargetServer 'DnsForwarder' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -match '<Host>DnsForwarder</Host>'
            }
        }
    }

    Context 'Set-SfosDNSRequestRoute read-modify-write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers><Host>DnsForwarder</Host></TargetServers></DNSRequestRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSRequestRoute><Status code="200">OK</Status></DNSRequestRoute></Response>' }
                }
            }
        }
        It 'Should replace TargetServers with the new value on an explicit -TargetServer update' {
            Set-SfosDNSRequestRoute -DomainName 'corp.example.invalid' -TargetServer 'DnsForwarder2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Host>DnsForwarder2</Host>' -and $InnerXml -notmatch '<Host>DnsForwarder</Host>'
            }
        }
    }

    Context 'Remove-SfosDNSRequestRoute XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DNSRequestRoute><Status code="200">OK</Status></DNSRequestRoute></Response>' }
            }
        }
        It 'Should send a Remove request keyed on DomainName' {
            Remove-SfosDNSRequestRoute -DomainName 'corp.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<DomainName>corp\.example\.invalid</DomainName>'
            }
        }
    }

    Context 'Add-SfosDNSRequestRouteMember grows TargetServers (1 -> 2) and enforces the 8-server maximum' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers><Host>DnsForwarder</Host></TargetServers></DNSRequestRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSRequestRoute><Status code="200">OK</Status></DNSRequestRoute></Response>' }
                }
            }
        }
        It 'Should send both the existing and the new target server (1 -> 2)' {
            Add-SfosDNSRequestRouteMember -DomainName 'corp.example.invalid' -TargetServer 'DnsForwarder2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Host>DnsForwarder</Host>' -and $InnerXml -match '<Host>DnsForwarder2</Host>'
            }
        }

        It 'Should throw client-side when the result would exceed 8 target servers' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                $hostXml = (1..8 | ForEach-Object { "<Host>DnsForwarder$_</Host>" }) -join ''
                [PSCustomObject]@{ Content = "<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers>$hostXml</TargetServers></DNSRequestRoute></Response>" }
            }
            { Add-SfosDNSRequestRouteMember -DomainName 'corp.example.invalid' -TargetServer 'DnsForwarder99' @conn -Confirm:$false } |
                Should -Throw '*8*'
        }
    }

    Context 'Remove-SfosDNSRequestRouteMember shrinks TargetServers (2 -> 1) and detects an append-only firmware' {
        It 'Should send TargetServers without the removed entry (2 -> 1)' {
            # Two Get calls happen here: one before the update (still 2 servers) and one
            # afterwards to verify the removal actually took effect. The mock has to answer
            # them differently, or the cmdlet's own append-only defence throws.
            $script:sfosDnsRequestRouteMemberGetCount = 0
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    $script:sfosDnsRequestRouteMemberGetCount++
                    if ($script:sfosDnsRequestRouteMemberGetCount -eq 1) {
                        [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers><Host>DnsForwarder</Host><Host>DnsForwarder2</Host></TargetServers></DNSRequestRoute></Response>' }
                    }
                    else {
                        [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers><Host>DnsForwarder</Host></TargetServers></DNSRequestRoute></Response>' }
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSRequestRoute><Status code="200">OK</Status></DNSRequestRoute></Response>' }
                }
            }

            Remove-SfosDNSRequestRouteMember -DomainName 'corp.example.invalid' -TargetServer 'DnsForwarder2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Host>DnsForwarder</Host>' -and
                $InnerXml -notmatch '<Host>DnsForwarder2</Host>'
            } -Times 1 -Exactly
        }

        It 'Should throw when the requested server is still present after a 200 remove response (append-only firmware defence)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DNSRequestRoute><DomainName>corp.example.invalid</DomainName><TargetServers><Host>DnsForwarder</Host><Host>DnsForwarder2</Host></TargetServers></DNSRequestRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DNSRequestRoute><Status code="200">OK</Status></DNSRequestRoute></Response>' }
                }
            }

            { Remove-SfosDNSRequestRouteMember -DomainName 'corp.example.invalid' -TargetServer 'DnsForwarder2' @conn -Confirm:$false } |
                Should -Throw '*still present*'
        }
    }
}

Describe 'DynamicDNS Get/New/Set/Remove (XML level only - never sent to a real DDNS provider)' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosDynamicDNS parsing' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DynamicDNS><HostName>ddns9.example.invalid</HostName><Interface>PortB</Interface><IPv4Address>UsePortIP</IPv4Address><ServiceProvider>DynDNS</ServiceProvider><LoginName>ddnsuser9</LoginName><Password>masked</Password></DynamicDNS></Response>' }
            }
        }
        It 'Should parse HostName/Interface/ServiceProvider/LoginName' {
            $result = @(Get-SfosDynamicDNS @conn)
            $result.Count | Should -Be 1
            $result[0].ServiceProvider | Should -Be 'DynDNS'
        }
    }

    Context 'New-SfosDynamicDNS XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DynamicDNS><Status code="200">OK</Status></DynamicDNS></Response>' }
            }
        }
        It 'Should map -DDNSPassword to the wire element Password, not this module''s own connection secret' {
            New-SfosDynamicDNS -HostName 'ddns9.example.invalid' -Interface 'PortB' -IPv4Address UsePortIP -ServiceProvider DynDNS -LoginName 'ddnsuser9' -DDNSPassword 'ddnspass9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Password>ddnspass9</Password>' -and
                $InnerXml -match '<LoginName>ddnsuser9</LoginName>'
            }
        }
    }

    Context 'Set-SfosDynamicDNS read-modify-write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DynamicDNS><HostName>ddns9.example.invalid</HostName><Interface>PortB</Interface><IPv4Address>UsePortIP</IPv4Address><ServiceProvider>DynDNS</ServiceProvider><LoginName>ddnsuser9</LoginName><Password>ddnspass9</Password></DynamicDNS></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DynamicDNS><Status code="200">OK</Status></DynamicDNS></Response>' }
                }
            }
        }
        It 'Should resend LoginName/ServiceProvider unchanged on an IPv4Address-only update' {
            Set-SfosDynamicDNS -HostName 'ddns9.example.invalid' -IPv4Address NATedPublicIP @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<IPv4Address>NATedPublicIP</IPv4Address>' -and
                $InnerXml -match '<LoginName>ddnsuser9</LoginName>' -and
                $InnerXml -match '<ServiceProvider>DynDNS</ServiceProvider>'
            }
        }
    }

    Context 'Remove-SfosDynamicDNS XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DynamicDNS><Status code="200">OK</Status></DynamicDNS></Response>' }
            }
        }
        It 'Should send a Remove request keyed on HostName' {
            Remove-SfosDynamicDNS -HostName 'ddns9.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<HostName>ddns9\.example\.invalid</HostName>'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Section: DHCPServer / DHCPServerStatus / DHCPServerIpv6 / DHCPRelay
# All four RISK: red - none was ever exercised against a real firewall (a productive scope on
# a live segment). The mocked XML-generation tests below are the only verification layer that
# exists for these cmdlets.
# ---------------------------------------------------------------------------

Describe 'DHCPServer Get/New/Set/Remove (XML level only)' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosDHCPServer parsing with a single StaticLease/DHCPOption entry' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServer><Name>Scope9</Name><Status>1</Status><Interface>PortC</Interface><IPLease><IP>10.10.10.10-10.10.10.200</IP></IPLease><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.10.10.1</Gateway><StaticLease><Lease><HostName>host9</HostName><MACAddress>00:11:22:33:44:55</MACAddress><IPAddress>10.10.10.50</IPAddress></Lease></StaticLease><DHCPOption><Options><OptionName>opt9</OptionName><OptionType>text</OptionType><OptionCode>66</OptionCode><OptionValue>val9</OptionValue></Options></DHCPOption></DHCPServer></Response>' }
            }
        }
        It 'Should return StaticLease and DHCPOption as one-element arrays, and Status as the data field (not an API status)' {
            $result = @(Get-SfosDHCPServer @conn)
            $result.Count | Should -Be 1
            $result[0].Status | Should -Be '1'
            , $result[0].StaticLease | Should -BeOfType [object[]]
            $result[0].StaticLease.Count | Should -Be 1
            $result[0].StaticLease[0].MACAddress | Should -Be '00:11:22:33:44:55'
            $result[0].DHCPOption.Count | Should -Be 1
        }
    }

    Context 'New-SfosDHCPServer XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPServer><Status code="200">OK</Status></DHCPServer></Response>' }
            }
        }
        It 'Should send operation=add without a Status element - Status is not settable through this entity' {
            New-SfosDHCPServer -Name 'Scope9' -Interface 'PortC' -IPLease '10.10.10.10-10.10.10.200' -SubnetMask '255.255.255.0' -Gateway '10.10.10.1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<IP>10\.10\.10\.10-10\.10\.10\.200</IP>' -and
                $InnerXml -notmatch '<Status>'
            }
        }
    }

    Context 'Set-SfosDHCPServer read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServer><Name>Scope9</Name><Status>1</Status><Interface>PortC</Interface><IPLease><IP>10.10.10.10-10.10.10.200</IP></IPLease><SubnetMask>255.255.255.0</SubnetMask><Gateway>10.10.10.1</Gateway></DHCPServer></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DHCPServer><Status code="200">OK</Status></DHCPServer></Response>' }
                }
            }
        }
        It 'Should resend Interface/Gateway unchanged on a MaxLeaseTime-only update' {
            Set-SfosDHCPServer -Name 'Scope9' -MaxLeaseTime 4320 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<MaxLeaseTime>4320</MaxLeaseTime>' -and
                $InnerXml -match '<Interface>PortC</Interface>' -and
                $InnerXml -match '<Gateway>10\.10\.10\.1</Gateway>'
            }
        }

        It 'Should throw naming the entity type and object name when the DHCPServer does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServer><Status>No. of records Zero.</Status></DHCPServer></Response>' }
            }
            { Set-SfosDHCPServer -Name 'Scope-Missing' -MaxLeaseTime 4320 @conn -Confirm:$false } |
                Should -Throw '*DHCPServer*Scope-Missing*'
        }
    }

    Context 'Remove-SfosDHCPServer XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPServer><Status code="200">OK</Status></DHCPServer></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Name' {
            Remove-SfosDHCPServer -Name 'Scope9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Scope9</Name>'
            }
        }
    }
}

Describe 'DHCPServerStatus XML generation (never sent to the lab firewall)' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosDHCPServerStatus' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPServerStatus><Status code="200">OK</Status></DHCPServerStatus></Response>' }
            }
        }
        It 'Should send the literal documented element DHCPServerNamedhcpname, not Name, with no read step first' {
            Set-SfosDHCPServerStatus -Name 'Scope9' -Status OFF @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<DHCPServerNamedhcpname>Scope9</DHCPServerNamedhcpname>' -and
                $InnerXml -match '<Status>OFF</Status>' -and
                $InnerXml -notmatch '<Get>'
            }
        }
    }
}

Describe 'DHCPServerIpv6 Get/New/Set/Remove (XML level only)' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosDHCPServerIpv6 parsing with a single StaticLease entry using DUID' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServerIpv6><Name>Scope9v6</Name><Interface>PortC</Interface><IPLease><IP>2001:db8::10-2001:db8::200</IP></IPLease><StaticLease><Lease><HostName>host9</HostName><DUID>00:01:02:03</DUID><IPAddress>2001:db8::50</IPAddress></Lease></StaticLease><UseApplianceDNSSettings>Enable</UseApplianceDNSSettings><PreferredTime>540</PreferredTime><ValidTime>720</ValidTime></DHCPServerIpv6></Response>' }
            }
        }
        It 'Should parse the StaticLease DUID field (not MACAddress, unlike the IPv4 sibling)' {
            $result = @(Get-SfosDHCPServerIpv6 @conn)
            $result.Count | Should -Be 1
            $result[0].StaticLease.Count | Should -Be 1
            $result[0].StaticLease[0].DUID | Should -Be '00:01:02:03'
        }
    }

    Context 'New-SfosDHCPServerIpv6 XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPServerIpv6><Status code="200">OK</Status></DHCPServerIpv6></Response>' }
            }
        }
        It 'Should send operation=add with PreferredTime/ValidTime' {
            New-SfosDHCPServerIpv6 -Name 'Scope9v6' -Interface 'PortC' -IPLease '2001:db8::10-2001:db8::200' -PreferredTime 540 -ValidTime 720 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<PreferredTime>540</PreferredTime>' -and
                $InnerXml -match '<ValidTime>720</ValidTime>'
            }
        }
    }

    Context 'Set-SfosDHCPServerIpv6 read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServerIpv6><Name>Scope9v6</Name><Interface>PortC</Interface><IPLease><IP>2001:db8::10-2001:db8::200</IP></IPLease><UseApplianceDNSSettings>Enable</UseApplianceDNSSettings><PreferredTime>540</PreferredTime><ValidTime>720</ValidTime></DHCPServerIpv6></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DHCPServerIpv6><Status code="200">OK</Status></DHCPServerIpv6></Response>' }
                }
            }
        }
        It 'Should resend IPLease and PreferredTime unchanged on a ValidTime-only update' {
            Set-SfosDHCPServerIpv6 -Name 'Scope9v6' -ValidTime 1440 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ValidTime>1440</ValidTime>' -and
                $InnerXml -match '<PreferredTime>540</PreferredTime>' -and
                $InnerXml -match '<IP>2001:db8::10-2001:db8::200</IP>'
            }
        }

        It 'Should throw naming the entity type and object name when the DHCPServerIpv6 does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPServerIpv6><Status>No. of records Zero.</Status></DHCPServerIpv6></Response>' }
            }
            { Set-SfosDHCPServerIpv6 -Name 'Scope-Missing-v6' -ValidTime 1440 @conn -Confirm:$false } |
                Should -Throw '*DHCPServerIpv6*Scope-Missing-v6*'
        }
    }

    Context 'Remove-SfosDHCPServerIpv6 XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPServerIpv6><Status code="200">OK</Status></DHCPServerIpv6></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Name' {
            Remove-SfosDHCPServerIpv6 -Name 'Scope9v6' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Scope9v6</Name>'
            }
        }
    }
}

Describe 'DHCPRelay Get/New/Set/Remove (XML level only)' {
    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'; Port = 4444; Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosDHCPRelay parsing with a single DHCPServerIP entry' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPRelay><Name>Relay9</Name><IPFamily>IPv4</IPFamily><Interface>PortC</Interface><DHCPServerIP>203.0.113.53</DHCPServerIP><RelaythroughIPSec>Disable</RelaythroughIPSec></DHCPRelay></Response>' }
            }
        }
        It 'Should return DHCPServerIP as a one-element array, not an unrolled string' {
            $result = @(Get-SfosDHCPRelay @conn)
            $result.Count | Should -Be 1
            , $result[0].DHCPServerIP | Should -BeOfType [string[]]
            $result[0].DHCPServerIP.Count | Should -Be 1
            $result[0].DHCPServerIP[0] | Should -Be '203.0.113.53'
        }
    }

    Context 'New-SfosDHCPRelay XML generation emits one DHCPServerIP element per target' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPRelay><Status code="200">OK</Status></DHCPRelay></Response>' }
            }
        }
        It 'Should emit two sibling DHCPServerIP elements for two target servers' {
            New-SfosDHCPRelay -Name 'Relay9' -Interface 'PortC' -DHCPServerIP '203.0.113.53', '203.0.113.54' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<DHCPServerIP>203\.0\.113\.53</DHCPServerIP>' -and
                $InnerXml -match '<DHCPServerIP>203\.0\.113\.54</DHCPServerIP>'
            }
        }
    }

    Context 'Set-SfosDHCPRelay read-modify-write and not-found error path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPRelay><Name>Relay9</Name><IPFamily>IPv4</IPFamily><Interface>PortC</Interface><DHCPServerIP>203.0.113.53</DHCPServerIP><RelaythroughIPSec>Disable</RelaythroughIPSec></DHCPRelay></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DHCPRelay><Status code="200">OK</Status></DHCPRelay></Response>' }
                }
            }
        }
        It 'Should resend Interface and DHCPServerIP unchanged on a RelaythroughIPSec-only update' {
            Set-SfosDHCPRelay -Name 'Relay9' -RelaythroughIPSec Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<RelaythroughIPSec>Enable</RelaythroughIPSec>' -and
                $InnerXml -match '<Interface>PortC</Interface>' -and
                $InnerXml -match '<DHCPServerIP>203\.0\.113\.53</DHCPServerIP>'
            }
        }

        It 'Should throw naming the entity type and object name when the DHCPRelay does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DHCPRelay><Status>No. of records Zero.</Status></DHCPRelay></Response>' }
            }
            { Set-SfosDHCPRelay -Name 'Relay-Missing' -RelaythroughIPSec Enable @conn -Confirm:$false } |
                Should -Throw '*DHCPRelay*Relay-Missing*'
        }
    }

    Context 'Remove-SfosDHCPRelay XML generation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
                [PSCustomObject]@{ Content = '<Response><DHCPRelay><Status code="200">OK</Status></DHCPRelay></Response>' }
            }
        }
        It 'Should send a Remove request keyed on Name' {
            Remove-SfosDHCPRelay -Name 'Relay9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>Relay9</Name>'
            }
        }
    }
}

Describe 'Session parameter (multi-session support)' {

    BeforeAll {
        $cred1 = [pscredential]::new('apiuser', (ConvertTo-SecureString 'pw1' -AsPlainText -Force))
        $cred2 = [pscredential]::new('apiuser', (ConvertTo-SecureString 'pw2' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred1 -Name 'fw1' | Out-Null
        Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred2 -Name 'fw2' -NoDefault | Out-Null
    }

    AfterAll { Disconnect-SfosFirewall -All }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VLAN><Status>No. of records Zero.</Status></VLAN></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosVLAN -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosVLAN | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on the begin-block pipeline path (New-SfosDNSHostEntry)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -MockWith {
            [PSCustomObject]@{ Content = '<Response><DNSHostEntry><Status code="200">OK</Status></DNSHostEntry></Response>' }
        }
        $addr = New-SfosDNSHostEntryAddress -IPAddress '203.0.113.10'
        New-SfosDNSHostEntry -HostName 'crossfw.example.invalid' -Address $addr -Session 'fw2' -Confirm:$false
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<HostName>crossfw\.example\.invalid</HostName>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosVLAN -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Network -Times 0 -Exactly
    }
}
