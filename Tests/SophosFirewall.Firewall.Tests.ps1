#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Firewall module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

# Get module path - use relative paths that work in any environment
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Firewall\SophosFirewall.Firewall.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $ModulePath)) {
    Write-Error "Module manifest not found: $ModulePath"
    exit 1
}

# Import modules
Import-Module $CoreModulePath -Force
Import-Module $ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Firewall module should load' {
        Get-Module SophosFirewall.Firewall | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 21 functions' {
        (Get-Module SophosFirewall.Firewall).ExportedFunctions.Count | Should -Be 21
    }

    Context 'Private helpers are not exported' {
        # These build the FirewallRule/SSLTLSInspectionRule XML internally. If the manifest's
        # FunctionsToExport ever grew to include them by accident, callers could bypass the
        # read-modify-write logic in Set-SfosFirewallRule/Set-SfosSSLTLSInspectionRule and send
        # an incomplete entity that silently drops Position/After/Before or another field.
        It 'ConvertTo-SfosFirewallRuleXml should not be visible' {
            Get-Command ConvertTo-SfosFirewallRuleXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'ConvertTo-SfosFirewallRuleNetworkPolicyXml should not be visible' {
            Get-Command ConvertTo-SfosFirewallRuleNetworkPolicyXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'ConvertTo-SfosSSLTLSInspectionRuleXmlList should not be visible' {
            Get-Command ConvertTo-SfosSSLTLSInspectionRuleXmlList -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'ConvertTo-SfosSSLTLSInspectionRuleWebsitesXml should not be visible' {
            Get-Command ConvertTo-SfosSSLTLSInspectionRuleWebsitesXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }

        It 'ConvertTo-SfosSSLTLSInspectionRuleEntityXml should not be visible' {
            Get-Command ConvertTo-SfosSSLTLSInspectionRuleEntityXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
}

Describe 'Request XML Generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        # One shared success response covering every entity area exercised in this Describe -
        # Assert-SfosApiReturnSuccess only looks at the <Status> under the object name the
        # calling cmdlet passes, so the unrelated blocks are simply ignored.
        $okResponse = @'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule><Status code="200">Configuration applied successfully.</Status></FirewallRule>
  <FirewallRuleGroup><Status code="200">Configuration applied successfully.</Status></FirewallRuleGroup>
  <NATRule><Status code="200">Configuration applied successfully.</Status></NATRule>
  <SSLTLSInspectionRule><Status code="200">Configuration applied successfully.</Status></SSLTLSInspectionRule>
</Response>
'@
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = $okResponse }
        }
    }

    Context 'New-SfosFirewallRule' {
        It 'Should build a FirewallRule root (not SecurityPolicy) with PolicyType Network and a NetworkPolicy subtree' {
            $np = New-SfosFirewallRuleNetworkPolicy -SourceZone 'LAN' -DestinationZone 'WAN'
            New-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -Status Enable -Position Bottom -PolicyType Network -NetworkPolicy $np @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<FirewallRule>' -and
                $InnerXml -notmatch '<SecurityPolicy>' -and
                $InnerXml -match '<PolicyType>Network</PolicyType>' -and
                $InnerXml -match '<NetworkPolicy>' -and
                $InnerXml -match '<Action>Accept</Action>'
            }
        }

        # Documentation folder for this entity is "SecurityPolicy"; sending that as the
        # wire root answers 529 "Input request module is Invalid" on a live firewall.
        It 'Should never send SecurityPolicy as the wire root element' {
            $np = New-SfosFirewallRuleNetworkPolicy -SourceZone 'LAN' -DestinationZone 'WAN'
            New-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -Status Enable -Position Bottom -PolicyType Network -NetworkPolicy $np @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -cnotmatch '<SecurityPolicy>' -and $InnerXml -cnotmatch '<SecurityPolicy '
            }
        }
    }

    Context 'New-SfosFirewallRuleNetworkPolicy / TrafficShappingPolicy wire spelling' {
        # The wire element is genuinely misspelled "TrafficShappingPolicy" (double p) on a live
        # firewall; the vendor doc spells it correctly as "TrafficShapingPolicy". Sending the
        # documented spelling lands on an unknown element and the field is silently not set -
        # so this test locks in the measured (misspelled) wire element, not the documented one.
        It 'Should emit the measured TrafficShappingPolicy element, not the documented TrafficShapingPolicy' {
            $np = New-SfosFirewallRuleNetworkPolicy -SourceZone 'LAN' -DestinationZone 'WAN' -TrafficShappingPolicy 'Guest-Limit'
            New-SfosFirewallRule -Name 'Allow-LAN-to-WAN' -Status Enable -Position Bottom -PolicyType Network -NetworkPolicy $np @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<TrafficShappingPolicy>Guest-Limit</TrafficShappingPolicy>' -and
                $InnerXml -notmatch '<TrafficShapingPolicy>'
            }
        }
    }

    Context 'New-SfosFirewallRuleGroup' {
        It 'Should wrap members in SecurityPolicyList/SecurityPolicy' {
            New-SfosFirewallRuleGroup -Name 'Outbound' -members @('Allow-LAN-to-WAN', 'Allow-LAN-to-DMZ') @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<SecurityPolicyList>' -and
                $InnerXml -match '<SecurityPolicy>Allow-LAN-to-WAN</SecurityPolicy>' -and
                $InnerXml -match '<SecurityPolicy>Allow-LAN-to-DMZ</SecurityPolicy>'
            }
        }
    }

    Context 'New-SfosNATRule' {
        It 'Should build a NATRule root with a Status element and operation="add"' {
            New-SfosNATRule -Name 'SNAT-LAN-to-WAN' -TranslatedSource MASQ -Status Enable -Position Bottom @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<NATRule>' -and
                $InnerXml -match '<Status>Enable</Status>' -and
                $InnerXml -match '<TranslatedSource>MASQ</TranslatedSource>'
            }
        }
    }

    Context 'Remove-SfosFirewallRule' {
        It 'Should build a Remove request with the FirewallRule root and the target name' {
            Remove-SfosFirewallRule -Name 'Allow-LAN-to-WAN' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<FirewallRule>' -and
                $InnerXml -match '<Name>Allow-LAN-to-WAN</Name>'
            }
        }
    }

    Context 'Remove-SfosFirewallRuleGroup' {
        It 'Should build a Remove request with the FirewallRuleGroup root and the target name' {
            Remove-SfosFirewallRuleGroup -Name 'Outbound' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<FirewallRuleGroup>' -and
                $InnerXml -match '<Name>Outbound</Name>'
            }
        }
    }

    Context 'Remove-SfosNATRule' {
        It 'Should build a Remove request with the NATRule root and the target name' {
            Remove-SfosNATRule -Name 'SNAT-LAN-to-WAN' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<NATRule>' -and
                $InnerXml -match '<Name>SNAT-LAN-to-WAN</Name>'
            }
        }
    }

    Context 'New-SfosSSLTLSInspectionRule Position handling' {
        # An unbound -Position must not be forwarded into ConvertTo-SfosSSLTLSInspectionRuleEntityXml:
        # its -Position parameter carries ValidateSet('Top','Bottom'), and an unbound PowerShell
        # parameter binds as an empty string, which violates the set.
        It 'Should build valid Add XML with no Position element when -Position is omitted' {
            { New-SfosSSLTLSInspectionRule -Name 'Bypass-Banking' -Enable No @conn -Confirm:$false } | Should -Not -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<SSLTLSInspectionRule>' -and
                $InnerXml -notmatch '<Position>'
            }
        }

        It 'Should include the Position element when -Position Bottom is supplied' {
            New-SfosSSLTLSInspectionRule -Name 'Bypass-Banking' -Enable No -Position Bottom @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Position>Bottom</Position>'
            }
        }
    }

    Context 'Write cmdlets never send an unsupported Set operation' {
        It 'New-SfosFirewallRule should send operation="add", never anything else' {
            $np = New-SfosFirewallRuleNetworkPolicy
            New-SfosFirewallRule -Name 'Op-Check' -Status Enable -Position Bottom -PolicyType Network -NetworkPolicy $np @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -notmatch 'operation="edit"' -and $InnerXml -notmatch 'operation="remove"'
            }
        }

        It 'New-SfosNATRule should send operation="add", never anything else' {
            New-SfosNATRule -Name 'Op-Check-NAT' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -notmatch 'operation="edit"' -and $InnerXml -notmatch 'operation="remove"'
            }
        }

        It 'New-SfosFirewallRuleGroup should send operation="add", never anything else' {
            New-SfosFirewallRuleGroup -Name 'Op-Check-Group' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and $InnerXml -notmatch 'operation="edit"' -and $InnerXml -notmatch 'operation="remove"'
            }
        }
    }
}

Describe 'Status is a data field, not an API status' {
    # <Status> inside a FirewallRule node is the rule's own Enable/Disable flag, not a
    # request status. A response carrying several
    # <FirewallRule><Status>Enable</Status></FirewallRule> siblings must not be read as a
    # broken/erroring request - Core's Get-SfosApiStatus tells the two apart before this
    # cmdlet ever sees a status, and this test guards that boundary from this module's side.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule><Name>Rule1</Name><Description>d1</Description><IPFamily>IPv4</IPFamily><Status>Enable</Status><Position>Top</Position></FirewallRule>
  <FirewallRule><Name>Rule2</Name><Description>d2</Description><IPFamily>IPv4</IPFamily><Status>Enable</Status><Position>After</Position></FirewallRule>
  <FirewallRule><Name>Rule3</Name><Description>d3</Description><IPFamily>IPv4</IPFamily><Status>Disable</Status><Position>Bottom</Position></FirewallRule>
</Response>
'@
            }
        }
    }

    It 'Get-SfosFirewallRule should not throw and should return every rule' {
        $result = @(Get-SfosFirewallRule @conn)

        $result.Count | Should -Be 3
        ($result | ForEach-Object { $_.Name }) | Should -Be @('Rule1', 'Rule2', 'Rule3')
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

    Context 'Set-SfosFirewallRule' {
        BeforeEach {
            # Set-SfosFirewallRule reads the current rule before writing, so the mock has to
            # answer a <Get> with a matching, fully resolved rule - including Position/After,
            # the single most expensive field to lose.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule>
    <Name>ExampleRule</Name>
    <Description>Original description</Description>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>After</Position>
    <PolicyType>Network</PolicyType>
    <After><Name>AnchorRule</Name></After>
    <NetworkPolicy>
      <Action>Accept</Action>
      <LogTraffic>Disable</LogTraffic>
      <SkipLocalDestined>Disable</SkipLocalDestined>
      <SourceZones><Zone>LAN</Zone></SourceZones>
      <DestinationZones><Zone>WAN</Zone></DestinationZones>
      <Schedule>All The Time</Schedule>
      <DSCPMarking>-1</DSCPMarking>
      <WebFilter>None</WebFilter>
      <BlockQuickQuic>Disable</BlockQuickQuic>
      <ScanVirus>Disable</ScanVirus>
      <ZeroDayProtection>Disable</ZeroDayProtection>
      <ProxyMode>Disable</ProxyMode>
      <DecryptHTTPS>Disable</DecryptHTTPS>
      <ApplicationControl>None</ApplicationControl>
      <IntrusionPrevention>None</IntrusionPrevention>
      <NDRActiveThreatIntelligence>Disable</NDRActiveThreatIntelligence>
      <TrafficShappingPolicy>None</TrafficShappingPolicy>
      <ScanSMTP>Disable</ScanSMTP>
      <ScanSMTPS>Disable</ScanSMTPS>
      <ScanIMAP>Disable</ScanIMAP>
      <ScanIMAPS>Disable</ScanIMAPS>
      <ScanPOP3>Disable</ScanPOP3>
      <ScanPOP3S>Disable</ScanPOP3S>
      <ScanFTP>Disable</ScanFTP>
      <SourceSecurityHeartbeat>Disable</SourceSecurityHeartbeat>
      <MinimumSourceHBPermitted>No Restriction</MinimumSourceHBPermitted>
      <DestSecurityHeartbeat>Disable</DestSecurityHeartbeat>
      <MinimumDestinationHBPermitted>No Restriction</MinimumDestinationHBPermitted>
    </NetworkPolicy>
  </FirewallRule>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><FirewallRule><Status code="200">OK</Status></FirewallRule></Response>' }
                }
            }
        }

        It 'Should resend the existing Position and After when only the description changes' {
            # An update that forgot to resend Position/After would move the rule and silently
            # reorder the whole rulebase - the single most damaging property of this API.
            Set-SfosFirewallRule -Name 'ExampleRule' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<Position>After</Position>' -and
                $InnerXml -match '<After><Name>AnchorRule</Name></After>' -and
                $InnerXml -match '<Action>Accept</Action>'
            }
        }

        # The NetworkPolicy subtree carries what the rule actually does. Read-modify-write has
        # to reach into it as well: changing one field there used to require rebuilding the
        # whole policy through New-SfosFirewallRuleNetworkPolicy, whose parameters all carry
        # defaults - so "turn on virus scanning" silently also turned off intrusion prevention
        # and application control. These tests pin the per-field behaviour.

        It 'Should change only the named NetworkPolicy field and keep the rest' {
            # The mocked rule has ScanVirus=Disable, Schedule='All The Time', SourceZones=LAN.
            Set-SfosFirewallRule -Name 'ExampleRule' -ScanVirus Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ScanVirus>Enable</ScanVirus>' -and
                $InnerXml -match '<Schedule>All The Time</Schedule>' -and
                $InnerXml -match '<SourceZones><Zone>LAN</Zone></SourceZones>' -and
                $InnerXml -match '<DestinationZones><Zone>WAN</Zone></DestinationZones>' -and
                $InnerXml -match '<Description>Original description</Description>' -and
                $InnerXml -match '<Position>After</Position>'
            }
        }

        It 'Should keep the other NetworkPolicy fields when a list field is replaced' {
            Set-SfosFirewallRule -Name 'ExampleRule' -SourceZone 'DMZ' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<SourceZones><Zone>DMZ</Zone></SourceZones>' -and
                $InnerXml -notmatch '<Zone>LAN</Zone>' -and
                $InnerXml -match '<DestinationZones><Zone>WAN</Zone></DestinationZones>' -and
                $InnerXml -match '<ScanVirus>Disable</ScanVirus>' -and
                $InnerXml -match '<Schedule>All The Time</Schedule>'
            }
        }

        It 'Should not let an untouched NetworkPolicy field fall back to a builder default' {
            # Action defaults to 'Accept' and Schedule to 'All The Time' in the builder. Here
            # the stored rule happens to match, so the guard that matters is IntrusionPrevention:
            # it must come from the rule, never from a default that was never asked for.
            Set-SfosFirewallRule -Name 'ExampleRule' -LogTraffic Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<LogTraffic>Enable</LogTraffic>' -and
                $InnerXml -match '<IntrusionPrevention>None</IntrusionPrevention>' -and
                $InnerXml -match '<ApplicationControl>None</ApplicationControl>' -and
                $InnerXml -match '<MinimumSourceHBPermitted>No Restriction</MinimumSourceHBPermitted>'
            }
        }
    }

    Context 'New-SfosFirewallRuleNetworkPolicy -InputObject' {

        It 'Should override only the supplied field and inherit the rest' {
            $base = [PSCustomObject]@{
                Action              = 'Drop'
                LogTraffic          = 'Enable'
                ScanVirus           = 'Disable'
                IntrusionPrevention = 'lantowan_general'
                Schedule            = 'Work hours (5 Day week)'
                SourceZoneList      = @('LAN')
                DestinationZoneList = @('WAN')
            }

            $result = $base | New-SfosFirewallRuleNetworkPolicy -ScanVirus Enable

            $result.ScanVirus | Should -Be 'Enable'
            $result.Action | Should -Be 'Drop'
            $result.LogTraffic | Should -Be 'Enable'
            $result.IntrusionPrevention | Should -Be 'lantowan_general'
            $result.Schedule | Should -Be 'Work hours (5 Day week)'
        }

        It 'Should carry the list fields across the name change from SourceZoneList to SourceZone' {
            # Get-SfosFirewallRule returns SourceZoneList/ServiceList, the builder parameters are
            # -SourceZone/-Service. Mapping them wrongly loses exactly the zones and services the
            # caller meant to keep, and does so without any error.
            $base = [PSCustomObject]@{
                SourceZoneList         = @('LAN', 'DMZ')
                DestinationZoneList    = @('WAN')
                ServiceList            = @('HTTP', 'HTTPS')
                SourceNetworkList      = @('Internal-Net')
                DestinationNetworkList = @('Any')
            }

            $result = $base | New-SfosFirewallRuleNetworkPolicy -LogTraffic Enable

            @($result.SourceZoneList) | Should -Be @('LAN', 'DMZ')
            @($result.DestinationZoneList) | Should -Be @('WAN')
            @($result.ServiceList) | Should -Be @('HTTP', 'HTTPS')
            @($result.SourceNetworkList) | Should -Be @('Internal-Net')
        }

        It 'Should still apply its defaults when no InputObject is supplied' {
            $result = New-SfosFirewallRuleNetworkPolicy -SourceZone 'LAN'

            $result.Action | Should -Be 'Accept'
            $result.ScanVirus | Should -Be 'Disable'
            $result.IntrusionPrevention | Should -Be 'None'
        }
    }

    Context 'Set-SfosNATRule' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <NATRule>
    <Name>ExampleNAT</Name>
    <Description>Original description</Description>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>After</Position>
    <After><Name>AnchorNAT</Name></After>
    <TranslatedSource>MASQ</TranslatedSource>
    <TranslatedDestination>Original</TranslatedDestination>
    <TranslatedService>Original</TranslatedService>
    <OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy>
  </NATRule>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><NATRule><Status code="200">OK</Status></NATRule></Response>' }
                }
            }
        }

        It 'Should resend the existing Position and After when only the description changes' {
            Set-SfosNATRule -Name 'ExampleNAT' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<Position>After</Position>' -and
                $InnerXml -match '<After><Name>AnchorNAT</Name></After>' -and
                $InnerXml -match '<TranslatedSource>MASQ</TranslatedSource>'
            }
        }
    }

    Context 'Set-SfosFirewallRuleGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRuleGroup>
    <Name>ExampleGroup</Name>
    <Description>Original description</Description>
    <SecurityPolicyList><SecurityPolicy>Rule1</SecurityPolicy><SecurityPolicy>Rule2</SecurityPolicy></SecurityPolicyList>
  </FirewallRuleGroup>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><FirewallRuleGroup><Status code="200">OK</Status></FirewallRuleGroup></Response>' }
                }
            }
        }

        It 'Should resend the existing members when only the description changes' {
            # SFOS replaces the whole entity on update - omitting SecurityPolicyList would
            # empty the group.
            Set-SfosFirewallRuleGroup -Name 'ExampleGroup' -Description 'Updated description' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Updated description</Description>' -and
                $InnerXml -match '<SecurityPolicy>Rule1</SecurityPolicy>' -and
                $InnerXml -match '<SecurityPolicy>Rule2</SecurityPolicy>'
            }
        }
    }

    Context 'Set-SfosSSLTLSInspectionSettings' {
        # This entity is on the never-write-live list (module .NOTES); verified here only
        # against a mock. Read-modify-write matters just as much on a singleton: a Set that
        # resent only the changed field would reset every other device-wide TLS setting to
        # whatever the firewall treats as its default.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SSLTLSInspectionSettings>
    <RSACA>ExampleRSACA</RSACA>
    <ECCA>ExampleECCA</ECCA>
    <SSLv2SSLv3>Drop</SSLv2SSLv3>
    <SSLCompression>Drop</SSLCompression>
    <SSLConnectionsExceeded>Allow without decryption</SSLConnectionsExceeded>
    <TLS13Decryption>Decrypt as 1.3</TLS13Decryption>
    <SSLTLSEngine>Enabled</SSLTLSEngine>
    <SSLTLSInspection>Enabled</SSLTLSInspection>
  </SSLTLSInspectionSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLTLSInspectionSettings><Status code="200">OK</Status></SSLTLSInspectionSettings></Response>' }
                }
            }
        }

        It 'Should change only RSACA and keep every other device-wide field' {
            Set-SfosSSLTLSInspectionSettings -RSACA 'NewIssuingCA' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<RSACA>NewIssuingCA</RSACA>' -and
                $InnerXml -match '<ECCA>ExampleECCA</ECCA>' -and
                $InnerXml -match '<SSLv2SSLv3>Drop</SSLv2SSLv3>' -and
                $InnerXml -match '<SSLCompression>Drop</SSLCompression>' -and
                $InnerXml -match '<SSLConnectionsExceeded>Allow without decryption</SSLConnectionsExceeded>' -and
                $InnerXml -match '<TLS13Decryption>Decrypt as 1.3</TLS13Decryption>' -and
                $InnerXml -match '<SSLTLSEngine>Enabled</SSLTLSEngine>' -and
                $InnerXml -match '<SSLTLSInspection>Enabled</SSLTLSInspection>'
            }
        }
    }
}

Describe 'Add-SfosFirewallRuleGroupMember' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Adding a member to a group that already has one' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRuleGroup>
    <Name>Outbound</Name>
    <Description>Original description</Description>
    <SecurityPolicyList><SecurityPolicy>Allow-LAN-to-WAN</SecurityPolicy></SecurityPolicyList>
  </FirewallRuleGroup>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><FirewallRuleGroup><Status code="200">OK</Status></FirewallRuleGroup></Response>' }
                }
            }
        }

        It 'Should resend the existing member together with the new one and keep the description' {
            Add-SfosFirewallRuleGroupMember -Name 'Outbound' -members 'Allow-LAN-to-DMZ' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Original description</Description>' -and
                $InnerXml -match '<SecurityPolicy>Allow-LAN-to-WAN</SecurityPolicy>' -and
                $InnerXml -match '<SecurityPolicy>Allow-LAN-to-DMZ</SecurityPolicy>'
            }
        }
    }

    Context 'Adding a member to a group that does not exist' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRuleGroup><Status>No. of records Zero.</Status></FirewallRuleGroup>
</Response>
'@
                }
            }
        }

        It 'Should throw naming the group' {
            { Add-SfosFirewallRuleGroupMember -Name 'DoesNotExist' -members 'Allow-LAN-to-WAN' @conn -Confirm:$false } |
                Should -Throw '*FirewallRuleGroup*DoesNotExist*'
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
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule><Status>No. of records Zero.</Status></FirewallRule>
</Response>
'@
                }
            }
        }

        It 'Should throw an error naming the entity type and the object name' {
            { Set-SfosFirewallRule -Name 'DoesNotExist' -Description 'x' @conn -Confirm:$false } |
                Should -Throw '*FirewallRule*DoesNotExist*'
        }
    }

    Context 'A firewall error response' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <NATRule><Status code="500">Operation could not be performed on Entity.</Status></NATRule>
</Response>
'@
                }
            }
        }

        It 'Should throw for New-SfosNATRule' {
            { New-SfosNATRule -Name 'ErrCase' @conn -Confirm:$false } | Should -Throw
        }
    }

    Context 'New-SfosFirewallRule with an unsupported PolicyType' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = '<Response><FirewallRule><Status code="200">OK</Status></FirewallRule></Response>' }
            }
        }

        It 'Should throw client-side for -PolicyType User without ever calling the API' {
            { New-SfosFirewallRule -Name 'UserPolicyCase' -Status Enable -Position Bottom -PolicyType User @conn -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 0 -Exactly
        }

        It 'Should throw client-side for -PolicyType HTTPBased without ever calling the API' {
            { New-SfosFirewallRule -Name 'HTTPBasedCase' -Status Enable -Position Bottom -PolicyType HTTPBased @conn -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 0 -Exactly
        }
    }

    Context 'Set-/Remove-SfosSSLTLSInspectionRule on the default rule' {
        BeforeEach {
            # The firewall's only built-in TLS bypass rule, flagged IsDefault=Yes. Both
            # cmdlets must refuse before sending any write.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SSLTLSInspectionRule>
    <Name>Exclusions by website or category</Name>
    <IsDefault>Yes</IsDefault>
    <Description>Default</Description>
    <Enable>Yes</Enable>
    <LogConnections>Enable</LogConnections>
    <DecryptAction>Do not decrypt</DecryptAction>
  </SSLTLSInspectionRule>
</Response>
'@
                }
            }
        }

        It 'Set-SfosSSLTLSInspectionRule should throw before writing' {
            { Set-SfosSSLTLSInspectionRule -Name 'Exclusions by website or category' -Description 'x' @conn -Confirm:$false } |
                Should -Throw '*IsDefault*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -ParameterFilter {
                $InnerXml -match '<Set operation'
            } -Times 0 -Exactly
        }

        It 'Remove-SfosSSLTLSInspectionRule should throw before writing' {
            { Remove-SfosSSLTLSInspectionRule -Name 'Exclusions by website or category' @conn -Confirm:$false } |
                Should -Throw '*IsDefault*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -ParameterFilter {
                $InnerXml -match '<Remove>'
            } -Times 0 -Exactly
        }
    }

    Context 'Remove-SfosFirewallRuleGroupMember append-only firmware behaviour' {
        BeforeEach {
            # Known SFOS 22.0 limitation (module .DESCRIPTION): the member list is
            # append-only on update. The mock answers every <Get> - the pre-check and the
            # post-write verification - with the same unchanged member list, exactly as the
            # real firmware does when the removal is ignored.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRuleGroup>
    <Name>ExampleGroup</Name>
    <Description>Original description</Description>
    <SecurityPolicyList><SecurityPolicy>RuleA</SecurityPolicy><SecurityPolicy>RuleB</SecurityPolicy></SecurityPolicyList>
  </FirewallRuleGroup>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><FirewallRuleGroup><Status code="200">OK</Status></FirewallRuleGroup></Response>' }
                }
            }
        }

        It 'Should throw naming the member that is still present after the update' {
            { Remove-SfosFirewallRuleGroupMember -Name 'ExampleGroup' -members 'RuleA' @conn -Confirm:$false } |
                Should -Throw '*RuleA*is still a member*'
        }
    }

    Context 'Remove-SfosFirewallRule on a non-existent rule' {
        # The raw firewall answer is passed through unchanged rather than a "was not found"
        # message: 528 "Trying to update default entities which are not editable". 528 is in
        # the documented 500-599 failure range, so the cmdlet still throws rather than
        # reporting a false success, even though the message is misleading.
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRule><Status code="528">Trying to update default entities which are not editable</Status></FirewallRule>
</Response>
'@
                }
            }
        }

        It 'Should throw rather than silently succeed' {
            { Remove-SfosFirewallRule -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw
        }
    }
}

Describe 'Get-SfosSSLTLSInspectionRule parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'A rule with website references and zone lists' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SSLTLSInspectionRule>
    <Name>Exclusions by website or category</Name>
    <IsDefault>Yes</IsDefault>
    <Description>Default</Description>
    <Enable>Yes</Enable>
    <LogConnections>Enable</LogConnections>
    <SourceZones><Zone>LAN</Zone></SourceZones>
    <DestinationZones><Zone>WAN</Zone></DestinationZones>
    <Websites>
      <Activity><Name>Banking</Name><Type>Web Category</Type></Activity>
    </Websites>
    <DecryptAction>Do not decrypt</DecryptAction>
  </SSLTLSInspectionRule>
</Response>
'@
                }
            }
        }

        It 'Should parse the top-level fields, the zone lists and the website references' {
            $result = @(Get-SfosSSLTLSInspectionRule @conn)

            $result.Count | Should -Be 1
            $result[0].IsDefault | Should -Be 'Yes'
            $result[0].DecryptAction | Should -Be 'Do not decrypt'
            $result[0].SourceZones.Count | Should -Be 1
            $result[0].SourceZones[0] | Should -Be 'LAN'
            $result[0].DestinationZones.Count | Should -Be 1
            $result[0].DestinationZones[0] | Should -Be 'WAN'
            $result[0].Website.Count | Should -Be 1
            $result[0].Website[0].Name | Should -Be 'Banking'
            $result[0].Website[0].Type | Should -Be 'Web Category'
        }
    }

    Context 'No SSLTLSInspectionRule records exist' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SSLTLSInspectionRule><Status>No. of records Zero.</Status></SSLTLSInspectionRule>
</Response>
'@
                }
            }
        }

        It 'Should return an empty array rather than throwing' {
            $result = @(Get-SfosSSLTLSInspectionRule @conn)

            $result.Count | Should -Be 0
        }
    }
}

Describe 'Get-SfosSSLTLSInspectionSettings parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SSLTLSInspectionSettings>
    <RSACA>ExampleRSACA</RSACA>
    <ECCA>ExampleECCA</ECCA>
    <SSLv2SSLv3>Drop</SSLv2SSLv3>
    <SSLCompression>Drop</SSLCompression>
    <SSLConnectionsExceeded>Allow without decryption</SSLConnectionsExceeded>
    <TLS13Decryption>Decrypt as 1.3</TLS13Decryption>
    <SSLTLSEngine>Enabled</SSLTLSEngine>
    <SSLTLSInspection>Enabled</SSLTLSInspection>
  </SSLTLSInspectionSettings>
</Response>
'@
            }
        }
    }

    It 'Should return the singleton as a single object with every documented field' {
        $result = Get-SfosSSLTLSInspectionSettings @conn

        $result.RSACA | Should -Be 'ExampleRSACA'
        $result.ECCA | Should -Be 'ExampleECCA'
        $result.SSLv2SSLv3 | Should -Be 'Drop'
        $result.TLS13Decryption | Should -Be 'Decrypt as 1.3'
        $result.SSLTLSEngine | Should -Be 'Enabled'
        $result.SSLTLSInspection | Should -Be 'Enabled'
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

    Context 'Get-SfosFirewallRuleGroup without a SecurityPolicyList wrapper' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallRuleGroup>
    <Name>EmptyGroup</Name>
    <Description>none</Description>
  </FirewallRuleGroup>
</Response>
'@
                }
            }
        }

        It 'Should return SecurityPolicyList as an empty array, not @('''')' {
            $result = @(Get-SfosFirewallRuleGroup @conn)

            $result.Count | Should -Be 1
            , $result[0].SecurityPolicyList | Should -BeOfType [string[]]
            $result[0].SecurityPolicyList.Count | Should -Be 0
        }
    }

    Context 'Get-SfosNATRule without Inbound/OutboundInterfaces wrappers' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <NATRule>
    <Name>EmptyNAT</Name>
    <Description>none</Description>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>Bottom</Position>
    <TranslatedSource>Original</TranslatedSource>
    <TranslatedDestination>Original</TranslatedDestination>
    <TranslatedService>Original</TranslatedService>
  </NATRule>
</Response>
'@
                }
            }
        }

        It 'Should return InboundInterfaces and OutboundInterfaces as empty arrays' {
            $result = @(Get-SfosNATRule @conn)

            $result.Count | Should -Be 1
            $result[0].InboundInterfaces.Count | Should -Be 0
            $result[0].OutboundInterfaces.Count | Should -Be 0
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = '<Response><FirewallRuleGroup><Status code="200">OK</Status></FirewallRuleGroup></Response>' }
        }
    }

    It 'Should escape ampersand and angle brackets in the object name' {
        New-SfosFirewallRuleGroup -Name 'A&B<C>' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Name>A&amp;B&lt;C&gt;</Name>'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = '<Response><NATRule><Status code="200">OK</Status></NATRule></Response>' }
        }
    }

    It 'Remove-SfosNATRule should not call the API with -WhatIf' {
        Remove-SfosNATRule -Name 'Example' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 0 -Exactly
    }

    It 'Set-SfosSSLTLSInspectionSettings should read the current settings but never write with -WhatIf' {
        # This entity is on the never-write-live list; -WhatIf is the only way this suite
        # exercises the write path at all. The read-modify-write still has to fetch the
        # current settings first (a <Get>), so only the <Set operation="update"> half must be
        # suppressed by ShouldProcess.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SSLTLSInspectionSettings>
    <RSACA>ExampleRSACA</RSACA>
    <ECCA>ExampleECCA</ECCA>
    <SSLv2SSLv3>Drop</SSLv2SSLv3>
    <SSLCompression>Drop</SSLCompression>
    <SSLConnectionsExceeded>Allow without decryption</SSLConnectionsExceeded>
    <TLS13Decryption>Decrypt as 1.3</TLS13Decryption>
    <SSLTLSEngine>Enabled</SSLTLSEngine>
    <SSLTLSInspection>Enabled</SSLTLSInspection>
  </SSLTLSInspectionSettings>
</Response>
'@
            }
        }

        Set-SfosSSLTLSInspectionSettings -SSLTLSEngine Enabled @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        } -Times 0 -Exactly
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallRule transactionid=""><Status>No. of records Zero.</Status></FirewallRule></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosFirewallRule -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosFirewallRule | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on the begin-block pipeline path (Set-SfosNATRule)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <NATRule>
    <Name>CrossFwNAT</Name>
    <Description>none</Description>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>Bottom</Position>
    <TranslatedSource>Original</TranslatedSource>
    <TranslatedDestination>Original</TranslatedDestination>
    <TranslatedService>Original</TranslatedService>
  </NATRule>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><NATRule><Status code="200">OK</Status></NATRule></Response>' }
            }
        }
        Set-SfosNATRule -Name 'CrossFwNAT' -Status Disable -Session 'fw2' -Confirm:$false
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<Status>Disable</Status>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosFirewallRule -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Firewall -Times 0 -Exactly
    }
}
