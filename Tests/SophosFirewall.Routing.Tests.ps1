#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Routing module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement; a Get smoke test (root element, empty-result
    handling) for every one of the ten entities; New/Set XML-generation checks for every
    New-*/Set-* group including the Healthcheck-ON/OFF branch on GatewayHost and the
    always-sent IPFamily on SDWANPolicyRoute; read-modify-write checks for Set-SfosGatewayHost,
    Set-SfosSDWANProfile and Set-SfosSDWANPolicyRoute; the module's measured special-case
    behaviours (UnicastRoute's remove-then-recreate update and client-side duplicate check,
    SDWANPolicyRouteStatus's read-back-after-write no-op detection and its codeless-status
    handling, and the DSCPMarking '0' -> '0-Best Effort' normalisation); the shared error paths
    (5xx throws, a failed login with no entity status throws, "No. of records Zero." yields
    @()); and a -WhatIf check against every one of the module's 21 write cmdlets.

.NOTES
    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders (e.g. "C:\Program Files\PowerShell\7\Modules") before
    the native Windows PowerShell ones. Pester 6, once loaded, ends up importing the PS7 copy
    of Microsoft.PowerShell.Security and its type data collides with the one PS 5.1 already
    loaded at startup ("The member AuditToString is already present", etc.) - a machine/
    environment issue, reproducible against any test file in this repo, not specific to this
    suite. Work around it by restricting $env:PSModulePath in the child process before
    importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Routing.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Routing\SophosFirewall.Routing.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Routing module should load' {
        Get-Module SophosFirewall.Routing | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 31 functions' {
        (Get-Module SophosFirewall.Routing).ExportedFunctions.Count | Should -Be 31
    }

    It 'Manifest FunctionsToExport should list exactly 31 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Routing\SophosFirewall.Routing.psd1'

        # Test-ModuleManifest resolves RequiredModules through the search path. Without the
        # repository's Modules directory on it, the cmdlet writes an error about
        # SophosFirewall.Core being invalid and still returns a usable object - so the
        # assertion below passed while the manifest check itself had failed. Set the path for
        # the duration of this test and let the failure terminate.
        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 31
    }

    Context 'Private helper is not exported' {
        # ConvertTo-SfosDSCPMarkingWireValue is the module's one internal helper (32 functions
        # total, 31 exported). If FunctionsToExport ever grew to include it by accident,
        # callers could bypass the '0' -> '0-Best Effort' normalisation it exists to enforce.
        It 'ConvertTo-SfosDSCPMarkingWireValue should not be visible' {
            Get-Command ConvertTo-SfosDSCPMarkingWireValue -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-* commands - correct root element and empty-result handling' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosGatewayHost' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Status>No. of records Zero.</Status></GatewayHost></Response>' }
            }
        }
        It 'sends Get/GatewayHost' {
            Get-SfosGatewayHost @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<GatewayHost>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosGatewayHost @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosHealthCheckProfile' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><HealthCheckProfile transactionid=""><Status>No. of records Zero.</Status></HealthCheckProfile></Response>' }
            }
        }
        It 'sends Get/HealthCheckProfile' {
            Get-SfosHealthCheckProfile @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<HealthCheckProfile>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosHealthCheckProfile @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosSDWANProfile' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANProfile transactionid=""><Status>No. of records Zero.</Status></SDWANProfile></Response>' }
            }
        }
        It 'sends Get/SDWANProfile' {
            Get-SfosSDWANProfile @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<SDWANProfile>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosSDWANProfile @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosSDWANPolicyRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRoute transactionid=""><Status>No. of records Zero.</Status></SDWANPolicyRoute></Response>' }
            }
        }
        It 'sends Get/SDWANPolicyRoute' {
            Get-SfosSDWANPolicyRoute @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<SDWANPolicyRoute>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosSDWANPolicyRoute @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosUnicastRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><Status>No. of records Zero.</Status></UnicastRoute></Response>' }
            }
        }
        It 'sends Get/UnicastRoute' {
            Get-SfosUnicastRoute @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<UnicastRoute>'
            }
        }
        It 'returns @() for an empty result, without throwing - the UnicastRoute-scoped status check must still catch it' {
            $result = @(Get-SfosUnicastRoute @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosMulticastRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastRoute transactionid=""><Status>No. of records Zero.</Status></MulticastRoute></Response>' }
            }
        }
        It 'sends Get/MulticastRoute' {
            Get-SfosMulticastRoute @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<MulticastRoute>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosMulticastRoute @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosHealthCheckProfileStatus - undocumented Get, no server-side filter ever' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><HealthCheckProfileStatus transactionid=""><Status>No. of records Zero.</Status></HealthCheckProfileStatus></Response>' }
            }
        }
        It 'sends Get/HealthCheckProfileStatus' {
            Get-SfosHealthCheckProfileStatus @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<HealthCheckProfileStatus>'
            }
        }
        It 'never sends a Filter element, even with -NameLike' {
            Get-SfosHealthCheckProfileStatus -NameLike 'ISP1' @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -notmatch '<Filter>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosHealthCheckProfileStatus @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosMulticastConfiguration - singleton, no filter' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastConfiguration transactionid=""><MulticastForwardingSetting>Disable</MulticastForwardingSetting></MulticastConfiguration></Response>' }
            }
        }
        It 'sends Get/MulticastConfiguration and returns the singleton value' {
            $result = Get-SfosMulticastConfiguration @conn
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<MulticastConfiguration>'
            }
            $result.MulticastForwardingSetting | Should -Be 'Disable'
        }
    }

    Context 'Get-SfosPIMDynamicRouting - singleton, no filter' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><PIMDynamicRouting transactionid=""><ManagePIM>Disable</ManagePIM><CandidateRP></CandidateRP></PIMDynamicRouting></Response>' }
            }
        }
        It 'sends Get/PIMDynamicRouting and returns ManagePIM plus an empty CandidateRP' {
            $result = Get-SfosPIMDynamicRouting @conn
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<PIMDynamicRouting>'
            }
            $result.ManagePIM | Should -Be 'Disable'
            $result.CandidateRP | Should -Be ''
        }
    }
}

Describe 'New-*/Set-* XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    Context 'New-SfosGatewayHost' {
        It 'sends no Interval/Timeout/FailureRetries/MonitoringCondition when Healthcheck is OFF (the default)' {
            New-SfosGatewayHost -Name 'ZZGW1' -IPFamily IPv4 -GatewayIP '198.51.100.1' -Interface 'Port1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Name>ZZGW1</Name>' -and
                $InnerXml -match '<Healthcheck>OFF</Healthcheck>' -and
                $InnerXml -notmatch '<Interval>' -and
                $InnerXml -notmatch '<MonitoringCondition>'
            }
        }

        It 'sends Interval/Timeout/FailureRetries/MonitoringCondition when Healthcheck is ON' {
            $rule = [PSCustomObject]@{ Protocol = 'PING'; IPAddress = '198.51.100.1'; Port = '*'; Condition = '' }
            New-SfosGatewayHost -Name 'ZZGW2' -IPFamily IPv4 -GatewayIP '198.51.100.1' -Interface 'Port1' `
                -Healthcheck ON -Interval 60 -Timeout 5 -FailureRetries 3 -MonitoringCondition $rule @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Healthcheck>ON</Healthcheck>' -and
                $InnerXml -match '<Interval>60</Interval>' -and
                $InnerXml -match '<Timeout>5</Timeout>' -and
                $InnerXml -match '<FailureRetries>3</FailureRetries>' -and
                $InnerXml -match '<Rule><Protocol>PING</Protocol><Port>\*</Port><IPAddress>198\.51\.100\.1</IPAddress>'
            }
        }

        It 'throws client-side when Healthcheck ON is requested without the required health-check parameters' {
            { New-SfosGatewayHost -Name 'ZZGW3' -IPFamily IPv4 -GatewayIP '198.51.100.1' -Interface 'Port1' -Healthcheck ON @conn -Confirm:$false } |
                Should -Throw '*requires*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly
        }
    }

    Context 'New-SfosHealthCheckProfile' {
        It 'sends operation="add" with the ProbeTargets/ProbeTarget shape' {
            $t = [PSCustomObject]@{ monitormethod = 'PING'; monitorip = '198.51.100.2'; port = '0'; operator = '|' }
            New-SfosHealthCheckProfile -Name 'ZZHCP1' -IPFamily IPv4 -ProbeTarget $t @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<ProbeTargets><ProbeTarget><monitormethod>PING</monitormethod><monitorip>198\.51\.100\.2</monitorip><port>0</port><operator>\|</operator></ProbeTarget></ProbeTargets>'
            }
        }
    }

    Context 'New-SfosSDWANProfile' {
        It 'numbers GatewayPreferences/Gateway orderid 1..N and omits gatewayweights when not supplied' {
            New-SfosSDWANProfile -Name 'ZZProfile1' -GatewayName 'GW1', 'GW2' -EnableSLA OFF -HealthCheckProfileName 'ZZHCP1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Gateway><gatewayname>GW1</gatewayname><orderid>1</orderid></Gateway>' -and
                $InnerXml -match '<Gateway><gatewayname>GW2</gatewayname><orderid>2</orderid></Gateway>' -and
                $InnerXml -match '<EnableSLA>OFF</EnableSLA>' -and
                $InnerXml -match '<HealthCheckProfileName>ZZHCP1</HealthCheckProfileName>' -and
                $InnerXml -notmatch '<gatewayweights>'
            }
        }

        It 'throws client-side when -GatewayWeights does not supply one value per -GatewayName entry' {
            { New-SfosSDWANProfile -Name 'ZZProfile2' -GatewayName 'GW1', 'GW2' -GatewayWeights 10 -EnableSLA OFF -HealthCheckProfileName 'ZZHCP1' @conn -Confirm:$false } |
                Should -Throw '*GatewayWeights*GatewayName*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly
        }
    }

    Context 'New-SfosSDWANPolicyRoute' {
        It 'always sends IPFamily even when omitted, defaulting to IPv4' {
            New-SfosSDWANPolicyRoute -Name 'ZZRoute1' -DestinationNetwork 'NetA', 'NetB' -SDWANProfileName 'ZZProfile1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<IPFamily>IPv4</IPFamily>' -and
                $InnerXml -match '<DestinationNetworks><Network>NetA</Network><Network>NetB</Network></DestinationNetworks>' -and
                $InnerXml -match '<SDWANProfileName>ZZProfile1</SDWANProfileName>'
            }
        }
    }

    Context 'New-SfosUnicastRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><Status>No. of records Zero.</Status></UnicastRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
                }
            }
        }

        It 'sends a dotted-decimal Netmask and the default Status ON' {
            New-SfosUnicastRoute -DestinationIP '198.51.100.70' -Netmask '255.255.255.0' -Interface 'Port1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Netmask>255\.255\.255\.0</Netmask>' -and
                $InnerXml -match '<Status>ON</Status>' -and
                $InnerXml -match '<Distance>0</Distance>' -and
                $InnerXml -match '<AdministrativeDistance>1</AdministrativeDistance>'
            }
        }
    }

    Context 'New-SfosMulticastRoute' {
        It 'wraps destination interfaces in DestinationInterfaceList/DestinationInterface with matching TunnelType by position' {
            New-SfosMulticastRoute -SourceIPAddress '198.51.100.80' -MulticastAddress '239.1.1.8' `
                -DestinationInterface 'Port1', 'Port2' -DestinationTunnelType 'SystemInterface', 'GRE' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<DestinationInterface><Interface>Port1</Interface><TunnelType>SystemInterface</TunnelType></DestinationInterface>' -and
                $InnerXml -match '<DestinationInterface><Interface>Port2</Interface><TunnelType>GRE</TunnelType></DestinationInterface>'
            }
        }

        It 'throws client-side when -DestinationInterface and -DestinationTunnelType counts differ' {
            { New-SfosMulticastRoute -SourceIPAddress '198.51.100.80' -MulticastAddress '239.1.1.8' `
                    -DestinationInterface 'Port1', 'Port2' -DestinationTunnelType 'GRE' @conn -Confirm:$false } |
                Should -Throw '*same number of entries*'
        }
    }

    Context 'Set-SfosHealthCheckProfileStatus' {
        It 'sends operation="update" with Name/Status directly, without reading the object first' {
            Set-SfosHealthCheckProfileStatus -Name 'HealthCheckObject_GW_ZZGW1' -Status OFF @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Name>HealthCheckObject_GW_ZZGW1</Name>' -and
                $InnerXml -match '<Status>OFF</Status>'
            }
        }
    }

    Context 'Set-SfosPIMDynamicRouting - structural only, per module NOTES never sent live' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><PIMDynamicRouting transactionid=""><ManagePIM>Disable</ManagePIM><CandidateRP></CandidateRP></PIMDynamicRouting></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><PIMDynamicRouting><Status code="200">Configuration applied successfully.</Status></PIMDynamicRouting></Response>' }
                }
            }
        }

        It 'wraps InterfaceList/Interface and sends CandidateRP when provided' {
            Set-SfosPIMDynamicRouting -ManagePIM Enable -InterfaceList 'Port1', 'Port2' -CandidateRP Static @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<ManagePIM>Enable</ManagePIM>' -and
                $InnerXml -match '<InterfaceList>\s*<Interface>Port1</Interface><Interface>Port2</Interface>' -and
                $InnerXml -match '<CandidateRP>Static</CandidateRP>'
            }
        }

        It 'nests StaticRPIP/IPAddress and GroupIP/IPAddress when -StaticRPIP is supplied' {
            Set-SfosPIMDynamicRouting -StaticRPIP '198.51.100.90' -StaticRPGroupIP '239.1.1.0/24' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
                $InnerXml -match '<StaticRPIP>\s*<IPAddress>198\.51\.100\.90</IPAddress>\s*<GroupIP>\s*<IPAddress>239\.1\.1\.0/24</IPAddress>'
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

    Context 'Set-SfosGatewayHost' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Name>ZZGWRmw</Name><IPFamily>IPv4</IPFamily><GatewayIP>198.51.100.100</GatewayIP><Interface>Port1</Interface><NetworkZone>LAN</NetworkZone><Healthcheck>OFF</Healthcheck><MailNotification>OFF</MailNotification></GatewayHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GatewayHost><Status code="200">Configuration applied successfully.</Status></GatewayHost></Response>' }
                }
            }
        }

        It 'preserves GatewayIP, Interface, NetworkZone and Healthcheck when only MailNotification changes' {
            Set-SfosGatewayHost -Name 'ZZGWRmw' -MailNotification ON @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<MailNotification>ON</MailNotification>' -and
                $InnerXml -match '<GatewayIP>198\.51\.100\.100</GatewayIP>' -and
                $InnerXml -match '<Interface>Port1</Interface>' -and
                $InnerXml -match '<NetworkZone>LAN</NetworkZone>' -and
                $InnerXml -match '<Healthcheck>OFF</Healthcheck>' -and
                $InnerXml -notmatch '<Interval>'
            }
        }
    }

    Context 'Set-SfosSDWANProfile' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANProfile transactionid=""><Name>ZZProfileRmw</Name><Description></Description><IPFamily>IPv4</IPFamily><GatewayPreferences><Gateway><gatewayname>GWRmw</gatewayname><orderid>1</orderid></Gateway></GatewayPreferences><EnableSLA>ON</EnableSLA><RoutingStrategy>FirstAvailable</RoutingStrategy><SLAStrategy>BestQualityv</SLAStrategy><IsLatency>ON</IsLatency><IsJitter>OFF</IsJitter><IsPacketloss>OFF</IsPacketloss><LatencyValue>0</LatencyValue><JitterValue>0</JitterValue><PacketlossValue>0</PacketlossValue><ProbeCount>30</ProbeCount><HealthCheckProfileName>HCPRmw</HealthCheckProfileName></SDWANProfile></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SDWANProfile><Status code="200">Configuration applied successfully.</Status></SDWANProfile></Response>' }
                }
            }
        }

        It 'preserves GatewayPreferences and HealthCheckProfileName when only EnableSLA changes' {
            Set-SfosSDWANProfile -Name 'ZZProfileRmw' -EnableSLA OFF @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<EnableSLA>OFF</EnableSLA>' -and
                $InnerXml -match '<Gateway><gatewayname>GWRmw</gatewayname><orderid>1</orderid></Gateway>' -and
                $InnerXml -match '<HealthCheckProfileName>HCPRmw</HealthCheckProfileName>'
            }
        }

        It 'resends the non-enumerated SLAStrategy value read from the firewall (BestQualityv) verbatim when not supplied' {
            Set-SfosSDWANProfile -Name 'ZZProfileRmw' -EnableSLA OFF @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<SLAStrategy>BestQualityv</SLAStrategy>'
            }
        }
    }

    Context 'Set-SfosSDWANPolicyRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRoute transactionid=""><Name>ZZRouteRmw</Name><Description></Description><IPFamily>IPv4</IPFamily><DestinationNetworks><Network>NetRmw</Network></DestinationNetworks><SDWANProfileName>ZZProfileRmw</SDWANProfileName><Interface>Port2</Interface><DSCPMarking>10</DSCPMarking><Status>1</Status></SDWANPolicyRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SDWANPolicyRoute><Status code="200">Configuration applied successfully.</Status></SDWANPolicyRoute></Response>' }
                }
            }
        }

        It 'preserves DestinationNetworks, Interface and DSCPMarking when only Gateway changes' {
            Set-SfosSDWANPolicyRoute -Name 'ZZRouteRmw' -Gateway 'NewGW' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Gateway>NewGW</Gateway>' -and
                $InnerXml -match '<DestinationNetworks><Network>NetRmw</Network></DestinationNetworks>' -and
                $InnerXml -match '<Interface>Port2</Interface>' -and
                $InnerXml -match '<SDWANProfileName>ZZProfileRmw</SDWANProfileName>' -and
                $InnerXml -match '<DSCPMarking>10</DSCPMarking>'
            }
        }
    }

    Context 'Set-SfosHealthCheckProfile' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><HealthCheckProfile transactionid=""><Name>ZZHCPRmw</Name><IPFamily>IPv4</IPFamily><ProbeInterval>60</ProbeInterval><ResponseTimeout>2</ResponseTimeout><ProbesResponseFailure>1</ProbesResponseFailure><ProbeResponseSuccess>3</ProbeResponseSuccess><Status>1</Status><ProbeTargets><ProbeTarget><conditionid>1</conditionid><monitorip>198.51.100.5</monitorip><monitormethod>PING</monitormethod><operator>|</operator><port>0</port></ProbeTarget></ProbeTargets></HealthCheckProfile></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><HealthCheckProfile><Status code="200">Configuration applied successfully.</Status></HealthCheckProfile></Response>' }
                }
            }
        }

        It 'preserves ResponseTimeout, ProbesResponseFailure, ProbeResponseSuccess and ProbeTargets when only ProbeInterval changes' {
            Set-SfosHealthCheckProfile -Name 'ZZHCPRmw' -ProbeInterval 30 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<ProbeInterval>30</ProbeInterval>' -and
                $InnerXml -match '<ResponseTimeout>2</ResponseTimeout>' -and
                $InnerXml -match '<ProbesResponseFailure>1</ProbesResponseFailure>' -and
                $InnerXml -match '<ProbeResponseSuccess>3</ProbeResponseSuccess>' -and
                $InnerXml -match '<ProbeTarget><monitormethod>PING</monitormethod><monitorip>198\.51\.100\.5</monitorip><port>0</port><operator>\|</operator></ProbeTarget>'
            }
        }
    }

    Context 'Set-SfosMulticastRoute' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastRoute transactionid=""><SourceIPAddress>198.51.100.70</SourceIPAddress><SourceInterface>Port1</SourceInterface><MulticastAddress>239.1.1.7</MulticastAddress><DestinationInterfaceList><DestinationInterface><Interface>Port2</Interface><TunnelType>GRE</TunnelType></DestinationInterface></DestinationInterfaceList></MulticastRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><MulticastRoute><Status code="200">Configuration applied successfully.</Status></MulticastRoute></Response>' }
                }
            }
        }

        # @() must wrap the whole if/else: assigning straight from `if (...) { A } else { B }`
        # unwraps a one-element array to a scalar even when the branch itself wraps in @().
        It 'preserves a single DestinationInterface/TunnelType intact' {
            Set-SfosMulticastRoute -SourceIPAddress '198.51.100.70' -MulticastAddress '239.1.1.7' -SourceInterface 'Port3' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<SourceInterface>Port3</SourceInterface>' -and
                $InnerXml -match '<DestinationInterface><Interface>Port2</Interface><TunnelType>GRE</TunnelType></DestinationInterface>'
            }
        }

        It 'preserves DestinationInterfaceList intact when there are two or more destination interfaces (single-element array-unwrap does not trigger)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastRoute transactionid=""><SourceIPAddress>198.51.100.72</SourceIPAddress><SourceInterface>Port1</SourceInterface><MulticastAddress>239.1.1.9</MulticastAddress><DestinationInterfaceList><DestinationInterface><Interface>Port2</Interface><TunnelType>GRE</TunnelType></DestinationInterface><DestinationInterface><Interface>Port5</Interface><TunnelType>IPSec</TunnelType></DestinationInterface></DestinationInterfaceList></MulticastRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><MulticastRoute><Status code="200">Configuration applied successfully.</Status></MulticastRoute></Response>' }
                }
            }

            Set-SfosMulticastRoute -SourceIPAddress '198.51.100.72' -MulticastAddress '239.1.1.9' -SourceInterface 'Port3' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<DestinationInterface><Interface>Port2</Interface><TunnelType>GRE</TunnelType></DestinationInterface>' -and
                $InnerXml -match '<DestinationInterface><Interface>Port5</Interface><TunnelType>IPSec</TunnelType></DestinationInterface>'
            }
        }

        It 'throws when the target route does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastRoute transactionid=""><Status>No. of records Zero.</Status></MulticastRoute></Response>' }
            }

            { Set-SfosMulticastRoute -SourceIPAddress '198.51.100.71' -MulticastAddress '239.1.1.8' -SourceInterface 'Port3' @conn -Confirm:$false } |
                Should -Throw '*was not found*'
        }

        It 'throws client-side, before any API call, when -DestinationInterface and -DestinationTunnelType counts differ' {
            { Set-SfosMulticastRoute -SourceIPAddress '198.51.100.70' -MulticastAddress '239.1.1.7' `
                    -DestinationInterface 'Port1', 'Port2' -DestinationTunnelType 'GRE' @conn -Confirm:$false } |
                Should -Throw '*same number of entries*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly
        }
    }
}

Describe 'Measured special-case behaviours' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosUnicastRoute - operation="update" answers 500 on this firmware, so this cmdlet removes then recreates' {
        BeforeEach {
            $script:routeExists = $true
            $script:callOrder = @()

            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Remove>') {
                    $script:callOrder += 'Remove'
                    $script:routeExists = $false
                    return [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
                }
                if ($InnerXml -match '<Set operation="add">') {
                    $script:callOrder += 'Add'
                    $script:routeExists = $true
                    return [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
                }
                # <Get>. Blackhole is deliberately a valid enum value here ('Disable'), not
                # empty - see the dedicated defect Context below for why an empty Blackhole
                # (the common case for a route that was never configured as a blackhole route)
                # breaks this cmdlet on this firmware. That defect is orthogonal to the ordering
                # behaviour this Context exists to verify, so it is kept out of this mock.
                if ($script:routeExists) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><IPFamily>IPv4</IPFamily><DestinationIP>198.51.100.110</DestinationIP><Netmask>255.255.255.255</Netmask><Gateway></Gateway><Interface>Port1</Interface><Distance>0</Distance><AdministrativeDistance>1</AdministrativeDistance><Blackhole>Disable</Blackhole><Status>ON</Status><Description>original</Description></UnicastRoute></Response>' }
                }
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><Status>No. of records Zero.</Status></UnicastRoute></Response>' }
            }
        }

        It 'calls Remove before the recreating Set operation="add", in that exact order' {
            Set-SfosUnicastRoute -DestinationIP '198.51.100.110' -Netmask '255.255.255.255' -Description 'changed' @conn -Confirm:$false

            $script:callOrder | Should -Be @('Remove', 'Add')
        }
    }

    Context 'Set-SfosUnicastRoute updates a route whose Blackhole was never set (the common case)' {
        # Get-SfosUnicastRoute reads a route with no <Blackhole> element as Blackhole = ''.
        # -Blackhole '' fails [ValidateSet('Enable','Disable')], which has no empty-string
        # member, so the read-modify-write preserve path must pass -Blackhole only when the
        # preserved value is non-empty.
        BeforeEach {
            # Stateful mock: after the Remove that Set-SfosUnicastRoute issues, the follow-up
            # Get inside New-SfosUnicastRoute's duplicate guard has to see an empty table -
            # exactly like the real firewall - or the guard fires against the ghost of the
            # route that was just removed.
            $script:routeRemoved = $false
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Remove>') {
                    $script:routeRemoved = $true
                    return [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
                }
                if ($InnerXml -match '<Set operation="add">') {
                    return [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
                }
                if ($script:routeRemoved) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><Status>No. of records Zero.</Status></UnicastRoute></Response>' }
                }
                # <Get> before the remove - no <Blackhole> element at all, matching a route
                # that was created without -Blackhole.
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><IPFamily>IPv4</IPFamily><DestinationIP>198.51.100.111</DestinationIP><Netmask>255.255.255.255</Netmask><Interface>Port1</Interface><Distance>0</Distance><AdministrativeDistance>1</AdministrativeDistance><Status>ON</Status><Description>original</Description></UnicastRoute></Response>' }
            }
        }

        It 'completes the update and sends no Blackhole element for a route that never had one' {
            { Set-SfosUnicastRoute -DestinationIP '198.51.100.111' -Netmask '255.255.255.255' -Description 'changed' @conn -Confirm:$false } |
                Should -Not -Throw
            Should -Invoke Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Description>changed</Description>' -and
                $InnerXml -notmatch '<Blackhole>'
            }
        }
    }

    Context 'New-SfosUnicastRoute - the firewall does not enforce DestinationIP+Netmask uniqueness, so this cmdlet checks client-side' {
        BeforeEach {
            $script:addCallCount = 0
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Set operation="add">') {
                    $script:addCallCount++
                }
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><IPFamily>IPv4</IPFamily><DestinationIP>198.51.100.120</DestinationIP><Netmask>255.255.255.255</Netmask><Interface>Port1</Interface><Distance>0</Distance><AdministrativeDistance>1</AdministrativeDistance><Status>ON</Status></UnicastRoute></Response>' }
            }
        }

        It 'throws when a route for the same DestinationIP/Netmask already exists, without sending a create request' {
            # A stateful counter, not Should -Invoke -ParameterFilter: with Pester 6.0.1, a
            # -ParameterFilter-based Should -Invoke here left the mock call history in a state
            # that broke an unrelated Get-* test in a later Context in this same file (a
            # CommandNotFoundException for the literal text "$/Status", reproduced deterministically
            # by running the two Contexts back to back and disappearing when this assertion style
            # was removed). A local counter avoids relying on Pester's cross-call-history
            # ParameterFilter evaluation entirely.
            { New-SfosUnicastRoute -DestinationIP '198.51.100.120' -Netmask '255.255.255.255' -Interface 'Port1' @conn -Confirm:$false } |
                Should -Throw '*already exists*'

            $script:addCallCount | Should -Be 0
        }
    }

    Context 'Set-SfosSDWANPolicyRouteStatus - a nonexistent name answers 200 and changes nothing, so this cmdlet reads back and throws' {
        It 'throws when the confirming Get shows the requested status was not actually applied' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    [PSCustomObject]@{ Content = '<Response><SDWANPolicyRouteStatus><Status code="200">Configuration applied successfully.</Status></SDWANPolicyRouteStatus></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRouteStatus transactionid=""><Status>No. of records Zero.</Status></SDWANPolicyRouteStatus></Response>' }
                }
            }

            { Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName 'GhostRoute' -Status ON @conn -Confirm:$false } |
                Should -Throw '*could not be confirmed*'
        }

        It 'does not throw when the confirming Get matches the requested status' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    [PSCustomObject]@{ Content = '<Response><SDWANPolicyRouteStatus><Status code="200">Configuration applied successfully.</Status></SDWANPolicyRouteStatus></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRouteStatus transactionid=""><SDWANPolicyRouteName>ZZRoute</SDWANPolicyRouteName><Status>ON</Status></SDWANPolicyRouteStatus></Response>' }
                }
            }

            { Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName 'ZZRoute' -Status ON @conn -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Get-SfosSDWANPolicyRouteStatus - codeless status handling (Filter is completely broken for this entity)' {
        It 'reads a codeless Status element containing OFF as route data, not a broken API status' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRouteStatus transactionid=""><SDWANPolicyRouteName>ZZRoute</SDWANPolicyRouteName><Status>OFF</Status></SDWANPolicyRouteStatus></Response>' }
            }

            $result = @(Get-SfosSDWANPolicyRouteStatus @conn)
            $result.Count | Should -Be 1
            $result[0].SDWANPolicyRouteName | Should -Be 'ZZRoute'
            $result[0].Status | Should -Be 'OFF'
        }

        It 'throws on a codeless "Transaction fail" status instead of misreading it as data or as an empty result' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRouteStatus transactionid=""><Status>Transaction fail</Status></SDWANPolicyRouteStatus></Response>' }
            }

            { Get-SfosSDWANPolicyRouteStatus @conn } | Should -Throw '*unrecognised status*'
        }
    }

    Context 'DSCPMarking 0 is rejected by the firewall unless normalised to 0-Best Effort' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRoute transactionid=""><Name>ZZDscp</Name><Description></Description><IPFamily>IPv4</IPFamily><SDWANProfileName>ZZProfile</SDWANProfileName><Interface>Port1</Interface><DSCPMarking>0</DSCPMarking><Status>1</Status></SDWANPolicyRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SDWANPolicyRoute><Status code="200">Configuration applied successfully.</Status></SDWANPolicyRoute></Response>' }
                }
            }
        }

        It 'New-SfosSDWANPolicyRoute sends 0-Best Effort when the caller explicitly passes DSCPMarking 0' {
            New-SfosSDWANPolicyRoute -Name 'ZZDscpNew' -SDWANProfileName 'ZZProfile' -DSCPMarking '0' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<DSCPMarking>0-Best Effort</DSCPMarking>'
            }
        }

        It 'Set-SfosSDWANPolicyRoute resends an existing DSCPMarking of 0, read back from the firewall, as 0-Best Effort' {
            Set-SfosSDWANPolicyRoute -Name 'ZZDscp' -Interface 'Port2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<DSCPMarking>0-Best Effort</DSCPMarking>'
            }
        }
    }
}

Describe 'Error handling common to every Get-*' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws on a 5xx status code' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Status code="529">Invalid XML request</Status></GatewayHost></Response>' }
        }

        { Get-SfosGatewayHost @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosGatewayHost @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRoute transactionid=""><Status>No. of records Zero.</Status></SDWANPolicyRoute></Response>' }
        }

        $result = @(Get-SfosSDWANPolicyRoute @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'Remove-* XML generation and cmdlet-specific error paths' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Remove-SfosGatewayHost' {
        It 'reads the object first and sends <Remove><GatewayHost><Name>' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Name>ZZGWRemove</Name><IPFamily>IPv4</IPFamily><GatewayIP>198.51.100.1</GatewayIP><Interface>Port1</Interface></GatewayHost></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GatewayHost><Status code="200">Configuration applied successfully.</Status></GatewayHost></Response>' }
                }
            }

            Remove-SfosGatewayHost -Name 'ZZGWRemove' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<GatewayHost>\s*<Name>ZZGWRemove</Name>'
            }
        }

        It 'throws "was not found" and sends no Remove request when the object does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Status>No. of records Zero.</Status></GatewayHost></Response>' }
            }

            { Remove-SfosGatewayHost -Name 'Ghost' @conn -Confirm:$false } | Should -Throw '*was not found*'
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly
        }
    }

    Context 'Remove-SfosHealthCheckProfile - deliberately no pre-check, see module NOTES' {
        It 'sends <Remove><HealthCheckProfile><Name> directly, without a prior Get' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><HealthCheckProfile><Status code="200">Configuration applied successfully.</Status></HealthCheckProfile></Response>' }
            }

            Remove-SfosHealthCheckProfile -Name 'ZZHCPRemove' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<HealthCheckProfile>\s*<Name>ZZHCPRemove</Name>'
            }
        }

        It 'throws on the measured code-less "Operation could not be performed on Entity." status for a name that was never created' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><HealthCheckProfile><Status>Operation could not be performed on Entity.</Status></HealthCheckProfile></Response>' }
            }

            { Remove-SfosHealthCheckProfile -Name 'Ghost' @conn -Confirm:$false } | Should -Throw '*could not be performed*'
        }
    }

    Context 'Remove-SfosSDWANProfile' {
        It 'sends <Remove><SDWANProfile><Name> with no pre-check' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><SDWANProfile><Status code="200">Configuration applied successfully.</Status></SDWANProfile></Response>' }
            }

            Remove-SfosSDWANProfile -Name 'ZZProfileRemove' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SDWANProfile><Name>ZZProfileRemove</Name></SDWANProfile></Remove>'
            }
        }
    }

    Context 'Remove-SfosSDWANPolicyRoute' {
        It 'sends <Remove><SDWANPolicyRoute><Name> with no pre-check' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><SDWANPolicyRoute><Status code="200">Configuration applied successfully.</Status></SDWANPolicyRoute></Response>' }
            }

            Remove-SfosSDWANPolicyRoute -Name 'ZZRouteRemove' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SDWANPolicyRoute><Name>ZZRouteRemove</Name></SDWANPolicyRoute></Remove>'
            }
        }
    }

    Context 'Remove-SfosUnicastRoute' {
        It 'reads the object first and resends the full set of fields (Interface, Distance, AdministrativeDistance, Status)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><IPFamily>IPv4</IPFamily><DestinationIP>198.51.100.130</DestinationIP><Netmask>255.255.255.255</Netmask><Interface>Port1</Interface><Distance>0</Distance><AdministrativeDistance>1</AdministrativeDistance><Status>ON</Status><Description>original</Description></UnicastRoute></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
                }
            }

            Remove-SfosUnicastRoute -DestinationIP '198.51.100.130' -Netmask '255.255.255.255' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<DestinationIP>198\.51\.100\.130</DestinationIP>' -and
                $InnerXml -match '<Netmask>255\.255\.255\.255</Netmask>' -and
                $InnerXml -match '<Interface>Port1</Interface>' -and
                $InnerXml -match '<Distance>0</Distance>' -and
                $InnerXml -match '<AdministrativeDistance>1</AdministrativeDistance>' -and
                $InnerXml -match '<Status>ON</Status>'
            }
        }

        It 'throws "was not found" and sends no Remove request when the route does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><Status>No. of records Zero.</Status></UnicastRoute></Response>' }
            }

            { Remove-SfosUnicastRoute -DestinationIP '198.51.100.131' -Netmask '255.255.255.255' @conn -Confirm:$false } |
                Should -Throw '*was not found*'
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly
        }
    }

    Context 'Remove-SfosMulticastRoute' {
        It 'sends <Remove><MulticastRoute><SourceIPAddress>/<MulticastAddress> with no pre-check' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
                [PSCustomObject]@{ Content = '<Response><MulticastRoute><Status code="200">Configuration applied successfully.</Status></MulticastRoute></Response>' }
            }

            Remove-SfosMulticastRoute -SourceIPAddress '198.51.100.90' -MulticastAddress '239.1.1.9' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<MulticastRoute>\s*<SourceIPAddress>198\.51\.100\.90</SourceIPAddress>\s*<MulticastAddress>239\.1\.1\.9</MulticastAddress>'
            }
        }
    }
}

Describe 'MulticastRoute write paths - every documented variant answers 500 on this firmware [measured]' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosMulticastRoute throws on the measured 500 "Operation could not be performed on Entity."' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><MulticastRoute><Status code="500">Operation could not be performed on Entity.</Status></MulticastRoute></Response>' }
        }

        { New-SfosMulticastRoute -SourceIPAddress '198.51.100.80' -MulticastAddress '239.1.1.8' -DestinationInterface 'Port1' @conn -Confirm:$false } |
            Should -Throw '*500*'
    }

    It 'Set-SfosMulticastRoute throws on the measured 500 after a successful read of the existing route' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastRoute transactionid=""><SourceIPAddress>198.51.100.80</SourceIPAddress><MulticastAddress>239.1.1.8</MulticastAddress><DestinationInterfaceList><DestinationInterface><Interface>Port1</Interface></DestinationInterface></DestinationInterfaceList></MulticastRoute></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MulticastRoute><Status code="500">Operation could not be performed on Entity.</Status></MulticastRoute></Response>' }
            }
        }

        { Set-SfosMulticastRoute -SourceIPAddress '198.51.100.80' -MulticastAddress '239.1.1.8' -SourceInterface 'Port2' @conn -Confirm:$false } |
            Should -Throw '*500*'
    }

    It 'Remove-SfosMulticastRoute throws on the measured 500, whether the key ever existed or not' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><MulticastRoute><Status code="500">Operation could not be performed on Entity.</Status></MulticastRoute></Response>' }
        }

        { Remove-SfosMulticastRoute -SourceIPAddress '198.51.100.80' -MulticastAddress '239.1.1.8' @conn -Confirm:$false } |
            Should -Throw '*500*'
    }
}

Describe 'ShouldProcess - -WhatIf prevents every write cmdlet from sending a write request' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            if ($InnerXml -notmatch '<Get>') {
                return [PSCustomObject]@{ Content = '<Response><Status code="200">Configuration applied successfully.</Status></Response>' }
            }
            if ($InnerXml -match '<GatewayHost>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Name>ZZWIGateway</Name><IPFamily>IPv4</IPFamily><GatewayIP>198.51.100.1</GatewayIP><Interface>Port1</Interface><NetworkZone></NetworkZone><Healthcheck>OFF</Healthcheck><MailNotification>OFF</MailNotification></GatewayHost></Response>' }
            }
            if ($InnerXml -match '<HealthCheckProfile>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><HealthCheckProfile transactionid=""><Name>ZZWIHCP</Name><IPFamily>IPv4</IPFamily><ProbeInterval>60</ProbeInterval><ResponseTimeout>2</ResponseTimeout><ProbesResponseFailure>1</ProbesResponseFailure><ProbeResponseSuccess>3</ProbeResponseSuccess><Status>1</Status><ProbeTargets><ProbeTarget><conditionid>1</conditionid><monitorip>198.51.100.2</monitorip><monitormethod>PING</monitormethod><operator>|</operator><port>0</port></ProbeTarget></ProbeTargets></HealthCheckProfile></Response>' }
            }
            if ($InnerXml -match '<SDWANProfile>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANProfile transactionid=""><Name>ZZWIProfile</Name><Description></Description><IPFamily>IPv4</IPFamily><GatewayPreferences><Gateway><gatewayname>ZZWIGateway</gatewayname><orderid>1</orderid></Gateway></GatewayPreferences><EnableSLA>OFF</EnableSLA><RoutingStrategy>FirstAvailable</RoutingStrategy><SLAStrategy>BestQuality</SLAStrategy><IsLatency>OFF</IsLatency><IsJitter>OFF</IsJitter><IsPacketloss>OFF</IsPacketloss><LatencyValue>0</LatencyValue><JitterValue>0</JitterValue><PacketlossValue>0</PacketlossValue><ProbeCount>30</ProbeCount><HealthCheckProfileName>ZZWIHCP</HealthCheckProfileName></SDWANProfile></Response>' }
            }
            if ($InnerXml -match '<SDWANPolicyRoute>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SDWANPolicyRoute transactionid=""><Name>ZZWIRoute</Name><Description></Description><IPFamily>IPv4</IPFamily><SDWANProfileName>ZZWIProfile</SDWANProfileName><Interface>Port1</Interface><Status>1</Status></SDWANPolicyRoute></Response>' }
            }
            if ($InnerXml -match '<UnicastRoute>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><IPFamily>IPv4</IPFamily><DestinationIP>198.51.100.30</DestinationIP><Netmask>255.255.255.255</Netmask><Interface>Port1</Interface><Distance>0</Distance><AdministrativeDistance>1</AdministrativeDistance><Status>ON</Status></UnicastRoute></Response>' }
            }
            if ($InnerXml -match '<MulticastRoute>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MulticastRoute transactionid=""><SourceIPAddress>198.51.100.60</SourceIPAddress><MulticastAddress>239.1.1.6</MulticastAddress><SourceInterface>Port1</SourceInterface><DestinationInterfaceList><DestinationInterface><Interface>Port2</Interface></DestinationInterface></DestinationInterfaceList></MulticastRoute></Response>' }
            }
            if ($InnerXml -match '<PIMDynamicRouting>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><PIMDynamicRouting transactionid=""><ManagePIM>Disable</ManagePIM><CandidateRP></CandidateRP></PIMDynamicRouting></Response>' }
            }
            return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    It 'New-SfosGatewayHost sends no write request under -WhatIf' {
        New-SfosGatewayHost -Name 'ZZWIGateway' -IPFamily IPv4 -GatewayIP '198.51.100.1' -Interface 'Port1' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosGatewayHost sends no write request under -WhatIf' {
        Set-SfosGatewayHost -Name 'ZZWIGateway' -MailNotification ON @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosGatewayHost sends no write request under -WhatIf' {
        Remove-SfosGatewayHost -Name 'ZZWIGateway' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'New-SfosHealthCheckProfile sends no write request under -WhatIf' {
        $t = [PSCustomObject]@{ monitormethod = 'PING'; monitorip = '198.51.100.2'; port = '0'; operator = '|' }
        New-SfosHealthCheckProfile -Name 'ZZWIHCP' -ProbeTarget $t @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosHealthCheckProfile sends no write request under -WhatIf' {
        Set-SfosHealthCheckProfile -Name 'ZZWIHCP' -ProbeInterval 30 @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosHealthCheckProfile sends no write request under -WhatIf' {
        Remove-SfosHealthCheckProfile -Name 'ZZWIHCP' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosHealthCheckProfileStatus sends no write request under -WhatIf' {
        Set-SfosHealthCheckProfileStatus -Name 'ZZWIHCP' -Status OFF @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'New-SfosSDWANProfile sends no write request under -WhatIf' {
        New-SfosSDWANProfile -Name 'ZZWIProfile' -GatewayName 'ZZWIGateway' -EnableSLA OFF -HealthCheckProfileName 'ZZWIHCP' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosSDWANProfile sends no write request under -WhatIf' {
        Set-SfosSDWANProfile -Name 'ZZWIProfile' -EnableSLA ON @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosSDWANProfile sends no write request under -WhatIf' {
        Remove-SfosSDWANProfile -Name 'ZZWIProfile' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'New-SfosSDWANPolicyRoute sends no write request under -WhatIf' {
        New-SfosSDWANPolicyRoute -Name 'ZZWIRoute' -SDWANProfileName 'ZZWIProfile' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosSDWANPolicyRoute sends no write request under -WhatIf' {
        Set-SfosSDWANPolicyRoute -Name 'ZZWIRoute' -Interface 'Port2' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosSDWANPolicyRoute sends no write request under -WhatIf' {
        Remove-SfosSDWANPolicyRoute -Name 'ZZWIRoute' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosSDWANPolicyRouteStatus sends no write request under -WhatIf' {
        Set-SfosSDWANPolicyRouteStatus -SDWANPolicyRouteName 'ZZWIRoute' -Status OFF @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'New-SfosUnicastRoute sends no write request under -WhatIf' {
        New-SfosUnicastRoute -DestinationIP '198.51.100.40' -Netmask '255.255.255.0' -Interface 'Port1' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosUnicastRoute sends no write request under -WhatIf' {
        Set-SfosUnicastRoute -DestinationIP '198.51.100.30' -Netmask '255.255.255.255' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosUnicastRoute sends no write request under -WhatIf' {
        Remove-SfosUnicastRoute -DestinationIP '198.51.100.30' -Netmask '255.255.255.255' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'New-SfosMulticastRoute sends no write request under -WhatIf' {
        New-SfosMulticastRoute -SourceIPAddress '198.51.100.50' -MulticastAddress '239.1.1.5' -DestinationInterface 'Port1' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosMulticastRoute sends no write request under -WhatIf' {
        Set-SfosMulticastRoute -SourceIPAddress '198.51.100.60' -MulticastAddress '239.1.1.6' -SourceInterface 'Port2' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosMulticastRoute sends no write request under -WhatIf' {
        Remove-SfosMulticastRoute -SourceIPAddress '198.51.100.60' -MulticastAddress '239.1.1.6' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosPIMDynamicRouting sends no write request under -WhatIf' {
        Set-SfosPIMDynamicRouting -ManagePIM Enable @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GatewayHost transactionid=""><Status>No. of records Zero.</Status></GatewayHost></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosGatewayHost -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosGatewayHost | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on the begin-block pipeline path (New-SfosUnicastRoute)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UnicastRoute transactionid=""><Status>No. of records Zero.</Status></UnicastRoute></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><UnicastRoute><Status code="200">Configuration applied successfully.</Status></UnicastRoute></Response>' }
            }
        }
        New-SfosUnicastRoute -DestinationIP '198.51.100.70' -Netmask '255.255.255.0' -Interface 'Port1' -Session 'fw2' -Confirm:$false
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<Netmask>255\.255\.255\.0</Netmask>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosGatewayHost -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Routing -Times 0 -Exactly
    }
}
