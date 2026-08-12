#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.VPN module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement (51 functions); a Get smoke test (root
    element, empty-result handling / singleton field mapping) for all 13 entities, including
    the two-level nested status handling of SSLVPNPolicy; New/Set XML-generation checks for
    every New-*/Set-* group; read-modify-write checks for Set-SfosVPNProfile,
    Set-SfosSSLBookmark, Set-SfosSSLTunnelAccessSettings and Set-SfosL2TPConfiguration; the
    module's measured special-case behaviours (SSLBookmark's Password/hashform round trip and
    the confirmed Remove-SfosSSLBookmark no-op, the nested Remove shape of
    Remove-SfosSSLVPNPolicy, the New-SfosSSLVPNPolicy UserGroup-write-back warning, and
    SecureString parameter binding under -WhatIf); the shared error paths (5xx throws, a
    failed login with no entity status throws, "No. of records Zero." yields @(), a code-less
    "Transaction fail" throws); and a -WhatIf check against every one of the module's 38 write
    cmdlets (9 New-*, 12 Set-*, 13 Remove-*, 4 Add-/Remove-*Member).

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
        Invoke-Pester -Path '.\SophosFirewall.VPN.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.VPN\SophosFirewall.VPN.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.VPN module should load' {
        Get-Module SophosFirewall.VPN | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 51 functions' {
        (Get-Module SophosFirewall.VPN).ExportedFunctions.Count | Should -Be 51
    }

    It 'Manifest FunctionsToExport should list exactly 51 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.VPN\SophosFirewall.VPN.psd1'

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

        $manifest.ExportedFunctions.Count | Should -Be 51
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

    Context 'Get-SfosIPsecConnection - VPNIPSecConnection, wrapped one level deeper in Configuration' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Status>No. of records Zero.</Status></Configuration></VPNIPSecConnection></Response>' }
            }
        }
        It 'sends Get/VPNIPSecConnection/Configuration' {
            Get-SfosIPsecConnection @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<VPNIPSecConnection>\s*<Configuration>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosIPsecConnection @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosVPNProfile' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNProfile><Status>No. of records Zero.</Status></VPNProfile></Response>' }
            }
        }
        It 'sends Get/VPNProfile' {
            Get-SfosVPNProfile @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<VPNProfile>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosVPNProfile @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosVPNFailoverGroup - VPNFailoverGroup, wrapped one level deeper in GroupDetail' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Status>No. of records Zero.</Status></GroupDetail></VPNFailoverGroup></Response>' }
            }
        }
        It 'sends Get/VPNFailoverGroup/GroupDetail' {
            Get-SfosVPNFailoverGroup @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<VPNFailoverGroup>\s*<GroupDetail>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosVPNFailoverGroup @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosSophosConnectClient - undocumented singleton, no fields match the documented Configure sample' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SophosConnectClient><Reset>Yes</Reset></SophosConnectClient></Response>' }
            }
        }
        It 'sends the exact documented Get shape' {
            Get-SfosSophosConnectClient @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Get><SophosConnectClient></SophosConnectClient></Get>'
            }
        }
        It 'maps the measured Reset field, not any documented Configure field' {
            $result = Get-SfosSophosConnectClient @conn
            $result.Reset | Should -Be 'Yes'
        }
    }

    Context 'Get-SfosSSLTunnelAccessSettings - device-wide singleton' {
        BeforeEach {
            # Real captured shape (scratchpad/vpn-live/SSLTunnelAccessSettings.xml)
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLTunnelAccessSettings><Protocol>TCP</Protocol><SSLServerCertificate>ApplianceCertificate</SSLServerCertificate><OverrideHostName/><Port>8443</Port><IPLeaseRange><StartIP>10.81.0.0</StartIP></IPLeaseRange><SubnetMask>255.255.0.0</SubnetMask><IPv6Lease>2001:db8::1:0</IPv6Lease><IPv6Prefix>64</IPv6Prefix><LeaseMode>IPv4</LeaseMode><PrimaryDNSIPv4/><SecondaryDNSIPv4/><PrimaryWINSIPv4/><SecondaryWINSIPv4/><DomainName/><DisconnectDeadPeerAfter>180</DisconnectDeadPeerAfter><DisconnectIdlePeerAfter>15</DisconnectIdlePeerAfter><EncryptionAlgorithm>AES-128-CBC</EncryptionAlgorithm><AuthenticationAlgorithm>SHA256</AuthenticationAlgorithm><Keysize>2048bit</Keysize><KeyLifetime>28800</KeyLifetime><DebugMode>Disable</DebugMode><SecurityHeartbeat>Disable</SecurityHeartbeat><SaveCredential>Disable</SaveCredential><TwoFAToken>Disable</TwoFAToken><AdLogon>Disable</AdLogon><AutoConnect>Disable</AutoConnect><HostorDNSName/><StaticIPAddresses>Disable</StaticIPAddresses></SSLTunnelAccessSettings></Response>' }
            }
        }
        It 'sends the exact documented Get shape' {
            Get-SfosSSLTunnelAccessSettings @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Get><SSLTunnelAccessSettings></SSLTunnelAccessSettings></Get>'
            }
        }
        It 'maps every field from the real captured shape, including the empty StartIP/EndIP split' {
            $result = Get-SfosSSLTunnelAccessSettings @conn
            $result.Protocol | Should -Be 'TCP'
            $result.Port | Should -Be '8443'
            $result.StartIP | Should -Be '10.81.0.0'
            $result.EndIP | Should -Be ''
            $result.DebugMode | Should -Be 'Disable'
            $result.Keysize | Should -Be '2048bit'
        }
    }

    Context 'Get-SfosSSLVPNPolicy - two-level nested no-records status under either sub-type' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><ClientlessPolicy><Status>No. of records Zero.</Status></ClientlessPolicy></SSLVPNPolicy></Response>' }
            }
        }
        It 'sends the exact documented Get shape' {
            Get-SfosSSLVPNPolicy @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Get><SSLVPNPolicy></SSLVPNPolicy></Get>'
            }
        }
        It 'returns @() for the measured nested-Status empty result, without throwing' {
            $result = @(Get-SfosSSLVPNPolicy @conn)
            $result.Count | Should -Be 0
        }
        It 'throws on a code-less status nested under a sub-type that is not "No. of records Zero."' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><TunnelPolicy><Status>Transaction fail</Status></TunnelPolicy></SSLVPNPolicy></Response>' }
            }
            { Get-SfosSSLVPNPolicy @conn } | Should -Throw '*status without a code*'
        }
    }

    Context 'Get-SfosSSLBookmark' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Status>No. of records Zero.</Status></SSLBookmark></Response>' }
            }
        }
        It 'sends Get/SSLBookmark' {
            Get-SfosSSLBookmark @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<SSLBookmark>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosSSLBookmark @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosSSLBookmarkGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Status>No. of records Zero.</Status></SSLBookmarkGroup></Response>' }
            }
        }
        It 'sends Get/SSLBookmarkGroup' {
            Get-SfosSSLBookmarkGroup @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<SSLBookmarkGroup>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosSSLBookmarkGroup @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosSiteToSiteClient' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteClient><Status>No. of records Zero.</Status></SiteToSiteClient></Response>' }
            }
        }
        It 'sends Get/SiteToSiteClient' {
            Get-SfosSiteToSiteClient @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<SiteToSiteClient>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosSiteToSiteClient @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosSiteToSiteServer' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteServer><Status>No. of records Zero.</Status></SiteToSiteServer></Response>' }
            }
        }
        It 'sends Get/SiteToSiteServer' {
            Get-SfosSiteToSiteServer @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<SiteToSiteServer>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosSiteToSiteServer @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosL2TPConfiguration - singleton, no Status element at all on a normal response' {
        BeforeEach {
            # Real captured shape (scratchpad/vpn-live/L2TPConfiguration.xml): only the two
            # fields ever configured in the lab are present; AssignIPFrom/DNS/WINS are omitted
            # entirely, not empty elements.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConfiguration><L2TPSettings><L2TPGeneralSettings>Disable</L2TPGeneralSettings><LeaseIPFromRadiusServer>Disable</LeaseIPFromRadiusServer></L2TPSettings></L2TPConfiguration></Response>' }
            }
        }
        It 'sends the exact documented Get shape' {
            Get-SfosL2TPConfiguration @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Get><L2TPConfiguration></L2TPConfiguration></Get>'
            }
        }
        It 'maps omitted elements (StartIP, PrimaryDNSServer, ...) to empty string, never $null' {
            $result = Get-SfosL2TPConfiguration @conn
            $result.L2TPGeneralSettings | Should -Be 'Disable'
            $result.LeaseIPFromRadiusServer | Should -Be 'Disable'
            $result.StartIP | Should -Be ''
            $result.EndIP | Should -Be ''
            $result.PrimaryDNSServer | Should -Be ''
            $result.MemberList | Should -Be @()
        }
    }

    Context 'Get-SfosL2TPConnection - L2TPConnection, wrapped one level deeper in Configuration' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConnection><Configuration><Status>No. of records Zero.</Status></Configuration></L2TPConnection></Response>' }
            }
        }
        It 'sends Get/L2TPConnection/Configuration' {
            Get-SfosL2TPConnection @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>\s*<L2TPConnection>'
            }
        }
        It 'returns @() for an empty result, without throwing' {
            $result = @(Get-SfosL2TPConnection @conn)
            $result.Count | Should -Be 0
        }
    }

    Context 'Get-SfosPPTPConfiguration - singleton, mirrors L2TPConfiguration' {
        BeforeEach {
            # Real captured shape (scratchpad/vpn-live/PPTPConfiguration.xml)
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><PPTPConfiguration><PPTPSettings><PPTPGeneralSettings>Disable</PPTPGeneralSettings><LeaseIPFromRadiusServer>Disable</LeaseIPFromRadiusServer></PPTPSettings></PPTPConfiguration></Response>' }
            }
        }
        It 'sends the exact documented Get shape' {
            Get-SfosPPTPConfiguration @conn | Out-Null
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Get><PPTPConfiguration></PPTPConfiguration></Get>'
            }
        }
        It 'maps omitted elements to empty string, never $null' {
            $result = Get-SfosPPTPConfiguration @conn
            $result.PPTPGeneralSettings | Should -Be 'Disable'
            $result.StartIP | Should -Be ''
            $result.PrimaryDNSServer | Should -Be ''
            $result.MemberList | Should -Be @()
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    Context 'New-SfosIPsecConnection' {
        It 'sends operation="add" with the mandatory ID/type fields and the default Status Deactive' {
            New-SfosIPsecConnection -Name 'ZZWVIPsec' -ConnectionType SiteToSite `
                -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                -LocalSubnet 'ZZLocalNet' -AliasLocalWANPort 'Port1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<VPNIPSecConnection>\s*<Configuration>' -and
                $InnerXml -match '<Name>ZZWVIPsec</Name>' -and
                $InnerXml -match '<ConnectionType>SiteToSite</ConnectionType>' -and
                $InnerXml -match '<AliasLocalWANPort>Port1</AliasLocalWANPort>' -and
                $InnerXml -match '<Status>Deactive</Status>'
            }
        }

        It 'converts -ConnectionPassword (SecureString) to a plain Password element' {
            $sec = ConvertTo-SecureString 'ConnSecret1' -AsPlainText -Force
            New-SfosIPsecConnection -Name 'ZZWVIPsec2' -ConnectionType RemoteAccess `
                -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                -LocalSubnet 'ZZLocalNet' -AliasLocalWANPort 'Port1' `
                -ConnectionUsername 'vpnuser' -ConnectionPassword $sec @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Username>vpnuser</Username>' -and
                $InnerXml -match '<Password>ConnSecret1</Password>'
            }
        }

        It 'converts -PresharedKey (SecureString) to a plain, escaped PresharedKey element' {
            (Get-Command New-SfosIPsecConnection).Parameters['PresharedKey'].ParameterType.Name | Should -Be 'SecureString'
            $psk = ConvertTo-SecureString 'IPsecSecret1' -AsPlainText -Force
            New-SfosIPsecConnection -Name 'ZZWVIPsec3' -ConnectionType SiteToSite `
                -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                -LocalSubnet 'ZZLocalNet' -AliasLocalWANPort 'Port1' `
                -AuthenticationType PresharedKey -PresharedKey $psk @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<PresharedKey>IPsecSecret1</PresharedKey>'
            }
        }

        It 'defaults -LocalWANPort to -AliasLocalWANPort and always sends it, for a route-based connection with no LocalSubnet/RemoteNetwork' {
            New-SfosIPsecConnection -Name 'ZZWVIPsec4' -ConnectionType TunnelInterface `
                -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                -AliasLocalWANPort 'Port2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<AliasLocalWANPort>Port2</AliasLocalWANPort>' -and
                $InnerXml -match '<LocalWANPort>Port2</LocalWANPort>' -and
                $InnerXml -notmatch '<LocalSubnet>' -and
                $InnerXml -notmatch '<RemoteNetwork>'
            }
        }

        It 'honours an explicit -LocalWANPort that differs from -AliasLocalWANPort' {
            New-SfosIPsecConnection -Name 'ZZWVIPsec5' -ConnectionType TunnelInterface `
                -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                -AliasLocalWANPort 'Port2' -LocalWANPort 'Port3' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<AliasLocalWANPort>Port2</AliasLocalWANPort>' -and
                $InnerXml -match '<LocalWANPort>Port3</LocalWANPort>'
            }
        }

        It 'accepts SubnetFamily Dual and always sends LocalPort/RemotePort defaulted to *' {
            New-SfosIPsecConnection -Name 'ZZWVIPsec6' -ConnectionType TunnelInterface `
                -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                -AliasLocalWANPort 'Port2' -SubnetFamily Dual @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<SubnetFamily>Dual</SubnetFamily>' -and
                $InnerXml -match '<LocalPort>\*</LocalPort>' -and
                $InnerXml -match '<RemotePort>\*</RemotePort>'
            }
        }

        It 'throws client-side, without calling the API, when Name contains a hyphen' {
            { New-SfosIPsecConnection -Name 'ZZ-Hyphen' -ConnectionType TunnelInterface `
                    -LocalIDType 'IP Address' -LocalID '198.51.100.1' `
                    -RemoteIDType 'IP Address' -RemoteID '198.51.100.2' `
                    -AliasLocalWANPort 'Port2' @conn -Confirm:$false } |
                Should -Throw '*hyphen*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0
        }
    }

    Context 'New-SfosVPNProfile' {
        It 'wraps SupportedDHGroups/DHGroup and always sends the DeadPeerDetection/PFSGroup quartet' {
            New-SfosVPNProfile -Name 'ZZWVProfile' -AuthenticationMode MainMode `
                -Phase1EncryptionAlgorithm1 AES256 -Phase1AuthenticationAlgorithm1 SHA2_256 `
                -Phase1KeyLife 3600 -Phase1ReKeyMargin 120 -Phase1RandomizeReKeyingMarginBy 100 `
                -Phase2EncryptionAlgorithm1 AES256 -Phase2AuthenticationAlgorithm1 SHA2_256 `
                -Phase2KeyLife 3600 -SupportedDHGroup '14(DH2048)', '16(DH4096)' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<SupportedDHGroups><DHGroup>14\(DH2048\)</DHGroup><DHGroup>16\(DH4096\)</DHGroup></SupportedDHGroups>' -and
                $InnerXml -match '<DeadPeerDetection>Enable</DeadPeerDetection>' -and
                $InnerXml -match '<CheckPeerAfterEvery>30</CheckPeerAfterEvery>' -and
                $InnerXml -match '<PFSGroup>SameasPhase-I</PFSGroup>'
            }
        }
    }

    Context 'New-SfosVPNFailoverGroup' {
        It 'wraps MemberConnections/Connection and sends the measured-mandatory MailNotification' {
            New-SfosVPNFailoverGroup -Name 'ZZWVFailover' -Connection 'ZZWVIPsec' -MailNotification Disable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<MemberConnections><Connection>ZZWVIPsec</Connection></MemberConnections>' -and
                $InnerXml -match '<MailNotification>Disable</MailNotification>'
            }
        }

        It 'MailNotification is a mandatory parameter (measured contradiction to the doc)' {
            { New-SfosVPNFailoverGroup -Name 'ZZWVFailover2' -Connection 'ZZWVIPsec' @conn -Confirm:$false -ErrorAction Stop } |
                Should -Throw '*MailNotification*'
        }
    }

    Context 'New-SfosSSLVPNPolicy' {
        It 'Tunnel: sends the TunnelPolicy sub-shape with PolicyMembers and PermittedNetworkResources' {
            New-SfosSSLVPNPolicy -Name 'ZZWVTunnelPolicy' -PolicyType Tunnel -Member 'ZZTestVBGrp' `
                -PermittedNetworkResourcesIPv4 'ZZTestNet' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<SSLVPNPolicy>\s*<TunnelPolicy>' -and
                $InnerXml -match '<PolicyMembers><Member>ZZTestVBGrp</Member></PolicyMembers>' -and
                $InnerXml -match '<PermittedNetworkResourcesIPv4><Resource>ZZTestNet</Resource></PermittedNetworkResourcesIPv4>' -and
                $InnerXml -match '<UseAsDefaultGateway>Off</UseAsDefaultGateway>'
            }
        }

        It 'Clientless: sends the ClientlessPolicy sub-shape with WebAccessibleResources' {
            New-SfosSSLVPNPolicy -Name 'ZZWVClientlessPolicy' -PolicyType Clientless -Member 'ZZTestVBGrp' `
                -BookmarkGroup 'ZZWVBookmarkGroup' -Bookmark 'ZZWVBookmark' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<SSLVPNPolicy>\s*<ClientlessPolicy>' -and
                $InnerXml -match '<WebAccessibleResources><BookmarkGroups>ZZWVBookmarkGroup</BookmarkGroups><Bookmarks>ZZWVBookmark</Bookmarks></WebAccessibleResources>'
            }
        }
    }

    Context 'New-SfosSSLBookmark' {
        It 'sends the mandatory Type/URL fields, no Password element when -SecurePassword is not supplied' {
            New-SfosSSLBookmark -Name 'ZZWVBookmark' -Type HTTP -URL 'intranet.example' -BookmarkPort 80 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Type>HTTP</Type>' -and
                $InnerXml -match '<URL>intranet\.example</URL>' -and
                $InnerXml -match '<Port>80</Port>' -and
                $InnerXml -notmatch '<Password'
            }
        }

        It 'converts -SecurePassword to a bare, un-hashed Password element on create' {
            $sec = ConvertTo-SecureString 'BookmarkSecret1' -AsPlainText -Force
            New-SfosSSLBookmark -Name 'ZZWVBookmark2' -Type RDP -URL 'rdp.example' -AutoLogin Enable `
                -LoginUserName 'rdpuser' -SecurePassword $sec @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<UserName>rdpuser</UserName>' -and
                $InnerXml -match '<Password>BookmarkSecret1</Password>' -and
                $InnerXml -notmatch 'hashform'
            }
        }
    }

    Context 'New-SfosSSLBookmarkGroup' {
        It 'wraps BookmarkList/Bookmark and requires at least one member' {
            New-SfosSSLBookmarkGroup -Name 'ZZWVBookmarkGroup' -Bookmark 'ZZWVBookmark', 'ZZWVBookmark2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<BookmarkList><Bookmark>ZZWVBookmark</Bookmark><Bookmark>ZZWVBookmark2</Bookmark></BookmarkList>'
            }
        }

        It 'throws client-side (parameter validation) when -Bookmark is empty' {
            { New-SfosSSLBookmarkGroup -Name 'ZZWVBookmarkGroup2' -Bookmark @() @conn -Confirm:$false } | Should -Throw
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly
        }
    }

    Context 'New-SfosSiteToSiteClient - unconfirmed transport, XML shape only' {
        It 'converts -FilePassword and -ProxySecurePassword (SecureString) to plain XML elements' {
            $filePw = ConvertTo-SecureString 'FileSecret1' -AsPlainText -Force
            $proxyPw = ConvertTo-SecureString 'ProxySecret1' -AsPlainText -Force
            New-SfosSiteToSiteClient -Name 'ZZWVS2SClient' -ServerConfigurationFile 'base64placeholder' `
                -FilePassword $filePw -ProxyAuthentication Enable -ProxyUsername 'proxyuser' `
                -ProxySecurePassword $proxyPw @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<FilePassword>FileSecret1</FilePassword>' -and
                $InnerXml -match '<Username>proxyuser</Username>' -and
                $InnerXml -match '<Password>ProxySecret1</Password>'
            }
        }

        It 'throws client-side when -HttpProxyServer Enable is requested without -ProxyServer/-ProxyPort' {
            { New-SfosSiteToSiteClient -Name 'ZZWVS2SClient2' -ServerConfigurationFile 'x' -HttpProxyServer Enable @conn -Confirm:$false } |
                Should -Throw '*ProxyServer*ProxyPort*'
        }
    }

    Context 'New-SfosSiteToSiteServer' {
        It 'wraps LocalNetworks/RemoteNetworks and rejects a hyphenated Name client-side' {
            New-SfosSiteToSiteServer -Name 'ZZWVS2SServer' -LocalNetworks 'ZZLocalNet' -RemoteNetworks 'ZZRemoteNet' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<LocalNetworks><Network>ZZLocalNet</Network></LocalNetworks>' -and
                $InnerXml -match '<RemoteNetworks><Network>ZZRemoteNet</Network></RemoteNetworks>'
            }

            { New-SfosSiteToSiteServer -Name 'ZZ-WVBad' -LocalNetworks 'ZZLocalNet' -RemoteNetworks 'ZZRemoteNet' @conn -Confirm:$false } | Should -Throw
        }
    }

    Context 'New-SfosL2TPConnection' {
        It 'converts -PresharedKey (SecureString) to a plain, escaped PresharedKey element on the wire' {
            (Get-Command New-SfosL2TPConnection).Parameters['PresharedKey'].ParameterType.Name | Should -Be 'SecureString'
            $psk = ConvertTo-SecureString 'L2TPSecret1' -AsPlainText -Force

            New-SfosL2TPConnection -Name 'ZZWVL2TP' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey `
                -PresharedKey $psk -AliasLocalWANPort 'Port2' -LocalID '198.51.100.1' `
                -RemoteHost '198.51.100.2' -RemoteLANNetwork 'ZZRemoteLAN' -RemoteID '198.51.100.2' `
                -LocalPort 1701 -RemotePort '*' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<L2TPConnection>\s*<Configuration>' -and
                $InnerXml -match '<PresharedKey>L2TPSecret1</PresharedKey>'
            }
        }

        It 'throws client-side when -AuthenticationType PresharedKey is requested without -PresharedKey' {
            { New-SfosL2TPConnection -Name 'ZZWVL2TP2' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey `
                    -AliasLocalWANPort 'Port2' -LocalID '198.51.100.1' -RemoteHost '198.51.100.2' `
                    -RemoteLANNetwork 'ZZRemoteLAN' -RemoteID '198.51.100.2' -LocalPort 1701 -RemotePort '*' @conn -Confirm:$false } |
                Should -Throw '*requires -PresharedKey*'
        }
    }

    Context 'Set-SfosL2TPConnection' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConnection><Configuration><Name>ZZWVL2TPSet</Name><Description></Description><ActionOnVPNRestart>Disable</ActionOnVPNRestart><AuthenticationType>PresharedKey</AuthenticationType><AliasLocalWANPort>Port2</AliasLocalWANPort><LocalID>198.51.100.1</LocalID><RemoteHost>198.51.100.2</RemoteHost><AllowNATTraversal>Enable</AllowNATTraversal><RemoteID>198.51.100.2</RemoteID><LocalPort>1701</LocalPort><RemotePort>*</RemotePort></Configuration></L2TPConnection></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><L2TPConnection><Configuration><Status code="200">Configuration applied successfully.</Status></Configuration></L2TPConnection></Response>' }
                }
            }
        }

        It 'converts -PresharedKey (SecureString) to a plain, escaped PresharedKey element on the wire' {
            (Get-Command Set-SfosL2TPConnection).Parameters['PresharedKey'].ParameterType.Name | Should -Be 'SecureString'
            $psk = ConvertTo-SecureString 'NewL2TPSecret1' -AsPlainText -Force

            Set-SfosL2TPConnection -Name 'ZZWVL2TPSet' -PresharedKey $psk @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<PresharedKey>NewL2TPSecret1</PresharedKey>'
            }
        }
    }

    Context 'Set-SfosSSLTunnelAccessSettings - -SslPort maps to the wire Port element' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLTunnelAccessSettings><Protocol>TCP</Protocol><SSLServerCertificate>ApplianceCertificate</SSLServerCertificate><OverrideHostName/><Port>8443</Port><IPLeaseRange><StartIP>10.81.0.0</StartIP></IPLeaseRange><SubnetMask>255.255.0.0</SubnetMask><IPv6Lease>2001:db8::1:0</IPv6Lease><IPv6Prefix>64</IPv6Prefix><LeaseMode>IPv4</LeaseMode><PrimaryDNSIPv4/><SecondaryDNSIPv4/><PrimaryWINSIPv4/><SecondaryWINSIPv4/><DomainName/><DisconnectDeadPeerAfter>180</DisconnectDeadPeerAfter><DisconnectIdlePeerAfter>15</DisconnectIdlePeerAfter><EncryptionAlgorithm>AES-128-CBC</EncryptionAlgorithm><AuthenticationAlgorithm>SHA256</AuthenticationAlgorithm><Keysize>2048bit</Keysize><KeyLifetime>28800</KeyLifetime><DebugMode>Disable</DebugMode><SecurityHeartbeat>Disable</SecurityHeartbeat><SaveCredential>Disable</SaveCredential><TwoFAToken>Disable</TwoFAToken><AdLogon>Disable</AdLogon><AutoConnect>Disable</AutoConnect><HostorDNSName/><StaticIPAddresses>Disable</StaticIPAddresses></SSLTunnelAccessSettings></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLTunnelAccessSettings><Status code="200">Configuration applied successfully.</Status></SSLTunnelAccessSettings></Response>' }
                }
            }
        }

        It 'sends -SslPort as the wire Port element, not the connection -Port' {
            Set-SfosSSLTunnelAccessSettings -SslPort 9443 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Port>9443</Port>'
            }
        }
    }

    Context 'Set-SfosL2TPConfiguration - StartIP/EndIP/PrimaryDNSServer are unconditionally mandatory on every update' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConfiguration><L2TPSettings><L2TPGeneralSettings>Disable</L2TPGeneralSettings><LeaseIPFromRadiusServer>Disable</LeaseIPFromRadiusServer></L2TPSettings></L2TPConfiguration></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><L2TPSettings><Status code="200">Configuration applied successfully.</Status></L2TPSettings></Response>' }
                }
            }
        }

        It 'throws client-side when the current object has no IP range and none is supplied' {
            { Set-SfosL2TPConfiguration -L2TPGeneralSettings Enable @conn -Confirm:$false } |
                Should -Throw '*StartIP, EndIP and PrimaryDNSServer*'
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
        }

        It 'succeeds and builds the AssignIPFrom wrapper when all three are supplied' {
            Set-SfosL2TPConfiguration -StartIP '203.0.113.10' -EndIP '203.0.113.20' -PrimaryDNSServer '203.0.113.1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<L2TPConfiguration>\s*<L2TPSettings>' -and
                $InnerXml -match '<AssignIPFrom>\s*<StartIP>203\.0\.113\.10</StartIP>\s*<EndIP>203\.0\.113\.20</EndIP>' -and
                $InnerXml -match '<PrimaryDNSServer>203\.0\.113\.1</PrimaryDNSServer>'
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

    Context 'Set-SfosVPNProfile' {
        BeforeEach {
            # Real captured "Default Profile" shape (scratchpad/vpn-live/VPNProfile.xml)
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNProfile><Name>ZZRmwProfile</Name><Description>original</Description><KeyingMethod>Automatic</KeyingMethod><AllowReKeying>Enable</AllowReKeying><KeyNegotiationTries>0</KeyNegotiationTries><AuthenticationMode>MainMode</AuthenticationMode><PassDataInCompressedFormat>Disable</PassDataInCompressedFormat><UseStrictProfile>Disable</UseStrictProfile><Phase1><EncryptionAlgorithm1>AES256</EncryptionAlgorithm1><AuthenticationAlgorithm1>SHA2_256</AuthenticationAlgorithm1><SupportedDHGroups><DHGroup>14(DH2048)</DHGroup><DHGroup>16(DH4096)</DHGroup></SupportedDHGroups><KeyLife>3600</KeyLife><ReKeyMargin>120</ReKeyMargin><RandomizeRe-KeyingMarginBy>100</RandomizeRe-KeyingMarginBy><DeadPeerDetection>Enable</DeadPeerDetection><CheckPeerAfterEvery>30</CheckPeerAfterEvery><WaitForResponseUpto>120</WaitForResponseUpto><ActionWhenPeerUnreachable>Disconnect</ActionWhenPeerUnreachable></Phase1><Phase2><EncryptionAlgorithm1>AES256</EncryptionAlgorithm1><AuthenticationAlgorithm1>SHA2_256</AuthenticationAlgorithm1><PFSGroup>SameasPhase-I</PFSGroup><KeyLife>3600</KeyLife></Phase2><sha2_96_truncate>no</sha2_96_truncate><keyexchange>ikev1</keyexchange></VPNProfile></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VPNProfile><Status code="200">Configuration applied successfully.</Status></VPNProfile></Response>' }
                }
            }
        }

        It 'preserves Phase1/Phase2 (including DHGroupList) and keyexchange when only Description changes' {
            Set-SfosVPNProfile -Name 'ZZRmwProfile' -Description 'updated' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>updated</Description>' -and
                $InnerXml -match '<SupportedDHGroups><DHGroup>14\(DH2048\)</DHGroup><DHGroup>16\(DH4096\)</DHGroup></SupportedDHGroups>' -and
                $InnerXml -match '<EncryptionAlgorithm1>AES256</EncryptionAlgorithm1>' -and
                $InnerXml -match '<PFSGroup>SameasPhase-I</PFSGroup>' -and
                $InnerXml -match '<keyexchange>ikev1</keyexchange>'
            }
        }
    }

    Context 'Set-SfosIPsecConnection' {
        BeforeEach {
            # Real captured shape (scratchpad/vpn-live), PresharedKey-authenticated route-based
            # tunnel: SubnetFamily Dual, LocalWANPort/AliasLocalWANPort both Port2, Protocol ALL.
            # Every call's InnerXml is also collected into $script:ipsecCalls, because
            # Should -Invoke -ParameterFilter against a multi-line, multi-call InnerXml has
            # proven flaky under this Pester version/module-boundary combination in this suite -
            # collecting and asserting on the plain array sidesteps that.
            $script:ipsecCalls = New-Object System.Collections.Generic.List[string]
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                $script:ipsecCalls.Add($InnerXml)
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Name>ZZRmwIPsec</Name><Description>original</Description><ConnectionType>TunnelInterface</ConnectionType><Policy>Head office (IKEv2)</Policy><ActionOnVPNRestart>RespondOnly</ActionOnVPNRestart><AuthenticationType>PresharedKey</AuthenticationType><SubnetFamily>Dual</SubnetFamily><EndpointFamily>IPv4</EndpointFamily><AliasLocalWANPort>Port2</AliasLocalWANPort><RemoteHost>198.51.100.10</RemoteHost><LocalIDType>IP Address</LocalIDType><LocalID>198.51.100.1</LocalID><RemoteIDType>IP Address</RemoteIDType><RemoteID>198.51.100.10</RemoteID><UserAuthenticationMode>Disable</UserAuthenticationMode><Protocol>ALL</Protocol><LocalPort>*</LocalPort><RemotePort>*</RemotePort><LocalWANPort>Port2</LocalWANPort><Status>Active</Status><PresharedKey hashform="mode1">$sfos$7$0$deadbeef</PresharedKey></Configuration></VPNIPSecConnection></Response>' }
                }
                elseif ($InnerXml -match '<Active>|<DeActive>') {
                    $tag = if ($InnerXml -match '<Active>') { 'Active' } else { 'DeActive' }
                    $toggleContent = '<Response><Login><status>Authentication Successful</status></Login><' + $tag + '><Status code="200">Configuration applied successfully.</Status></' + $tag + '></Response>'
                    [PSCustomObject]@{ Content = $toggleContent }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Configuration><Status code="200">Configuration applied successfully.</Status></Configuration></Response>' }
                }
            }
        }

        It 'preserves LocalWANPort, SubnetFamily, Protocol, UserAuthenticationMode and the hashed PresharedKey when only Description changes' {
            Set-SfosIPsecConnection -Name 'ZZRmwIPsec' -Description 'updated' @conn -Confirm:$false

            $setCall = $script:ipsecCalls | Where-Object { $_ -match '<Set operation="update">' }
            $setCall | Should -Not -BeNullOrEmpty
            $setCall | Should -Match '<Description>updated</Description>'
            $setCall | Should -Match '<LocalWANPort>Port2</LocalWANPort>'
            $setCall | Should -Match '<SubnetFamily>Dual</SubnetFamily>'
            $setCall | Should -Match '<Protocol>ALL</Protocol>'
            $setCall | Should -Match '<UserAuthenticationMode>Disable</UserAuthenticationMode>'
            $setCall | Should -Match '<PresharedKey hashform="mode1">\$sfos\$7\$0\$deadbeef</PresharedKey>'
        }

        It 'does not send the Active/DeActive toggle when -Status is not specified' {
            Set-SfosIPsecConnection -Name 'ZZRmwIPsec' -Description 'updated' @conn -Confirm:$false

            $script:ipsecCalls.Count | Should -Be 2
            ($script:ipsecCalls | Where-Object { $_ -match '<Active>|<DeActive>' }).Count | Should -Be 0
        }

        It 'sends a separate Active toggle request when -Status Active is specified' {
            Set-SfosIPsecConnection -Name 'ZZRmwIPsec' -Status Active @conn -Confirm:$false

            $script:ipsecCalls.Count | Should -Be 3
            $toggleCall = $script:ipsecCalls[2]
            $toggleCall | Should -Match '<Set operation="update">'
            $toggleCall | Should -Match '<Active><Name>ZZRmwIPsec</Name></Active>'
            $toggleCall | Should -Not -Match '<Configuration>'
        }

        It 'sends a separate DeActive toggle request when -Status Deactive is specified' {
            Set-SfosIPsecConnection -Name 'ZZRmwIPsec' -Status Deactive @conn -Confirm:$false

            $script:ipsecCalls.Count | Should -Be 3
            $toggleCall = $script:ipsecCalls[2]
            $toggleCall | Should -Match '<Set operation="update">'
            $toggleCall | Should -Match '<DeActive><Name>ZZRmwIPsec</Name></DeActive>'
            $toggleCall | Should -Not -Match '<Configuration>'
        }

        It 'accepts SubnetFamily Dual as an override' {
            (Get-Command Set-SfosIPsecConnection).Parameters['SubnetFamily'].Attributes.ValidValues | Should -Contain 'Dual'
        }

        It 'throws client-side, without calling the API, when Name contains a hyphen' {
            { Set-SfosIPsecConnection -Name 'ZZ-Hyphen' -Description 'x' @conn -Confirm:$false } |
                Should -Throw '*hyphen*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0
        }
    }

    Context 'Set-SfosSSLBookmark' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZRmwBookmark</Name><Description>original</Description><Type>RDP</Type><URL>rdp.example</URL><ShareSession>Disable</ShareSession><AutoLogin>Enable</AutoLogin><UserName>rdpuser</UserName><Password hashform="mode1">$sfos$7$0$deadbeef</Password><Port>3389</Port></SSLBookmark></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmark><Status code="200">Configuration applied successfully.</Status></SSLBookmark></Response>' }
                }
            }
        }

        It 'preserves Type, URL, UserName and Port when only Description changes' {
            Set-SfosSSLBookmark -Name 'ZZRmwBookmark' -Description 'updated' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>updated</Description>' -and
                $InnerXml -match '<Type>RDP</Type>' -and
                $InnerXml -match '<URL>rdp\.example</URL>' -and
                $InnerXml -match '<UserName>rdpuser</UserName>' -and
                $InnerXml -match '<Port>3389</Port>'
            }
        }
    }

    Context 'Set-SfosSSLTunnelAccessSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLTunnelAccessSettings><Protocol>TCP</Protocol><SSLServerCertificate>ApplianceCertificate</SSLServerCertificate><OverrideHostName/><Port>8443</Port><IPLeaseRange><StartIP>10.81.0.0</StartIP></IPLeaseRange><SubnetMask>255.255.0.0</SubnetMask><IPv6Lease>2001:db8::1:0</IPv6Lease><IPv6Prefix>64</IPv6Prefix><LeaseMode>IPv4</LeaseMode><PrimaryDNSIPv4/><SecondaryDNSIPv4/><PrimaryWINSIPv4/><SecondaryWINSIPv4/><DomainName/><DisconnectDeadPeerAfter>180</DisconnectDeadPeerAfter><DisconnectIdlePeerAfter>15</DisconnectIdlePeerAfter><EncryptionAlgorithm>AES-128-CBC</EncryptionAlgorithm><AuthenticationAlgorithm>SHA256</AuthenticationAlgorithm><Keysize>2048bit</Keysize><KeyLifetime>28800</KeyLifetime><DebugMode>Disable</DebugMode><SecurityHeartbeat>Disable</SecurityHeartbeat><SaveCredential>Disable</SaveCredential><TwoFAToken>Disable</TwoFAToken><AdLogon>Disable</AdLogon><AutoConnect>Disable</AutoConnect><HostorDNSName/><StaticIPAddresses>Disable</StaticIPAddresses></SSLTunnelAccessSettings></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLTunnelAccessSettings><Status code="200">Configuration applied successfully.</Status></SSLTunnelAccessSettings></Response>' }
                }
            }
        }

        It 'preserves every other field (SSLServerCertificate, EncryptionAlgorithm, Keysize, ...) when only DebugMode changes' {
            Set-SfosSSLTunnelAccessSettings -DebugMode Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<DebugMode>Enable</DebugMode>' -and
                $InnerXml -match '<SSLServerCertificate>ApplianceCertificate</SSLServerCertificate>' -and
                $InnerXml -match '<Port>8443</Port>' -and
                $InnerXml -match '<StartIP>10\.81\.0\.0</StartIP>' -and
                $InnerXml -match '<EncryptionAlgorithm>AES-128-CBC</EncryptionAlgorithm>' -and
                $InnerXml -match '<Keysize>2048bit</Keysize>' -and
                $InnerXml -match '<SaveCredential>Disable</SaveCredential>'
            }
        }

        It 'does not send a CompressSSLVPNTraffic element (Get never returns it, so it cannot be preserved)' {
            (Get-Command Set-SfosSSLTunnelAccessSettings).Parameters.Keys | Should -Not -Contain 'CompressSSLVPNTraffic'

            Set-SfosSSLTunnelAccessSettings -DebugMode Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and $InnerXml -notmatch 'CompressSSLVPNTraffic'
            }
        }
    }

    Context 'Set-SfosL2TPConfiguration' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConfiguration><L2TPSettings><L2TPGeneralSettings>Disable</L2TPGeneralSettings><AssignIPFrom><StartIP>203.0.113.10</StartIP><EndIP>203.0.113.20</EndIP></AssignIPFrom><LeaseIPFromRadiusServer>Disable</LeaseIPFromRadiusServer><PrimaryDNSServer>203.0.113.1</PrimaryDNSServer><PrimaryWINSServer>203.0.113.5</PrimaryWINSServer></L2TPSettings></L2TPConfiguration></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><L2TPSettings><Status code="200">Configuration applied successfully.</Status></L2TPSettings></Response>' }
                }
            }
        }

        It 'preserves StartIP, EndIP, PrimaryDNSServer and PrimaryWINSServer when only L2TPGeneralSettings changes' {
            Set-SfosL2TPConfiguration -L2TPGeneralSettings Enable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<L2TPGeneralSettings>Enable</L2TPGeneralSettings>' -and
                $InnerXml -match '<StartIP>203\.0\.113\.10</StartIP>' -and
                $InnerXml -match '<EndIP>203\.0\.113\.20</EndIP>' -and
                $InnerXml -match '<PrimaryDNSServer>203\.0\.113\.1</PrimaryDNSServer>' -and
                $InnerXml -match '<PrimaryWINSServer>203\.0\.113\.5</PrimaryWINSServer>'
            }
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

    Context 'SSLBookmark.Password - hashed on Get, must not collapse to "System.Xml.XmlElement"' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZHashBookmark</Name><Description></Description><Type>RDP</Type><URL>rdp.example</URL><ShareSession>Disable</ShareSession><AutoLogin>Enable</AutoLogin><UserName>rdpuser</UserName><Password hashform="mode1">$sfos$7$0$deadbeef</Password><Port>3389</Port></SSLBookmark></Response>' }
            }
        }

        It 'maps the hashed Password element (hashform attribute) to PasswordHash/PasswordHashForm, not the element object' {
            $result = Get-SfosSSLBookmark @conn | Select-Object -First 1

            $result.PasswordHash | Should -Be '$sfos$7$0$deadbeef'
            $result.PasswordHashForm | Should -Be 'mode1'
            # Regression: a naive [string]$node.Password on an element that carries the
            # hashform attribute yields the literal CLR type name below instead of the hash.
            $result.PasswordHash | Should -Not -Be 'System.Xml.XmlElement'
        }
    }

    Context 'Set-SfosSSLBookmark - Password round trip' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZPwBookmark</Name><Description></Description><Type>RDP</Type><URL>rdp.example</URL><ShareSession>Disable</ShareSession><AutoLogin>Enable</AutoLogin><UserName>rdpuser</UserName><Password hashform="mode1">$sfos$7$0$deadbeef</Password><Port>3389</Port></SSLBookmark></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmark><Status code="200">Configuration applied successfully.</Status></SSLBookmark></Response>' }
                }
            }
        }

        It 'without -SecurePassword: resends the hash together with its hashform attribute' {
            Set-SfosSSLBookmark -Name 'ZZPwBookmark' -Description 'x' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Password hashform="mode1">\$sfos\$7\$0\$deadbeef</Password>'
            }
        }

        It 'with -SecurePassword: sends a blank, un-hashed Password element' {
            $sec = ConvertTo-SecureString 'NewPlainSecret1' -AsPlainText -Force
            Set-SfosSSLBookmark -Name 'ZZPwBookmark' -SecurePassword $sec @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Password>NewPlainSecret1</Password>' -and
                $InnerXml -notmatch 'hashform'
            }
        }
    }

    Context 'Remove-SfosSSLBookmark - confirmed firmware no-op, reads back and throws if still present' {
        It 'throws when the object is still present after a reported-successful Remove' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmark><Status code="200">Configuration applied successfully.</Status></SSLBookmark></Response>' }
                }
                else {
                    # Still there before AND after the (falsely successful) Remove.
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZStuckBookmark</Name><Description></Description><Type>HTTP</Type><URL>x</URL><ShareSession>Disable</ShareSession><AutoLogin>Disable</AutoLogin></SSLBookmark></Response>' }
                }
            }

            { Remove-SfosSSLBookmark -Name 'ZZStuckBookmark' @conn -Confirm:$false } |
                Should -Throw '*still present*'
        }

        It 'does not throw when the object is genuinely gone after Remove' {
            $script:removed = $false
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    $script:removed = $true
                    return [PSCustomObject]@{ Content = '<Response><SSLBookmark><Status code="200">Configuration applied successfully.</Status></SSLBookmark></Response>' }
                }
                if ($script:removed) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Status>No. of records Zero.</Status></SSLBookmark></Response>' }
                }
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZGoneBookmark</Name><Description></Description><Type>HTTP</Type><URL>x</URL><ShareSession>Disable</ShareSession><AutoLogin>Disable</AutoLogin></SSLBookmark></Response>' }
            }

            { Remove-SfosSSLBookmark -Name 'ZZGoneBookmark' @conn -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Remove-SfosSSLVPNPolicy - nested Remove shape and status path' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNPolicy><TunnelPolicy><Status code="200">Configuration applied successfully.</Status></TunnelPolicy></SSLVPNPolicy></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><TunnelPolicy><Name>ZZRemovePolicy</Name><Description></Description><PolicyMembers></PolicyMembers><UseAsDefaultGateway>Off</UseAsDefaultGateway></TunnelPolicy></SSLVPNPolicy></Response>' }
                }
            }
        }

        It 'sends the nested Remove/SSLVPNPolicy/TunnelPolicy/Name shape, not a flat Remove/SSLVPNPolicy' {
            Remove-SfosSSLVPNPolicy -Name 'ZZRemovePolicy' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SSLVPNPolicy><TunnelPolicy><Name>ZZRemovePolicy</Name></TunnelPolicy></SSLVPNPolicy></Remove>'
            }
        }

        It 'uses ClientlessPolicy nesting for a Clientless policy' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNPolicy><ClientlessPolicy><Status code="200">Configuration applied successfully.</Status></ClientlessPolicy></SSLVPNPolicy></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><ClientlessPolicy><Name>ZZRemoveClientless</Name><Description></Description><PolicyMembers></PolicyMembers><RestrictWebApplications>Disable</RestrictWebApplications></ClientlessPolicy></SSLVPNPolicy></Response>' }
                }
            }

            Remove-SfosSSLVPNPolicy -Name 'ZZRemoveClientless' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SSLVPNPolicy><ClientlessPolicy><Name>ZZRemoveClientless</Name></ClientlessPolicy></SSLVPNPolicy></Remove>'
            }
        }
    }

    Context 'Remove-SfosIPsecConnection - nested Remove/Configuration shape, reads back and throws if still present' {
        It 'sends the nested Remove/VPNIPSecConnection/Configuration/Name shape, not a flat Remove/VPNIPSecConnection' {
            # First Get (existence pre-check) must still find the object, so answer it once
            # with a real object and every later Get with "gone" - matches the cmdlet's own
            # read-first-then-read-back-after design.
            $script:callCount = 0
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                $script:callCount++
                if ($InnerXml -match '<Remove>') {
                    return [PSCustomObject]@{ Content = '<Response><Configuration><Status code="200">Configuration applied successfully.</Status></Configuration></Response>' }
                }
                if ($script:callCount -eq 1) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Name>ZZRemoveIPsec</Name><ConnectionType>TunnelInterface</ConnectionType></Configuration></VPNIPSecConnection></Response>' }
                }
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Status>No. of records Zero.</Status></Configuration></VPNIPSecConnection></Response>' }
            }

            Remove-SfosIPsecConnection -Name 'ZZRemoveIPsec' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<VPNIPSecConnection>\s*<Configuration>\s*<Name>ZZRemoveIPsec</Name>\s*</Configuration>\s*</VPNIPSecConnection>'
            }
        }

        It 'throws when the object is still present after a reported-successful Remove' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><Configuration><Status code="200">Configuration applied successfully.</Status></Configuration></Response>' }
                }
                else {
                    # Still there before AND after the (falsely successful) Remove.
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Name>ZZStuckIPsec</Name><ConnectionType>TunnelInterface</ConnectionType></Configuration></VPNIPSecConnection></Response>' }
                }
            }

            { Remove-SfosIPsecConnection -Name 'ZZStuckIPsec' @conn -Confirm:$false } |
                Should -Throw '*still present*'
        }
    }

    Context 'New-SfosSSLVPNPolicy - documented UserGroup write-back warning' {
        It 'the comment-based help documents that -Member writes back onto the referenced UserGroup' {
            $help = Get-Help New-SfosSSLVPNPolicy -Full
            $helpText = ($help.description | Out-String) + ($help.parameters.parameter | Where-Object { $_.name -eq 'Member' } | Select-Object -ExpandProperty description | Out-String)

            $helpText | Should -Match 'writ(ten|es) back'
            $helpText | Should -Match 'UserGroup'
        }
    }

    Context 'SecureString parameter binding - -WhatIf does not throw' {
        It 'ConnectionPassword (New-SfosIPsecConnection) binds as SecureString' {
            (Get-Command New-SfosIPsecConnection).Parameters['ConnectionPassword'].ParameterType.Name | Should -Be 'SecureString'
            $sec = ConvertTo-SecureString 'x' -AsPlainText -Force
            {
                New-SfosIPsecConnection -Name 'ZZWI' -ConnectionType SiteToSite -LocalIDType 'IP Address' -LocalID '1.1.1.1' `
                    -RemoteIDType 'IP Address' -RemoteID '2.2.2.2' -LocalSubnet 'Net' -AliasLocalWANPort 'Port1' `
                    -ConnectionPassword $sec @conn -WhatIf
            } | Should -Not -Throw
        }

        It 'SecurePassword (New-SfosSSLBookmark) binds as SecureString' {
            (Get-Command New-SfosSSLBookmark).Parameters['SecurePassword'].ParameterType.Name | Should -Be 'SecureString'
            $sec = ConvertTo-SecureString 'x' -AsPlainText -Force
            { New-SfosSSLBookmark -Name 'ZZWI' -Type HTTP -URL 'x' -SecurePassword $sec @conn -WhatIf } | Should -Not -Throw
        }

        It 'FilePassword and ProxySecurePassword (New-SfosSiteToSiteClient) bind as SecureString' {
            (Get-Command New-SfosSiteToSiteClient).Parameters['FilePassword'].ParameterType.Name | Should -Be 'SecureString'
            (Get-Command New-SfosSiteToSiteClient).Parameters['ProxySecurePassword'].ParameterType.Name | Should -Be 'SecureString'
            $sec = ConvertTo-SecureString 'x' -AsPlainText -Force
            {
                New-SfosSiteToSiteClient -Name 'ZZWI' -ServerConfigurationFile 'x' -FilePassword $sec `
                    -ProxyAuthentication Enable -ProxyUsername 'u' -ProxySecurePassword $sec @conn -WhatIf
            } | Should -Not -Throw
        }

        It 'PresharedKey binds as SecureString on New-SfosIPsecConnection, New-SfosL2TPConnection and Set-SfosL2TPConnection' {
            (Get-Command New-SfosIPsecConnection).Parameters['PresharedKey'].ParameterType.Name | Should -Be 'SecureString'
            (Get-Command New-SfosL2TPConnection).Parameters['PresharedKey'].ParameterType.Name | Should -Be 'SecureString'
            (Get-Command Set-SfosL2TPConnection).Parameters['PresharedKey'].ParameterType.Name | Should -Be 'SecureString'

            $psk = ConvertTo-SecureString 'plain' -AsPlainText -Force
            {
                New-SfosL2TPConnection -Name 'ZZWI' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey `
                    -PresharedKey $psk -AliasLocalWANPort 'Port2' -LocalID '1.1.1.1' -RemoteHost '2.2.2.2' `
                    -RemoteLANNetwork 'Net' -RemoteID '2.2.2.2' -LocalPort 1701 -RemotePort '*' @conn -WhatIf
            } | Should -Not -Throw
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNProfile><Status code="529">Invalid XML request</Status></VPNProfile></Response>' }
        }

        { Get-SfosVPNProfile @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosVPNProfile @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Status>No. of records Zero.</Status></SSLBookmark></Response>' }
        }

        $result = @(Get-SfosSSLBookmark @conn)
        $result.Count | Should -Be 0
    }

    It 'a code-less "Transaction fail" status throws instead of being read as an empty result' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Status>Transaction fail</Status></SSLBookmark></Response>' }
        }

        { Get-SfosSSLBookmark @conn } | Should -Throw '*status without a code*'
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
        # Defined in BeforeAll, not as a bare Describe-body statement: a plain assignment in
        # the Describe body only exists during Pester's Discovery phase and is $null again by
        # the time the It blocks actually run, which turned every -ParameterFilter below into
        # a binding error against a null ScriptBlock.
        $writeFilter = { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
        $psk = ConvertTo-SecureString 'x' -AsPlainText -Force
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
            if ($InnerXml -notmatch '<Get>') {
                return [PSCustomObject]@{ Content = '<Response><Status code="200">Configuration applied successfully.</Status></Response>' }
            }
            if ($InnerXml -match '<VPNIPSecConnection>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Name>ZZWIIPsec</Name><Description></Description><ConnectionType>SiteToSite</ConnectionType><Status>Deactive</Status></Configuration></VPNIPSecConnection></Response>' }
            }
            if ($InnerXml -match '<VPNProfile>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNProfile><Name>ZZWIProfile</Name><Description></Description><KeyingMethod>Automatic</KeyingMethod><AllowReKeying>Enable</AllowReKeying><KeyNegotiationTries>0</KeyNegotiationTries><AuthenticationMode>MainMode</AuthenticationMode><PassDataInCompressedFormat>Disable</PassDataInCompressedFormat><UseStrictProfile>Disable</UseStrictProfile><Phase1><EncryptionAlgorithm1>AES256</EncryptionAlgorithm1><AuthenticationAlgorithm1>SHA2_256</AuthenticationAlgorithm1><SupportedDHGroups><DHGroup>14(DH2048)</DHGroup></SupportedDHGroups><KeyLife>3600</KeyLife><ReKeyMargin>120</ReKeyMargin><RandomizeRe-KeyingMarginBy>100</RandomizeRe-KeyingMarginBy><DeadPeerDetection>Enable</DeadPeerDetection><CheckPeerAfterEvery>30</CheckPeerAfterEvery><WaitForResponseUpto>120</WaitForResponseUpto><ActionWhenPeerUnreachable>Disconnect</ActionWhenPeerUnreachable></Phase1><Phase2><EncryptionAlgorithm1>AES256</EncryptionAlgorithm1><AuthenticationAlgorithm1>SHA2_256</AuthenticationAlgorithm1><PFSGroup>SameasPhase-I</PFSGroup><KeyLife>3600</KeyLife></Phase2><keyexchange>ikev1</keyexchange></VPNProfile></Response>' }
            }
            if ($InnerXml -match '<VPNFailoverGroup>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZWIFailover</Name><MemberConnections><Connection>ZZWIIPsec</Connection></MemberConnections><MailNotification>Disable</MailNotification></GroupDetail></VPNFailoverGroup></Response>' }
            }
            if ($InnerXml -match '<SSLVPNPolicy>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><TunnelPolicy><Name>ZZWIPolicy</Name><Description></Description><PolicyMembers></PolicyMembers><UseAsDefaultGateway>Off</UseAsDefaultGateway></TunnelPolicy></SSLVPNPolicy></Response>' }
            }
            if ($InnerXml -match '<SSLBookmarkGroup>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Name>ZZWIBookmarkGroup</Name><Description></Description><BookmarkList><Bookmark>ZZWIBookmark</Bookmark></BookmarkList></SSLBookmarkGroup></Response>' }
            }
            if ($InnerXml -match '<SSLBookmark>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZWIBookmark</Name><Description></Description><Type>HTTP</Type><URL>x</URL><ShareSession>Disable</ShareSession><AutoLogin>Disable</AutoLogin></SSLBookmark></Response>' }
            }
            if ($InnerXml -match '<SiteToSiteClient>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteClient><Name>ZZWIS2SClient</Name><Description></Description><HttpProxyServer>Disable</HttpProxyServer><ProxyAuthentication>Disable</ProxyAuthentication><PeerHost>Disable</PeerHost></SiteToSiteClient></Response>' }
            }
            if ($InnerXml -match '<SiteToSiteServer>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteServer><Name>ZZWIS2SServer</Name><Description></Description><StaticIP>Disable</StaticIP><LocalNetworks><Network>Net1</Network></LocalNetworks><RemoteNetworks><Network>Net2</Network></RemoteNetworks></SiteToSiteServer></Response>' }
            }
            if ($InnerXml -match '<L2TPConfiguration>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConfiguration><L2TPSettings><L2TPGeneralSettings>Disable</L2TPGeneralSettings><AssignIPFrom><StartIP>203.0.113.10</StartIP><EndIP>203.0.113.20</EndIP></AssignIPFrom><LeaseIPFromRadiusServer>Disable</LeaseIPFromRadiusServer><PrimaryDNSServer>203.0.113.1</PrimaryDNSServer></L2TPSettings></L2TPConfiguration></Response>' }
            }
            if ($InnerXml -match '<L2TPConnection>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConnection><Configuration><Name>ZZWIL2TPConn</Name><Description></Description><ActionOnVPNRestart>Disable</ActionOnVPNRestart><AuthenticationType>PresharedKey</AuthenticationType><AliasLocalWANPort>Port2</AliasLocalWANPort><LocalID>1.1.1.1</LocalID><RemoteHost>2.2.2.2</RemoteHost><AllowNATTraversal>Enable</AllowNATTraversal><RemoteID>2.2.2.2</RemoteID><LocalPort>1701</LocalPort><RemotePort>*</RemotePort></Configuration></L2TPConnection></Response>' }
            }
            if ($InnerXml -match '<PPTPConfiguration>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><PPTPConfiguration><PPTPSettings><PPTPGeneralSettings>Disable</PPTPGeneralSettings><AssignIPFrom><StartIP>203.0.113.30</StartIP><EndIP>203.0.113.40</EndIP></AssignIPFrom><LeaseIPFromRadiusServer>Disable</LeaseIPFromRadiusServer><PrimaryDNSServer>203.0.113.1</PrimaryDNSServer></PPTPSettings></PPTPConfiguration></Response>' }
            }
            if ($InnerXml -match '<SSLTunnelAccessSettings>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLTunnelAccessSettings><Protocol>TCP</Protocol><Port>8443</Port><IPLeaseRange><StartIP>10.81.0.0</StartIP></IPLeaseRange></SSLTunnelAccessSettings></Response>' }
            }
            return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    # New-* (9) - none of these pre-check via Get, so -WhatIf prevents any Invoke-SfosApi call.
    It 'New-SfosIPsecConnection sends no write request under -WhatIf' {
        New-SfosIPsecConnection -Name 'ZZWIIPsec' -ConnectionType SiteToSite -LocalIDType 'IP Address' -LocalID '1.1.1.1' -RemoteIDType 'IP Address' -RemoteID '2.2.2.2' -LocalSubnet 'Net' -AliasLocalWANPort 'Port1' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosVPNProfile sends no write request under -WhatIf' {
        New-SfosVPNProfile -Name 'ZZWIProfile' -AuthenticationMode MainMode -Phase1EncryptionAlgorithm1 AES256 -Phase1AuthenticationAlgorithm1 SHA2_256 -Phase1KeyLife 3600 -Phase1ReKeyMargin 120 -Phase1RandomizeReKeyingMarginBy 100 -Phase2EncryptionAlgorithm1 AES256 -Phase2AuthenticationAlgorithm1 SHA2_256 -Phase2KeyLife 3600 -SupportedDHGroup '14(DH2048)' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosVPNFailoverGroup sends no write request under -WhatIf' {
        New-SfosVPNFailoverGroup -Name 'ZZWIFailover' -Connection 'ZZWIIPsec' -MailNotification Disable @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosSSLVPNPolicy sends no write request under -WhatIf' {
        New-SfosSSLVPNPolicy -Name 'ZZWIPolicy' -PolicyType Tunnel @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosSSLBookmark sends no write request under -WhatIf' {
        New-SfosSSLBookmark -Name 'ZZWIBookmark' -Type HTTP -URL 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosSSLBookmarkGroup sends no write request under -WhatIf' {
        New-SfosSSLBookmarkGroup -Name 'ZZWIBookmarkGroup' -Bookmark 'ZZWIBookmark' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosSiteToSiteClient sends no write request under -WhatIf' {
        New-SfosSiteToSiteClient -Name 'ZZWIS2SClient' -ServerConfigurationFile 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosSiteToSiteServer sends no write request under -WhatIf' {
        New-SfosSiteToSiteServer -Name 'ZZWIS2SServer' -LocalNetworks 'Net1' -RemoteNetworks 'Net2' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'New-SfosL2TPConnection sends no write request under -WhatIf' {
        New-SfosL2TPConnection -Name 'ZZWIL2TPConn' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey -PresharedKey $psk -AliasLocalWANPort 'Port2' -LocalID '1.1.1.1' -RemoteHost '2.2.2.2' -RemoteLANNetwork 'Net' -RemoteID '2.2.2.2' -LocalPort 1701 -RemotePort '*' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }

    # Set-* (12)
    It 'Set-SfosIPsecConnection sends no write request under -WhatIf' {
        Set-SfosIPsecConnection -Name 'ZZWIIPsec' -Status Active @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosVPNProfile sends no write request under -WhatIf' {
        Set-SfosVPNProfile -Name 'ZZWIProfile' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosVPNFailoverGroup sends no write request under -WhatIf' {
        Set-SfosVPNFailoverGroup -Name 'ZZWIFailover' -MailNotification Enable @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosSSLTunnelAccessSettings sends no write request under -WhatIf' {
        Set-SfosSSLTunnelAccessSettings -DebugMode Enable @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosSSLVPNPolicy sends no write request under -WhatIf' {
        Set-SfosSSLVPNPolicy -Name 'ZZWIPolicy' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosSSLBookmark sends no write request under -WhatIf' {
        Set-SfosSSLBookmark -Name 'ZZWIBookmark' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosSSLBookmarkGroup sends no write request under -WhatIf' {
        Set-SfosSSLBookmarkGroup -Name 'ZZWIBookmarkGroup' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosSiteToSiteClient sends no write request under -WhatIf' {
        Set-SfosSiteToSiteClient -Name 'ZZWIS2SClient' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosSiteToSiteServer sends no write request under -WhatIf' {
        Set-SfosSiteToSiteServer -Name 'ZZWIS2SServer' -Description 'x' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosL2TPConfiguration sends no write request under -WhatIf' {
        Set-SfosL2TPConfiguration -L2TPGeneralSettings Enable @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosL2TPConnection sends no write request under -WhatIf' {
        Set-SfosL2TPConnection -Name 'ZZWIL2TPConn' -AuthenticationType PresharedKey -PresharedKey $psk @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Set-SfosPPTPConfiguration sends no write request under -WhatIf' {
        Set-SfosPPTPConfiguration -PPTPGeneralSettings Enable @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }

    # Remove-* (13)
    It 'Remove-SfosIPsecConnection sends no write request under -WhatIf' {
        Remove-SfosIPsecConnection -Name 'ZZWIIPsec' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosVPNProfile sends no write request under -WhatIf' {
        Remove-SfosVPNProfile -Name 'ZZWIProfile' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosVPNFailoverGroup sends no write request under -WhatIf' {
        Remove-SfosVPNFailoverGroup -Name 'ZZWIFailover' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosVPNFailoverGroupMember sends no write request under -WhatIf' {
        Remove-SfosVPNFailoverGroupMember -Name 'ZZWIFailover' -Connection 'ZZOther' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosSSLVPNPolicy sends no write request under -WhatIf' {
        Remove-SfosSSLVPNPolicy -Name 'ZZWIPolicy' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosSSLBookmark sends no write request under -WhatIf' {
        Remove-SfosSSLBookmark -Name 'ZZWIBookmark' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosSSLBookmarkGroup sends no write request under -WhatIf' {
        Remove-SfosSSLBookmarkGroup -Name 'ZZWIBookmarkGroup' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosSSLBookmarkGroupMember sends no write request under -WhatIf' {
        Remove-SfosSSLBookmarkGroupMember -GroupName 'ZZWIBookmarkGroup' -Bookmark 'ZZWIBookmark' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosSiteToSiteClient sends no write request under -WhatIf' {
        Remove-SfosSiteToSiteClient -Name 'ZZWIS2SClient' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosSiteToSiteServer sends no write request under -WhatIf' {
        Remove-SfosSiteToSiteServer -Name 'ZZWIS2SServer' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosL2TPConfigurationMember sends no write request under -WhatIf' {
        Remove-SfosL2TPConfigurationMember -MemberName 'ZZUser' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosL2TPConnection sends no write request under -WhatIf' {
        Remove-SfosL2TPConnection -Name 'ZZWIL2TPConn' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Remove-SfosPPTPConfigurationMember sends no write request under -WhatIf' {
        Remove-SfosPPTPConfigurationMember -MemberName 'ZZUser' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }

    # Add-* member cmdlets (4)
    It 'Add-SfosL2TPConfigurationMember sends no write request under -WhatIf' {
        Add-SfosL2TPConfigurationMember -MemberName 'ZZUser' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Add-SfosPPTPConfigurationMember sends no write request under -WhatIf' {
        Add-SfosPPTPConfigurationMember -MemberName 'ZZUser' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Add-SfosSSLBookmarkGroupMember sends no write request under -WhatIf' {
        Add-SfosSSLBookmarkGroupMember -GroupName 'ZZWIBookmarkGroup' -Bookmark 'ZZOtherBookmark' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
    It 'Add-SfosVPNFailoverGroupMember sends no write request under -WhatIf' {
        Add-SfosVPNFailoverGroupMember -Name 'ZZWIFailover' -Connection 'ZZOtherConn' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 0 -Exactly -ParameterFilter $writeFilter
    }
}

Describe 'Additional coverage (2026-08-12 test-ausbau) - functions without a prior XML-generation or error-path test' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-/Set-/Remove-SfosL2TPConnection - fail-open regression fix (2026-08-12)' {
        # Measured 2026-08-12: the firewall reports a create/update failure for this entity
        # FLAT at Response/Configuration/Status, with no L2TPConnection wrapper at all - unlike
        # every other write on this entity's own Get/Remove, which nest one level deeper.
        # Before the fix, New-/Set-SfosL2TPConnection called Assert-SfosApiReturnSuccess with
        # -ObjectName 'L2TPConnection/Configuration'; against this exact response that XPath
        # finds zero status nodes, which the "no status at all" rule reads as an empty result,
        # i.e. success - so the cmdlet reported success while creating/updating nothing. The
        # fix uses the flat -ObjectName 'Configuration' for New-/Set-, matching what the wire
        # actually returns.
        BeforeAll {
            # A bare assignment in the Context body only lives through Pester's Discovery
            # phase and is $null again once the It blocks run - the same trap the
            # 'ShouldProcess' Describe block above documents for $writeFilter. BeforeAll is
            # required here, not a Context-level statement.
            $psk = ConvertTo-SecureString 'L2TPFailOpenSecret1' -AsPlainText -Force
        }

        It 'New-SfosL2TPConnection throws on the measured flat Response/Configuration/Status path (no L2TPConnection wrapper)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Configuration><Status code="501">Operation could not be performed on Entity.</Status></Configuration></Response>' }
            }

            { New-SfosL2TPConnection -Name 'ZZFailOpenL2TP' -ActionOnVPNRestart Disable -AuthenticationType PresharedKey `
                    -PresharedKey $psk -AliasLocalWANPort 'Port2' -LocalID '198.51.100.1' -RemoteHost '198.51.100.2' `
                    -RemoteLANNetwork 'ZZRemoteLAN' -RemoteID '198.51.100.2' -LocalPort 1701 -RemotePort '*' @conn -Confirm:$false } |
                Should -Throw '*501*'
        }

        It 'Set-SfosL2TPConnection throws on the same flat status path' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConnection><Configuration><Name>ZZFailOpenL2TPSet</Name><Description></Description><ActionOnVPNRestart>Disable</ActionOnVPNRestart><AuthenticationType>PresharedKey</AuthenticationType><AliasLocalWANPort>Port2</AliasLocalWANPort><LocalID>198.51.100.1</LocalID><RemoteHost>198.51.100.2</RemoteHost><AllowNATTraversal>Enable</AllowNATTraversal><RemoteID>198.51.100.2</RemoteID><LocalPort>1701</LocalPort><RemotePort>*</RemotePort></Configuration></L2TPConnection></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Configuration><Status code="501">Operation could not be performed on Entity.</Status></Configuration></Response>' }
                }
            }

            { Set-SfosL2TPConnection -Name 'ZZFailOpenL2TPSet' -PresharedKey $psk @conn -Confirm:$false } | Should -Throw '*501*'
        }

        It 'Remove-SfosL2TPConnection succeeds on the measured nested Response/L2TPConnection/Configuration/Status path' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><L2TPConnection><Configuration><Status code="200">Configuration applied successfully.</Status></Configuration></L2TPConnection></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><L2TPConnection><Configuration><Name>ZZFailOpenL2TPRemove</Name></Configuration></L2TPConnection></Response>' }
                }
            }

            { Remove-SfosL2TPConnection -Name 'ZZFailOpenL2TPRemove' @conn -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Set-SfosIPsecConnection -Status toggle - exact VPNIPSecConnection/Active wrapper shape' {
        BeforeEach {
            $script:ipsecToggleCalls = New-Object System.Collections.Generic.List[string]
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                $script:ipsecToggleCalls.Add($InnerXml)
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNIPSecConnection><Configuration><Name>ZZToggleIPsec</Name><Description></Description><ConnectionType>TunnelInterface</ConnectionType><AliasLocalWANPort>Port2</AliasLocalWANPort><AuthenticationType>PresharedKey</AuthenticationType><SubnetFamily>Dual</SubnetFamily><LocalIDType>IP Address</LocalIDType><LocalID>198.51.100.1</LocalID><RemoteIDType>IP Address</RemoteIDType><RemoteID>198.51.100.10</RemoteID><UserAuthenticationMode>Disable</UserAuthenticationMode><Protocol>ALL</Protocol><LocalPort>*</LocalPort><RemotePort>*</RemotePort><LocalWANPort>Port2</LocalWANPort><Status>Deactive</Status></Configuration></VPNIPSecConnection></Response>' }
                }
                elseif ($InnerXml -match '<Active>') {
                    [PSCustomObject]@{ Content = '<Response><Active><Status code="200">Configuration applied successfully.</Status></Active></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Configuration><Status code="200">Configuration applied successfully.</Status></Configuration></Response>' }
                }
            }
        }

        It 'sends the toggle as exactly Set/VPNIPSecConnection/Active/Name, with no Configuration sibling' {
            Set-SfosIPsecConnection -Name 'ZZToggleIPsec' -Status Active @conn -Confirm:$false

            $toggleCall = $script:ipsecToggleCalls | Where-Object { $_ -match '<Active>' }
            $toggleCall | Should -Be '<Set operation="update"><VPNIPSecConnection><Active><Name>ZZToggleIPsec</Name></Active></VPNIPSecConnection></Set>'
        }
    }

    Context 'Set-SfosSSLVPNPolicy - read-modify-write preservation (Tunnel)' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><TunnelPolicy><Name>ZZRmwPolicy</Name><Description>original</Description><PolicyMembers><Member>ZZExistingGroup</Member></PolicyMembers><UseAsDefaultGateway>On</UseAsDefaultGateway><PermittedNetworkResourcesIPv4><Resource>ZZExistingNet</Resource></PermittedNetworkResourcesIPv4><PermittedNetworkResourcesIPv6></PermittedNetworkResourcesIPv6><DisconnectIdleClients>On</DisconnectIdleClients><OverrideGlobalTimeout>60</OverrideGlobalTimeout></TunnelPolicy></SSLVPNPolicy></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNPolicy><TunnelPolicy><Status code="200">Configuration applied successfully.</Status></TunnelPolicy></SSLVPNPolicy></Response>' }
                }
            }
        }

        It 'preserves PolicyMembers, PermittedNetworkResourcesIPv4 and UseAsDefaultGateway when only Description changes' {
            Set-SfosSSLVPNPolicy -Name 'ZZRmwPolicy' -Description 'updated' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>updated</Description>' -and
                $InnerXml -match '<PolicyMembers><Member>ZZExistingGroup</Member></PolicyMembers>' -and
                $InnerXml -match '<PermittedNetworkResourcesIPv4><Resource>ZZExistingNet</Resource></PermittedNetworkResourcesIPv4>' -and
                $InnerXml -match '<UseAsDefaultGateway>On</UseAsDefaultGateway>' -and
                $InnerXml -match '<OverrideGlobalTimeout>60</OverrideGlobalTimeout>'
            }
        }
    }

    Context 'Remove-SfosSSLVPNPolicy - referencing UserGroup blocks delete (measured 500)' {
        It 'throws when the firewall answers 500 "Deleted some configurations. Couldn''t delete all."' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNPolicy><TunnelPolicy><Status code="500">Deleted some configurations. Couldn''t delete all.</Status></TunnelPolicy></SSLVPNPolicy></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNPolicy><TunnelPolicy><Name>ZZBlockedPolicy</Name><Description></Description><PolicyMembers><Member>ZZTestGroup</Member></PolicyMembers><UseAsDefaultGateway>Off</UseAsDefaultGateway></TunnelPolicy></SSLVPNPolicy></Response>' }
                }
            }

            { Remove-SfosSSLVPNPolicy -Name 'ZZBlockedPolicy' @conn -Confirm:$false } | Should -Throw '*500*'
        }
    }

    Context 'Set-SfosSSLBookmark - never resends the literal element-object text as a password' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmark><Name>ZZLiteralBookmark</Name><Description></Description><Type>RDP</Type><URL>rdp.example</URL><ShareSession>Disable</ShareSession><AutoLogin>Enable</AutoLogin><UserName>rdpuser</UserName><Password hashform="mode1">$sfos$7$0$deadbeef</Password><Port>3389</Port></SSLBookmark></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmark><Status code="200">Configuration applied successfully.</Status></SSLBookmark></Response>' }
                }
            }
        }

        It 'never sends the CLR type name "System.Xml.XmlElement" as the Password value' {
            Set-SfosSSLBookmark -Name 'ZZLiteralBookmark' -Description 'x' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and $InnerXml -notmatch 'System\.Xml\.XmlElement'
            }
        }
    }

    Context 'New-SfosSiteToSiteClient - measured field-less 500 (transport cannot carry the required file upload)' {
        It 'throws on the field-less 500 the firewall answers for every variant tried' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><SiteToSiteClient><Status code="500">Operation could not be performed on Entity.</Status></SiteToSiteClient></Response>' }
            }

            { New-SfosSiteToSiteClient -Name 'ZZFieldlessS2SClient' -ServerConfigurationFile 'placeholder' @conn -Confirm:$false } |
                Should -Throw '*500*'
        }
    }

    Context 'Set-SfosSiteToSiteClient - read-modify-write preservation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteClient><Name>ZZRmwS2SClient</Name><Description>original</Description><HttpProxyServer>Enable</HttpProxyServer><ProxyServer>proxy.example</ProxyServer><ProxyPort>8080</ProxyPort><ProxyAuthentication>Disable</ProxyAuthentication><Username></Username><PeerHost>Disable</PeerHost><HostName></HostName><Status>On</Status></SiteToSiteClient></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SiteToSiteClient><Status code="200">Configuration applied successfully.</Status></SiteToSiteClient></Response>' }
                }
            }
        }

        It 'preserves HttpProxyServer, ProxyServer/ProxyPort and Status when only Description changes' {
            Set-SfosSiteToSiteClient -Name 'ZZRmwS2SClient' -Description 'updated' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>updated</Description>' -and
                $InnerXml -match '<HttpProxyServer>Enable</HttpProxyServer>' -and
                $InnerXml -match '<ProxyServer>proxy\.example</ProxyServer>' -and
                $InnerXml -match '<ProxyPort>8080</ProxyPort>' -and
                $InnerXml -match '<Status>On</Status>'
            }
        }
    }

    Context 'Remove-SfosSiteToSiteClient - XML shape' {
        It 'sends the flat Remove/SiteToSiteClient/Name shape' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SiteToSiteClient><Status code="200">Configuration applied successfully.</Status></SiteToSiteClient></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteClient><Name>ZZRemoveS2SClient</Name><Description></Description><HttpProxyServer>Disable</HttpProxyServer><ProxyAuthentication>Disable</ProxyAuthentication><PeerHost>Disable</PeerHost></SiteToSiteClient></Response>' }
                }
            }

            Remove-SfosSiteToSiteClient -Name 'ZZRemoveS2SClient' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SiteToSiteClient><Name>ZZRemoveS2SClient</Name></SiteToSiteClient></Remove>'
            }
        }
    }

    Context 'Set-SfosSiteToSiteServer - read-modify-write preservation with single-element network lists' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteServer><Name>ZZRmwS2SServer</Name><Description>original</Description><StaticIP>Disable</StaticIP><LocalNetworks><Network>ZZExistingLocal</Network></LocalNetworks><RemoteNetworks><Network>ZZExistingRemote</Network></RemoteNetworks><Status>On</Status></SiteToSiteServer></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SiteToSiteServer><Status code="200">Configuration applied successfully.</Status></SiteToSiteServer></Response>' }
                }
            }
        }

        It 'preserves a single-element LocalNetworks/RemoteNetworks list and escapes a "&" in Description' {
            Set-SfosSiteToSiteServer -Name 'ZZRmwS2SServer' -Description 'R&D link' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>R&amp;D link</Description>' -and
                $InnerXml -match '<LocalNetworks><Network>ZZExistingLocal</Network></LocalNetworks>' -and
                $InnerXml -match '<RemoteNetworks><Network>ZZExistingRemote</Network></RemoteNetworks>' -and
                $InnerXml -match '<Status>On</Status>'
            }
        }
    }

    Context 'Remove-SfosSiteToSiteServer - XML shape and the measured empty-code failure path' {
        It 'sends the flat Remove/SiteToSiteServer/Name shape' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SiteToSiteServer><Status code="200">Configuration applied successfully.</Status></SiteToSiteServer></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteServer><Name>ZZRemoveS2SServer</Name><Description></Description><StaticIP>Disable</StaticIP><LocalNetworks><Network>Net1</Network></LocalNetworks><RemoteNetworks><Network>Net2</Network></RemoteNetworks></SiteToSiteServer></Response>' }
                }
            }

            Remove-SfosSiteToSiteServer -Name 'ZZRemoveS2SServer' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SiteToSiteServer><Name>ZZRemoveS2SServer</Name></SiteToSiteServer></Remove>'
            }
        }

        It 'throws on the measured empty-code "Operation could not be performed on Entity." status (removing an already-gone object)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SiteToSiteServer><Status code="">Operation could not be performed on Entity.</Status></SiteToSiteServer></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SiteToSiteServer><Name>ZZStuckS2SServer</Name><Description></Description><StaticIP>Disable</StaticIP><LocalNetworks><Network>Net1</Network></LocalNetworks><RemoteNetworks><Network>Net2</Network></RemoteNetworks></SiteToSiteServer></Response>' }
                }
            }

            { Remove-SfosSiteToSiteServer -Name 'ZZStuckS2SServer' @conn -Confirm:$false } | Should -Throw '*status without a code*'
        }
    }

    Context 'Add-/Remove-SfosL2TPConfigurationMember - XML shape and error path' {
        # Unlike VPNFailoverGroup/SSLBookmarkGroup member cmdlets, this pair does NOT read the
        # current member list and write a full replacement back - each call sends a single
        # direct add/remove of one UserName element, confirmed by reading the module source.
        # There is therefore no read-modify-write "single-element list" hazard to test here.
        It 'Add sends Set/L2TPConfiguration/L2TPMembers/UserName, status path L2TPMembers' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><L2TPMembers><Status code="201">Operation partially successful.</Status></L2TPMembers></Response>' }
            }

            Add-SfosL2TPConfigurationMember -MemberName 'ZZL2TPUser' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<L2TPConfiguration>\s*<L2TPMembers>\s*<UserName>ZZL2TPUser</UserName>\s*</L2TPMembers>\s*</L2TPConfiguration>'
            }
        }

        It 'Add throws on the measured 500 for a nonexistent local user' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><L2TPMembers><Status code="500">Operation could not be performed on Entity.</Status></L2TPMembers></Response>' }
            }

            { Add-SfosL2TPConfigurationMember -MemberName 'ZZNoSuchUser' @conn -Confirm:$false } | Should -Throw '*500*'
        }

        It 'Remove sends Remove/L2TPConfiguration/L2TPMembers/UserName, status path nested one level deeper than Add' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><L2TPConfiguration><L2TPMembers><Status code="200">Configuration applied successfully.</Status></L2TPMembers></L2TPConfiguration></Response>' }
            }

            Remove-SfosL2TPConfigurationMember -MemberName 'ZZL2TPUser' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<L2TPConfiguration>\s*<L2TPMembers>\s*<UserName>ZZL2TPUser</UserName>\s*</L2TPMembers>\s*</L2TPConfiguration>\s*</Remove>'
            }
        }
    }

    Context 'Add-/Remove-SfosPPTPConfigurationMember - XML shape (mirrors L2TPConfigurationMember)' {
        It 'Add sends Set/PPTPConfiguration/PPTPMembers/UserName, status path PPTPMembers' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><PPTPMembers><Status code="201">Operation partially successful.</Status></PPTPMembers></Response>' }
            }

            Add-SfosPPTPConfigurationMember -MemberName 'ZZPPTPUser' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<PPTPConfiguration>\s*<PPTPMembers>\s*<UserName>ZZPPTPUser</UserName>\s*</PPTPMembers>\s*</PPTPConfiguration>'
            }
        }

        It 'Remove sends Remove/PPTPConfiguration/PPTPMembers/UserName, status path nested one level deeper than Add' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><PPTPConfiguration><PPTPMembers><Status code="200">Configuration applied successfully.</Status></PPTPMembers></PPTPConfiguration></Response>' }
            }

            Remove-SfosPPTPConfigurationMember -MemberName 'ZZPPTPUser' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<PPTPConfiguration>\s*<PPTPMembers>\s*<UserName>ZZPPTPUser</UserName>\s*</PPTPMembers>\s*</PPTPConfiguration>\s*</Remove>'
            }
        }
    }

    Context 'Remove-SfosVPNProfile' {
        It 'sends the flat Remove/VPNProfile/Name shape' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><VPNProfile><Status code="200">Configuration applied successfully.</Status></VPNProfile></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNProfile><Name>ZZRemoveProfile</Name></VPNProfile></Response>' }
                }
            }

            Remove-SfosVPNProfile -Name 'ZZRemoveProfile' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<VPNProfile>\s*<Name>ZZRemoveProfile</Name>\s*</VPNProfile>\s*</Remove>'
            }
        }
    }

    Context 'Set-SfosVPNFailoverGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZRmwFailover</Name><MemberConnections><Connection>ZZExistingConn</Connection></MemberConnections><MailNotification>Enable</MailNotification><AutomaticFailback>Disable</AutomaticFailback></GroupDetail></VPNFailoverGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
                }
            }
        }

        It 'preserves a single-element MemberConnectionList and AutomaticFailback when only MailNotification changes' {
            Set-SfosVPNFailoverGroup -Name 'ZZRmwFailover' -MailNotification Disable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<MemberConnections><Connection>ZZExistingConn</Connection></MemberConnections>' -and
                $InnerXml -match '<MailNotification>Disable</MailNotification>' -and
                $InnerXml -match '<AutomaticFailback>Disable</AutomaticFailback>'
            }
        }

        It 'throws client-side when -Connection is explicitly emptied' {
            { Set-SfosVPNFailoverGroup -Name 'ZZRmwFailover' -Connection @() @conn -Confirm:$false } |
                Should -Throw '*at least one member Connection*'
        }
    }

    Context 'Add-/Remove-SfosVPNFailoverGroupMember' {
        It 'Add reads the current single-element member list and writes both connections back' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZAddMemberFailover</Name><MemberConnections><Connection>ZZExistingConn</Connection></MemberConnections><MailNotification>Enable</MailNotification></GroupDetail></VPNFailoverGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
                }
            }

            Add-SfosVPNFailoverGroupMember -Name 'ZZAddMemberFailover' -Connection 'ZZNewConn' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<MemberConnections><Connection>ZZExistingConn</Connection><Connection>ZZNewConn</Connection></MemberConnections>'
            }
        }

        It 'Remove reads a two-element member list and writes the remaining one back' {
            $script:failoverUpdated = $false
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    $script:failoverUpdated = $true
                    return [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
                }
                if ($script:failoverUpdated) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZRemoveMemberFailover</Name><MemberConnections><Connection>ZZConnA</Connection></MemberConnections><MailNotification>Enable</MailNotification></GroupDetail></VPNFailoverGroup></Response>' }
                }
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZRemoveMemberFailover</Name><MemberConnections><Connection>ZZConnA</Connection><Connection>ZZConnB</Connection></MemberConnections><MailNotification>Enable</MailNotification></GroupDetail></VPNFailoverGroup></Response>' }
            }

            Remove-SfosVPNFailoverGroupMember -Name 'ZZRemoveMemberFailover' -Connection 'ZZConnB' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<MemberConnections><Connection>ZZConnA</Connection></MemberConnections>'
            }
        }

        It 'Remove throws client-side rather than emptying the mandatory member list' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZLastMemberFailover</Name><MemberConnections><Connection>ZZOnlyConn</Connection></MemberConnections><MailNotification>Enable</MailNotification></GroupDetail></VPNFailoverGroup></Response>' }
            }

            { Remove-SfosVPNFailoverGroupMember -Name 'ZZLastMemberFailover' -Connection 'ZZOnlyConn' @conn -Confirm:$false } |
                Should -Throw '*only remaining member*'
        }
    }

    Context 'Remove-SfosVPNFailoverGroup' {
        It 'sends the flat Remove/VPNFailoverGroup/Name shape (not nested under GroupDetail, unlike Get)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNFailoverGroup><GroupDetail><Name>ZZRemoveFailover</Name><MemberConnections><Connection>ZZConn</Connection></MemberConnections></GroupDetail></VPNFailoverGroup></Response>' }
                }
            }

            Remove-SfosVPNFailoverGroup -Name 'ZZRemoveFailover' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>\s*<VPNFailoverGroup>\s*<Name>ZZRemoveFailover</Name>\s*</VPNFailoverGroup>\s*</Remove>'
            }
        }
    }

    Context 'Set-SfosSSLBookmarkGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Name>ZZRmwBookmarkGroup</Name><Description>original</Description><BookmarkList><Bookmark>ZZExistingBookmark</Bookmark></BookmarkList></SSLBookmarkGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmarkGroup><Status code="200">Configuration applied successfully.</Status></SSLBookmarkGroup></Response>' }
                }
            }
        }

        It 'preserves a single-element BookmarkList and escapes a "&" in Description' {
            Set-SfosSSLBookmarkGroup -Name 'ZZRmwBookmarkGroup' -Description 'R&D group' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>R&amp;D group</Description>' -and
                $InnerXml -match '<BookmarkList><Bookmark>ZZExistingBookmark</Bookmark></BookmarkList>'
            }
        }
    }

    Context 'Add-/Remove-SfosSSLBookmarkGroupMember' {
        It 'Add reads the current single-element bookmark list and writes both bookmarks back' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Name>ZZAddMemberBookmarkGroup</Name><Description></Description><BookmarkList><Bookmark>ZZExistingBookmark</Bookmark></BookmarkList></SSLBookmarkGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmarkGroup><Status code="200">Configuration applied successfully.</Status></SSLBookmarkGroup></Response>' }
                }
            }

            Add-SfosSSLBookmarkGroupMember -GroupName 'ZZAddMemberBookmarkGroup' -Bookmark 'ZZNewBookmark' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<BookmarkList><Bookmark>ZZExistingBookmark</Bookmark><Bookmark>ZZNewBookmark</Bookmark></BookmarkList>'
            }
        }

        It 'Remove reads a two-element bookmark list and writes the remaining one back' {
            $script:bookmarkGroupUpdated = $false
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    $script:bookmarkGroupUpdated = $true
                    return [PSCustomObject]@{ Content = '<Response><SSLBookmarkGroup><Status code="200">Configuration applied successfully.</Status></SSLBookmarkGroup></Response>' }
                }
                if ($script:bookmarkGroupUpdated) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Name>ZZRemoveMemberBookmarkGroup</Name><Description></Description><BookmarkList><Bookmark>ZZBookmarkA</Bookmark></BookmarkList></SSLBookmarkGroup></Response>' }
                }
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Name>ZZRemoveMemberBookmarkGroup</Name><Description></Description><BookmarkList><Bookmark>ZZBookmarkA</Bookmark><Bookmark>ZZBookmarkB</Bookmark></BookmarkList></SSLBookmarkGroup></Response>' }
            }

            Remove-SfosSSLBookmarkGroupMember -GroupName 'ZZRemoveMemberBookmarkGroup' -Bookmark 'ZZBookmarkB' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<BookmarkList><Bookmark>ZZBookmarkA</Bookmark></BookmarkList>'
            }
        }
    }

    Context 'Remove-SfosSSLBookmarkGroup' {
        It 'sends the flat Remove/SSLBookmarkGroup/Name shape' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><SSLBookmarkGroup><Status code="200">Configuration applied successfully.</Status></SSLBookmarkGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLBookmarkGroup><Name>ZZRemoveBookmarkGroup</Name><Description></Description><BookmarkList><Bookmark>ZZBookmark</Bookmark></BookmarkList></SSLBookmarkGroup></Response>' }
                }
            }

            Remove-SfosSSLBookmarkGroup -Name 'ZZRemoveBookmarkGroup' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.VPN -Times 1 -Exactly -ParameterFilter {
                $InnerXml -eq '<Remove><SSLBookmarkGroup><Name>ZZRemoveBookmarkGroup</Name></SSLBookmarkGroup></Remove>'
            }
        }
    }
}
