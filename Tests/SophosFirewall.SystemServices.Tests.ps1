#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.SystemServices module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 21 exported
    functions; XML-generation checks for New-SfosQoSPolicy (bandwidth field group
    selection); Set-SfosSyslogServer (LogSettings subtree preservation on a partial
    update); Set-SfosSystemService (nested per-daemon element plus Action, and the
    undocumented code 202 treated as a local success-with-warning); the HAConfigure
    code-less "Transaction fail" no-peer-configured case; and the shared status-parsing
    error paths (5xx throws, "No. of records Zero." yields @()). A final Describe
    exercises the -Session parameter end to end against a named, non-default session.

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/
    Context, never at the script's top level - a top-level $script: variable set outside
    any Describe block was found unreliable during Pester's Run phase in this project.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Work
    around Pester 6 type-data collisions by restricting $env:PSModulePath in a child
    process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.SystemServices.Tests.ps1'
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.SystemServices\SophosFirewall.SystemServices.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.SystemServices module should load' {
        Get-Module SophosFirewall.SystemServices | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 21 functions' {
        (Get-Module SophosFirewall.SystemServices).ExportedFunctions.Count | Should -Be 21
    }

    It 'Manifest FunctionsToExport should list exactly 21 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.SystemServices\SophosFirewall.SystemServices.psd1'

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

        $manifest.ExportedFunctions.Count | Should -Be 21
    }

    It 'Every documented function exists' {
        $expected = @(
            'Disable-SfosHAConfiguration', 'Get-SfosHAConfiguration', 'Get-SfosQoSPolicy',
            'Get-SfosREDConfiguration', 'Get-SfosREDDeviceDeauthorizationSettings',
            'Get-SfosREDTLSVersionSettings', 'Get-SfosSyslogServer', 'Get-SfosSystemServiceStatus',
            'Initialize-SfosHAConfiguration', 'New-SfosQoSPolicy', 'New-SfosSyslogServer',
            'Remove-SfosQoSPolicy', 'Remove-SfosSyslogServer', 'Reset-SfosHAConfiguration',
            'Set-SfosQoSPolicy', 'Set-SfosREDBetaFirmware', 'Set-SfosREDConfiguration',
            'Set-SfosREDDeviceDeauthorizationSettings', 'Set-SfosREDTLSVersionSettings',
            'Set-SfosSyslogServer', 'Set-SfosSystemService'
        )
        foreach ($name in $expected) {
            Get-Command $name -Module SophosFirewall.SystemServices -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$name should be exported"
        }
    }
}

Describe 'New-SfosQoSPolicy - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><QoSPolicy><Status code="200">Configuration applied successfully.</Status></QoSPolicy></Response>' }
        }
    }

    It 'builds the TotalBandwidth field for Total/Strict' {
        New-SfosQoSPolicy -Name 'Branch Office Cap' -PolicyBasedOn User -ImplementationOn Total `
            -PolicyType Strict -Priority Normal3 -TotalBandwidth 512 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Name>Branch Office Cap</Name>' -and
            $InnerXml -match '<PolicyBasedOn>User</PolicyBasedOn>' -and
            $InnerXml -match '<ImplementationOn>Total</ImplementationOn>' -and
            $InnerXml -match '<PolicyType>Strict</PolicyType>' -and
            $InnerXml -match '<TotalBandwidth>512</TotalBandwidth>' -and
            $InnerXml -notmatch '<GuaranteedBandwidth>' -and
            $InnerXml -match '<SchedulebasedPolicyRuleList\s*/>'
        }
    }

    It 'builds the four Individual/Committed bandwidth fields' {
        New-SfosQoSPolicy -Name 'VoIP App Guarantee' -PolicyBasedOn Application -ImplementationOn Individual `
            -PolicyType Committed -Priority RealTime -GuaranteedUploadBandwidth 64 -BurstableUploadBandwidth 128 `
            -GuaranteedDownloadBandwidth 64 -BurstableDownloadBandwidth 128 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<GuaranteedUploadBandwidth>64</GuaranteedUploadBandwidth>' -and
            $InnerXml -match '<BurstableUploadBandwidth>128</BurstableUploadBandwidth>' -and
            $InnerXml -match '<GuaranteedDownloadBandwidth>64</GuaranteedDownloadBandwidth>' -and
            $InnerXml -match '<BurstableDownloadBandwidth>128</BurstableDownloadBandwidth>'
        }
    }

    It 'throws client-side when the required bandwidth fields for the chosen combination are missing' {
        { New-SfosQoSPolicy -Name 'Broken' -PolicyBasedOn User -ImplementationOn Total -PolicyType Strict -Priority Normal3 @conn -Confirm:$false } |
            Should -Throw '*require -TotalBandwidth*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -Times 0 -Exactly
    }
}

Describe 'Set-SfosSyslogServer - LogSettings subtree preservation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'resends the existing LogSettings subtree unchanged when only SeverityLevel is updated' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SyslogServers transactionid=""><Name>Branch Syslog</Name><ServerAddress>syslog.example.internal</ServerAddress><Port>514</Port><EnableSecureConnection>Disable</EnableSecureConnection><Facility>LOCAL3</Facility><SeverityLevel>Information</SeverityLevel><Format>DeviceStandardFormat</Format><LogSettings><AntiVirus><HTTP>Disable</HTTP><FTP>Enable</FTP></AntiVirus></LogSettings></SyslogServers></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SyslogServers><Status code="200">Configuration applied successfully.</Status></SyslogServers></Response>' }
            }
        }

        Set-SfosSyslogServer -Name 'Branch Syslog' -SeverityLevel Debug @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SeverityLevel>Debug</SeverityLevel>' -and
            $InnerXml -match '<ServerAddress>syslog.example.internal</ServerAddress>' -and
            $InnerXml -match '<LogSettings><AntiVirus><HTTP>Disable</HTTP><FTP>Enable</FTP></AntiVirus></LogSettings>'
        }
    }

    It 'replaces the whole LogSettings subtree when -LogSettings is supplied explicitly' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SyslogServers transactionid=""><Name>Branch Syslog</Name><ServerAddress>syslog.example.internal</ServerAddress><Port>514</Port><EnableSecureConnection>Disable</EnableSecureConnection><Facility>LOCAL3</Facility><SeverityLevel>Information</SeverityLevel><Format>DeviceStandardFormat</Format><LogSettings><AntiVirus><HTTP>Disable</HTTP></AntiVirus></LogSettings></SyslogServers></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SyslogServers><Status code="200">Configuration applied successfully.</Status></SyslogServers></Response>' }
            }
        }

        $newSettings = [PSCustomObject]@{ AntiVirus = [PSCustomObject]@{ HTTP = 'Enable' } }
        Set-SfosSyslogServer -Name 'Branch Syslog' -LogSettings $newSettings @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -ParameterFilter {
            $InnerXml -match '<LogSettings><AntiVirus><HTTP>Enable</HTTP></AntiVirus></LogSettings>'
        }
    }

    It 'throws "was not found" for a nonexistent syslog server' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SyslogServers transactionid=""><Status>No. of records Zero.</Status></SyslogServers></Response>' }
        }

        { Set-SfosSyslogServer -Name 'DoesNotExist' -SeverityLevel Debug @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Set-SfosSystemService - nested daemon element and Action' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'wraps Action inside an element named after the daemon, flat under Response on read-back' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirus><Status code="200">Configuration applied successfully.</Status></AntiVirus></Response>' }
        }

        Set-SfosSystemService -Name AntiVirus -Action Restart @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SystemServices>\s*<AntiVirus>\s*<Action>Restart</Action>\s*</AntiVirus>\s*</SystemServices>'
        }
    }

    It 'treats the undocumented code 202 as a local success, not a table-driven error' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirus><Status code="202">Unable to get status message</Status></AntiVirus></Response>' }
        }

        { Set-SfosSystemService -Name AntiVirus -Action Stop @conn -Confirm:$false -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'throws on a table-covered 501 for an invalid Action-shaped error' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirus><Status code="501">Configuration parameters validation failed.</Status></AntiVirus></Response>' }
        }

        { Set-SfosSystemService -Name AntiVirus -Action Start @conn -Confirm:$false } | Should -Throw '*501*'
    }
}

Describe 'Get-SfosHAConfiguration - code-less Transaction fail (no HA peer)' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'returns $null when HA is not configured, rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><HAConfigure><HA_Interactive><Status>Transaction fail</Status></HA_Interactive></HAConfigure></Response>' }
        }

        Get-SfosHAConfiguration @conn | Should -BeNullOrEmpty
    }

    It 'throws on a genuine coded API error under HAConfigure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><HAConfigure><Status code="529">Invalid XML request</Status></HAConfigure></Response>' }
        }

        { Get-SfosHAConfiguration @conn } | Should -Throw '*529*'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><QoSPolicy transactionid=""><Status code="529">Invalid XML request</Status></QoSPolicy></Response>' }
        }

        { Get-SfosQoSPolicy @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosQoSPolicy @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SyslogServers transactionid=""><Status>No. of records Zero.</Status></SyslogServers></Response>' }
        }

        $result = @(Get-SfosSyslogServer @conn)
        $result.Count | Should -Be 0
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><QoSPolicy transactionid=""><Status>No. of records Zero.</Status></QoSPolicy></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default' {
        Get-SfosQoSPolicy -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosQoSPolicy | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosQoSPolicy -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SystemServices -Times 0 -Exactly
    }
}
