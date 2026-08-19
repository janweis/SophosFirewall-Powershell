#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Diagnostics module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of both exported functions
    with their connection parameters (order and type); Get-SfosSupportAccess parsing both
    the enabled state (ConfigOption + GrantAccessFor) and the disabled state (no duration
    element on the wire, GrantAccessFor comes back as an empty string, not null);
    Set-SfosSupportAccess always sending ConfigOption and sending GrantAccessFor only while
    the resolved state is Enable; the wire spelling GrantAccessFor (one 'r', not the
    documentation's GrantAccessForr); a Set that cannot resolve ConfigOption (existing value
    on the firewall is neither Enable nor Disable) throwing instead of sending;
    -WhatIf suppressing the write call while still allowing the read-first existence check;
    and a 501 validation failure surfacing as an exception naming the code.

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/Context,
    never at the script's top level, following the pattern already used across this project's
    test suites.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6,
    once loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its type
    data collides with the one PS 5.1 already loaded at startup. Work around it by restricting
    $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Diagnostics.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Diagnostics\SophosFirewall.Diagnostics.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

# --------------------------------------------------------------------------------------------

Describe 'Module Loading' {
    It 'SophosFirewall.Diagnostics module should load' {
        Get-Module SophosFirewall.Diagnostics | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 2 functions' {
        (Get-Module SophosFirewall.Diagnostics).ExportedFunctions.Count | Should -Be 2
    }

    It 'Manifest FunctionsToExport should list exactly 2 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Diagnostics\SophosFirewall.Diagnostics.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 2
        @($manifest.ExportedFunctions.Keys | Sort-Object) | Should -Be @('Get-SfosSupportAccess', 'Set-SfosSupportAccess')
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosSupportAccess' }
    @{ Function = 'Set-SfosSupportAccess' }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with the six connection parameters, no identifying parameter' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.Diagnostics -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"

        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
        $cmd.Parameters.Keys | Should -Not -Contain 'Name'
        $cmd.Parameters.Keys | Should -Not -Contain 'NameLike'
    }

    It 'Exports <Function> with the connection parameters in the fixed order and types' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.Diagnostics

        $expectedTypes = [ordered]@{
            Firewall             = [string]
            Port                 = [int]
            Username             = [string]
            Password             = [securestring]
            SkipCertificateCheck = [switch]
            Session              = [object]
        }

        $connKeys = @($cmd.Parameters.Keys | Where-Object { $expectedTypes.Contains($_) })
        $connKeys | Should -Be @($expectedTypes.Keys)

        foreach ($name in $expectedTypes.Keys) {
            $cmd.Parameters[$name].ParameterType | Should -Be $expectedTypes[$name]
        }
    }

    It 'Set-SfosSupportAccess supports ShouldProcess' {
        $cmd = Get-Command Set-SfosSupportAccess -Module SophosFirewall.Diagnostics
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
    }
}

Describe 'Get-SfosSupportAccess' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'returns ConfigOption and GrantAccessFor while access is switched on' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Enable</ConfigOption><GrantAccessFor>1 week</GrantAccessFor></SupportAccess></Response>' }
        }

        $result = Get-SfosSupportAccess @conn

        $result.ConfigOption | Should -Be 'Enable'
        $result.GrantAccessFor | Should -Be '1 week'
    }

    It 'returns an empty GrantAccessFor - not null - while access is switched off, because the firewall omits the duration element' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Disable</ConfigOption></SupportAccess></Response>' }
        }

        $result = Get-SfosSupportAccess @conn

        $result.ConfigOption | Should -Be 'Disable'
        $result.GrantAccessFor | Should -BeOfType [string]
        $result.GrantAccessFor | Should -Be ''
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="501">Configuration parameters validation failed.</Status></SupportAccess></Response>' }
        }

        { Get-SfosSupportAccess @conn } | Should -Throw '*501*'
    }
}

Describe 'Set-SfosSupportAccess - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        # Existing state used for calls where the resolved ConfigOption is not itself under
        # test, so the value returned by the read-first Get is irrelevant to the assertion.
        $script:DisabledArchive = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Disable</ConfigOption></SupportAccess></Response>'
        $script:EnabledArchive = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption>Enable</ConfigOption><GrantAccessFor>1 week</GrantAccessFor></SupportAccess></Response>'
        $script:UnresolvedArchive = '<Response><Login><status>Authentication Successful</status></Login><SupportAccess transactionid=""><ConfigOption></ConfigOption></SupportAccess></Response>'
    }

    It 'sends ConfigOption and GrantAccessFor - wire name with exactly one r - while switching on' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:DisabledArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="200">Configuration applied successfully.</Status></SupportAccess></Response>' }
            }
        }

        Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SupportAccess>' -and
            $InnerXml -match '<ConfigOption>Enable</ConfigOption>' -and
            $InnerXml -match '<GrantAccessFor>1 day</GrantAccessFor>' -and
            $InnerXml -notmatch 'GrantAccessForr'
        }
    }

    It 'sends ConfigOption but never GrantAccessFor while switching off' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:EnabledArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="200">Configuration applied successfully.</Status></SupportAccess></Response>' }
            }
        }

        Set-SfosSupportAccess -ConfigOption Disable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ConfigOption>Disable</ConfigOption>' -and
            $InnerXml -notmatch '<GrantAccessFor>'
        }
    }

    It 'a Set without -ConfigOption against a firewall value that is neither Enable nor Disable throws instead of sending' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = $script:UnresolvedArchive }
        }

        { Set-SfosSupportAccess -GrantAccessFor '1 day' @conn -Confirm:$false } | Should -Throw '*resolved*'

        # Only the read-first existence check ran; no update was ever attempted.
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:DisabledArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SupportAccess><Status code="501">Configuration parameters validation failed.</Status></SupportAccess></Response>' }
            }
        }

        { Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check read but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -MockWith {
            [PSCustomObject]@{ Content = $script:DisabledArchive }
        }

        Set-SfosSupportAccess -ConfigOption Enable -GrantAccessFor '1 day' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Diagnostics -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}
