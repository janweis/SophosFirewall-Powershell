#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.ZeroDayProtection module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of both exported functions
    with their connection parameters (order and type); Get-SfosZeroDayProtectionSettings
    turning an empty <ExcludeFileTypes/> into an empty array (not null, not a one-element
    array holding an empty string), a single value into a one-element array and a
    comma-separated value into the split list; Set-SfosZeroDayProtectionSettings always
    sending both DataCenterLocation and ExcludeFileTypes (full-replace singleton), a call
    that passes only one of the two taking the other from the read-first Get (RMW), and
    -ExcludeFileTypes @() actually clearing the list on the wire; -WhatIf suppressing the
    write call while still allowing the read-first existence check; and a 501 validation
    failure surfacing as an exception naming the code.

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
        Invoke-Pester -Path '.\SophosFirewall.ZeroDayProtection.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.ZeroDayProtection\SophosFirewall.ZeroDayProtection.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

# --------------------------------------------------------------------------------------------

Describe 'Module Loading' {
    It 'SophosFirewall.ZeroDayProtection module should load' {
        Get-Module SophosFirewall.ZeroDayProtection | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 2 functions' {
        (Get-Module SophosFirewall.ZeroDayProtection).ExportedFunctions.Count | Should -Be 2
    }

    It 'Manifest FunctionsToExport should list exactly 2 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.ZeroDayProtection\SophosFirewall.ZeroDayProtection.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 2
        @($manifest.ExportedFunctions.Keys | Sort-Object) | Should -Be @('Get-SfosZeroDayProtectionSettings', 'Set-SfosZeroDayProtectionSettings')
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosZeroDayProtectionSettings' }
    @{ Function = 'Set-SfosZeroDayProtectionSettings' }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with the six connection parameters, no identifying parameter' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.ZeroDayProtection -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"

        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
        $cmd.Parameters.Keys | Should -Not -Contain 'Name'
        $cmd.Parameters.Keys | Should -Not -Contain 'NameLike'
    }

    It 'Exports <Function> with the connection parameters in the fixed order and types' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.ZeroDayProtection

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

    It 'Set-SfosZeroDayProtectionSettings supports ShouldProcess' {
        $cmd = Get-Command Set-SfosZeroDayProtectionSettings -Module SophosFirewall.ZeroDayProtection
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
    }
}

Describe 'Get-SfosZeroDayProtectionSettings - ExcludeFileTypes parsing' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'returns an empty array - not null, not a one-element array of an empty string - for an empty ExcludeFileTypes element' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ZeroDayProtectionSettings transactionid=""><DataCenterLocation>sandbox.sophos.com</DataCenterLocation><ExcludeFileTypes></ExcludeFileTypes></ZeroDayProtectionSettings></Response>' }
        }

        $result = Get-SfosZeroDayProtectionSettings @conn

        $result.DataCenterLocation | Should -Be 'sandbox.sophos.com'
        ($null -eq $result.ExcludeFileTypes) | Should -Be $false
        , $result.ExcludeFileTypes | Should -BeOfType [array]
        @($result.ExcludeFileTypes).Count | Should -Be 0
    }

    It 'returns a one-element array for a single ExcludeFileTypes value' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ZeroDayProtectionSettings transactionid=""><DataCenterLocation>sandbox.sophos.com</DataCenterLocation><ExcludeFileTypes>Audio Files</ExcludeFileTypes></ZeroDayProtectionSettings></Response>' }
        }

        $result = Get-SfosZeroDayProtectionSettings @conn

        @($result.ExcludeFileTypes).Count | Should -Be 1
        $result.ExcludeFileTypes[0] | Should -Be 'Audio Files'
    }

    It 'splits a comma-separated ExcludeFileTypes value into the full list' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ZeroDayProtectionSettings transactionid=""><DataCenterLocation>sandbox.sophos.com</DataCenterLocation><ExcludeFileTypes>Audio Files,Video Files,Compressed Files</ExcludeFileTypes></ZeroDayProtectionSettings></Response>' }
        }

        $result = Get-SfosZeroDayProtectionSettings @conn

        @($result.ExcludeFileTypes).Count | Should -Be 3
        @($result.ExcludeFileTypes) | Should -Be @('Audio Files', 'Video Files', 'Compressed Files')
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            [PSCustomObject]@{ Content = '<Response><ZeroDayProtectionSettings><Status code="501">Configuration parameters validation failed.</Status></ZeroDayProtectionSettings></Response>' }
        }

        { Get-SfosZeroDayProtectionSettings @conn } | Should -Throw '*501*'
    }
}

Describe 'Set-SfosZeroDayProtectionSettings - full-replace singleton, RMW' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:ExistingArchive = '<Response><Login><status>Authentication Successful</status></Login><ZeroDayProtectionSettings transactionid=""><DataCenterLocation>sandbox.sophos.com</DataCenterLocation><ExcludeFileTypes>Audio Files,Video Files</ExcludeFileTypes></ZeroDayProtectionSettings></Response>'
    }

    It 'always sends both fields: -DataCenterLocation only carries over the ExcludeFileTypes read from the firewall' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ZeroDayProtectionSettings><Status code="200">Configuration applied successfully.</Status></ZeroDayProtectionSettings></Response>' }
            }
        }

        Set-SfosZeroDayProtectionSettings -DataCenterLocation 'eu.sandbox.sophos.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ZeroDayProtectionSettings>' -and
            $InnerXml -match '<DataCenterLocation>eu\.sandbox\.sophos\.com</DataCenterLocation>' -and
            $InnerXml -match '<ExcludeFileTypes>Audio Files,Video Files</ExcludeFileTypes>'
        }
    }

    It 'always sends both fields: -ExcludeFileTypes only carries over the DataCenterLocation read from the firewall' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ZeroDayProtectionSettings><Status code="200">Configuration applied successfully.</Status></ZeroDayProtectionSettings></Response>' }
            }
        }

        Set-SfosZeroDayProtectionSettings -ExcludeFileTypes 'Compressed Files' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<DataCenterLocation>sandbox\.sophos\.com</DataCenterLocation>' -and
            $InnerXml -match '<ExcludeFileTypes>Compressed Files</ExcludeFileTypes>'
        }
    }

    It '-ExcludeFileTypes @() clears the list on the wire instead of preserving the existing one' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ZeroDayProtectionSettings><Status code="200">Configuration applied successfully.</Status></ZeroDayProtectionSettings></Response>' }
            }
        }

        Set-SfosZeroDayProtectionSettings -ExcludeFileTypes @() @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<DataCenterLocation>sandbox\.sophos\.com</DataCenterLocation>' -and
            $InnerXml -match '<ExcludeFileTypes></ExcludeFileTypes>' -and
            $InnerXml -notmatch '<ExcludeFileTypes>Audio Files'
        }
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingArchive }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ZeroDayProtectionSettings><Status code="501">Configuration parameters validation failed.</Status></ZeroDayProtectionSettings></Response>' }
            }
        }

        { Set-SfosZeroDayProtectionSettings -DataCenterLocation 'eu.sandbox.sophos.com' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check read but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingArchive }
        }

        Set-SfosZeroDayProtectionSettings -DataCenterLocation 'eu.sandbox.sophos.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ZeroDayProtection -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}
