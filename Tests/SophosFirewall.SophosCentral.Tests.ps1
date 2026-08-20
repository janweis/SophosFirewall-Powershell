#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.SophosCentral module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of both exported functions
    with their connection parameters (order and type); Get-SfosCentralManagement parsing
    the four fields into a PSCustomObject and, with -AsXml, into the raw XmlElement; the
    undocumented value WaitingForApproval passing through Get unchanged, neither validated
    nor translated; Set-SfosCentralManagement always sending all four fields on the wire
    even when the caller supplies only one (read-modify-write against a mocked Get); the
    FWBackup/CMStatus dependency guard throwing before any firewall call, both as the
    cheap short-circuit (both passed explicitly) and via the value resolved from a mocked
    existing object; the read-back check after a write - throwing with field, requested and
    actual value when the firewall reports success but the change did not take effect, and
    warning instead of throwing when the read-back value is WaitingForApproval; -WhatIf
    suppressing the write call while still allowing the read-first existence check; and a
    501 validation failure surfacing as an exception naming the code.

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
        Invoke-Pester -Path '.\SophosFirewall.SophosCentral.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.SophosCentral\SophosFirewall.SophosCentral.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

# --------------------------------------------------------------------------------------------

Describe 'Module Loading' {
    It 'SophosFirewall.SophosCentral module should load' {
        Get-Module SophosFirewall.SophosCentral | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 2 functions' {
        (Get-Module SophosFirewall.SophosCentral).ExportedFunctions.Count | Should -Be 2
    }

    It 'Manifest FunctionsToExport should list exactly 2 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.SophosCentral\SophosFirewall.SophosCentral.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 2
        @($manifest.ExportedFunctions.Keys | Sort-Object) | Should -Be @('Get-SfosCentralManagement', 'Set-SfosCentralManagement')
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosCentralManagement' }
    @{ Function = 'Set-SfosCentralManagement' }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with the six connection parameters' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.SophosCentral -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"

        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
    }

    It 'Exports <Function> with the connection parameters in the fixed order and types, Session last' -TestCases $script:CmdletParameterCases {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.SophosCentral

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

    It 'Get-SfosCentralManagement exposes -AsXml and does not support ShouldProcess' {
        $cmd = Get-Command Get-SfosCentralManagement -Module SophosFirewall.SophosCentral
        $cmd.Parameters.Keys | Should -Contain 'AsXml'
        $cmd.Parameters.Keys | Should -Not -Contain 'WhatIf'
    }

    It 'Set-SfosCentralManagement supports ShouldProcess and exposes the four entity fields' {
        $cmd = Get-Command Set-SfosCentralManagement -Module SophosFirewall.SophosCentral
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
        foreach ($field in 'FWBackup', 'JoinMethod', 'UseCentralReporting', 'CMStatus') {
            $cmd.Parameters.Keys | Should -Contain $field
        }
    }
}

Describe 'Get-SfosCentralManagement' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $script:FullStateArchive = '<Response><Login><status>Authentication Successful</status></Login><EnableCloudCentralManagement transactionid=""><FWBackup>BackupDisable</FWBackup><JoinMethod>Manual</JoinMethod><UseCentralReporting>Enable</UseCentralReporting><CMStatus>Enable</CMStatus></EnableCloudCentralManagement></Response>'
    }

    It 'returns the four fields as a PSCustomObject' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = $script:FullStateArchive }
        }

        $result = Get-SfosCentralManagement @conn

        $result | Should -BeOfType [PSCustomObject]
        $result.FWBackup | Should -Be 'BackupDisable'
        $result.JoinMethod | Should -Be 'Manual'
        $result.UseCentralReporting | Should -Be 'Enable'
        $result.CMStatus | Should -Be 'Enable'
    }

    It '-AsXml returns the raw XmlElement instead of a PSCustomObject' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = $script:FullStateArchive }
        }

        $result = Get-SfosCentralManagement -AsXml @conn

        $result | Should -BeOfType [System.Xml.XmlElement]
        $result.FWBackup | Should -Be 'BackupDisable'
    }

    It 'passes the undocumented value WaitingForApproval through unchanged, without validation or translation' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><EnableCloudCentralManagement transactionid=""><FWBackup>BackupDisable</FWBackup><JoinMethod>Manual</JoinMethod><UseCentralReporting>WaitingForApproval</UseCentralReporting><CMStatus>WaitingForApproval</CMStatus></EnableCloudCentralManagement></Response>' }
        }

        $result = Get-SfosCentralManagement @conn

        $result.UseCentralReporting | Should -Be 'WaitingForApproval'
        $result.CMStatus | Should -Be 'WaitingForApproval'
    }

    It 'throws naming the code on a 501 validation failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = '<Response><EnableCloudCentralManagement><Status code="501">Configuration parameters validation failed.</Status></EnableCloudCentralManagement></Response>' }
        }

        { Get-SfosCentralManagement @conn } | Should -Throw '*501*'
    }
}

Describe 'Set-SfosCentralManagement - dependency guard' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws before any firewall call when FWBackup BackupEnable and CMStatus Disable are both passed explicitly' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = '<Response><EnableCloudCentralManagement><Status code="200">Configuration applied successfully.</Status></EnableCloudCentralManagement></Response>' }
        }

        { Set-SfosCentralManagement -FWBackup BackupEnable -CMStatus Disable @conn -Confirm:$false } | Should -Throw '*BackupEnable*Disable*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -Times 0 -Exactly
    }

    It 'throws before any write when CMStatus is not passed and the existing object resolves it to Disable' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><EnableCloudCentralManagement transactionid=""><FWBackup>BackupDisable</FWBackup><JoinMethod>Manual</JoinMethod><UseCentralReporting>Enable</UseCentralReporting><CMStatus>Disable</CMStatus></EnableCloudCentralManagement></Response>' }
        }

        { Set-SfosCentralManagement -FWBackup BackupEnable @conn -Confirm:$false } | Should -Throw '*BackupEnable*Disable*'

        # Only the read-first existing-object check ran; no update was ever attempted.
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}

Describe 'Set-SfosCentralManagement - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = '192.0.2.1'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        # Safe baseline: FWBackup/CMStatus combination never triggers the dependency guard.
        $script:BeforeState = '<Response><Login><status>Authentication Successful</status></Login><EnableCloudCentralManagement transactionid=""><FWBackup>BackupDisable</FWBackup><JoinMethod>Manual</JoinMethod><UseCentralReporting>Enable</UseCentralReporting><CMStatus>Enable</CMStatus></EnableCloudCentralManagement></Response>'
        # Same object, only UseCentralReporting actually changed - what the read-back sees
        # after a write that really took effect.
        $script:AfterStateApplied = '<Response><Login><status>Authentication Successful</status></Login><EnableCloudCentralManagement transactionid=""><FWBackup>BackupDisable</FWBackup><JoinMethod>Manual</JoinMethod><UseCentralReporting>Disable</UseCentralReporting><CMStatus>Enable</CMStatus></EnableCloudCentralManagement></Response>'
        $script:SetOkArchive = '<Response><EnableCloudCentralManagement><Status code="200">Configuration applied successfully.</Status></EnableCloudCentralManagement></Response>'
    }

    It 'sends all four fields on the wire even when only one is passed, keeping the other three from the existing object' {
        $script:getCalls = 0
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            if ($InnerXml -match '<Get>') {
                $script:getCalls++
                if ($script:getCalls -eq 1) {
                    [PSCustomObject]@{ Content = $script:BeforeState }
                }
                else {
                    [PSCustomObject]@{ Content = $script:AfterStateApplied }
                }
            }
            else {
                [PSCustomObject]@{ Content = $script:SetOkArchive }
            }
        }

        Set-SfosCentralManagement -UseCentralReporting Disable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<FWBackup>BackupDisable</FWBackup>' -and
            $InnerXml -match '<JoinMethod>Manual</JoinMethod>' -and
            $InnerXml -match '<UseCentralReporting>Disable</UseCentralReporting>' -and
            $InnerXml -match '<CMStatus>Enable</CMStatus>'
        }
    }

    It 'throws naming field, requested and actual value when the firewall reports success but the read-back shows the old value' {
        $script:getCalls = 0
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            if ($InnerXml -match '<Get>') {
                $script:getCalls++
                # Both reads return the unchanged state - the write was accepted (200) but
                # silently did nothing.
                [PSCustomObject]@{ Content = $script:BeforeState }
            }
            else {
                [PSCustomObject]@{ Content = $script:SetOkArchive }
            }
        }

        $errorRecord = $null
        try {
            Set-SfosCentralManagement -UseCentralReporting Disable @conn -Confirm:$false
        }
        catch {
            $errorRecord = $_
        }

        $errorRecord | Should -Not -BeNullOrEmpty
        $errorRecord.Exception.Message | Should -Match 'UseCentralReporting'
        $errorRecord.Exception.Message | Should -Match "requested 'Disable'"
        $errorRecord.Exception.Message | Should -Match "reports 'Enable'"
    }

    It 'warns instead of throwing when the read-back value is WaitingForApproval' {
        $script:getCalls = 0
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            if ($InnerXml -match '<Get>') {
                $script:getCalls++
                if ($script:getCalls -eq 1) {
                    [PSCustomObject]@{ Content = $script:BeforeState }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><EnableCloudCentralManagement transactionid=""><FWBackup>BackupDisable</FWBackup><JoinMethod>Manual</JoinMethod><UseCentralReporting>WaitingForApproval</UseCentralReporting><CMStatus>Enable</CMStatus></EnableCloudCentralManagement></Response>' }
                }
            }
            else {
                [PSCustomObject]@{ Content = $script:SetOkArchive }
            }
        }

        Set-SfosCentralManagement -UseCentralReporting Enable @conn -Confirm:$false -WarningVariable warnings -WarningAction SilentlyContinue

        $warnings.Count | Should -BeGreaterThan 0
        ($warnings | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'WaitingForApproval'
        ($warnings | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'UseCentralReporting'
    }

    It 'a 501 on the update itself throws naming the code' {
        $script:getCalls = 0
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:BeforeState }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><EnableCloudCentralManagement><Status code="501">Configuration parameters validation failed.</Status></EnableCloudCentralManagement></Response>' }
            }
        }

        { Set-SfosCentralManagement -UseCentralReporting Disable @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf allows the read-first existing-object check but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -MockWith {
            [PSCustomObject]@{ Content = $script:BeforeState }
        }

        Set-SfosCentralManagement -CMStatus Disable @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -Times 1 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.SophosCentral -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}
