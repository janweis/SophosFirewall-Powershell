#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Profiles module.

.DESCRIPTION
    Tests cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 20 exported
    functions with their identifying and connection parameters; inner XML
    generation (root element, operation, name) for every New/Set/Remove cmdlet
    across all five entities; the read-modify-write path of Set-SfosSchedule;
    the New-SfosDecryptionProfile TLS version pairing and omitted IsDefault; the
    New-SfosAdministrationProfile least-privilege default; shared status-parsing
    error paths (5xx throws, login failure throws, "No. of records Zero." yields
    an empty array); and the -Session parameter against a named, non-default
    session.

.NOTES
    Minimum supported PowerShell version: 5.1

    Under Windows PowerShell 5.1 restrict $env:PSModulePath in a child process
    before importing Pester (PowerShell 7's module folders otherwise collide
    with Pester 6 type data), then Invoke-Pester on this file.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Profiles\SophosFirewall.Profiles.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Profiles module should load' {
        Get-Module SophosFirewall.Profiles | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 20 functions' {
        (Get-Module SophosFirewall.Profiles).ExportedFunctions.Count | Should -Be 20
    }

    It 'Manifest FunctionsToExport should list exactly 20 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Profiles\SophosFirewall.Profiles.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 20
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosSchedule'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosSchedule'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosSchedule'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosSchedule'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosAccessTimePolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosAccessTimePolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosAccessTimePolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosAccessTimePolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosDataTransferPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosDataTransferPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosDataTransferPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosDataTransferPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosDecryptionProfile'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosDecryptionProfile'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosDecryptionProfile'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosDecryptionProfile'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosAdministrationProfile'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosAdministrationProfile'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosAdministrationProfile'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosAdministrationProfile'; IdParam = 'Name'; Mandatory = $true }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with an identifying parameter <IdParam> and the six connection parameters' -TestCases $script:CmdletParameterCases {
        param($Function, $IdParam, $Mandatory)

        $cmd = Get-Command $Function -Module SophosFirewall.Profiles -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"

        $cmd.Parameters.Keys | Should -Contain $IdParam
        $isMandatory = ($cmd.Parameters[$IdParam].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory }) -contains $true
        $isMandatory | Should -Be $Mandatory

        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
    }
}

Describe 'Schedule - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosSchedule sends an add operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule><Status code="200">Configuration applied successfully.</Status></Schedule></Response>' }
        }

        New-SfosSchedule -Name 'Weekend Allhours' -Type Recurring -Days 'Saturday' -StartTime '00:00' -StopTime '23:59' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Schedule>' -and
            $InnerXml -match '<Name>Weekend Allhours</Name>'
        }
    }

    It 'Remove-SfosSchedule sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule><Status code="200">Configuration applied successfully.</Status></Schedule></Response>' }
        }

        Remove-SfosSchedule -Name 'Weekend Allhours' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<Schedule>' -and
            $InnerXml -match '<Name>Weekend Allhours</Name>'
        }
    }
}

Describe 'Set-SfosSchedule - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule transactionid=""><Name>Night shift</Name><Description>Existing desc</Description><Type>Recurring</Type><ScheduleDetails><ScheduleDetail><Days>Week Days</Days><StartTime>22:00</StartTime><StopTime>06:00</StopTime></ScheduleDetail></ScheduleDetails></Schedule></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule><Status code="200">Configuration applied successfully.</Status></Schedule></Response>' }
            }
        }
    }

    It 'sends an update operation carrying the name' {
        Set-SfosSchedule -Name 'Night shift' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Schedule>' -and
            $InnerXml -match '<Name>Night shift</Name>'
        }
    }

    It 'changes only the field the caller passed' {
        Set-SfosSchedule -Name 'Night shift' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Description>Updated</Description>'
        }
    }

    It 'keeps the time windows the caller did not pass' {
        Set-SfosSchedule -Name 'Night shift' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Days>Week Days</Days>' -and
            $InnerXml -match '<StartTime>22:00</StartTime>' -and
            $InnerXml -match '<StopTime>06:00</StopTime>'
        }
    }
}

Describe 'AccessTimePolicy - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosAccessTimePolicy sends an add operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AccessTimePolicy><Status code="200">Configuration applied successfully.</Status></AccessTimePolicy></Response>' }
        }

        New-SfosAccessTimePolicy -Name 'Allowed Work Hours' -Strategy Allow -Schedule 'Work hours' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AccessTimePolicy>' -and
            $InnerXml -match '<Name>Allowed Work Hours</Name>'
        }
    }

    It 'Set-SfosAccessTimePolicy sends an update operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AccessTimePolicy transactionid=""><Name>Allowed Work Hours</Name><Strategy>Allow</Strategy><Schedule>Work hours</Schedule></AccessTimePolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AccessTimePolicy><Status code="200">Configuration applied successfully.</Status></AccessTimePolicy></Response>' }
            }
        }

        Set-SfosAccessTimePolicy -Name 'Allowed Work Hours' -Strategy Deny @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<AccessTimePolicy>' -and
            $InnerXml -match '<Name>Allowed Work Hours</Name>' -and
            $InnerXml -match '<Strategy>Deny</Strategy>'
        }
    }

    It 'Remove-SfosAccessTimePolicy sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AccessTimePolicy><Status code="200">Configuration applied successfully.</Status></AccessTimePolicy></Response>' }
        }

        Remove-SfosAccessTimePolicy -Name 'Allowed Work Hours' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AccessTimePolicy>' -and
            $InnerXml -match '<Name>Allowed Work Hours</Name>'
        }
    }
}

Describe 'DataTransferPolicy - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosDataTransferPolicy sends an add operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataTransferPolicy><Status code="200">Configuration applied successfully.</Status></DataTransferPolicy></Response>' }
        }

        New-SfosDataTransferPolicy -Name '100 MB Cap' -RestrictionBasedOn TotalDataTransfer -CycleType NonCyclic @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<DataTransferPolicy>' -and
            $InnerXml -match '<Name>100 MB Cap</Name>'
        }
    }

    It 'Set-SfosDataTransferPolicy sends an update operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataTransferPolicy transactionid=""><Name>100 MB Cap</Name><RestrictionBasedOn>TotalDataTransfer</RestrictionBasedOn><CycleType>NonCyclic</CycleType></DataTransferPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataTransferPolicy><Status code="200">Configuration applied successfully.</Status></DataTransferPolicy></Response>' }
            }
        }

        Set-SfosDataTransferPolicy -Name '100 MB Cap' -RestrictionBasedOn TotalDataTransfer -CycleType NonCyclic -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<DataTransferPolicy>' -and
            $InnerXml -match '<Name>100 MB Cap</Name>'
        }
    }

    It 'Remove-SfosDataTransferPolicy sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataTransferPolicy><Status code="200">Configuration applied successfully.</Status></DataTransferPolicy></Response>' }
        }

        Remove-SfosDataTransferPolicy -Name '100 MB Cap' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<DataTransferPolicy>' -and
            $InnerXml -match '<Name>100 MB Cap</Name>'
        }
    }
}

Describe 'DecryptionProfile - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosDecryptionProfile sends an add operation carrying the name, without IsDefault' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DecryptionProfile><Status code="200">Configuration applied successfully.</Status></DecryptionProfile></Response>' }
        }

        New-SfosDecryptionProfile -Name 'Custom TLS' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<DecryptionProfile>' -and
            $InnerXml -match '<Name>Custom TLS</Name>' -and
            $InnerXml -notmatch '<IsDefault>'
        }
    }

    It 'New-SfosDecryptionProfile fills in the missing half of the TLS version pair' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DecryptionProfile><Status code="200">Configuration applied successfully.</Status></DecryptionProfile></Response>' }
        }

        New-SfosDecryptionProfile -Name 'Custom TLS' -MinTLSVersion 'TLS v1.2' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<MinTLSVersion>TLS v1.2</MinTLSVersion>' -and
            $InnerXml -match '<MaxTLSVersion>Maximum supported</MaxTLSVersion>'
        }
    }

    It 'Set-SfosDecryptionProfile sends an update operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DecryptionProfile transactionid=""><Name>Custom TLS</Name><Description>Existing</Description></DecryptionProfile></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DecryptionProfile><Status code="200">Configuration applied successfully.</Status></DecryptionProfile></Response>' }
            }
        }

        Set-SfosDecryptionProfile -Name 'Custom TLS' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<DecryptionProfile>' -and
            $InnerXml -match '<Name>Custom TLS</Name>'
        }
    }

    It 'Remove-SfosDecryptionProfile sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DecryptionProfile><Status code="200">Configuration applied successfully.</Status></DecryptionProfile></Response>' }
        }

        Remove-SfosDecryptionProfile -Name 'Custom TLS' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<DecryptionProfile>' -and
            $InnerXml -match '<Name>Custom TLS</Name>'
        }
    }
}

Describe 'AdministrationProfile - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosAdministrationProfile sends an add operation carrying the name, defaulting unset areas to None' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdministrationProfile><Status code="200">Configuration applied successfully.</Status></AdministrationProfile></Response>' }
        }

        New-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Write @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AdministrationProfile>' -and
            $InnerXml -match '<Name>Report Viewer</Name>' -and
            $InnerXml -match '<Dashboard>Read-Write</Dashboard>' -and
            $InnerXml -match '<Wizard>None</Wizard>'
        }
    }

    It 'Set-SfosAdministrationProfile sends an update operation carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdministrationProfile transactionid=""><Name>Report Viewer</Name><Dashboard>Read-Only</Dashboard></AdministrationProfile></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdministrationProfile><Status code="200">Configuration applied successfully.</Status></AdministrationProfile></Response>' }
            }
        }

        Set-SfosAdministrationProfile -Name 'Report Viewer' -Dashboard Read-Write @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<AdministrationProfile>' -and
            $InnerXml -match '<Name>Report Viewer</Name>' -and
            $InnerXml -match '<Dashboard>Read-Write</Dashboard>'
        }
    }

    It 'Remove-SfosAdministrationProfile sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdministrationProfile><Status code="200">Configuration applied successfully.</Status></AdministrationProfile></Response>' }
        }

        Remove-SfosAdministrationProfile -Name 'Report Viewer' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AdministrationProfile>' -and
            $InnerXml -match '<Name>Report Viewer</Name>'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule transactionid=""><Status code="529">Invalid XML request</Status></Schedule></Response>' }
        }

        { Get-SfosSchedule @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosSchedule @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule transactionid=""><Status>No. of records Zero.</Status></Schedule></Response>' }
        }

        $result = @(Get-SfosSchedule @conn)
        $result.Count | Should -Be 0
    }

    It 'Set-SfosSchedule throws when the target object does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule transactionid=""><Status>No. of records Zero.</Status></Schedule></Response>' }
        }

        { Set-SfosSchedule -Name 'Does not exist' -Description 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Session parameter (multi-session support)' {

    BeforeEach {
        $cred1 = [pscredential]::new('apiuser', (ConvertTo-SecureString 'pw1' -AsPlainText -Force))
        $cred2 = [pscredential]::new('apiuser', (ConvertTo-SecureString 'pw2' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred1 -Name 'fw1' | Out-Null
        Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred2 -Name 'fw2' -NoDefault | Out-Null

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Schedule transactionid=""><Status>No. of records Zero.</Status></Schedule></Response>' }
        }
    }

    AfterEach { Disconnect-SfosFirewall -All }

    It 'Resolves the named session instead of the ambient default' {
        Get-SfosSchedule -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosSchedule | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosSchedule -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Profiles -Times 0 -Exactly
    }
}
