#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Applications module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 20 exported
    functions; XML-generation checks for New-SfosApplicationFilterPolicy (including a
    nested Rule built via New-SfosApplicationFilterPolicyRule) and
    Set-SfosApplicationClassificationAssignmentBatch (asserting the measured lower-case
    <app>/<class> wire element names, distinct from the single-assignment operation's
    <Application>/<Classification>); Set-SfosApplicationClassification confirm-after-write
    behaviour; XML escaping; the ApplicationFilterCategory Description silent-no-op
    detection; the misleading 503 "already exists" response measured on Remove of a
    nonexistent object; and the shared status-parsing error paths (5xx throws, a failed
    login with no entity status throws, "No. of records Zero." yields @()).

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/
    Context, never at the script's top level - a top-level $script: variable set outside
    any Describe block was found unreliable during Pester's Run phase in this project (it
    populated fine during Discovery but came back empty once the It blocks actually ran).
    This file follows the same per-Describe BeforeAll pattern as the sibling
    IntrusionPrevention test suite.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6,
    once loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its
    type data collides with the one PS 5.1 already loaded at startup ("The member
    AuditToString is already present", etc.) - a machine/environment issue, reproducible
    against any test file in this repo, not specific to this suite. Work around it by
    restricting $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Applications.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Applications\SophosFirewall.Applications.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Applications module should load' {
        Get-Module SophosFirewall.Applications | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 20 functions' {
        (Get-Module SophosFirewall.Applications).ExportedFunctions.Count | Should -Be 20
    }

    It 'Manifest FunctionsToExport should list exactly 20 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Applications\SophosFirewall.Applications.psd1'

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

        $manifest.ExportedFunctions.Count | Should -Be 20
    }

    It 'Every documented function exists' {
        $expected = @(
            'Add-SfosApplicationFilterCategoryMember', 'Add-SfosApplicationFilterPolicyRule',
            'Get-SfosApplicationClassification', 'Get-SfosApplicationClassificationAssignment',
            'Get-SfosApplicationFilterCategory', 'Get-SfosApplicationFilterPolicy',
            'Get-SfosApplicationObject', 'New-SfosApplicationFilterPolicy',
            'New-SfosApplicationFilterPolicyRule', 'New-SfosApplicationObject',
            'Remove-SfosApplicationFilterCategoryMember', 'Remove-SfosApplicationFilterPolicy',
            'Remove-SfosApplicationFilterPolicyRule', 'Remove-SfosApplicationObject',
            'Set-SfosApplicationClassification', 'Set-SfosApplicationClassificationAssignment',
            'Set-SfosApplicationClassificationAssignmentBatch', 'Set-SfosApplicationFilterCategory',
            'Set-SfosApplicationFilterPolicy', 'Set-SfosApplicationObject'
        )
        foreach ($name in $expected) {
            Get-Command $name -Module SophosFirewall.Applications -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$name should be exported"
        }
    }
}

Describe 'New-SfosApplicationFilterPolicy - XML generation with a nested Rule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="200">Configuration applied successfully.</Status></ApplicationFilterPolicy></Response>' }
        }
    }

    It 'builds the full nested Rule XML for a Disable/Application-mode rule' {
        $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'Lantern' -Action Deny -Schedule 'All The Time'
        New-SfosApplicationFilterPolicy -Name 'TestPolicy' -Description 'Test policy' -DefaultAction Allow -Rule $rule @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Name>TestPolicy</Name>' -and
            $InnerXml -match '<Description>Test policy</Description>' -and
            $InnerXml -match '<DefaultAction>Allow</DefaultAction>' -and
            $InnerXml -match '<MicroAppSupport>True</MicroAppSupport>' -and
            $InnerXml -match '<SelectAllRule>Disable</SelectAllRule>' -and
            $InnerXml -match '<ApplicationList><Application>Lantern</Application></ApplicationList>' -and
            $InnerXml -match '<Action>Deny</Action>' -and
            $InnerXml -match '<Schedule>All The Time</Schedule>' -and
            $InnerXml -notmatch '<Template>'
        }
    }

    It 'creates a policy with an empty RuleList when -Rule is omitted' {
        New-SfosApplicationFilterPolicy -Name 'EmptyPolicy' -DefaultAction Deny @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<RuleList>\s*</RuleList>'
        }
    }

    It 'escapes Name and Description' {
        New-SfosApplicationFilterPolicy -Name 'Esc' -Description 'Smith & Sons "Test" <ok>' -DefaultAction Allow @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Description>Smith &amp; Sons &quot;Test&quot; &lt;ok&gt;</Description>'
        }
    }

    It 'builds an Enable/Category-mode rule without an ApplicationList entry' {
        $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Enable -Category 'Gaming' -Action Deny
        New-SfosApplicationFilterPolicy -Name 'GamingBlock' -DefaultAction Allow -Rule $rule @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<SelectAllRule>Enable</SelectAllRule>' -and
            $InnerXml -match '<CategoryList><Category>Gaming</Category></CategoryList>' -and
            $InnerXml -match '<ApplicationList></ApplicationList>'
        }
    }
}

Describe 'New-SfosApplicationFilterPolicyRule - client-side guard' {
    It 'throws when SelectAllRule Disable has no Application entry' {
        { New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Action Deny } | Should -Throw '*at least one -Application entry*'
    }
}

Describe 'Set-SfosApplicationClassificationAssignmentBatch - lower-case wire element names' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends lower-case app/class elements, not the single-assignment Application/Classification names' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><ApplicationClassificationBatchAssignment><Status code="200">Configuration applied successfully.</Status></ApplicationClassificationBatchAssignment></Response>' }
        }

        @(
            [PSCustomObject]@{ Application = '10Web'; Classification = 'New' }
            [PSCustomObject]@{ Application = '1Password'; Classification = 'New' }
        ) | Set-SfosApplicationClassificationAssignmentBatch @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ApplicationClassificationBatchAssignment>' -and
            $InnerXml -match '<ClassAssignmentList>' -and
            $InnerXml -match '<ClassAssignment><app>10Web</app><class>New</class></ClassAssignment>' -and
            $InnerXml -match '<ClassAssignment><app>1Password</app><class>New</class></ClassAssignment>' -and
            $InnerXml -notmatch '<Application>' -and
            $InnerXml -notmatch '<Classification>'
        }
    }
}

Describe 'Set-SfosApplicationClassification' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends the expected update XML and confirms via a follow-up Get' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassification transactionid=""><ACTION>Off</ACTION></ApplicationClassification></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationClassification><Status code="200">Configuration applied successfully.</Status></ApplicationClassification></Response>' }
            }
        }

        Set-SfosApplicationClassification -ACTION Off @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<ACTION>Off</ACTION>'
        }
    }

    It 'throws when the confirming Get does not match the requested value' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassification transactionid=""><ACTION>On</ACTION></ApplicationClassification></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationClassification><Status code="200">Configuration applied successfully.</Status></ApplicationClassification></Response>' }
            }
        }

        { Set-SfosApplicationClassification -ACTION Off @conn -Confirm:$false } | Should -Throw '*could not be confirmed*'
    }

    It 'throws on a coded API error (invalid ACTION rejected by the firewall)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><ApplicationClassification><Status code="501">Configuration parameters validation failed.</Status></ApplicationClassification></Response>' }
        }

        { Set-SfosApplicationClassification -ACTION On @conn -Confirm:$false } | Should -Throw '*501*'
    }
}

Describe 'Set-SfosApplicationFilterCategory - Description silent no-op' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws when a requested Description change is not confirmed by the firewall' {
        # Measured: an update that changes only Description answers 200, but a following Get
        # shows the original text unchanged. Both the pre-read and the post-write confirm
        # read return the same (unchanged) Description here to reproduce that.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description>Old description</Description></ApplicationFilterCategory></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterCategory><Status code="200">Configuration applied successfully.</Status></ApplicationFilterCategory></Response>' }
            }
        }

        { Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -Description 'New description' @conn -Confirm:$false } | Should -Throw '*was not confirmed*'
    }

    It 'succeeds when Description is not part of the request' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description>Old description</Description></ApplicationFilterCategory></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterCategory><Status code="200">Configuration applied successfully.</Status></ApplicationFilterCategory></Response>' }
            }
        }

        { Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -QoSPolicy 'None' @conn -Confirm:$false } | Should -Not -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<QoSPolicy>None</QoSPolicy>'
        }
    }
}

Describe 'Remove-SfosApplicationFilterPolicy - the misleading 503 "already exists" response' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws "was not found" for a nonexistent policy without ever attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Status>No. of records Zero.</Status></ApplicationFilterPolicy></Response>' }
        }

        { Remove-SfosApplicationFilterPolicy -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
    }

    It 'throws on the real 503 response shape if Remove is rejected after the object was confirmed present' {
        # Measured live: removing a nonexistent object answers 503 "Operation failed. Entity
        # having same parameter details already exists." - reproduced here as the raw Remove
        # response to prove Assert-SfosApiReturnSuccess treats a 5xx as failure regardless.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>BranchOfficeApps</Name><Description></Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport></ApplicationFilterPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="503">Operation failed. Entity having same parameter details already exists.</Status></ApplicationFilterPolicy></Response>' }
            }
        }

        { Remove-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' @conn -Confirm:$false } | Should -Throw '*503*'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Status code="529">Invalid XML request</Status></ApplicationFilterPolicy></Response>' }
        }

        { Get-SfosApplicationFilterPolicy @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosApplicationFilterPolicy @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Status>No. of records Zero.</Status></ApplicationObject></Response>' }
        }

        $result = @(Get-SfosApplicationObject @conn)
        $result.Count | Should -Be 0
    }
}
