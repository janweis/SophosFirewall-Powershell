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

Describe 'Get-SfosApplicationFilterPolicy - XML parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses Name, Description, DefaultAction, MicroAppSupport and a nested Rule' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>BranchOfficeApps</Name><Description>Test policy</Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
        }

        $result = Get-SfosApplicationFilterPolicy @conn

        $result.Name | Should -Be 'BranchOfficeApps'
        $result.Description | Should -Be 'Test policy'
        $result.DefaultAction | Should -Be 'Allow'
        $result.MicroAppSupport | Should -Be 'True'
        $result.RuleList.Count | Should -Be 1
        $result.RuleList[0].SelectAllRule | Should -Be 'Disable'
        $result.RuleList[0].ApplicationList | Should -Be @('Lantern')
        $result.RuleList[0].Action | Should -Be 'Deny'
        $result.RuleList[0].Schedule | Should -Be 'All The Time'
    }

    It 'returns RuleList as @() for a policy with no RuleList element at all (measured shape)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>EmptyPolicy</Name><Description></Description><DefaultAction>Deny</DefaultAction><MicroAppSupport>True</MicroAppSupport></ApplicationFilterPolicy></Response>' }
        }

        $result = Get-SfosApplicationFilterPolicy @conn
        @($result.RuleList).Count | Should -Be 0
    }
}

Describe 'Get-SfosApplicationObject - XML parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses Name, SelectAllRule and a multi-entry ApplicationList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Name>KnownProxyApp</Name><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application><Application>TurboVPN</Application></ApplicationList><SmartFilter></SmartFilter></ApplicationObject></Response>' }
        }

        $result = Get-SfosApplicationObject @conn

        $result.Name | Should -Be 'KnownProxyApp'
        $result.SelectAllRule | Should -Be 'Disable'
        $result.ApplicationList | Should -Be @('Lantern', 'TurboVPN')
    }
}

Describe 'Get-SfosApplicationFilterCategory - XML parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses Name, QoSPolicy, BandwidthUsageType, Description and a nested ApplicationSettings override' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy><BandwidthUsageType>Individual</BandwidthUsageType><Description>Mobile apps category</Description><ApplicationSettings><Application><Name>Instagram</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy></Application></ApplicationSettings></ApplicationFilterCategory></Response>' }
        }

        $result = Get-SfosApplicationFilterCategory @conn

        $result.Name | Should -Be 'Mobile Applications'
        $result.QoSPolicy | Should -Be 'Streaming Video - Limit to SD Quality'
        $result.BandwidthUsageType | Should -Be 'Individual'
        $result.ApplicationSettings.Count | Should -Be 1
        $result.ApplicationSettings[0].Name | Should -Be 'Instagram'
        $result.ApplicationSettings[0].QoSPolicy | Should -Be 'Streaming Video - Limit to SD Quality'
    }

    It 'returns ApplicationSettings as @() when the category has no per-application override' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Gaming</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description></Description></ApplicationFilterCategory></Response>' }
        }

        $result = Get-SfosApplicationFilterCategory @conn
        @($result.ApplicationSettings).Count | Should -Be 0
    }
}

Describe 'Get-SfosApplicationClassificationAssignment - XML parsing and client-side filtering' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        # Measured: server-side filtering is a no-op for both Application and Classification
        # keys on this entity, so the mock always returns every row.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassificationAssignment transactionid=""><Application>10Web</Application><Classification>New</Classification></ApplicationClassificationAssignment><ApplicationClassificationAssignment transactionid=""><Application>1Password</Application><Classification>New</Classification></ApplicationClassificationAssignment></Response>' }
        }
    }

    It 'parses every Application/Classification pair' {
        $result = @(Get-SfosApplicationClassificationAssignment @conn)
        $result.Count | Should -Be 2
        $result[0].Application | Should -Be '10Web'
        $result[0].Classification | Should -Be 'New'
    }

    It 'filters client-side on -ApplicationLike, since server-side filtering is a no-op for this entity' {
        $result = @(Get-SfosApplicationClassificationAssignment -ApplicationLike '10Web' @conn)
        $result.Count | Should -Be 1
        $result[0].Application | Should -Be '10Web'
    }
}

Describe 'Get-SfosApplicationClassification - XML parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses ACTION On' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassification transactionid=""><ACTION>On</ACTION></ApplicationClassification></Response>' }
        }

        (Get-SfosApplicationClassification @conn).ACTION | Should -Be 'On'
    }

    It 'throws on an ACTION value that is neither On nor Off' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassification transactionid=""><ACTION>Maybe</ACTION></ApplicationClassification></Response>' }
        }

        { Get-SfosApplicationClassification @conn } | Should -Throw '*unrecognised*'
    }
}

Describe 'New-SfosApplicationObject - XML generation and client-side guard' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'builds the add XML for a Disable/Application-mode object' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><ApplicationObject><Status code="200">Configuration applied successfully.</Status></ApplicationObject></Response>' }
        }

        New-SfosApplicationObject -Name 'KnownProxyApp' -SelectAllRule Disable -Application 'Lantern' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Name>KnownProxyApp</Name>' -and
            $InnerXml -match '<SelectAllRule>Disable</SelectAllRule>' -and
            $InnerXml -match '<ApplicationList><Application>Lantern</Application></ApplicationList>'
        }
    }

    It 'throws client-side when SelectAllRule Disable has no Application entry, without calling the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications

        { New-SfosApplicationObject -Name 'Empty' -SelectAllRule Disable @conn -Confirm:$false } | Should -Throw '*at least one -Application entry*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 0 -Exactly
    }
}

Describe 'Set-SfosApplicationObject - Read-Modify-Write preservation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'keeps the existing ApplicationList when only SmartFilter is changed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Name>KnownProxyApp</Name><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application><Application>TurboVPN</Application></ApplicationList><SmartFilter></SmartFilter></ApplicationObject></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationObject><Status code="200">Configuration applied successfully.</Status></ApplicationObject></Response>' }
            }
        }

        Set-SfosApplicationObject -Name 'KnownProxyApp' -SmartFilter 'unused' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ApplicationList><Application>Lantern</Application><Application>TurboVPN</Application></ApplicationList>' -and
            $InnerXml -match '<SmartFilter>unused</SmartFilter>'
        }
    }

    It 'throws "was not found" for a nonexistent object' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Status>No. of records Zero.</Status></ApplicationObject></Response>' }
        }

        { Set-SfosApplicationObject -Name 'DoesNotExist' -SmartFilter 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'throws client-side rather than sending a Disable object with an empty ApplicationList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Name>KnownProxyApp</Name><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application></ApplicationList><SmartFilter></SmartFilter></ApplicationObject></Response>' }
        }

        { Set-SfosApplicationObject -Name 'KnownProxyApp' -Application @() @conn -Confirm:$false } | Should -Throw '*no -Application entries*'
    }
}

Describe 'Remove-SfosApplicationObject' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws "was not found" without attempting a Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Status>No. of records Zero.</Status></ApplicationObject></Response>' }
        }

        { Remove-SfosApplicationObject -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
    }

    It 'sends the Remove XML with the escaped Name for an existing object' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationObject transactionid=""><Name>Proxy &amp; VPN</Name><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application></ApplicationList><SmartFilter></SmartFilter></ApplicationObject></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationObject><Status code="200">Configuration applied successfully.</Status></ApplicationObject></Response>' }
            }
        }

        Remove-SfosApplicationObject -Name 'Proxy & VPN' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Remove><ApplicationObject><Name>Proxy &amp; VPN</Name></ApplicationObject></Remove>'
        }
    }
}

Describe 'New-SfosApplicationFilterPolicyRule - InputObject editing path' {

    It 'changes only the bound parameter, preserving every other field from a piped -InputObject' {
        $existingRule = [PSCustomObject]@{
            SelectAllRule       = 'Disable'
            CategoryList        = @()
            RiskList            = @()
            CharacteristicsList = @()
            TechnologyList      = @()
            ApplicationList     = @('Lantern')
            SmartFilter         = ''
            Action              = 'Deny'
            Schedule            = 'All The Time'
        }

        $edited = $existingRule | New-SfosApplicationFilterPolicyRule -Action 'Allow'

        $edited.Action | Should -Be 'Allow'
        $edited.SelectAllRule | Should -Be 'Disable'
        $edited.ApplicationList | Should -Be @('Lantern')
        $edited.Schedule | Should -Be 'All The Time'
    }

    It 'accepts -InputObject as a direct parameter as well as via the pipeline' {
        $existingRule = [PSCustomObject]@{
            SelectAllRule       = 'Enable'
            CategoryList        = @('Gaming')
            RiskList            = @()
            CharacteristicsList = @()
            TechnologyList      = @()
            ApplicationList     = @()
            SmartFilter         = ''
            Action              = 'Deny'
            Schedule            = 'All The Time'
        }

        $edited = New-SfosApplicationFilterPolicyRule -InputObject $existingRule -Schedule 'Work Hours'

        $edited.Schedule | Should -Be 'Work Hours'
        $edited.CategoryList | Should -Be @('Gaming')
        $edited.SelectAllRule | Should -Be 'Enable'
    }
}

Describe 'Add-SfosApplicationFilterPolicyRule - preserves existing rules while appending' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends a RuleList containing both the existing rule and the new one' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>BranchOfficeApps</Name><Description></Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Existing1</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="200">Configuration applied successfully.</Status></ApplicationFilterPolicy></Response>' }
            }
        }

        $newRule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'NewApp' -Action Allow

        Add-SfosApplicationFilterPolicyRule -Name 'BranchOfficeApps' -Rule $newRule @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ApplicationList><Application>Existing1</Application></ApplicationList>' -and
            $InnerXml -match '<ApplicationList><Application>NewApp</Application></ApplicationList>' -and
            ([regex]::Matches($InnerXml, '<Rule>').Count -eq 2)
        }
    }

    It 'throws "was not found" for a nonexistent policy' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Status>No. of records Zero.</Status></ApplicationFilterPolicy></Response>' }
        }

        $newRule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'NewApp'

        { Add-SfosApplicationFilterPolicyRule -Name 'DoesNotExist' -Rule $newRule @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Remove-SfosApplicationFilterPolicyRule - RuleList preservation and confirm-after-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        $script:RemoveRuleGetCount = 0
    }

    It 'throws when Index is out of range, without ever calling Set' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>OneRulePolicy</Name><Description></Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>OnlyApp</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
        }

        { Remove-SfosApplicationFilterPolicyRule -Name 'OneRulePolicy' -Index 5 @conn -Confirm:$false } | Should -Throw '*out of range*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
    }

    It 'removes only the targeted rule and resends the remaining one unchanged' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                $script:RemoveRuleGetCount++
                if ($script:RemoveRuleGetCount -eq 1) {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>TwoRulePolicy</Name><Description></Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>AppA</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>AppB</Application></ApplicationList><SmartFilter></SmartFilter><Action>Allow</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>TwoRulePolicy</Name><Description></Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>AppB</Application></ApplicationList><SmartFilter></SmartFilter><Action>Allow</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="200">Configuration applied successfully.</Status></ApplicationFilterPolicy></Response>' }
            }
        }

        Remove-SfosApplicationFilterPolicyRule -Name 'TwoRulePolicy' -Index 0 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Application>AppB</Application>' -and
            $InnerXml -notmatch '<Application>AppA</Application>'
        }
    }

    It 'throws when the follow-up Get still reports the original rule count (a 200 that changed nothing)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                # Both reads return the same 2-rule state - the removal did not take effect.
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>StuckPolicy</Name><Description></Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>AppA</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>AppB</Application></ApplicationList><SmartFilter></SmartFilter><Action>Allow</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="200">Configuration applied successfully.</Status></ApplicationFilterPolicy></Response>' }
            }
        }

        { Remove-SfosApplicationFilterPolicyRule -Name 'StuckPolicy' -Index 0 @conn -Confirm:$false } | Should -Throw '*instead of the expected*'
    }
}

Describe 'Set-SfosApplicationFilterPolicy - Read-Modify-Write preservation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'keeps RuleList and DefaultAction intact when only Description is changed' {
        # The most valuable test class per this suite's own framework doc: this entity
        # replaces itself wholesale on update, so an update that forgets RuleList would
        # silently delete every rule while reporting 200.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Name>BranchOfficeApps</Name><Description>Old description</Description><DefaultAction>Allow</DefaultAction><MicroAppSupport>True</MicroAppSupport><RuleList><Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule></RuleList></ApplicationFilterPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="200">Configuration applied successfully.</Status></ApplicationFilterPolicy></Response>' }
            }
        }

        Set-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -Description 'New description' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Description>New description</Description>' -and
            $InnerXml -match '<DefaultAction>Allow</DefaultAction>' -and
            $InnerXml -match '<Rule><SelectAllRule>Disable</SelectAllRule><ApplicationList><Application>Lantern</Application></ApplicationList><SmartFilter></SmartFilter><Action>Deny</Action><Schedule>All The Time</Schedule></Rule>'
        }
    }

    It 'throws "was not found" for a nonexistent policy' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Status>No. of records Zero.</Status></ApplicationFilterPolicy></Response>' }
        }

        { Set-SfosApplicationFilterPolicy -Name 'DoesNotExist' -Description 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Set-SfosApplicationClassificationAssignment' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends the update XML for an existing assignment' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassificationAssignment transactionid=""><Application>10Web</Application><Classification>New</Classification></ApplicationClassificationAssignment></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationClassificationAssignment><Status code="200">Configuration applied successfully.</Status></ApplicationClassificationAssignment></Response>' }
            }
        }

        Set-SfosApplicationClassificationAssignment -Application '10Web' -Classification 'New' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Application>10Web</Application>' -and
            $InnerXml -match '<Classification>New</Classification>'
        }
    }

    It 'throws "was not found" for an application with no assignment' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationClassificationAssignment transactionid=""><Status>No. of records Zero.</Status></ApplicationClassificationAssignment></Response>' }
        }

        { Set-SfosApplicationClassificationAssignment -Application 'DoesNotExist' -Classification 'New' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Set-SfosApplicationClassificationAssignmentBatch - edge cases' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'does not call the API when no input objects were collected' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications

        @() | Set-SfosApplicationClassificationAssignmentBatch @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 0 -Exactly
    }

    It 'throws when an input object is missing Application or Classification' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications

        { [PSCustomObject]@{ Application = '10Web' } | Set-SfosApplicationClassificationAssignmentBatch @conn -Confirm:$false } |
            Should -Throw '*Application and Classification*'
    }
}

Describe 'Add-SfosApplicationFilterCategoryMember - QoSPolicy None client-side guard' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws at parameter binding for -QoSPolicy None and never calls the API' {
        # -QoSPolicy 'None' is a silent no-op on the firewall (200, nothing stored), so it
        # must be rejected before any API call.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications

        { Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -QoSPolicy 'None' @conn -Confirm:$false } |
            Should -Throw '*silent no-op*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 0 -Exactly
    }

    It 'upserts a new member while preserving an existing per-application override' {
        # Two existing/target entries deliberately, not one: on Windows PowerShell 5.1 a
        # genuine single-element array assigned through the '$x = if (cond) { @($y) } else
        # {...}' idiom collapses back to a bare scalar, which would make this assertion fail
        # for reasons unrelated to what it actually checks (Read-Modify-Write preservation).
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description>Mobile apps</Description><ApplicationSettings><Application><Name>WhatsApp</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy></Application></ApplicationSettings></ApplicationFilterCategory></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterCategory><Status code="200">Configuration applied successfully.</Status></ApplicationFilterCategory></Response>' }
            }
        }

        Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -QoSPolicy 'Streaming Video - Limit to SD Quality' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Application><Name>WhatsApp</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy></Application>' -and
            $InnerXml -match '<Application><Name>Instagram</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy></Application>' -and
            $InnerXml -match '<Description>Mobile apps</Description>'
        }
    }
}

Describe 'Set-SfosApplicationFilterCategory - single-element ApplicationSettings' {
    # @() must wrap the whole if/else: on Windows PowerShell 5.1, assigning straight from
    # `if (...) { @(A) } else { @(B) }` collapses a genuine single-element array back to a
    # bare scalar, which has no .Count, so the whole ApplicationSettings wrapper is silently
    # omitted from the request - the first per-app override of a category could never be
    # added on 5.1. This test asserts the correct behavior on both engines.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'adds the first override to a category without any, on both engines' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description>Mobile apps</Description></ApplicationFilterCategory></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterCategory><Status code="200">Configuration applied successfully.</Status></ApplicationFilterCategory></Response>' }
            }
        }

        Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -QoSPolicy 'Streaming Video - Limit to SD Quality' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Application><Name>Instagram</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy></Application>'
        }
    }
}

Describe 'Remove-SfosApplicationFilterCategoryMember' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws when the application has no override on the category, without calling Set' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description></Description></ApplicationFilterCategory></Response>' }
        }

        { Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' @conn -Confirm:$false } |
            Should -Throw '*has no QoS override*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
    }

    It 'throws when the member is still present after the confirming Get (a 200 that changed nothing)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            if ($InnerXml -match '<Get>') {
                # Every read still shows the override - the removal did not take effect.
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description></Description><ApplicationSettings><Application><Name>Instagram</Name><QoSPolicy>Streaming Video - Limit to SD Quality</QoSPolicy></Application></ApplicationSettings></ApplicationFilterCategory></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ApplicationFilterCategory><Status code="200">Configuration applied successfully.</Status></ApplicationFilterCategory></Response>' }
            }
        }

        { Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' @conn -Confirm:$false } |
            Should -Throw '*is still present*'
    }
}

Describe 'Set-SfosApplicationFilterCategory - additional validation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws on an invalid BandwidthUsageType value, without calling Set' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Name>Mobile Applications</Name><QoSPolicy>None</QoSPolicy><BandwidthUsageType></BandwidthUsageType><Description></Description></ApplicationFilterCategory></Response>' }
        }

        { Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -BandwidthUsageType 'Bogus' @conn -Confirm:$false } |
            Should -Throw "*'Individual', 'Shared'*"

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
    }

    It 'throws "was not found" for a nonexistent category' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterCategory transactionid=""><Status>No. of records Zero.</Status></ApplicationFilterCategory></Response>' }
        }

        { Set-SfosApplicationFilterCategory -Name 'DoesNotExist' -QoSPolicy 'None' @conn -Confirm:$false } | Should -Throw '*was not found*'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ApplicationFilterPolicy transactionid=""><Status>No. of records Zero.</Status></ApplicationFilterPolicy></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosApplicationFilterPolicy -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosApplicationFilterPolicy | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on the begin-block pipeline path (New-SfosApplicationFilterPolicy)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -MockWith {
            [PSCustomObject]@{ Content = '<Response><ApplicationFilterPolicy><Status code="200">Configuration applied successfully.</Status></ApplicationFilterPolicy></Response>' }
        }
        $s2 = Get-SfosSession -Name 'fw2'
        New-SfosApplicationFilterPolicy -Name 'CrossFwPolicy' -DefaultAction Allow -Session 'fw2' -Confirm:$false
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<Name>CrossFwPolicy</Name>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosApplicationFilterPolicy -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Applications -Times 0 -Exactly
    }
}
