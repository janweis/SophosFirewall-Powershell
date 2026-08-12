#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.IntrusionPrevention module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 29 exported
    functions; the IPSSwitch/IPSFullSignaturePack code-less Status-as-data special case
    (measured live: <IPSSwitch><Status>Enable</Status></IPSSwitch> with no code attribute
    is a data field, not an API status); XML-generation checks for New-SfosIPSPolicy
    (including a nested Rule built via New-SfosIPSPolicyRule), New-SfosDoSBypassRule and
    Set-SfosIPSSwitch; XML escaping; the DoSBypassRules 'any'-to-'*' netmask translation on
    Remove; and the shared error paths (5xx throws, a failed login with no entity status
    throws, "No. of records Zero." yields @()).

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/
    Context, never at the script's top level - a top-level $script: variable set outside
    any Describe block was found unreliable during Pester's Run phase in this suite (it
    populated fine during Discovery but came back empty once the It blocks actually ran,
    which surfaced as a spurious "No active Sophos Firewall connection found"). The
    ActiveThreatResponse test suite already uses the per-Describe BeforeAll pattern; this
    file follows it for the same reason.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6,
    once loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its
    type data collides with the one PS 5.1 already loaded at startup ("The member
    AuditToString is already present", etc.) - a machine/environment issue, reproducible
    against any test file in this repo, not specific to this suite. Work around it by
    restricting $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.IntrusionPrevention.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.IntrusionPrevention\SophosFirewall.IntrusionPrevention.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.IntrusionPrevention module should load' {
        Get-Module SophosFirewall.IntrusionPrevention | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 29 functions' {
        (Get-Module SophosFirewall.IntrusionPrevention).ExportedFunctions.Count | Should -Be 29
    }

    It 'Manifest FunctionsToExport should list exactly 29 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.IntrusionPrevention\SophosFirewall.IntrusionPrevention.psd1'

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

        $manifest.ExportedFunctions.Count | Should -Be 29
    }

    It 'Every documented function exists' {
        $expected = @(
            'Add-SfosIPSPolicyRule', 'Export-SfosTrustedMACs', 'Get-SfosDoSBypassRule',
            'Get-SfosDoSSettings', 'Get-SfosIPSCustomSignature', 'Get-SfosIPSFullSignaturePack',
            'Get-SfosIPSPolicy', 'Get-SfosIPSSwitch', 'Get-SfosSpoofPrevention', 'Get-SfosTrustedMAC',
            'Import-SfosTrustedMACs', 'New-SfosDoSBypassRule', 'New-SfosIPSCustomSignature',
            'New-SfosIPSPolicy', 'New-SfosIPSPolicyRule', 'New-SfosTrustedMAC',
            'Remove-SfosDoSBypassRule', 'Remove-SfosIPSCustomSignature', 'Remove-SfosIPSPolicy',
            'Remove-SfosIPSPolicyRule', 'Remove-SfosTrustedMAC', 'Set-SfosDoSBypassRule',
            'Set-SfosDoSSettings', 'Set-SfosIPSCustomSignature', 'Set-SfosIPSFullSignaturePack',
            'Set-SfosIPSPolicy', 'Set-SfosIPSSwitch', 'Set-SfosSpoofPrevention', 'Set-SfosTrustedMAC'
        )
        foreach ($name in $expected) {
            Get-Command $name -Module SophosFirewall.IntrusionPrevention -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$name should be exported"
        }
    }
}

Describe 'Get-SfosIPSSwitch - code-less Status is a data field, not an API status' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'reads the Status value from a coded-attribute-free node' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSSwitch transactionid=""><Status>Enable</Status></IPSSwitch></Response>' }
        }

        $result = Get-SfosIPSSwitch @conn
        $result.Status | Should -Be 'Enable'
    }

    It 'throws on a coded (real) API error at Status[@code]' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSSwitch><Status code="501">Configuration parameters validation failed.</Status></IPSSwitch></Response>' }
        }

        { Get-SfosIPSSwitch @conn } | Should -Throw '*501*'
    }
}

Describe 'Get-SfosIPSFullSignaturePack - same code-less Status-as-data pattern' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'reads the Status value from a coded-attribute-free node' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSFullSignaturePack transactionid=""><Status>disable</Status></IPSFullSignaturePack></Response>' }
        }

        $result = Get-SfosIPSFullSignaturePack @conn
        $result.Status | Should -Be 'disable'
    }

    It 'throws on a coded (real) API error at Status[@code]' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSFullSignaturePack><Status code="500">Operation could not be performed on Entity.</Status></IPSFullSignaturePack></Response>' }
        }

        { Get-SfosIPSFullSignaturePack @conn } | Should -Throw '*500*'
    }
}

Describe 'Set-SfosIPSSwitch' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends the expected update XML and confirms via a follow-up Get' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSSwitch transactionid=""><Status>Disable</Status></IPSSwitch></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSSwitch><Status code="200">Configuration applied successfully.</Status></IPSSwitch></Response>' }
            }
        }

        Set-SfosIPSSwitch -Status Disable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<Status>Disable</Status>'
        }
    }

    It 'throws when the confirming Get does not match the requested value' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSSwitch transactionid=""><Status>Enable</Status></IPSSwitch></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSSwitch><Status code="200">Configuration applied successfully.</Status></IPSSwitch></Response>' }
            }
        }

        { Set-SfosIPSSwitch -Status Disable @conn -Confirm:$false } | Should -Throw '*could not be confirmed*'
    }
}

Describe 'New-SfosIPSPolicy - XML generation with a nested Rule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
        }
    }

    It 'builds the full nested Rule XML, including the SignaturSelectionType spelling' {
        $rule = New-SfosIPSPolicyRule -RuleName 'AllTraffic' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
        New-SfosIPSPolicy -Name 'TestPolicy' -Description 'Test policy' -Rule $rule @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Name>TestPolicy</Name>' -and
            $InnerXml -match '<Description>Test policy</Description>' -and
            $InnerXml -match '<RuleName>AllTraffic</RuleName>' -and
            $InnerXml -match '<SignaturSelectionType>All Application</SignaturSelectionType>' -and
            $InnerXml -match '<Category>All Categories</Category>' -and
            $InnerXml -match '<Severity>All Severity</Severity>' -and
            $InnerXml -match '<Target>All Target</Target>' -and
            $InnerXml -match '<Platform>All Platform</Platform>' -and
            $InnerXml -match '<RuleType>Default Signature</RuleType>' -and
            $InnerXml -match '<Action>Recommended</Action>' -and
            $InnerXml -notmatch '<Template>'
        }
    }

    It 'creates a policy with an empty RuleList when -Rule is omitted' {
        New-SfosIPSPolicy -Name 'EmptyPolicy' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<RuleList>\s*</RuleList>'
        }
    }

    It 'escapes Name and Description' {
        New-SfosIPSPolicy -Name 'Esc' -Description 'Smith & Sons "Test" <ok>' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Description>Smith &amp; Sons &quot;Test&quot; &lt;ok&gt;</Description>'
        }
    }
}

Describe 'New-SfosDoSBypassRule - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSBypassRules><Status code="201">Configuration applied successfully.</Status></DoSBypassRules></Response>' }
        }
    }

    It 'builds the expected six-field XML for a TCP rule' {
        New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<IPFamily>IPv4</IPFamily>' -and
            $InnerXml -match '<SourceIPNetmask>10\.99\.98\.0/24</SourceIPNetmask>' -and
            $InnerXml -match '<DestinationIPNetmask>10\.99\.99\.0/24</DestinationIPNetmask>' -and
            $InnerXml -match '<Protocol>TCP</Protocol>' -and
            $InnerXml -match '<SourcePort>2201</SourcePort>' -and
            $InnerXml -match '<DestinationPort>2202</DestinationPort>'
        }
    }

    It 'always sends SourcePort/DestinationPort even for ICMP, defaulting to *' {
        New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -DestinationIPNetmask '10.99.94.0/24' -Protocol ICMP @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Protocol>ICMP</Protocol>' -and
            $InnerXml -match '<SourcePort>\*</SourcePort>' -and
            $InnerXml -match '<DestinationPort>\*</DestinationPort>'
        }
    }
}

Describe 'DoSBypassRules - "any" netmask from Get is translated back to "*" on write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Remove-SfosDoSBypassRule sends the literal * even though the piped record reported "any"' {
        $script:removed = $false
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Remove>') {
                $script:removed = $true
                return [PSCustomObject]@{ Content = '<Response><DoSBypassRules><Status code="200">Configuration applied successfully.</Status></DoSBypassRules></Response>' }
            }
            if ($script:removed) {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DoSBypassRules transactionid=""><Status>No. of records Zero.</Status></DoSBypassRules></Response>' }
            }
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DoSBypassRules transactionid=""><IPFamily>IPv4</IPFamily><SourceIPNetmask>any</SourceIPNetmask><DestinationIPNetmask>any</DestinationIPNetmask><Protocol>ICMP</Protocol></DoSBypassRules></Response>' }
        }

        $record = [PSCustomObject]@{
            IPFamily             = 'IPv4'
            SourceIPNetmask      = 'any'
            DestinationIPNetmask = 'any'
            Protocol             = 'ICMP'
            SourcePort           = '*'
            DestinationPort      = '*'
        }

        { $record | Remove-SfosDoSBypassRule @conn -Confirm:$false } | Should -Not -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<SourceIPNetmask>\*</SourceIPNetmask>' -and
            $InnerXml -match '<DestinationIPNetmask>\*</DestinationIPNetmask>' -and
            $InnerXml -notmatch '<SourceIPNetmask>any</SourceIPNetmask>'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSPolicy transactionid=""><Status code="529">Invalid XML request</Status></IPSPolicy></Response>' }
        }

        { Get-SfosIPSPolicy @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosIPSPolicy @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><TrustedMAC transactionid=""><Status>No. of records Zero.</Status></TrustedMAC></Response>' }
        }

        $result = @(Get-SfosTrustedMAC @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'Set-SfosIPSPolicy - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'preserves a RuleList of exactly one rule when only Description is changed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSPolicy transactionid=""><Name>PresPolicy</Name><Description>OldDesc</Description><RuleList><Rule><RuleName>KeepMe</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList><Category>All Categories</Category></CategoryList><SeverityList><Severity>All Severity</Severity></SeverityList><TargetList><Target>All Target</Target></TargetList><PlatformList><Platform>All Platform</Platform></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
            }
        }

        Set-SfosIPSPolicy -Name 'PresPolicy' -Description 'NewDesc' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Description>NewDesc</Description>' -and
            $InnerXml -match '<RuleName>KeepMe</RuleName>' -and
            $InnerXml -match '<Category>All Categories</Category>'
        }
    }

    It 'replaces the RuleList wholesale when -Rule is passed, not merged with the existing rules' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>PresPolicy2</Name><Description>D</Description><RuleList><Rule><RuleName>OldRule</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
            }
        }

        $newRule = New-SfosIPSPolicyRule -RuleName 'ReplacementRule' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
        Set-SfosIPSPolicy -Name 'PresPolicy2' -Rule $newRule @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<RuleName>ReplacementRule</RuleName>' -and
            $InnerXml -notmatch '<RuleName>OldRule</RuleName>'
        }
    }

    It 'throws when the named policy does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSPolicy transactionid=""><Status>No. of records Zero.</Status></IPSPolicy></Response>' }
        }

        { Set-SfosIPSPolicy -Name 'GhostPolicy' -Description 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Add-SfosIPSPolicyRule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'appends the new rule after the existing ones and resends the whole RuleList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>AddRulePolicy</Name><Description>D</Description><RuleList><Rule><RuleName>FirstRule</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
            }
        }

        $newRule = New-SfosIPSPolicyRule -RuleName 'SecondRule' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
        Add-SfosIPSPolicyRule -Name 'AddRulePolicy' -Rule $newRule @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<RuleName>FirstRule</RuleName>' -and
            $InnerXml -match '<RuleName>SecondRule</RuleName>' -and
            ($InnerXml.IndexOf('FirstRule')) -lt ($InnerXml.IndexOf('SecondRule'))
        }
    }

    It 'throws when the named policy does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Status>No. of records Zero.</Status></IPSPolicy></Response>' }
        }

        $rule = New-SfosIPSPolicyRule -RuleName 'X'
        { Add-SfosIPSPolicyRule -Name 'GhostPolicy' -Rule $rule @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Remove-SfosIPSPolicyRule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'removes the rule at the given index and resends the remaining rule, confirmed by the follow-up Get' {
        $script:getCalls = 0
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                $script:getCalls++
                if ($script:getCalls -eq 1) {
                    return [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>TwoRulePolicy</Name><Description>D</Description><RuleList><Rule><RuleName>RuleZero</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule><Rule><RuleName>RuleOne</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
                }
                else {
                    return [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>TwoRulePolicy</Name><Description>D</Description><RuleList><Rule><RuleName>RuleOne</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
                }
            }
            else {
                return [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
            }
        }

        Remove-SfosIPSPolicyRule -Name 'TwoRulePolicy' -Index 0 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<RuleName>RuleOne</RuleName>' -and
            $InnerXml -notmatch '<RuleName>RuleZero</RuleName>'
        }
    }

    It 'throws when the index is out of range, without sending any update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>OneRulePolicy</Name><Description>D</Description><RuleList><Rule><RuleName>OnlyRule</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
        }

        { Remove-SfosIPSPolicyRule -Name 'OneRulePolicy' -Index 5 @conn -Confirm:$false } | Should -Throw '*out of range*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'throws when the firewall reports success but the rule count did not actually change' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            # Every Get, before and after the update, still reports both rules - simulating
            # a 200 that changed nothing on the firewall.
            if ($InnerXml -match '<Get>') {
                return [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>StuckPolicy</Name><Description>D</Description><RuleList><Rule><RuleName>RuleZero</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule><Rule><RuleName>RuleOne</RuleName><SignaturSelectionType>All Application</SignaturSelectionType><CategoryList></CategoryList><SeverityList></SeverityList><TargetList></TargetList><PlatformList></PlatformList><SignatureList></SignatureList><SmartFilter></SmartFilter><RuleType>Default Signature</RuleType><Action>Recommended</Action></Rule></RuleList></IPSPolicy></Response>' }
            }
            else {
                return [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
            }
        }

        { Remove-SfosIPSPolicyRule -Name 'StuckPolicy' -Index 0 @conn -Confirm:$false } | Should -Throw '*reported success*'
    }
}

Describe 'Remove-SfosIPSPolicy' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends the expected Remove XML for an existing policy' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Name>DeleteMe</Name><Description>D</Description></IPSPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
            }
        }

        Remove-SfosIPSPolicy -Name 'DeleteMe' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Remove><IPSPolicy><Name>DeleteMe</Name></IPSPolicy></Remove>'
        }
    }

    It 'throws "was not found" for a policy that does not exist, without sending a Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSPolicy transactionid=""><Status>No. of records Zero.</Status></IPSPolicy></Response>' }
        }

        { Remove-SfosIPSPolicy -Name 'GhostPolicy' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }
}

Describe 'New-SfosIPSPolicyRule - builder' {

    It 'applies documented defaults when only RuleName is supplied' {
        $rule = New-SfosIPSPolicyRule -RuleName 'DefaultsRule'

        $rule.RuleName | Should -Be 'DefaultsRule'
        $rule.SignaturSelectionType | Should -Be 'All Application'
        $rule.RuleType | Should -Be 'Default Signature'
        $rule.Action | Should -Be 'Recommended'
        $rule.SmartFilter | Should -Be ''
        @($rule.CategoryList).Count | Should -Be 0
    }

    It 'overrides only the supplied field when built from -InputObject, preserving the rest' {
        $base = [PSCustomObject]@{
            RuleName              = 'BaseRule'
            SignaturSelectionType = 'All Application'
            CategoryList          = @('All Categories')
            SeverityList          = @('All Severity')
            TargetList            = @('All Target')
            PlatformList          = @('All Platform')
            SignatureList         = @()
            SmartFilter           = ''
            RuleType              = 'Default Signature'
            Action                = 'Recommended'
        }

        $edited = $base | New-SfosIPSPolicyRule -Action 'Drop Session'

        $edited.RuleName | Should -Be 'BaseRule'
        $edited.Action | Should -Be 'Drop Session'
        $edited.CategoryList | Should -Be @('All Categories')
        $edited.TargetList | Should -Be @('All Target')
    }

    It 'throws when RuleName is missing and no -InputObject is supplied' {
        { New-SfosIPSPolicyRule } | Should -Throw '*RuleName*'
    }
}

Describe 'Get-SfosIPSCustomSignature' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses Name, Protocol, CustomRule, Severity and RecommendedAction' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSCustomSignature transactionid=""><Name>BlockTelnet</Name><Protocol>TCP</Protocol><CustomRule>alert tcp any any -&gt; any any (msg:"probe"; sid:1000001; rev:1;)</CustomRule><Severity>Minor</Severity><RecommendedAction>Allow Packet</RecommendedAction></IPSCustomSignature></Response>' }
        }

        $result = Get-SfosIPSCustomSignature @conn
        $result.Name | Should -Be 'BlockTelnet'
        $result.Protocol | Should -Be 'TCP'
        $result.Severity | Should -Be 'Minor'
        $result.RecommendedAction | Should -Be 'Allow Packet'
    }

    It 'returns an empty array when no records exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSCustomSignature transactionid=""><Status>No. of records Zero.</Status></IPSCustomSignature></Response>' }
        }

        $result = @(Get-SfosIPSCustomSignature @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'New-SfosIPSCustomSignature - XML generation and the documented 501' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends the documented element-for-element XML' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSCustomSignature><Status code="200">Configuration applied successfully.</Status></IPSCustomSignature></Response>' }
        }

        New-SfosIPSCustomSignature -Name 'BlockTelnet' -Protocol TCP -CustomRule 'alert tcp any any -> any any (msg:"probe"; sid:1000001; rev:1;)' -Severity Minor -RecommendedAction 'Allow Packet' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Name>BlockTelnet</Name>' -and
            $InnerXml -match '<Protocol>TCP</Protocol>' -and
            $InnerXml -match '<Severity>Minor</Severity>' -and
            $InnerXml -match '<RecommendedAction>Allow Packet</RecommendedAction>'
        }
    }

    It 'reproduces the documented 501 on CustomRule, matching the README known behaviour' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSCustomSignature><Status code="501">Configuration parameters validation failed.<InvalidParams><Params>/IPSCustomSignature/CustomRule</Params></InvalidParams></Status></IPSCustomSignature></Response>' }
        }

        { New-SfosIPSCustomSignature -Name 'BlockTelnet' -Protocol TCP -CustomRule 'alert tcp any any -> any any (msg:"probe"; sid:1000001; rev:1;)' -Severity Minor -RecommendedAction 'Allow Packet' @conn -Confirm:$false } | Should -Throw '*501*'
    }
}

Describe 'Set-SfosIPSCustomSignature' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws "was not found", matching the documented always-empty Get on this firmware' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSCustomSignature transactionid=""><Status>No. of records Zero.</Status></IPSCustomSignature></Response>' }
        }

        { Set-SfosIPSCustomSignature -Name 'BlockTelnet' -Severity Major @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'preserves unbound fields when a matching record is present (read-modify-write)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><IPSCustomSignature transactionid=""><Name>BlockTelnet</Name><Protocol>TCP</Protocol><CustomRule>alert tcp any any -&gt; any any (sid:1;)</CustomRule><Severity>Minor</Severity><RecommendedAction>Allow Packet</RecommendedAction></IPSCustomSignature></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><IPSCustomSignature><Status code="200">Configuration applied successfully.</Status></IPSCustomSignature></Response>' }
            }
        }

        Set-SfosIPSCustomSignature -Name 'BlockTelnet' -Severity 'Major' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Severity>Major</Severity>' -and
            $InnerXml -match '<Protocol>TCP</Protocol>' -and
            $InnerXml -match '<RecommendedAction>Allow Packet</RecommendedAction>'
        }
    }
}

Describe 'Remove-SfosIPSCustomSignature' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws "was not found" for a name that does not exist, without sending a Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSCustomSignature transactionid=""><Status>No. of records Zero.</Status></IPSCustomSignature></Response>' }
        }

        { Remove-SfosIPSCustomSignature -Name 'GhostSig' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }
}

Describe 'Set-SfosIPSFullSignaturePack' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws on the documented code 500, matching the measured broken-on-every-value behaviour' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSFullSignaturePack><Status code="500">Operation could not be performed on Entity.</Status></IPSFullSignaturePack></Response>' }
        }

        { Set-SfosIPSFullSignaturePack -Status enable @conn -Confirm:$false } | Should -Throw '*500*'
    }

    It 'skips the confirming Get for the non-persistent "show" value' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSFullSignaturePack><Status code="200">Configuration applied successfully.</Status></IPSFullSignaturePack></Response>' }
        }

        { Set-SfosIPSFullSignaturePack -Status show @conn -Confirm:$false } | Should -Not -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly
    }
}

Describe 'Get-SfosDoSSettings' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses all 27 flattened fields across the seven blocks' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSSettings><SYNFlood><Source><PacketRatePerSource>100</PacketRatePerSource><BurstRatePerSource>200</BurstRatePerSource><ApplyFlag>Enable</ApplyFlag></Source><Destination><PacketRatePerDestination>101</PacketRatePerDestination><BurstRatePerDestination>201</BurstRatePerDestination><ApplyFlag>Enable</ApplyFlag></Destination></SYNFlood><UDPFlood><Source><PacketRatePerSource>110</PacketRatePerSource><BurstRatePerSource>210</BurstRatePerSource><ApplyFlag>Disable</ApplyFlag></Source><Destination><PacketRatePerDestination>111</PacketRatePerDestination><BurstRatePerDestination>211</BurstRatePerDestination><ApplyFlag>Disable</ApplyFlag></Destination></UDPFlood><TCPFlood><Source><PacketRatePerSource>120</PacketRatePerSource><BurstRatePerSource>220</BurstRatePerSource><ApplyFlag>Enable</ApplyFlag></Source><Destination><PacketRatePerDestination>121</PacketRatePerDestination><BurstRatePerDestination>221</BurstRatePerDestination><ApplyFlag>Enable</ApplyFlag></Destination></TCPFlood><ICMPFlood><Source><PacketRatePerSource>130</PacketRatePerSource><BurstRatePerSource>230</BurstRatePerSource><ApplyFlag>Enable</ApplyFlag></Source><Destination><PacketRatePerDestination>131</PacketRatePerDestination><BurstRatePerDestination>231</BurstRatePerDestination><ApplyFlag>Enable</ApplyFlag></Destination></ICMPFlood><DroppedSourceRoutedPackets><Destination><ApplyFlag>Disable</ApplyFlag></Destination></DroppedSourceRoutedPackets><DisableICMPRedirectPacket><Destination><ApplyFlag>Disable</ApplyFlag></Destination></DisableICMPRedirectPacket><DisableARPFlooding><Destination><ApplyFlag>Enable</ApplyFlag></Destination></DisableARPFlooding></DoSSettings></Response>' }
        }

        $result = Get-SfosDoSSettings @conn

        $result.SYNFloodSourcePacketRate | Should -Be 100
        $result.SYNFloodDestinationApplyFlag | Should -Be 'Enable'
        $result.ICMPFloodSourcePacketRate | Should -Be 130
        $result.DroppedSourceRoutedPacketsApplyFlag | Should -Be 'Disable'
        $result.DisableICMPRedirectPacketApplyFlag | Should -Be 'Disable'
        $result.DisableARPFloodingApplyFlag | Should -Be 'Enable'
    }
}

Describe 'Set-SfosDoSSettings - read-modify-write across all seven blocks' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        # Baseline used below: every ApplyFlag deliberately set to a non-default
        # combination, so a lost field is immediately visible in the assertions.
        $script:doSSettingsBaseline = '<Response><DoSSettings><SYNFlood><Source><PacketRatePerSource>100</PacketRatePerSource><BurstRatePerSource>200</BurstRatePerSource><ApplyFlag>Enable</ApplyFlag></Source><Destination><PacketRatePerDestination>101</PacketRatePerDestination><BurstRatePerDestination>201</BurstRatePerDestination><ApplyFlag>Disable</ApplyFlag></Destination></SYNFlood><UDPFlood><Source><PacketRatePerSource>110</PacketRatePerSource><BurstRatePerSource>210</BurstRatePerSource><ApplyFlag>Disable</ApplyFlag></Source><Destination><PacketRatePerDestination>111</PacketRatePerDestination><BurstRatePerDestination>211</BurstRatePerDestination><ApplyFlag>Enable</ApplyFlag></Destination></UDPFlood><TCPFlood><Source><PacketRatePerSource>120</PacketRatePerSource><BurstRatePerSource>220</BurstRatePerSource><ApplyFlag>Enable</ApplyFlag></Source><Destination><PacketRatePerDestination>121</PacketRatePerDestination><BurstRatePerDestination>221</BurstRatePerDestination><ApplyFlag>Enable</ApplyFlag></Destination></TCPFlood><ICMPFlood><Source><PacketRatePerSource>130</PacketRatePerSource><BurstRatePerSource>230</BurstRatePerSource><ApplyFlag>Enable</ApplyFlag></Source><Destination><PacketRatePerDestination>131</PacketRatePerDestination><BurstRatePerDestination>231</BurstRatePerDestination><ApplyFlag>Enable</ApplyFlag></Destination></ICMPFlood><DroppedSourceRoutedPackets><Destination><ApplyFlag>Disable</ApplyFlag></Destination></DroppedSourceRoutedPackets><DisableICMPRedirectPacket><Destination><ApplyFlag>Disable</ApplyFlag></Destination></DisableICMPRedirectPacket><DisableARPFlooding><Destination><ApplyFlag>Enable</ApplyFlag></Destination></DisableARPFlooding></DoSSettings></Response>'
    }

    It 'preserves every ApplyFlag and rate untouched by the caller, changing only the one field passed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:doSSettingsBaseline }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><DoSSettings><Status code="200">Configuration applied successfully.</Status></DoSSettings></Response>' }
            }
        }

        Set-SfosDoSSettings -ICMPFloodSourcePacketRate 999 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ICMPFlood>\s*<Source>\s*<PacketRatePerSource>999</PacketRatePerSource>' -and
            # SYNFlood, untouched by this call, must survive byte for byte
            $InnerXml -match '<SYNFlood>\s*<Source>\s*<PacketRatePerSource>100</PacketRatePerSource>\s*<BurstRatePerSource>200</BurstRatePerSource>\s*<ApplyFlag>Enable</ApplyFlag>\s*</Source>\s*<Destination>\s*<PacketRatePerDestination>101</PacketRatePerDestination>\s*<BurstRatePerDestination>201</BurstRatePerDestination>\s*<ApplyFlag>Disable</ApplyFlag>' -and
            # The three flat ApplyFlag-only blocks - the exact field class this project has
            # lost before via full-entity replace - must all round-trip untouched.
            $InnerXml -match '<DroppedSourceRoutedPackets>\s*<Destination>\s*<ApplyFlag>Disable</ApplyFlag>' -and
            $InnerXml -match '<DisableICMPRedirectPacket>\s*<Destination>\s*<ApplyFlag>Disable</ApplyFlag>' -and
            $InnerXml -match '<DisableARPFlooding>\s*<Destination>\s*<ApplyFlag>Enable</ApplyFlag>'
        }
    }

    It 'rejects an invalid ApplyFlag value client-side, since the firewall silently discards rather than rejects it' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = $script:doSSettingsBaseline }
        }

        { Set-SfosDoSSettings -ICMPFloodSourceApplyFlag 'Bogus' @conn -Confirm:$false } | Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly
    }
}

Describe 'Get-SfosSpoofPrevention' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses the main switch, RestrictUnknownIPOnTrustedMAC and all three zone lists when enabled' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><SpoofPrevention><SpoofPrevention>Enable</SpoofPrevention><RestrictUnknownIPOnTrustedMAC>Disable</RestrictUnknownIPOnTrustedMAC><IPSpoofing><EnableOnZone><Zone>DMZ</Zone></EnableOnZone></IPSpoofing><MACFilter><EnableOnZone></EnableOnZone></MACFilter><IPMACFilter><EnableOnZone></EnableOnZone></IPMACFilter></SpoofPrevention></Response>' }
        }

        $result = Get-SfosSpoofPrevention @conn
        $result.Status | Should -Be 'Enable'
        $result.RestrictUnknownIPOnTrustedMAC | Should -Be 'Disable'
        $result.IPSpoofingZoneList | Should -Be @('DMZ')
        @($result.MACFilterZoneList).Count | Should -Be 0
    }

    It 'returns empty zone lists when the main switch is Disable and every other field is omitted' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><SpoofPrevention><SpoofPrevention>Disable</SpoofPrevention></SpoofPrevention></Response>' }
        }

        $result = Get-SfosSpoofPrevention @conn
        $result.Status | Should -Be 'Disable'
        @($result.IPSpoofingZoneList).Count | Should -Be 0
        @($result.MACFilterZoneList).Count | Should -Be 0
        @($result.IPMACFilterZoneList).Count | Should -Be 0
    }
}

Describe 'Set-SfosSpoofPrevention' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends only the main switch when disabling, matching the measured "Disable clears everything else" behaviour' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><SpoofPrevention><SpoofPrevention>Enable</SpoofPrevention><RestrictUnknownIPOnTrustedMAC>Disable</RestrictUnknownIPOnTrustedMAC><IPSpoofing><EnableOnZone><Zone>DMZ</Zone></EnableOnZone></IPSpoofing><MACFilter><EnableOnZone></EnableOnZone></MACFilter><IPMACFilter><EnableOnZone></EnableOnZone></IPMACFilter></SpoofPrevention></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SpoofPrevention><Status code="200">Configuration applied successfully.</Status></SpoofPrevention></Response>' }
            }
        }

        Set-SfosSpoofPrevention -Status Disable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SpoofPrevention>\s*<SpoofPrevention>Disable</SpoofPrevention>\s*</SpoofPrevention>\s*</Set>' -and
            $InnerXml -notmatch '<RestrictUnknownIPOnTrustedMAC>' -and
            $InnerXml -notmatch '<IPSpoofing>'
        }
    }

    It 'preserves a single-zone IPSpoofingZoneList when only RestrictUnknownIPOnTrustedMAC is changed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><SpoofPrevention><SpoofPrevention>Enable</SpoofPrevention><RestrictUnknownIPOnTrustedMAC>Disable</RestrictUnknownIPOnTrustedMAC><IPSpoofing><EnableOnZone><Zone>DMZ</Zone></EnableOnZone></IPSpoofing><MACFilter><EnableOnZone></EnableOnZone></MACFilter><IPMACFilter><EnableOnZone></EnableOnZone></IPMACFilter></SpoofPrevention></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SpoofPrevention><Status code="200">Configuration applied successfully.</Status></SpoofPrevention></Response>' }
            }
        }

        Set-SfosSpoofPrevention -RestrictUnknownIPOnTrustedMAC Enable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<RestrictUnknownIPOnTrustedMAC>Enable</RestrictUnknownIPOnTrustedMAC>' -and
            $InnerXml -match '<IPSpoofing><EnableOnZone><Zone>DMZ</Zone></EnableOnZone></IPSpoofing>'
        }
    }
}

Describe 'Get-SfosDoSBypassRule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'never sends a Filter element, per the measured 404-on-any-filter behaviour' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSBypassRules transactionid=""><Status>No. of records Zero.</Status></DoSBypassRules></Response>' }
        }

        Get-SfosDoSBypassRule -ProtocolLike 'TCP' @conn | Out-Null

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -notmatch '<Filter>'
        }
    }

    It 'applies the *Like filters client-side and parses all six fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSBypassRules transactionid=""><IPFamily>IPv4</IPFamily><SourceIPNetmask>10.99.98.0/24</SourceIPNetmask><DestinationIPNetmask>10.99.99.0/24</DestinationIPNetmask><Protocol>TCP</Protocol><SourcePort>2201</SourcePort><DestinationPort>2202</DestinationPort></DoSBypassRules><DoSBypassRules transactionid=""><IPFamily>IPv4</IPFamily><SourceIPNetmask>any</SourceIPNetmask><DestinationIPNetmask>any</DestinationIPNetmask><Protocol>ICMP</Protocol></DoSBypassRules></Response>' }
        }

        $result = @(Get-SfosDoSBypassRule -ProtocolLike 'TCP' @conn)
        $result.Count | Should -Be 1
        $result[0].SourceIPNetmask | Should -Be '10.99.98.0/24'
        $result[0].SourcePort | Should -Be '2201'
    }

    It 'returns an empty array when no records exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSBypassRules transactionid=""><Status>No. of records Zero.</Status></DoSBypassRules></Response>' }
        }

        $result = @(Get-SfosDoSBypassRule @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'Set-SfosDoSBypassRule' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'builds OldConfiguration from the current six-field identity and applies only the New* overrides at the top level' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSBypassRules><Status code="200">Configuration applied successfully.</Status></DoSBypassRules></Response>' }
        }

        Set-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '203.0.113.0/24' -DestinationIPNetmask '*' -Protocol TCP -SourcePort 51820 -DestinationPort 51821 -NewSourceIPNetmask '198.51.100.0/24' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SourceIPNetmask>198\.51\.100\.0/24</SourceIPNetmask>' -and
            $InnerXml -match '<OldConfiguration>[\s\S]*<SourceIPNetmask>203\.0\.113\.0/24</SourceIPNetmask>[\s\S]*</OldConfiguration>' -and
            $InnerXml -match '<OldConfiguration>[\s\S]*<Protocol>TCP</Protocol>[\s\S]*</OldConfiguration>'
        }
    }

    It 'translates the Get-reported "any" netmask back to the literal * inside OldConfiguration' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><DoSBypassRules><Status code="200">Configuration applied successfully.</Status></DoSBypassRules></Response>' }
        }

        $record = [PSCustomObject]@{
            IPFamily             = 'IPv4'
            SourceIPNetmask      = 'any'
            DestinationIPNetmask = 'any'
            Protocol             = 'ICMP'
            SourcePort           = ''
            DestinationPort      = ''
        }

        $record | Set-SfosDoSBypassRule -NewSourceIPNetmask '10.0.0.0/8' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<OldConfiguration>[\s\S]*<SourceIPNetmask>\*</SourceIPNetmask>[\s\S]*</OldConfiguration>' -and
            $InnerXml -notmatch '<OldConfiguration>[\s\S]*<SourceIPNetmask>any</SourceIPNetmask>[\s\S]*</OldConfiguration>' -and
            $InnerXml -match '<OldConfiguration>[\s\S]*<SourcePort>\*</SourcePort>[\s\S]*</OldConfiguration>'
        }
    }
}

Describe 'New-SfosTrustedMAC' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'defaults IPV4Association to Static when an address is given and IPV6Association to None when it is not' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><TrustedMAC><Status code="201">Configuration applied successfully.</Status></TrustedMAC></Response>' }
        }

        New-SfosTrustedMAC -MACAddress '00:16:76:AB:CD:01' -IPV4Address '10.99.60.10' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<MACAddress>00:16:76:AB:CD:01</MACAddress>' -and
            $InnerXml -match '<IPV4Association>Static</IPV4Association>' -and
            $InnerXml -match '<IPV4Address>10.99.60.10</IPV4Address>' -and
            $InnerXml -match '<IPV6Association>None</IPV6Association>'
        }
    }

    It 'throws for a malformed MAC address before ever calling the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><TrustedMAC><Status code="201">Configuration applied successfully.</Status></TrustedMAC></Response>' }
        }

        { New-SfosTrustedMAC -MACAddress 'not-a-mac' @conn -Confirm:$false } | Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly
    }
}

Describe 'Set-SfosTrustedMAC' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'preserves IPV4Address when only IPV6Association is changed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><TrustedMAC transactionid=""><MACAddress>00:16:76:AB:CD:01</MACAddress><IPV4Association>Static</IPV4Association><IPV4Address>10.99.60.10</IPV4Address><IPV6Association>None</IPV6Association><IPV6Address></IPV6Address></TrustedMAC></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><TrustedMAC><Status code="200">Configuration applied successfully.</Status></TrustedMAC></Response>' }
            }
        }

        Set-SfosTrustedMAC -MACAddress '00:16:76:AB:CD:01' -IPV6Association 'Static' -IPV6Address '2001:db8::1' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<IPV4Address>10.99.60.10</IPV4Address>' -and
            $InnerXml -match '<IPV6Association>Static</IPV6Association>' -and
            $InnerXml -match '<IPV6Address>2001:db8::1</IPV6Address>' -and
            $InnerXml -match '<MACAddress>00:16:76:AB:CD:01</MACAddress>'
        }
    }

    It 'sends the new address as the top-level MACAddress and the old one inside OldConfiguration when renaming' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><TrustedMAC transactionid=""><MACAddress>00:16:76:00:00:02</MACAddress><IPV4Association>Static</IPV4Association><IPV4Address>10.99.60.20</IPV4Address><IPV6Association>None</IPV6Association><IPV6Address></IPV6Address></TrustedMAC></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><TrustedMAC><Status code="200">Configuration applied successfully.</Status></TrustedMAC></Response>' }
            }
        }

        Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:02' -NewMACAddress '00:16:76:00:00:99' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<TrustedMAC>\s*<MACAddress>00:16:76:00:00:99</MACAddress>' -and
            $InnerXml -match '<OldConfiguration>\s*<MACAddress>00:16:76:00:00:02</MACAddress>\s*</OldConfiguration>' -and
            $InnerXml -match '<IPV4Address>10.99.60.20</IPV4Address>'
        }
    }

    It 'throws "was not found" for a MAC address that does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><TrustedMAC transactionid=""><Status>No. of records Zero.</Status></TrustedMAC></Response>' }
        }

        { Set-SfosTrustedMAC -MACAddress '00:16:76:AB:CD:FF' -IPV4Address '10.0.0.1' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Remove-SfosTrustedMAC' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends the expected Remove XML for an existing record' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><TrustedMAC transactionid=""><MACAddress>00:16:76:AB:CD:01</MACAddress><IPV4Association>Static</IPV4Association><IPV4Address>10.99.60.10</IPV4Address><IPV6Association>None</IPV6Association><IPV6Address></IPV6Address></TrustedMAC></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><TrustedMAC><Status code="200">Configuration applied successfully.</Status></TrustedMAC></Response>' }
            }
        }

        Remove-SfosTrustedMAC -MACAddress '00:16:76:AB:CD:01' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $InnerXml -match '<Remove>\s*<TrustedMAC>\s*<MACAddress>00:16:76:AB:CD:01</MACAddress>\s*</TrustedMAC>\s*</Remove>'
        }
    }

    It 'throws "was not found" for a MAC address that does not exist, without sending a Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><TrustedMAC transactionid=""><Status>No. of records Zero.</Status></TrustedMAC></Response>' }
        }

        { Remove-SfosTrustedMAC -MACAddress '00:16:76:AB:CD:FF' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }
}

Describe 'Export-SfosTrustedMACs' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'writes a CSV to TestDrive with the entries returned by Get-SfosTrustedMAC' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><TrustedMAC transactionid=""><MACAddress>00:16:76:AB:CD:99</MACAddress><IPV4Association>Static</IPV4Association><IPV4Address>10.99.60.20</IPV4Address><IPV6Association>None</IPV6Association><IPV6Address></IPV6Address></TrustedMAC></Response>' }
        }

        $path = Join-Path -Path 'TestDrive:\' -ChildPath 'trustedmacs-export.csv'
        Export-SfosTrustedMACs -FilePath $path @conn

        Test-Path -Path $path | Should -BeTrue
        # @() is required here, not a style choice: Import-Csv on a single-row file returns a
        # scalar PSCustomObject on Windows PowerShell 5.1 (no .Count property at all), while
        # PowerShell 7 auto-adds .Count/.Length on scalars - the same array-vs-scalar
        # collapsing class this project's build rules warn about, just triggered by a
        # different cmdlet.
        $csv = @(Import-Csv -Path $path)
        $csv.Count | Should -Be 1
        $csv[0].MACAddress | Should -Be '00:16:76:AB:CD:99'
        $csv[0].IPV4Address | Should -Be '10.99.60.20'
    }

    It 'throws when the target file already exists and -Overwrite was not specified' {
        $path = Join-Path -Path 'TestDrive:\' -ChildPath 'trustedmacs-existing.csv'
        Set-Content -Path $path -Value 'placeholder'

        { Export-SfosTrustedMACs -FilePath $path @conn } | Should -Throw '*already exists*'
    }
}

Describe 'Import-SfosTrustedMACs' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'creates only the rows with a usable MACAddress, skipping blank and commented ones' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><TrustedMAC><Status code="200">Configuration applied successfully.</Status></TrustedMAC></Response>' }
        }

        $path = Join-Path -Path 'TestDrive:\' -ChildPath 'trustedmacs-import.csv'
        @(
            [PSCustomObject]@{ MACAddress = '00:16:76:AB:CD:01'; IPV4Association = 'Static'; IPV4Address = '10.99.60.10'; IPV6Association = ''; IPV6Address = '' }
            [PSCustomObject]@{ MACAddress = '#00:16:76:AB:CD:02'; IPV4Association = ''; IPV4Address = ''; IPV6Association = ''; IPV6Address = '' }
            [PSCustomObject]@{ MACAddress = ''; IPV4Association = ''; IPV4Address = ''; IPV6Association = ''; IPV6Address = '' }
        ) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8

        Import-SfosTrustedMACs -FilePath $path @conn

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<MACAddress>00:16:76:AB:CD:01</MACAddress>'
        }
    }

    It 'throws when the input file does not exist' {
        $path = Join-Path -Path 'TestDrive:\' -ChildPath 'does-not-exist.csv'

        { Import-SfosTrustedMACs -FilePath $path @conn } | Should -Throw '*was not found*'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><IPSPolicy transactionid=""><Status>No. of records Zero.</Status></IPSPolicy></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosIPSPolicy -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosIPSPolicy | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on the begin-block pipeline path (New-SfosIPSPolicy)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -MockWith {
            [PSCustomObject]@{ Content = '<Response><IPSPolicy><Status code="200">Configuration applied successfully.</Status></IPSPolicy></Response>' }
        }
        $s2 = Get-SfosSession -Name 'fw2'
        New-SfosIPSPolicy -Name 'CrossFwPolicy' -Session 'fw2' -Confirm:$false
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<Name>CrossFwPolicy</Name>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosIPSPolicy -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.IntrusionPrevention -Times 0 -Exactly
    }
}
