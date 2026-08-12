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
