#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Email module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 70 exported functions
    with their identifying (or absent, for the settings singletons) and connection
    parameters; inner XML generation (root element, add/update operation, Name, XML
    escaping) for every New-/Set-/Remove- cmdlet across roughly twenty entities; the
    read-modify-write path of Set-SfosSMTPPolicy, Set-SfosMailExceptionPolicy,
    Set-SfosMTAAddressGroup, Set-SfosMTADataControlList, Set-SfosAntiSpamRule,
    Set-SfosSMTPMalwareScanningPolicy, Set-SfosEmailConfiguration, Set-SfosAVASAddressGroup,
    Set-SfosDataControlList, Set-SfosSPXTemplate and Set-SfosSPXConfiguration; the two
    object-reference fields (SMTPPolicy.DomainName -> MTAAddressGroup,
    ExceptionPolicy.SourceHost -> host object) and what their error messages actually say
    on a rejected value; the 545/MTAModeDisableCheck mode gate on the legacy entities
    AntiSpamRule and SMTPMalwareScanningPolicy; the mandatory -MalwareScanning/
    -DropMessageGreaterThan on Set-SfosSMTPPolicy; the two-separate-status-path update of
    AntiSpamQuarantineDigestSettings; the BATV secret hash-resend pattern on
    AdvancedSMTPSetting; -WhatIf suppressing every write call; the shared empty-result and
    error-status handling ("No. of records Zero." vs. a code-less error), including the
    MTABlockedSender shape with no entity element and no status at all; and 502/501
    firewall error codes per entity family.

    Measured module property verified here, not a defect: Set-SfosMailExceptionPolicy's
    thrown message for a rejected -SourceHost value does NOT name the expected object type
    (unlike Set-/New-SfosSMTPPolicy, whose catch block appends a hint about
    -DomainName/MTAAddressGroup). Assert-SfosApiReturnSuccess is called outside the
    try/catch in New-/Set-SfosMailExceptionPolicy, so a rejected field surfaces as the raw
    firewall status text only. The module's own README states "both cmdlets say so in
    their error message" - that holds for SMTPPolicy but not, at the exception-message
    level, for MailExceptionPolicy. Reported to the caller of this test run rather than
    silently asserted around.

    Also measured here, not a defect: the client-side "needs at least one -Member/
    -Signature/-DomainName value" guards on New-SfosMTAAddressGroup, New-SfosMTADataControlList
    and New-SfosSMTPPolicy are unreachable through the public parameter surface. Each of those
    parameters is a Mandatory [string[]], and PowerShell's own parameter binding already
    rejects both an empty array and an array holding only an empty string before the function
    body ever runs ("Cannot bind argument ... because it is an empty array/string"). The three
    tests below for those cmdlets assert PowerShell's own binding failure, not the module's own
    throw text.

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/Context,
    never at the script's top level, following the pattern already used across this project's
    test suites.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6, once
    loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its type data
    collides with the one PS 5.1 already loaded at startup. Work around it by restricting
    $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Email.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Email\SophosFirewall.Email.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

# --------------------------------------------------------------------------------------------

Describe 'Module Loading' {
    It 'SophosFirewall.Email module should load' {
        Get-Module SophosFirewall.Email | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 70 functions' {
        (Get-Module SophosFirewall.Email).ExportedFunctions.Count | Should -Be 70
    }

    It 'Manifest FunctionsToExport should list exactly 70 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Email\SophosFirewall.Email.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 70
    }
}

# Every function with a single, clearly identifying parameter (NameLike/Name/DomainName/
# DomainLike on Get-, mandatory Name/DomainName on New-/Set-/Remove-). 42 of the 58 functions.
$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosSMTPPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosSMTPPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosSMTPPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosSMTPPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosMailExceptionPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosMailExceptionPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosMailExceptionPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosMailExceptionPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosMTAAddressGroup'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosMTAAddressGroup'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosMTAAddressGroup'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosMTAAddressGroup'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosMTADataControlList'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosMTADataControlList'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosMTADataControlList'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosMTADataControlList'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosMTASPXTemplate'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosMTASPXTemplate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosMTASPXTemplate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosMTASPXTemplate'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosAntiSpamRule'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosAntiSpamRule'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosAntiSpamRule'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosAntiSpamRule'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosSMTPMalwareScanningPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosSMTPMalwareScanningPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosSMTPMalwareScanningPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosSMTPMalwareScanningPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosAntiSpamEmailArchiver'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosAntiSpamEmailArchiver'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosAntiSpamEmailArchiver'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosAntiSpamEmailArchiver'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosPOPIMAPScanningPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosPOPIMAPScanningPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosPOPIMAPScanningPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosPOPIMAPScanningPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosAVASAddressGroup'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosAVASAddressGroup'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosAVASAddressGroup'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosAVASAddressGroup'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosDataControlList'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosDataControlList'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosDataControlList'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosDataControlList'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosSPXTemplate'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosSPXTemplate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosSPXTemplate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosSPXTemplate'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'New-SfosAntiSpamTrustedDomain'; IdParam = 'DomainName'; Mandatory = $true }
    @{ Function = 'Remove-SfosAntiSpamTrustedDomain'; IdParam = 'DomainName'; Mandatory = $true }

    @{ Function = 'Get-SfosDKIMSigning'; IdParam = 'DomainLike'; Mandatory = $false }
)

# The 16 settings-singleton functions: no identifying parameter at all, only the six
# connection parameters (plus -AsXml on the Get- side).
$script:SingletonFunctions = @(
    'Get-SfosMTASPXConfiguration', 'Set-SfosMTASPXConfiguration',
    'Get-SfosAdvancedSMTPSetting', 'Set-SfosAdvancedSMTPSetting',
    'Get-SfosAntiSpamQuarantineDigestSettings', 'Set-SfosAntiSpamQuarantineDigestSettings',
    'Get-SfosSPXConfiguration', 'Set-SfosSPXConfiguration',
    'Get-SfosSMTPDeploymentMode', 'Set-SfosSMTPDeploymentMode',
    'Get-SfosEmailConfiguration', 'Set-SfosEmailConfiguration',
    'Get-SfosMailMalwareProtection', 'Set-SfosMailMalwareProtection',
    'Get-SfosAntiSpamTrustedDomain',
    'Get-SfosMailRelaySettings',
    'Get-SfosSmarthostSettings',
    'Get-SfosMTABlockedSender',
    'Get-SfosDKIMVerification'
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with an identifying parameter <IdParam> and the six connection parameters' -TestCases $script:CmdletParameterCases {
        param($Function, $IdParam, $Mandatory)

        $cmd = Get-Command $Function -Module SophosFirewall.Email -ErrorAction SilentlyContinue
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

    It 'Exports the settings singleton <Function> with the six connection parameters and no identifying parameter' -TestCases (
        $script:SingletonFunctions | ForEach-Object { @{ Function = $_ } }
    ) {
        param($Function)

        $cmd = Get-Command $Function -Module SophosFirewall.Email -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"
        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
        $cmd.Parameters.Keys | Should -Not -Contain 'Name'
        $cmd.Parameters.Keys | Should -Not -Contain 'NameLike'
    }

    It 'Set-SfosSMTPPolicy requires -MalwareScanning and -DropMessageGreaterThan, deliberately, because Get- never returns them' {
        $cmd = Get-Command Set-SfosSMTPPolicy -Module SophosFirewall.Email
        foreach ($paramName in 'MalwareScanning', 'DropMessageGreaterThan') {
            $isMandatory = ($cmd.Parameters[$paramName].Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                    ForEach-Object { $_.Mandatory }) -contains $true
            $isMandatory | Should -Be $true -Because "$paramName cannot be preserved across an update and must not silently default"
        }
    }
}

Describe 'AntiSpamRule - XML generation, read-modify-write and the 545 mode gate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $script:Recipient = [PSCustomObject]@{ Action = 'Contains'; RecipientEmail = 'Any' }
        $script:Sender = [PSCustomObject]@{ Action = 'Contains'; SenderEmail = 'Any' }
    }

    It 'New-SfosAntiSpamRule sends an add operation carrying the root, Name (escaped) and the recipient/sender blocks' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamRules><Status code="200">Configuration applied successfully.</Status></AntiSpamRules></Response>' }
        }

        New-SfosAntiSpamRule -Name 'Rule & Co' -RecipientList $script:Recipient -SenderEmailList $script:Sender `
            -Condition 'CyberoamAntiSpamIdentifiesMailAs' -MatchIs 'Spam' -SMTPResponseAction 'Accept' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AntiSpamRules>' -and
            $InnerXml -match '<Name>Rule &amp; Co</Name>' -and
            $InnerXml -match '<RecipientList><Action>Contains</Action><RecipientEmail>Any</RecipientEmail></RecipientList>' -and
            $InnerXml -match '<SenderEmailList><Action>Contains</Action><SenderEmail>Any</SenderEmail></SenderEmailList>' -and
            $InnerXml -match '<Condition>CyberoamAntiSpamIdentifiesMailAs</Condition>' -and
            $InnerXml -match '<MatchIs>Spam</MatchIs>'
        }
    }

    It 'New-SfosAntiSpamRule throws mentioning the mode on a mocked 545 (MTAModeDisableCheck)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamRules><Status code="545">Operation failed. MTAModeDisableCheck - this legacy operation requires legacy mode, but MTA mode is currently active.</Status></AntiSpamRules></Response>' }
        }

        { New-SfosAntiSpamRule -Name 'ModeLocked' -RecipientList $script:Recipient -SenderEmailList $script:Sender `
                -Condition 'CyberoamAntiSpamIdentifiesMailAs' -MatchIs 'Spam' -SMTPResponseAction 'Accept' @conn -Confirm:$false } |
            Should -Throw '*MTAModeDisableCheck*'
    }

    It 'New-SfosAntiSpamRule throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamRules><Status code="502">Operation failed. Entity having same name already exists.</Status></AntiSpamRules></Response>' }
        }

        { New-SfosAntiSpamRule -Name 'DupRule' -RecipientList $script:Recipient -SenderEmailList $script:Sender `
                -Condition 'CyberoamAntiSpamIdentifiesMailAs' -MatchIs 'Spam' -SMTPResponseAction 'Accept' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosAntiSpamRule throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamRules><Status code="501">Configuration parameters validation failed.</Status></AntiSpamRules></Response>' }
        }

        { New-SfosAntiSpamRule -Name 'BadField' -RecipientList $script:Recipient -SenderEmailList $script:Sender `
                -Condition 'CyberoamAntiSpamIdentifiesMailAs' -MatchIs 'Spam' -SMTPResponseAction 'Accept' @conn -Confirm:$false } |
            Should -Throw '*501*'
    }

    It 'New-SfosAntiSpamRule -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosAntiSpamRule -Name 'WhatIfRule' -RecipientList $script:Recipient -SenderEmailList $script:Sender `
            -Condition 'CyberoamAntiSpamIdentifiesMailAs' -MatchIs 'Spam' -SMTPResponseAction 'Accept' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosAntiSpamRule sends an update operation, keeping the fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamRules transactionid=""><Name>ExistingRule</Name><RecipientList><Action>Contains</Action><RecipientEmail>Any</RecipientEmail></RecipientList><SenderEmailList><Action>Contains</Action><SenderEmail>Any</SenderEmail></SenderEmailList><MarkSpamIf><Condition>CyberoamAntiSpamIdentifiesMailAs</Condition><MatchIs>Spam</MatchIs></MarkSpamIf><SMTPAction><Action>Accept</Action><ActionParameter></ActionParameter><Quarantine>Disable</Quarantine></SMTPAction></AntiSpamRules></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiSpamRules><Status code="200">Configuration applied successfully.</Status></AntiSpamRules></Response>' }
            }
        }

        Set-SfosAntiSpamRule -Name 'ExistingRule' -Quarantine Enable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Quarantine>Enable</Quarantine>' -and
            $InnerXml -match '<Condition>CyberoamAntiSpamIdentifiesMailAs</Condition>' -and
            $InnerXml -match '<MatchIs>Spam</MatchIs>' -and
            $InnerXml -match '<Action>Accept</Action>' -and
            $InnerXml -match '<RecipientEmail>Any</RecipientEmail>' -and
            $InnerXml -match '<SenderEmail>Any</SenderEmail>'
        }
    }

    It 'Set-SfosAntiSpamRule throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamRules transactionid=""><Status>No. of records Zero.</Status></AntiSpamRules></Response>' }
        }

        { Set-SfosAntiSpamRule -Name 'DoesNotExist' -Quarantine Enable @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosAntiSpamRule reads first, then sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamRules transactionid=""><Name>ExistingRule</Name><RecipientList><Action>Contains</Action><RecipientEmail>Any</RecipientEmail></RecipientList><SenderEmailList><Action>Contains</Action><SenderEmail>Any</SenderEmail></SenderEmailList><MarkSpamIf><Condition>CyberoamAntiSpamIdentifiesMailAs</Condition><MatchIs>Spam</MatchIs></MarkSpamIf><SMTPAction><Action>Accept</Action><Quarantine>Disable</Quarantine></SMTPAction></AntiSpamRules></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiSpamRules><Status code="200">Configuration applied successfully.</Status></AntiSpamRules></Response>' }
            }
        }

        Remove-SfosAntiSpamRule -Name 'ExistingRule' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<AntiSpamRules>' -and $InnerXml -match '<Name>ExistingRule</Name>'
        }
    }

    It 'Remove-SfosAntiSpamRule throws "was not found" for an unknown name, without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamRules transactionid=""><Status>No. of records Zero.</Status></AntiSpamRules></Response>' }
        }

        { Remove-SfosAntiSpamRule -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'AntiSpamTrustedDomain - nested Remove shape, no Set-' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'has no Set-SfosAntiSpamTrustedDomain cmdlet' {
        Get-Command Set-SfosAntiSpamTrustedDomain -Module SophosFirewall.Email -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'New-SfosAntiSpamTrustedDomain sends an add operation with the nested DomainList wrapper and escaping' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamTrustedDomain><Status code="200">Configuration applied successfully.</Status></AntiSpamTrustedDomain></Response>' }
        }

        New-SfosAntiSpamTrustedDomain -DomainName 'trusted-and-co.example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AntiSpamTrustedDomain>' -and
            $InnerXml -match '<DomainList><DomainName>trusted-and-co\.example\.com</DomainName></DomainList>'
        }
    }

    It 'New-SfosAntiSpamTrustedDomain throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamTrustedDomain><Status code="502">Operation failed. Entity having same name already exists.</Status></AntiSpamTrustedDomain></Response>' }
        }

        { New-SfosAntiSpamTrustedDomain -DomainName 'dup.example.com' @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'New-SfosAntiSpamTrustedDomain throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamTrustedDomain><Status code="501">Configuration parameters validation failed.</Status></AntiSpamTrustedDomain></Response>' }
        }

        { New-SfosAntiSpamTrustedDomain -DomainName 'bad.example.com' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It 'New-SfosAntiSpamTrustedDomain -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosAntiSpamTrustedDomain -DomainName 'whatif.example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Remove-SfosAntiSpamTrustedDomain reads first, then sends a Remove with the nested DomainList wrapper' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamTrustedDomain transactionid=""><DomainList><DomainName>trusted.example.com</DomainName></DomainList></AntiSpamTrustedDomain></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiSpamTrustedDomain><Status code="200">Configuration applied successfully.</Status></AntiSpamTrustedDomain></Response>' }
            }
        }

        Remove-SfosAntiSpamTrustedDomain -DomainName 'trusted.example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AntiSpamTrustedDomain>' -and
            $InnerXml -match '<DomainList><DomainName>trusted\.example\.com</DomainName></DomainList>'
        }
    }

    It 'Remove-SfosAntiSpamTrustedDomain throws "was not found" for an unknown domain, without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamTrustedDomain transactionid=""><Status>No. of records Zero.</Status></AntiSpamTrustedDomain></Response>' }
        }

        { Remove-SfosAntiSpamTrustedDomain -DomainName 'ghost.example.com' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosAntiSpamTrustedDomain -WhatIf makes the existence-check call but never sends the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamTrustedDomain transactionid=""><DomainList><DomainName>trusted.example.com</DomainName></DomainList></AntiSpamTrustedDomain></Response>' }
        }

        Remove-SfosAntiSpamTrustedDomain -DomainName 'trusted.example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'AntiSpamEmailArchiver - XML generation, RMW and the Any-only recipient' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosAntiSpamEmailArchiver sends an add operation carrying the root, escaped Name and Recipient/SendCopyOfEmailTo' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamEmailArchiver><Status code="200">Configuration applied successfully.</Status></AntiSpamEmailArchiver></Response>' }
        }

        New-SfosAntiSpamEmailArchiver -Name 'Archive & Co' -Recipient 'Any' -SendCopyOfEmailTo 'archive@example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AntiSpamEmailArchiver>' -and
            $InnerXml -match '<Name>Archive &amp; Co</Name>' -and
            $InnerXml -match '<RecipientList><Recipient>Any</Recipient></RecipientList>' -and
            $InnerXml -match '<SendCopyOfEmailTo>archive@example\.com</SendCopyOfEmailTo>'
        }
    }

    It 'New-SfosAntiSpamEmailArchiver throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamEmailArchiver><Status code="502">Operation failed. Entity having same name already exists.</Status></AntiSpamEmailArchiver></Response>' }
        }

        { New-SfosAntiSpamEmailArchiver -Name 'DupArchiver' -Recipient 'Any' -SendCopyOfEmailTo 'archive@example.com' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosAntiSpamEmailArchiver throws on a raw address rejected as the only Recipient (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiSpamEmailArchiver><Status code="501">Configuration parameters validation failed.</Status><InvalidParams><Params>/AntiSpamEmailArchiver/RecipientList/Recipient</Params></InvalidParams></AntiSpamEmailArchiver></Response>' }
        }

        { New-SfosAntiSpamEmailArchiver -Name 'BadRecipient' -Recipient 'user1@example.com' -SendCopyOfEmailTo 'archive@example.com' @conn -Confirm:$false } |
            Should -Throw '*501*'
    }

    It 'New-SfosAntiSpamEmailArchiver -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosAntiSpamEmailArchiver -Name 'WhatIfArchiver' -Recipient 'Any' -SendCopyOfEmailTo 'archive@example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosAntiSpamEmailArchiver sends an update operation, keeping Recipient when only SendCopyOfEmailTo changes' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamEmailArchiver transactionid=""><Name>ExistingArchiver</Name><RecipientList><Recipient>Any</Recipient></RecipientList><SendCopyOfEmailTo>old@example.com</SendCopyOfEmailTo></AntiSpamEmailArchiver></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiSpamEmailArchiver><Status code="200">Configuration applied successfully.</Status></AntiSpamEmailArchiver></Response>' }
            }
        }

        Set-SfosAntiSpamEmailArchiver -Name 'ExistingArchiver' -SendCopyOfEmailTo 'new@example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SendCopyOfEmailTo>new@example\.com</SendCopyOfEmailTo>' -and
            $InnerXml -match '<RecipientList><Recipient>Any</Recipient></RecipientList>'
        }
    }

    It 'Set-SfosAntiSpamEmailArchiver throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamEmailArchiver transactionid=""><Status>No. of records Zero.</Status></AntiSpamEmailArchiver></Response>' }
        }

        { Set-SfosAntiSpamEmailArchiver -Name 'DoesNotExist' -SendCopyOfEmailTo 'new@example.com' @conn -Confirm:$false } |
            Should -Throw '*was not found*'
    }

    It 'Remove-SfosAntiSpamEmailArchiver reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamEmailArchiver transactionid=""><Name>ExistingArchiver</Name><RecipientList><Recipient>Any</Recipient></RecipientList><SendCopyOfEmailTo>old@example.com</SendCopyOfEmailTo></AntiSpamEmailArchiver></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiSpamEmailArchiver><Status code="200">Configuration applied successfully.</Status></AntiSpamEmailArchiver></Response>' }
            }
        }

        Remove-SfosAntiSpamEmailArchiver -Name 'ExistingArchiver' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<AntiSpamEmailArchiver>' -and $InnerXml -match '<Name>ExistingArchiver</Name>'
        }
    }

    It 'Remove-SfosAntiSpamEmailArchiver -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamEmailArchiver transactionid=""><Name>ExistingArchiver</Name><RecipientList><Recipient>Any</Recipient></RecipientList><SendCopyOfEmailTo>old@example.com</SendCopyOfEmailTo></AntiSpamEmailArchiver></Response>' }
        }

        Remove-SfosAntiSpamEmailArchiver -Name 'ExistingArchiver' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'AntiSpamQuarantineDigestSettings - RMW and the two independent status paths' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $script:ExistingDigest = '<Response><Login><status>Authentication Successful</status></Login><AntiSpamQuarantineDigestSettings transactionid=""><SpamDigestSettings><SpamQuarantineDigest>Enable</SpamQuarantineDigest><EmailFrequency>Day</EmailFrequency><SendEmailAt><Hour>8</Hour><Minute>0</Minute></SendEmailAt><FromEmailAddress>digest@example.com</FromEmailAddress><DisplayName>Quarantine Digest</DisplayName><ReferenceMyAccountIP></ReferenceMyAccountIP><AllowUserToOverride>Enable</AllowUserToOverride></SpamDigestSettings><SpamDigestUsers><EnableUsers></EnableUsers><DisableUsers></DisableUsers></SpamDigestUsers></AntiSpamQuarantineDigestSettings></Response>'
    }

    It 'Set-SfosAntiSpamQuarantineDigestSettings sends operation=update, keeping fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingDigest }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SpamDigestSettings><Status code="200">Configuration applied successfully.</Status></SpamDigestSettings><SpamDigestUsers><Status code="200">Configuration applied successfully.</Status></SpamDigestUsers></Response>' }
            }
        }

        Set-SfosAntiSpamQuarantineDigestSettings -Hour 9 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<AntiSpamQuarantineDigestSettings>' -and
            $InnerXml -match '<Hour>9</Hour>' -and
            $InnerXml -match '<EmailFrequency>Day</EmailFrequency>' -and
            $InnerXml -match '<FromEmailAddress>digest@example\.com</FromEmailAddress>' -and
            $InnerXml -match '<AllowUserToOverride>Enable</AllowUserToOverride>'
        }
    }

    It 'throws naming SpamDigestSettings when that block fails, even though SpamDigestUsers succeeds (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingDigest }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SpamDigestSettings><Status code="501">Configuration parameters validation failed.</Status></SpamDigestSettings><SpamDigestUsers><Status code="200">Configuration applied successfully.</Status></SpamDigestUsers></Response>' }
            }
        }

        { Set-SfosAntiSpamQuarantineDigestSettings -Hour 9 @conn -Confirm:$false } | Should -Throw '*501*SpamDigestSettings*'
    }

    It 'throws naming SpamDigestUsers when that block fails, even though SpamDigestSettings succeeds' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingDigest }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SpamDigestSettings><Status code="200">Configuration applied successfully.</Status></SpamDigestSettings><SpamDigestUsers><Status code="501">Configuration parameters validation failed.</Status></SpamDigestUsers></Response>' }
            }
        }

        { Set-SfosAntiSpamQuarantineDigestSettings -Hour 9 @conn -Confirm:$false } | Should -Throw '*501*SpamDigestUsers*'
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingDigest }
        }

        Set-SfosAntiSpamQuarantineDigestSettings -Hour 9 @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }
}

Describe 'SMTPMalwareScanningPolicy - XML generation, RMW and the 545 mode gate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosSMTPMalwareScanningPolicy sends an add operation with the plural root, escaped Name and sender/receiver/filetype lists' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirusMailSMTPScanningRules><Status code="200">Configuration applied successfully.</Status></AntiVirusMailSMTPScanningRules></Response>' }
        }

        New-SfosSMTPMalwareScanningPolicy -Name 'Scan & Block' -SenderAddress 'Any' -Receiver 'Any' -FileType 'None' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AntiVirusMailSMTPScanningRules>' -and
            $InnerXml -match '<Name>Scan &amp; Block</Name>' -and
            $InnerXml -match '<SenderList><Sender>Any</Sender></SenderList>' -and
            $InnerXml -match '<ReceiverList><Receiver>Any</Receiver></ReceiverList>' -and
            $InnerXml -match '<BlockFileTypes><FileType>None</FileType></BlockFileTypes>'
        }
    }

    It 'New-SfosSMTPMalwareScanningPolicy throws mentioning the mode on a mocked 545 (MTAModeDisableCheck)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirusMailSMTPScanningRules><Status code="545">Operation failed. MTAModeDisableCheck - legacy scanning is disabled while MTA mode is active.</Status></AntiVirusMailSMTPScanningRules></Response>' }
        }

        { New-SfosSMTPMalwareScanningPolicy -Name 'ModeLocked' -SenderAddress 'Any' -Receiver 'Any' -FileType 'None' @conn -Confirm:$false } |
            Should -Throw '*MTAModeDisableCheck*'
    }

    It 'New-SfosSMTPMalwareScanningPolicy throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirusMailSMTPScanningRules><Status code="502">Operation failed. Entity having same name already exists.</Status></AntiVirusMailSMTPScanningRules></Response>' }
        }

        { New-SfosSMTPMalwareScanningPolicy -Name 'DupScan' -SenderAddress 'Any' -Receiver 'Any' -FileType 'None' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosSMTPMalwareScanningPolicy throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AntiVirusMailSMTPScanningRules><Status code="501">Configuration parameters validation failed.</Status></AntiVirusMailSMTPScanningRules></Response>' }
        }

        { New-SfosSMTPMalwareScanningPolicy -Name 'BadScan' -SenderAddress 'Any' -Receiver 'Any' -FileType 'None' @conn -Confirm:$false } |
            Should -Throw '*501*'
    }

    It 'New-SfosSMTPMalwareScanningPolicy -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosSMTPMalwareScanningPolicy -Name 'WhatIfScan' -SenderAddress 'Any' -Receiver 'Any' -FileType 'None' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosSMTPMalwareScanningPolicy sends an update, keeping Sender/Receiver/FileType the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiVirusMailSMTPScanningRules transactionid=""><Name>ExistingScan</Name><SenderList><Sender>Any</Sender></SenderList><ReceiverList><Receiver>Any</Receiver></ReceiverList><Scanning>Single Anti-Virus (Maximum Performance)</Scanning><Quarantine>Disable</Quarantine><NotifySender>Disable</NotifySender><BlockFileTypes><FileType>None</FileType></BlockFileTypes><ReceiverActionInfected>Don''tDeliver</ReceiverActionInfected><NotifyAdministratorInfected>Don''tDeliver</NotifyAdministratorInfected><ReceiverActionProtectedAttachment>DeliverOriginal</ReceiverActionProtectedAttachment><NotifyAdministratorProtectedAttachment>Don''tDeliver</NotifyAdministratorProtectedAttachment></AntiVirusMailSMTPScanningRules></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiVirusMailSMTPScanningRules><Status code="200">Configuration applied successfully.</Status></AntiVirusMailSMTPScanningRules></Response>' }
            }
        }

        Set-SfosSMTPMalwareScanningPolicy -Name 'ExistingScan' -Quarantine Enable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Quarantine>Enable</Quarantine>' -and
            $InnerXml -match '<SenderList><Sender>Any</Sender></SenderList>' -and
            $InnerXml -match '<ReceiverList><Receiver>Any</Receiver></ReceiverList>' -and
            $InnerXml -match '<BlockFileTypes><FileType>None</FileType></BlockFileTypes>'
        }
    }

    It 'Set-SfosSMTPMalwareScanningPolicy throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiVirusMailSMTPScanningRules transactionid=""><Status>No. of records Zero.</Status></AntiVirusMailSMTPScanningRules></Response>' }
        }

        { Set-SfosSMTPMalwareScanningPolicy -Name 'DoesNotExist' -Quarantine Enable @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosSMTPMalwareScanningPolicy reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiVirusMailSMTPScanningRules transactionid=""><Name>ExistingScan</Name><SenderList><Sender>Any</Sender></SenderList><ReceiverList><Receiver>Any</Receiver></ReceiverList><BlockFileTypes><FileType>None</FileType></BlockFileTypes></AntiVirusMailSMTPScanningRules></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AntiVirusMailSMTPScanningRules><Status code="200">Configuration applied successfully.</Status></AntiVirusMailSMTPScanningRules></Response>' }
            }
        }

        Remove-SfosSMTPMalwareScanningPolicy -Name 'ExistingScan' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<AntiVirusMailSMTPScanningRules>' -and $InnerXml -match '<Name>ExistingScan</Name>'
        }
    }

    It 'Remove-SfosSMTPMalwareScanningPolicy -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AntiVirusMailSMTPScanningRules transactionid=""><Name>ExistingScan</Name><SenderList><Sender>Any</Sender></SenderList><ReceiverList><Receiver>Any</Receiver></ReceiverList><BlockFileTypes><FileType>None</FileType></BlockFileTypes></AntiVirusMailSMTPScanningRules></Response>' }
        }

        Remove-SfosSMTPMalwareScanningPolicy -Name 'ExistingScan' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'POPIMAPScanningPolicy - XML generation and RMW (shared between both shapes)' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosPOPIMAPScanningPolicy sends an add operation with escaped Name and the nested EmailAddress block' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><POPIMAPScanningPolicy><Status code="200">Configuration applied successfully.</Status></POPIMAPScanningPolicy></Response>' }
        }

        New-SfosPOPIMAPScanningPolicy -Name 'Outbreak & Spam' -FilterCriteria InboundEmailIs -Action 'Prefix Subject' -To 'Outbreak:' -MatchIs 'Virus Outbreak' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<POPIMAPScanningPolicy>' -and
            $InnerXml -match '<Name>Outbreak &amp; Spam</Name>' -and
            $InnerXml -match '<EmailAddress>\s*<SenderEmail>Any</SenderEmail>' -and
            $InnerXml -match '<FilterCriteria>InboundEmailIs</FilterCriteria>' -and
            $InnerXml -match '<To>Outbreak:</To>' -and
            $InnerXml -match '<MatchIs>Virus Outbreak</MatchIs>'
        }
    }

    It 'New-SfosPOPIMAPScanningPolicy throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><POPIMAPScanningPolicy><Status code="502">Operation failed. Entity having same name already exists.</Status></POPIMAPScanningPolicy></Response>' }
        }

        { New-SfosPOPIMAPScanningPolicy -Name 'DupPolicy' -FilterCriteria InboundEmailIs -Action 'Prefix Subject' -To 'x' -MatchIs 'Spam' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosPOPIMAPScanningPolicy throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><POPIMAPScanningPolicy><Status code="501">Configuration parameters validation failed.</Status></POPIMAPScanningPolicy></Response>' }
        }

        { New-SfosPOPIMAPScanningPolicy -Name 'BadPolicy' -FilterCriteria InboundEmailIs -Action 'Prefix Subject' -To 'x' -MatchIs 'Spam' @conn -Confirm:$false } |
            Should -Throw '*501*'
    }

    It 'New-SfosPOPIMAPScanningPolicy -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosPOPIMAPScanningPolicy -Name 'WhatIfPolicy' -FilterCriteria InboundEmailIs -Action 'Prefix Subject' -To 'x' -MatchIs 'Spam' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosPOPIMAPScanningPolicy sends an update, keeping fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><POPIMAPScanningPolicy transactionid=""><Name>ExistingPop</Name><EmailAddress><SenderEmail>Any</SenderEmail><SenderAction>Contains</SenderAction><RecipientEmail>Any</RecipientEmail><RecipientAction>Contains</RecipientAction></EmailAddress><FilterCriteria>InboundEmailIs</FilterCriteria><Action>Prefix Subject</Action><To>Old:</To><MatchIs>Virus Outbreak</MatchIs></POPIMAPScanningPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><POPIMAPScanningPolicy><Status code="200">Configuration applied successfully.</Status></POPIMAPScanningPolicy></Response>' }
            }
        }

        Set-SfosPOPIMAPScanningPolicy -Name 'ExistingPop' -FilterCriteria InboundEmailIs -To 'New:' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<To>New:</To>' -and
            $InnerXml -match '<SenderEmail>Any</SenderEmail>' -and
            $InnerXml -match '<RecipientEmail>Any</RecipientEmail>' -and
            $InnerXml -match '<MatchIs>Virus Outbreak</MatchIs>'
        }
    }

    It 'Set-SfosPOPIMAPScanningPolicy throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><POPIMAPScanningPolicy transactionid=""><Status>No. of records Zero.</Status></POPIMAPScanningPolicy></Response>' }
        }

        { Set-SfosPOPIMAPScanningPolicy -Name 'DoesNotExist' -FilterCriteria InboundEmailIs -To 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosPOPIMAPScanningPolicy reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><POPIMAPScanningPolicy transactionid=""><Name>ExistingPop</Name><EmailAddress><SenderEmail>Any</SenderEmail><RecipientEmail>Any</RecipientEmail></EmailAddress><FilterCriteria>InboundEmailIs</FilterCriteria><Action>Accept</Action></POPIMAPScanningPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><POPIMAPScanningPolicy><Status code="200">Configuration applied successfully.</Status></POPIMAPScanningPolicy></Response>' }
            }
        }

        Remove-SfosPOPIMAPScanningPolicy -Name 'ExistingPop' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<POPIMAPScanningPolicy>' -and $InnerXml -match '<Name>ExistingPop</Name>'
        }
    }

    It 'Remove-SfosPOPIMAPScanningPolicy -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><POPIMAPScanningPolicy transactionid=""><Name>ExistingPop</Name><EmailAddress><SenderEmail>Any</SenderEmail><RecipientEmail>Any</RecipientEmail></EmailAddress><FilterCriteria>InboundEmailIs</FilterCriteria><Action>Accept</Action></POPIMAPScanningPolicy></Response>' }
        }

        Remove-SfosPOPIMAPScanningPolicy -Name 'ExistingPop' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'MailMalwareProtection - RMW singleton' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Set-SfosMailMalwareProtection sends operation=update carrying the changed engine' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MalwareProtection transactionid=""><PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine></MalwareProtection></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MalwareProtection><Status code="200">Configuration applied successfully.</Status></MalwareProtection></Response>' }
            }
        }

        Set-SfosMailMalwareProtection -PrimaryAntiVirusEngine Avira @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<MalwareProtection>' -and
            $InnerXml -match '<PrimaryAntiVirusEngine>Avira</PrimaryAntiVirusEngine>'
        }
    }

    It 'a no-op call sends back the exact value it read, unchanged' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MalwareProtection transactionid=""><PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine></MalwareProtection></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MalwareProtection><Status code="200">Configuration applied successfully.</Status></MalwareProtection></Response>' }
            }
        }

        Set-SfosMailMalwareProtection @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine>'
        }
    }

    It 'throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MalwareProtection transactionid=""><PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine></MalwareProtection></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MalwareProtection><Status code="501">Configuration parameters validation failed.</Status></MalwareProtection></Response>' }
            }
        }

        { Set-SfosMailMalwareProtection -PrimaryAntiVirusEngine Avira @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf does not send the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MalwareProtection transactionid=""><PrimaryAntiVirusEngine>Sophos</PrimaryAntiVirusEngine></MalwareProtection></Response>' }
        }

        Set-SfosMailMalwareProtection -PrimaryAntiVirusEngine Avira @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }
}

Describe 'EmailConfiguration - RMW across every nested sub-tree' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $script:ExistingConfig = '<Response><Login><status>Authentication Successful</status></Login><EmailConfiguration transactionid=""><GeneralSettings><EmailSignature></EmailSignature></GeneralSettings><SMTPSSettings><smtphostname>SMTP</smtphostname><DontScanEmailsGreaterThan>0</DontScanEmailsGreaterThan><ActionForOversizeEmails>Accept</ActionForOversizeEmails><BypassSpamCheck>Disable</BypassSpamCheck><VerifySendersIPReputation>Disable</VerifySendersIPReputation><SMTPSDosSettings>Disable</SMTPSDosSettings></SMTPSSettings><POPIMAPSettings><DontScanEmailsGreaterThan>1024</DontScanEmailsGreaterThan><RecipientHeaders><Header>Delivered-To</Header><Header>Received</Header></RecipientHeaders></POPIMAPSettings><SMTPTLSConfiguration><TLSCertificate>Default</TLSCertificate><AllowInvalidCertificate>Enable</AllowInvalidCertificate><DisableTLS1>Enable</DisableTLS1></SMTPTLSConfiguration><POPSIMAPTLSConfiguration><TLSCertificate>Default</TLSCertificate><AllowInvalidCertificate>Enable</AllowInvalidCertificate><DisableTLS1>Enable</DisableTLS1></POPSIMAPTLSConfiguration></EmailConfiguration></Response>'
    }

    It 'Set-SfosEmailConfiguration sends operation=update, keeping every sub-tree the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><EmailConfiguration><Status code="200">Configuration applied successfully.</Status></EmailConfiguration></Response>' }
            }
        }

        Set-SfosEmailConfiguration -EmailSignature 'Sent from example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<EmailConfiguration>' -and
            $InnerXml -match '<EmailSignature>Sent from example\.com</EmailSignature>' -and
            $InnerXml -match '<smtphostname>SMTP</smtphostname>' -and
            $InnerXml -match '<ActionForOversizeEmails>Accept</ActionForOversizeEmails>' -and
            $InnerXml -match '<Header>Delivered-To</Header>' -and
            $InnerXml -match '<Header>Received</Header>' -and
            $InnerXml -match '<SMTPTLSConfiguration>' -and
            $InnerXml -match '<AllowInvalidCertificate>Enable</AllowInvalidCertificate>' -and
            $InnerXml -match '<DisableTLS1>Enable</DisableTLS1>' -and
            $InnerXml -match '<POPSIMAPTLSConfiguration>'
        }
    }

    It 'a no-op call (zero parameters) sends back the exact values it read, unchanged' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><EmailConfiguration><Status code="200">Configuration applied successfully.</Status></EmailConfiguration></Response>' }
            }
        }

        Set-SfosEmailConfiguration @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<BypassSpamCheck>Disable</BypassSpamCheck>' -and
            $InnerXml -match '<VerifySendersIPReputation>Disable</VerifySendersIPReputation>' -and
            $InnerXml -match '<DontScanEmailsGreaterThan>1024</DontScanEmailsGreaterThan>'
        }
    }

    It 'throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><EmailConfiguration><Status code="501">Configuration parameters validation failed.</Status></EmailConfiguration></Response>' }
            }
        }

        { Set-SfosEmailConfiguration -EmailSignature 'x' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingConfig }
        }

        Set-SfosEmailConfiguration -EmailSignature 'x' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }
}

Describe 'MTAAddressGroup - XML generation, RMW and the GroupType guard' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosMTAAddressGroup sends an add operation with escaped Name and the EmailAddressList member wrapper' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTAAddressGroup><Status code="200">Configuration applied successfully.</Status></MTAAddressGroup></Response>' }
        }

        New-SfosMTAAddressGroup -Name 'Partner & Co' -GroupType EmailAddressOrDomain -Member 'partner.example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<MTAAddressGroup>' -and
            $InnerXml -match '<Name>Partner &amp; Co</Name>' -and
            $InnerXml -match '<GroupType>EmailAddressOrDomain</GroupType>' -and
            $InnerXml -match '<EmailAddressList><EmailAddressDomain>partner\.example\.com</EmailAddressDomain></EmailAddressList>'
        }
    }

    It 'New-SfosMTAAddressGroup builds the IPAddressList wrapper for GroupType IPAddress' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTAAddressGroup><Status code="200">Configuration applied successfully.</Status></MTAAddressGroup></Response>' }
        }

        New-SfosMTAAddressGroup -Name 'Trusted' -GroupType IPAddress -Member '192.0.2.0/24' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<IPAddressList><IPAddressNetwork>192\.0\.2\.0/24</IPAddressNetwork></IPAddressList>' -and
            $InnerXml -notmatch '<EmailAddressList>'
        }
    }

    It 'New-SfosMTAAddressGroup rejects a missing -Member value before ever reaching the API (PowerShell''s own mandatory-array binding, not the module''s own guard - see file header)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        { New-SfosMTAAddressGroup -Name 'Empty' -GroupType EmailAddressOrDomain -Member @() @conn -Confirm:$false -ErrorAction Stop } |
            Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'New-SfosMTAAddressGroup throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTAAddressGroup><Status code="502">Operation failed. Entity having same name already exists.</Status></MTAAddressGroup></Response>' }
        }

        { New-SfosMTAAddressGroup -Name 'DupGroup' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosMTAAddressGroup throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTAAddressGroup><Status code="501">Configuration parameters validation failed.</Status></MTAAddressGroup></Response>' }
        }

        { New-SfosMTAAddressGroup -Name 'BadGroup' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -Confirm:$false } |
            Should -Throw '*501*'
    }

    It 'New-SfosMTAAddressGroup -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosMTAAddressGroup -Name 'WhatIfGroup' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosMTAAddressGroup sends an update, keeping Member and Description the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><Description>old desc</Description><EmailImportType>Manual</EmailImportType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></MTAAddressGroup></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTAAddressGroup><Status code="200">Configuration applied successfully.</Status></MTAAddressGroup></Response>' }
            }
        }

        Set-SfosMTAAddressGroup -Name 'ExistingGroup' -GroupType EmailAddressOrDomain -Description 'new desc' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Description>new desc</Description>' -and
            $InnerXml -match '<EmailAddressList><EmailAddressDomain>example\.com</EmailAddressDomain></EmailAddressList>'
        }
    }

    It 'Set-SfosMTAAddressGroup throws naming the current GroupType when -GroupType changes without -Member' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>IPAddress</GroupType><IPAddressList><IPAddressNetwork>192.0.2.0/24</IPAddressNetwork></IPAddressList></MTAAddressGroup></Response>' }
        }

        { Set-SfosMTAAddressGroup -Name 'ExistingGroup' -GroupType EmailAddressOrDomain @conn -Confirm:$false } |
            Should -Throw "*currently GroupType 'IPAddress'*"
    }

    It 'Set-SfosMTAAddressGroup throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Status>No. of records Zero.</Status></MTAAddressGroup></Response>' }
        }

        { Set-SfosMTAAddressGroup -Name 'DoesNotExist' -GroupType EmailAddressOrDomain @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosMTAAddressGroup reads first, then sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></MTAAddressGroup></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTAAddressGroup><Status code="200">Configuration applied successfully.</Status></MTAAddressGroup></Response>' }
            }
        }

        Remove-SfosMTAAddressGroup -Name 'ExistingGroup' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<MTAAddressGroup>' -and $InnerXml -match '<Name>ExistingGroup</Name>'
        }
    }

    It 'Remove-SfosMTAAddressGroup throws "was not found" for an unknown name, without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Status>No. of records Zero.</Status></MTAAddressGroup></Response>' }
        }

        { Remove-SfosMTAAddressGroup -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosMTAAddressGroup -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></MTAAddressGroup></Response>' }
        }

        Remove-SfosMTAAddressGroup -Name 'ExistingGroup' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'MTADataControlList - XML generation and RMW (full replace, not append-only)' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosMTADataControlList sends an add operation with escaped Name and the Signatures list' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTADataControlList><Status code="200">Configuration applied successfully.</Status></MTADataControlList></Response>' }
        }

        New-SfosMTADataControlList -Name 'Address Check & Co' -Signature 'Postal addresses [Germany]', 'Postal addresses [France]' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<MTADataControlList>' -and
            $InnerXml -match '<Name>Address Check &amp; Co</Name>' -and
            $InnerXml -match '<Signatures><Signature>Postal addresses \[Germany\]</Signature><Signature>Postal addresses \[France\]</Signature></Signatures>'
        }
    }

    It 'New-SfosMTADataControlList rejects a missing -Signature value before ever reaching the API (PowerShell''s own mandatory-array binding, not the module''s own guard - see file header)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        { New-SfosMTADataControlList -Name 'Empty' -Signature @() @conn -Confirm:$false -ErrorAction Stop } | Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'New-SfosMTADataControlList throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTADataControlList><Status code="502">Operation failed. Entity having same name already exists.</Status></MTADataControlList></Response>' }
        }

        { New-SfosMTADataControlList -Name 'DupList' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'New-SfosMTADataControlList throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTADataControlList><Status code="501">Configuration parameters validation failed.</Status></MTADataControlList></Response>' }
        }

        { New-SfosMTADataControlList -Name 'BadList' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It 'New-SfosMTADataControlList -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosMTADataControlList -Name 'WhatIfList' -Signature 'Postal addresses [Germany]' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosMTADataControlList sends an update carrying a shorter -Signature list, replacing rather than appending' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTADataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature><Signature>Postal addresses [France]</Signature></Signatures></MTADataControlList></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTADataControlList><Status code="200">Configuration applied successfully.</Status></MTADataControlList></Response>' }
            }
        }

        Set-SfosMTADataControlList -Name 'ExistingList' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Signatures><Signature>Postal addresses \[Germany\]</Signature></Signatures>' -and
            $InnerXml -notmatch 'France'
        }
    }

    It 'Set-SfosMTADataControlList keeps the current Signature list when -Signature is not passed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTADataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature><Signature>Postal addresses [France]</Signature></Signatures></MTADataControlList></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTADataControlList><Status code="200">Configuration applied successfully.</Status></MTADataControlList></Response>' }
            }
        }

        Set-SfosMTADataControlList -Name 'ExistingList' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Signature>Postal addresses \[Germany\]</Signature>' -and
            $InnerXml -match '<Signature>Postal addresses \[France\]</Signature>'
        }
    }

    It 'Set-SfosMTADataControlList throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTADataControlList transactionid=""><Status>No. of records Zero.</Status></MTADataControlList></Response>' }
        }

        { Set-SfosMTADataControlList -Name 'DoesNotExist' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosMTADataControlList reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTADataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature></Signatures></MTADataControlList></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTADataControlList><Status code="200">Configuration applied successfully.</Status></MTADataControlList></Response>' }
            }
        }

        Remove-SfosMTADataControlList -Name 'ExistingList' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<MTADataControlList>' -and $InnerXml -match '<Name>ExistingList</Name>'
        }
    }

    It 'Remove-SfosMTADataControlList -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTADataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature></Signatures></MTADataControlList></Response>' }
        }

        Remove-SfosMTADataControlList -Name 'ExistingList' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'MailExceptionPolicy - XML generation, RMW and the SourceHost object reference' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosMailExceptionPolicy sends an add operation with escaped Name and the three nested protection blocks' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><ExceptionPolicy><Status code="200">Configuration applied successfully.</Status></ExceptionPolicy></Response>' }
        }

        New-SfosMailExceptionPolicy -Name 'Relay & Bypass' -ORTheseSenderAddresses Enable -SenderAddress 'alice@example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<ExceptionPolicy>' -and
            $InnerXml -match '<Name>Relay &amp; Bypass</Name>' -and
            $InnerXml -match '<MalwareProtection>' -and
            $InnerXml -match '<SpamProtection>' -and
            $InnerXml -match '<CheckforSPF>Disable</CheckforSPF>' -and
            $InnerXml -match '<Other>' -and
            $InnerXml -match '<ORTheseSenderAddresses>Enable</ORTheseSenderAddresses>' -and
            $InnerXml -match '<SenderAddressesList><Address>alice@example\.com</Address></SenderAddressesList>'
        }
    }

    It 'writes the SpamProtection/CheckforSPF field the firewall actually honors, not the sample-documented Other/CheckForSPF' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><ExceptionPolicy><Status code="200">Configuration applied successfully.</Status></ExceptionPolicy></Response>' }
        }

        New-SfosMailExceptionPolicy -Name 'SPFCheck' -ORTheseSenderAddresses Enable -SenderAddress 'alice@example.com' -CheckforSPF Enable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<SpamProtection>[^<]*<Antispam>' -and
            $InnerXml -match '<CheckforSPF>Enable</CheckforSPF>'
        }
    }

    It 'New-SfosMailExceptionPolicy throws on a rejected -SourceHost value (measured 501); the message names the code but not the object type - see file header' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><ExceptionPolicy><Status code="501">Configuration parameters validation failed.</Status><InvalidParams><Params>/ExceptionPolicy/SourceHostList/SourceHost</Params></InvalidParams></ExceptionPolicy></Response>' }
        }

        $thrown = $null
        try {
            New-SfosMailExceptionPolicy -Name 'BadHost' -ForTheseSourceHost Enable -SourceHost '192.0.2.10' @conn -Confirm:$false
        }
        catch {
            $thrown = $_
        }

        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Message | Should -Match '501'
    }

    It 'New-SfosMailExceptionPolicy throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><ExceptionPolicy><Status code="502">Operation failed. Entity having same name already exists.</Status></ExceptionPolicy></Response>' }
        }

        { New-SfosMailExceptionPolicy -Name 'DupPolicy' -ORTheseSenderAddresses Enable -SenderAddress 'alice@example.com' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosMailExceptionPolicy -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosMailExceptionPolicy -Name 'WhatIfPolicy' -ORTheseSenderAddresses Enable -SenderAddress 'alice@example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosMailExceptionPolicy sends an update, keeping fields the caller did not pass across every nested block' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ExceptionPolicy transactionid=""><Name>ExistingPolicy</Name><MalwareProtection><Malware>Disable</Malware><ZeroDayProtection>Disable</ZeroDayProtection></MalwareProtection><SpamProtection><RBL>Disable</RBL><BATV>Enable</BATV><RDNSAndHelo>Disable</RDNSAndHelo><Antispam>Enable</Antispam><Greylisting>Enable</Greylisting><IPReputation>Disable</IPReputation><RecipientVerification>Enable</RecipientVerification><CheckforSPF>Disable</CheckforSPF></SpamProtection><Other><Encryption>Enable</Encryption><DataProtection>Enable</DataProtection><FileProtection>Disable</FileProtection><BanerAddition>Disable</BanerAddition><DKIMSigning>Enable</DKIMSigning><DKIMVerification>Enable</DKIMVerification></Other><ForTheseSourceHost>Disable</ForTheseSourceHost><ORTheseSenderAddresses>Enable</ORTheseSenderAddresses><ORTheseRecipientAddresses>Disable</ORTheseRecipientAddresses><SenderAddressesList><Address>alice@example.com</Address></SenderAddressesList><RecipientAddresses></RecipientAddresses></ExceptionPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ExceptionPolicy><Status code="200">Configuration applied successfully.</Status></ExceptionPolicy></Response>' }
            }
        }

        Set-SfosMailExceptionPolicy -Name 'ExistingPolicy' -Antispam Disable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Antispam>Disable</Antispam>' -and
            $InnerXml -match '<Greylisting>Enable</Greylisting>' -and
            $InnerXml -match '<BATV>Enable</BATV>' -and
            $InnerXml -match '<ORTheseSenderAddresses>Enable</ORTheseSenderAddresses>' -and
            $InnerXml -match '<SenderAddressesList><Address>alice@example\.com</Address></SenderAddressesList>'
        }
    }

    It 'Set-SfosMailExceptionPolicy throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ExceptionPolicy transactionid=""><Status>No. of records Zero.</Status></ExceptionPolicy></Response>' }
        }

        { Set-SfosMailExceptionPolicy -Name 'DoesNotExist' -Antispam Disable @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosMailExceptionPolicy reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ExceptionPolicy transactionid=""><Name>ExistingPolicy</Name><MalwareProtection><Malware>Disable</Malware></MalwareProtection><SpamProtection><Antispam>Enable</Antispam></SpamProtection><Other><Encryption>Disable</Encryption></Other><ORTheseSenderAddresses>Enable</ORTheseSenderAddresses><SenderAddressesList><Address>alice@example.com</Address></SenderAddressesList></ExceptionPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ExceptionPolicy><Status code="200">Configuration applied successfully.</Status></ExceptionPolicy></Response>' }
            }
        }

        Remove-SfosMailExceptionPolicy -Name 'ExistingPolicy' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<ExceptionPolicy>' -and $InnerXml -match '<Name>ExistingPolicy</Name>'
        }
    }

    It 'Remove-SfosMailExceptionPolicy -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ExceptionPolicy transactionid=""><Name>ExistingPolicy</Name><MalwareProtection><Malware>Disable</Malware></MalwareProtection><SpamProtection><Antispam>Enable</Antispam></SpamProtection><Other><Encryption>Disable</Encryption></Other><ORTheseSenderAddresses>Enable</ORTheseSenderAddresses><SenderAddressesList><Address>alice@example.com</Address></SenderAddressesList></ExceptionPolicy></Response>' }
        }

        Remove-SfosMailExceptionPolicy -Name 'ExistingPolicy' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'MTASPXConfiguration - RMW singleton' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $script:ExistingSpxConfig = '<Response><Login><status>Authentication Successful</status></Login><MTASPXConfiguration transactionid=""><SPXGlobalTemplate><DefaultSPXTemplate>Default Template</DefaultSPXTemplate></SPXGlobalTemplate><HostName>None</HostName><Port>8094</Port><AllowSecureReplyfor>30</AllowSecureReplyfor><KeepUnusedPassFor>30</KeepUnusedPassFor><AllowPassRegistrationFor>10</AllowPassRegistrationFor><SendNotifcationErrorTo>SenderOnly</SendNotifcationErrorTo></MTASPXConfiguration></Response>'
    }

    It 'Set-SfosMTASPXConfiguration sends operation=update, keeping fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingSpxConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTASPXConfiguration><Status code="200">Configuration applied successfully.</Status></MTASPXConfiguration></Response>' }
            }
        }

        Set-SfosMTASPXConfiguration -AllowPassRegistrationFor 14 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<MTASPXConfiguration>' -and
            $InnerXml -match '<AllowPassRegistrationFor>14</AllowPassRegistrationFor>' -and
            $InnerXml -match '<DefaultSPXTemplate>Default Template</DefaultSPXTemplate>' -and
            $InnerXml -match '<SendNotifcationErrorTo>SenderOnly</SendNotifcationErrorTo>'
        }
    }

    It 'clears -AllowedNetwork when an empty array is passed, the only confirmed working shape for that field' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingSpxConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTASPXConfiguration><Status code="200">Configuration applied successfully.</Status></MTASPXConfiguration></Response>' }
            }
        }

        Set-SfosMTASPXConfiguration -AllowedNetwork @() @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<AllowedNetworks>\s*</AllowedNetworks>'
        }
    }

    It 'throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingSpxConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTASPXConfiguration><Status code="501">Configuration parameters validation failed.</Status></MTASPXConfiguration></Response>' }
            }
        }

        { Set-SfosMTASPXConfiguration -AllowPassRegistrationFor 14 @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingSpxConfig }
        }

        Set-SfosMTASPXConfiguration -AllowPassRegistrationFor 14 @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }
}

Describe 'MTASPXTemplate - XML generation and RMW' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosMTASPXTemplate sends an add operation with the plural root and escaped Name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTASPXTemplates><Status code="200">Configuration applied successfully.</Status></MTASPXTemplates></Response>' }
        }

        New-SfosMTASPXTemplate -Name 'Partner & Co Template' -OrganizationName 'Example Org' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<MTASPXTemplates>' -and
            $InnerXml -match '<Name>Partner &amp; Co Template</Name>' -and
            $InnerXml -match '<OrganizationName>Example Org</OrganizationName>'
        }
    }

    It 'New-SfosMTASPXTemplate throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTASPXTemplates><Status code="502">Operation failed. Entity having same name already exists.</Status></MTASPXTemplates></Response>' }
        }

        { New-SfosMTASPXTemplate -Name 'DupTemplate' @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'New-SfosMTASPXTemplate throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><MTASPXTemplates><Status code="501">Configuration parameters validation failed.</Status></MTASPXTemplates></Response>' }
        }

        { New-SfosMTASPXTemplate -Name 'BadTemplate' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It 'New-SfosMTASPXTemplate -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosMTASPXTemplate -Name 'WhatIfTemplate' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosMTASPXTemplate sends an update, keeping fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTASPXTemplates transactionid=""><Name>ExistingTemplate</Name><Description>old</Description><OrganizationName>Old Org</OrganizationName><PDFEncryption>AES/128</PDFEncryption><PageSize>Letter</PageSize><PasswordType>SpecifiedBySender</PasswordType></MTASPXTemplates></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTASPXTemplates><Status code="200">Configuration applied successfully.</Status></MTASPXTemplates></Response>' }
            }
        }

        Set-SfosMTASPXTemplate -Name 'ExistingTemplate' -OrganizationName 'New Org' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<OrganizationName>New Org</OrganizationName>' -and
            $InnerXml -match '<PDFEncryption>AES/128</PDFEncryption>' -and
            $InnerXml -match '<PageSize>Letter</PageSize>'
        }
    }

    It 'Set-SfosMTASPXTemplate throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTASPXTemplates transactionid=""><Status>No. of records Zero.</Status></MTASPXTemplates></Response>' }
        }

        { Set-SfosMTASPXTemplate -Name 'DoesNotExist' -OrganizationName 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Remove-SfosMTASPXTemplate reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTASPXTemplates transactionid=""><Name>ExistingTemplate</Name><OrganizationName>Org</OrganizationName></MTASPXTemplates></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><MTASPXTemplates><Status code="200">Configuration applied successfully.</Status></MTASPXTemplates></Response>' }
            }
        }

        Remove-SfosMTASPXTemplate -Name 'ExistingTemplate' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<MTASPXTemplates>' -and $InnerXml -match '<Name>ExistingTemplate</Name>'
        }
    }

    It 'Remove-SfosMTASPXTemplate -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTASPXTemplates transactionid=""><Name>ExistingTemplate</Name><OrganizationName>Org</OrganizationName></MTASPXTemplates></Response>' }
        }

        Remove-SfosMTASPXTemplate -Name 'ExistingTemplate' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'AdvancedSMTPSetting - RMW singleton and the BATV secret hash-resend pattern' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $script:ExistingAdvSettings = '<Response><Login><status>Authentication Successful</status></Login><AdvancedSMTPSetting transactionid=""><RejectInvalidHELOorMissingRDNS>Disable</RejectInvalidHELOorMissingRDNS><ScanOutboundEmails>Disable</ScanOutboundEmails><DoStrictRDNSchecks>Disable</DoStrictRDNSchecks><FirewallRelateInboundMails>Turn off</FirewallRelateInboundMails><BATVsecret hashform="mode1">deadbeefcafebabe</BATVsecret></AdvancedSMTPSetting></Response>'
    }

    It 'preserves the BATV secret by resending its hash with the hashform attribute when -BATVSecret is not passed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingAdvSettings }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AdvancedSMTPSetting><Status code="200">Configuration applied successfully.</Status></AdvancedSMTPSetting></Response>' }
            }
        }

        Set-SfosAdvancedSMTPSetting -DoStrictRDNSchecks Enable @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<DoStrictRDNSchecks>Enable</DoStrictRDNSchecks>' -and
            $InnerXml -match '<BATVsecret hashform="mode1">deadbeefcafebabe</BATVsecret>' -and
            $InnerXml -match '<FirewallRelateInboundMails>Turn off</FirewallRelateInboundMails>'
        }
    }

    It 'sends the decrypted -BATVSecret as a plain element when passed explicitly' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingAdvSettings }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AdvancedSMTPSetting><Status code="200">Configuration applied successfully.</Status></AdvancedSMTPSetting></Response>' }
            }
        }

        $secret = ConvertTo-SecureString 'NewBatvSecret123' -AsPlainText -Force
        Set-SfosAdvancedSMTPSetting -BATVSecret $secret @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<BATVsecret>NewBatvSecret123</BATVsecret>' -and
            $InnerXml -notmatch 'hashform'
        }
    }

    It 'throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingAdvSettings }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AdvancedSMTPSetting><Status code="501">Configuration parameters validation failed.</Status></AdvancedSMTPSetting></Response>' }
            }
        }

        { Set-SfosAdvancedSMTPSetting -DoStrictRDNSchecks Enable @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingAdvSettings }
        }

        Set-SfosAdvancedSMTPSetting -DoStrictRDNSchecks Enable @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }
}

Describe 'SMTPPolicy - XML generation, RMW and the DomainName object reference' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosSMTPPolicy sends an add operation with escaped Name and the four nested protection blocks' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SMTPPolicy><Status code="200">Configuration applied successfully.</Status></SMTPPolicy></Response>' }
        }

        New-SfosSMTPPolicy -Name 'Partner & Co Policy' -DomainName 'PartnerGroup' -SpamProtectionStatus ON -MalwareProtectionStatus ON `
            -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<SMTPPolicy>' -and
            $InnerXml -match '<Name>Partner &amp; Co Policy</Name>' -and
            $InnerXml -match '<DomainList><DomainName>PartnerGroup</DomainName></DomainList>' -and
            $InnerXml -match '<SpamProtection>' -and
            $InnerXml -match '<SpamProtectionStatus>ON</SpamProtectionStatus>' -and
            $InnerXml -match '<MalwareProtection>' -and
            $InnerXml -match '<MalwareProtectionStatus>ON</MalwareProtectionStatus>' -and
            $InnerXml -match '<MalwareScanning>Dual Anti-Virus</MalwareScanning>' -and
            $InnerXml -match '<DropMessageGreaterThan>0</DropMessageGreaterThan>'
        }
    }

    It 'New-SfosSMTPPolicy throws naming MTAAddressGroup for a rejected -DomainName value (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SMTPPolicy><Status code="501">Configuration parameters validation failed.</Status><InvalidParams><Params>/SMTPPolicy/DomainList/DomainName</Params></InvalidParams></SMTPPolicy></Response>' }
        }

        { New-SfosSMTPPolicy -Name 'BadDomain' -DomainName 'partner.example.com' -SpamProtectionStatus OFF -MalwareProtectionStatus OFF `
                -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None @conn -Confirm:$false } |
            Should -Throw '*MTAAddressGroup*'
    }

    It 'New-SfosSMTPPolicy throws on a duplicate name/domain combination (measured 541)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SMTPPolicy><Status code="541">Operation failed. SMTPProfileduplicatedomain.</Status></SMTPPolicy></Response>' }
        }

        { New-SfosSMTPPolicy -Name 'DupPolicy' -DomainName 'PartnerGroup' -SpamProtectionStatus OFF -MalwareProtectionStatus OFF `
                -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None @conn -Confirm:$false } |
            Should -Throw '*541*'
    }

    It 'New-SfosSMTPPolicy rejects a missing -DomainName value before ever reaching the API (PowerShell''s own mandatory-array binding, not the module''s own guard - see file header)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        { New-SfosSMTPPolicy -Name 'Empty' -DomainName @() -SpamProtectionStatus OFF -MalwareProtectionStatus OFF `
                -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None @conn -Confirm:$false -ErrorAction Stop } |
            Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'New-SfosSMTPPolicy -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosSMTPPolicy -Name 'WhatIfPolicy' -DomainName 'PartnerGroup' -SpamProtectionStatus OFF -MalwareProtectionStatus OFF `
            -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosSMTPPolicy sends an update carrying the mandatory MalwareScanning/DropMessageGreaterThan and keeping other fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Name>ExistingPolicy</Name><DomainList><DomainName>PartnerGroup</DomainName></DomainList><RouteBy>Static Host</RouteBy><SpamProtection><SpamProtectionStatus>OFF</SpamProtectionStatus></SpamProtection><MalwareProtection><MalwareProtectionStatus>OFF</MalwareProtectionStatus></MalwareProtection><FiletypeFilter><FiletypeFilterStatus>OFF</FiletypeFilterStatus></FiletypeFilter><DataProtection><DataProtectionStatus>OFF</DataProtectionStatus></DataProtection><Action>Accept</Action><SPXEncryption>None</SPXEncryption><RouteList></RouteList></SMTPPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SMTPPolicy><Status code="200">Configuration applied successfully.</Status></SMTPPolicy></Response>' }
            }
        }

        Set-SfosSMTPPolicy -Name 'ExistingPolicy' -MalwareScanning 'Dual Anti-Virus' -DropMessageGreaterThan 0 -SpamProtectionStatus ON @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SpamProtectionStatus>ON</SpamProtectionStatus>' -and
            $InnerXml -match '<MalwareScanning>Dual Anti-Virus</MalwareScanning>' -and
            $InnerXml -match '<DropMessageGreaterThan>0</DropMessageGreaterThan>' -and
            $InnerXml -match '<DomainList><DomainName>PartnerGroup</DomainName></DomainList>' -and
            $InnerXml -match '<MalwareProtectionStatus>OFF</MalwareProtectionStatus>' -and
            $InnerXml -match '<Action>Accept</Action>' -and
            $InnerXml -match '<SPXEncryption>None</SPXEncryption>'
        }
    }

    It 'Set-SfosSMTPPolicy throws naming MTAAddressGroup for a rejected -DomainName value (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Name>ExistingPolicy</Name><DomainList><DomainName>PartnerGroup</DomainName></DomainList><SpamProtection><SpamProtectionStatus>OFF</SpamProtectionStatus></SpamProtection><MalwareProtection><MalwareProtectionStatus>OFF</MalwareProtectionStatus></MalwareProtection><FiletypeFilter><FiletypeFilterStatus>OFF</FiletypeFilterStatus></FiletypeFilter><DataProtection><DataProtectionStatus>OFF</DataProtectionStatus></DataProtection><Action>Accept</Action><SPXEncryption>None</SPXEncryption></SMTPPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SMTPPolicy><Status code="501">Configuration parameters validation failed.</Status><InvalidParams><Params>/SMTPPolicy/DomainList/DomainName</Params></InvalidParams></SMTPPolicy></Response>' }
            }
        }

        { Set-SfosSMTPPolicy -Name 'ExistingPolicy' -DomainName 'literal.example.com' -MalwareScanning 'Dual Anti-Virus' -DropMessageGreaterThan 0 @conn -Confirm:$false } |
            Should -Throw '*MTAAddressGroup*'
    }

    It 'Set-SfosSMTPPolicy throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Status>No. of records Zero.</Status></SMTPPolicy></Response>' }
        }

        { Set-SfosSMTPPolicy -Name 'DoesNotExist' -MalwareScanning 'Dual Anti-Virus' -DropMessageGreaterThan 0 @conn -Confirm:$false } |
            Should -Throw '*was not found*'
    }

    It 'Set-SfosSMTPPolicy -WhatIf does not send the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Name>ExistingPolicy</Name><DomainList><DomainName>PartnerGroup</DomainName></DomainList><SpamProtection><SpamProtectionStatus>OFF</SpamProtectionStatus></SpamProtection><MalwareProtection><MalwareProtectionStatus>OFF</MalwareProtectionStatus></MalwareProtection><FiletypeFilter><FiletypeFilterStatus>OFF</FiletypeFilterStatus></FiletypeFilter><DataProtection><DataProtectionStatus>OFF</DataProtectionStatus></DataProtection><Action>Accept</Action><SPXEncryption>None</SPXEncryption></SMTPPolicy></Response>' }
        }

        Set-SfosSMTPPolicy -Name 'ExistingPolicy' -MalwareScanning 'Dual Anti-Virus' -DropMessageGreaterThan 0 @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }

    It 'Remove-SfosSMTPPolicy reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Name>ExistingPolicy</Name><DomainList><DomainName>PartnerGroup</DomainName></DomainList><SpamProtection><SpamProtectionStatus>OFF</SpamProtectionStatus></SpamProtection><MalwareProtection><MalwareProtectionStatus>OFF</MalwareProtectionStatus></MalwareProtection><FiletypeFilter><FiletypeFilterStatus>OFF</FiletypeFilterStatus></FiletypeFilter><DataProtection><DataProtectionStatus>OFF</DataProtectionStatus></DataProtection><Action>Accept</Action><SPXEncryption>None</SPXEncryption></SMTPPolicy></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SMTPPolicy><Status code="200">Configuration applied successfully.</Status></SMTPPolicy></Response>' }
            }
        }

        Remove-SfosSMTPPolicy -Name 'ExistingPolicy' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<SMTPPolicy>' -and $InnerXml -match '<Name>ExistingPolicy</Name>'
        }
    }

    It 'Remove-SfosSMTPPolicy throws "was not found" without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Status>No. of records Zero.</Status></SMTPPolicy></Response>' }
        }

        { Remove-SfosSMTPPolicy -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosSMTPPolicy -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPPolicy transactionid=""><Name>ExistingPolicy</Name><DomainList><DomainName>PartnerGroup</DomainName></DomainList><SpamProtection><SpamProtectionStatus>OFF</SpamProtectionStatus></SpamProtection><MalwareProtection><MalwareProtectionStatus>OFF</MalwareProtectionStatus></MalwareProtection><FiletypeFilter><FiletypeFilterStatus>OFF</FiletypeFilterStatus></FiletypeFilter><DataProtection><DataProtectionStatus>OFF</DataProtectionStatus></DataProtection><Action>Accept</Action><SPXEncryption>None</SPXEncryption></SMTPPolicy></Response>' }
        }

        Remove-SfosSMTPPolicy -Name 'ExistingPolicy' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'Legacy read-only entities - AVASAddressGroup, SPXConfiguration, SPXTemplate, DataControlList' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosAVASAddressGroup parses Name, GroupType and the matching member list' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>Premium RBL Services</Name><GroupType>RBLIPv4</GroupType><Description>Premium RBLs.</Description><RBLList><RBLName>rbl.example.test</RBLName></RBLList></AVASAddressGroup></Response>' }
        }

        $result = @(Get-SfosAVASAddressGroup @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'Premium RBL Services'
        $result[0].GroupType | Should -Be 'RBLIPv4'
    }

    It 'Get-SfosAVASAddressGroup -NameLike filters client-side' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>Premium RBL Services</Name><GroupType>RBLIPv4</GroupType></AVASAddressGroup><AVASAddressGroup transactionid=""><Name>Standard RBL Services</Name><GroupType>RBLIPv4</GroupType></AVASAddressGroup></Response>' }
        }

        $result = @(Get-SfosAVASAddressGroup -NameLike 'Standard' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'Standard RBL Services'
    }

    It 'Get-SfosSPXConfiguration returns a PSCustomObject with the settings fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXConfiguration transactionid=""><SPXGlobalTemplate><DefaultSPXTemplate>Default Template</DefaultSPXTemplate></SPXGlobalTemplate><HostName>None</HostName><Port>8094</Port><AllowPassRegistrationFor>10</AllowPassRegistrationFor></SPXConfiguration></Response>' }
        }

        $result = Get-SfosSPXConfiguration @conn

        $result.DefaultSPXTemplate | Should -Be 'Default Template'
        $result.Port | Should -Be 8094
    }

    It 'Get-SfosSPXTemplate parses every template field' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Name>Default Template</Name><PDFEncryption>AES/128</PDFEncryption><PageSize>Letter</PageSize><PasswordType>SpecifiedBySender</PasswordType></SPXTemplates></Response>' }
        }

        $result = @(Get-SfosSPXTemplate @conn)

        $result.Count | Should -Be 1
        $result[0].PDFEncryption | Should -Be 'AES/128'
    }

    It 'Get-SfosDataControlList returns an empty array on an appliance running in MTA mode ("No. of records Zero.")' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Status>No. of records Zero.</Status></DataControlList></Response>' }
        }

        $result = @(Get-SfosDataControlList @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'Read-only MTA entities - RelaySettings, SmarthostSettings, MTABlockedSender, DKIMSigning, DKIMVerification' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosMailRelaySettings parses HostBased/UpstreamHost/AuthenticatedRelaySettings' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RelaySettings transactionid=""><HostBased><AllowRelay><HostsOrNetworks></HostsOrNetworks></AllowRelay><BlockRelay><HostsOrNetworks><HostsOrNetwork>Any</HostsOrNetwork></HostsOrNetworks></BlockRelay></HostBased><UpstreamHost><AllowRelay><HostsOrNetworks><HostsOrNetwork>Any</HostsOrNetwork></HostsOrNetworks></AllowRelay><BlockRelay><HostsOrNetworks></HostsOrNetworks></BlockRelay></UpstreamHost><AuthenticatedRelaySettings><AuthenticatedRelay>Disable</AuthenticatedRelay><UsersOrGroups></UsersOrGroups></AuthenticatedRelaySettings></RelaySettings></Response>' }
        }

        $result = Get-SfosMailRelaySettings @conn

        $result.HostBased.BlockRelay | Should -Contain 'Any'
        $result.UpstreamHost.AllowRelay | Should -Contain 'Any'
        $result.AuthenticatedRelaySettings.AuthenticatedRelay | Should -Be 'Disable'
    }

    It 'Get-SfosSmarthostSettings returns a PSCustomObject with the settings fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SmarthostSettings transactionid=""><UseSmarthost>Disable</UseSmarthost><Port>0</Port><AuthenticateDevicewithSmarthost>Disable</AuthenticateDevicewithSmarthost><Username></Username><Password></Password></SmarthostSettings></Response>' }
        }

        $result = Get-SfosSmarthostSettings @conn

        $result.UseSmarthost | Should -Be 'Disable'
    }

    It 'Get-SfosMTABlockedSender parses configured addresses' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MtaBlockedSenders transactionid=""><BlockedEmailAddresses><EmailAddress>spammer@example.com</EmailAddress></BlockedEmailAddresses></MtaBlockedSenders></Response>' }
        }

        $result = @(Get-SfosMTABlockedSender @conn)

        $result.Count | Should -Be 1
        $result[0].EmailAddress | Should -Be 'spammer@example.com'
    }

    It 'Get-SfosMTABlockedSender returns an empty array without throwing when the firewall answers with no entity element and no status at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }

        $result = @(Get-SfosMTABlockedSender @conn)
        $result.Count | Should -Be 0
    }

    It 'Get-SfosDKIMSigning parses Domain/KeySelector/PrivateRSAKey and filters client-side by -DomainLike' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DKIMSigning transactionid=""><Domain>example.com</Domain><KeySelector>mail</KeySelector><PrivateRSAKey>fake-key-material</PrivateRSAKey></DKIMSigning><DKIMSigning transactionid=""><Domain>example.net</Domain><KeySelector>mail</KeySelector><PrivateRSAKey>fake-key-material-2</PrivateRSAKey></DKIMSigning></Response>' }
        }

        $result = @(Get-SfosDKIMSigning -DomainLike 'example.net' @conn)

        $result.Count | Should -Be 1
        $result[0].Domain | Should -Be 'example.net'
    }

    It 'Get-SfosDKIMVerification returns a PSCustomObject with the settings fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DKIMVerification transactionid=""><VerifactionStatus>Disable</VerifactionStatus><ActionForVerifactionFail></ActionForVerifactionFail><ActionForSignatureInvalid></ActionForSignatureInvalid><ActionForSignatureNotFound></ActionForSignatureNotFound></DKIMVerification></Response>' }
        }

        $result = Get-SfosDKIMVerification @conn

        $result.VerifactionStatus | Should -Be 'Disable'
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

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Status>No. of records Zero.</Status></MTAAddressGroup></Response>' }
        }

        $result = @(Get-SfosMTAAddressGroup @conn)
        $result.Count | Should -Be 0
    }

    It 'a code-less status that is not "No. of records Zero." throws' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Status>Transaction fail</Status></MTAAddressGroup></Response>' }
        }

        { Get-SfosMTAAddressGroup @conn } | Should -Throw
    }

    It 'throws on a 5xx status code' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><MTAAddressGroup transactionid=""><Status code="529">Invalid XML request</Status></MTAAddressGroup></Response>' }
        }

        { Get-SfosMTAAddressGroup @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosMTAAddressGroup @conn } | Should -Throw '*login failed*'
    }
}

Describe 'AVASAddressGroup - XML generation, RMW and the 545 mode gate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosAVASAddressGroup sends an add operation with the root, escaped Name and the EmailAddressList member shape' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AVASAddressGroup><Status code="200">Configuration applied successfully.</Status></AVASAddressGroup></Response>' }
        }

        New-SfosAVASAddressGroup -Name 'Partner & Co' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AVASAddressGroup>' -and
            $InnerXml -match '<Name>Partner &amp; Co</Name>' -and
            $InnerXml -match '<GroupType>EmailAddressOrDomain</GroupType>' -and
            $InnerXml -match '<EmailAddressList><EmailAddressDomain>example\.com</EmailAddressDomain></EmailAddressList>'
        }
    }

    It 'New-SfosAVASAddressGroup rejects a missing -Member value before ever reaching the API (PowerShell''s own mandatory-array binding, not the module''s own guard - see file header)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        { New-SfosAVASAddressGroup -Name 'Empty' -GroupType EmailAddressOrDomain -Member @() @conn -Confirm:$false -ErrorAction Stop } | Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'New-SfosAVASAddressGroup throws mentioning the mode on a mocked 545 (MTAModeDisableCheck)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AVASAddressGroup><Status code="545">Operation failed. MTAModeDisableCheck - this legacy operation requires legacy mode, but MTA mode is currently active.</Status></AVASAddressGroup></Response>' }
        }

        { New-SfosAVASAddressGroup -Name 'ModeLocked' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -Confirm:$false } |
            Should -Throw '*MTAModeDisableCheck*'
    }

    It 'New-SfosAVASAddressGroup throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><AVASAddressGroup><Status code="502">Operation failed. Entity having same name already exists.</Status></AVASAddressGroup></Response>' }
        }

        { New-SfosAVASAddressGroup -Name 'DupGroup' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosAVASAddressGroup -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosAVASAddressGroup -Name 'WhatIfGroup' -GroupType EmailAddressOrDomain -Member 'example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosAVASAddressGroup sends an update operation, keeping the member list and Description the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><Description>Trusted partner domains</Description><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></AVASAddressGroup></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AVASAddressGroup><Status code="200">Configuration applied successfully.</Status></AVASAddressGroup></Response>' }
            }
        }

        Set-SfosAVASAddressGroup -Name 'ExistingGroup' -GroupType EmailAddressOrDomain @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Description>Trusted partner domains</Description>' -and
            $InnerXml -match '<EmailAddressList><EmailAddressDomain>example\.com</EmailAddressDomain></EmailAddressList>'
        }
    }

    It 'Set-SfosAVASAddressGroup throws when -GroupType differs from the current value and -Member is not passed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></AVASAddressGroup></Response>' }
        }

        { Set-SfosAVASAddressGroup -Name 'ExistingGroup' -GroupType IPAddress @conn -Confirm:$false } | Should -Throw '*-Member*'
    }

    It 'Set-SfosAVASAddressGroup throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Status>No. of records Zero.</Status></AVASAddressGroup></Response>' }
        }

        { Set-SfosAVASAddressGroup -Name 'DoesNotExist' -GroupType EmailAddressOrDomain @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Set-SfosAVASAddressGroup -WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></AVASAddressGroup></Response>' }
        }

        Set-SfosAVASAddressGroup -Name 'ExistingGroup' -GroupType EmailAddressOrDomain @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }

    It 'Remove-SfosAVASAddressGroup reads first, then sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></AVASAddressGroup></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AVASAddressGroup><Status code="200">Configuration applied successfully.</Status></AVASAddressGroup></Response>' }
            }
        }

        Remove-SfosAVASAddressGroup -Name 'ExistingGroup' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<AVASAddressGroup>' -and $InnerXml -match '<Name>ExistingGroup</Name>'
        }
    }

    It 'Remove-SfosAVASAddressGroup throws "was not found" for an unknown name, without attempting the Remove call (the firewall itself answers a false 200 here)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Status>No. of records Zero.</Status></AVASAddressGroup></Response>' }
        }

        { Remove-SfosAVASAddressGroup -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosAVASAddressGroup -WhatIf makes the existence-check call but never sends the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AVASAddressGroup transactionid=""><Name>ExistingGroup</Name><GroupType>EmailAddressOrDomain</GroupType><EmailAddressList><EmailAddressDomain>example.com</EmailAddressDomain></EmailAddressList></AVASAddressGroup></Response>' }
        }

        Remove-SfosAVASAddressGroup -Name 'ExistingGroup' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'DataControlList - XML generation, RMW and the 545 mode gate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosDataControlList sends an add operation with escaped Name and the Signatures list' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><DataControlList><Status code="200">Configuration applied successfully.</Status></DataControlList></Response>' }
        }

        New-SfosDataControlList -Name 'Address Check & Co' -Signature 'Postal addresses [Germany]', 'Postal addresses [France]' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<DataControlList>' -and
            $InnerXml -match '<Name>Address Check &amp; Co</Name>' -and
            $InnerXml -match '<Signatures><Signature>Postal addresses \[Germany\]</Signature><Signature>Postal addresses \[France\]</Signature></Signatures>'
        }
    }

    It 'New-SfosDataControlList rejects a missing -Signature value before ever reaching the API (PowerShell''s own mandatory-array binding, not the module''s own guard - see file header)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        { New-SfosDataControlList -Name 'Empty' -Signature @() @conn -Confirm:$false -ErrorAction Stop } | Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'New-SfosDataControlList throws mentioning the mode on a mocked 545 (MTAModeDisableCheck)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><DataControlList><Status code="545">Operation failed. MTAModeDisableCheck - this legacy operation requires legacy mode, but MTA mode is currently active.</Status></DataControlList></Response>' }
        }

        { New-SfosDataControlList -Name 'ModeLocked' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false } |
            Should -Throw '*MTAModeDisableCheck*'
    }

    It 'New-SfosDataControlList throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><DataControlList><Status code="502">Operation failed. Entity having same name already exists.</Status></DataControlList></Response>' }
        }

        { New-SfosDataControlList -Name 'DupList' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'New-SfosDataControlList -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosDataControlList -Name 'WhatIfList' -Signature 'Postal addresses [Germany]' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosDataControlList sends an update carrying a shorter -Signature list, replacing rather than appending' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature><Signature>Postal addresses [France]</Signature></Signatures></DataControlList></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><DataControlList><Status code="200">Configuration applied successfully.</Status></DataControlList></Response>' }
            }
        }

        Set-SfosDataControlList -Name 'ExistingList' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Signatures><Signature>Postal addresses \[Germany\]</Signature></Signatures>' -and
            $InnerXml -notmatch 'France'
        }
    }

    It 'Set-SfosDataControlList keeps the current Signature list when -Signature is not passed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature><Signature>Postal addresses [France]</Signature></Signatures></DataControlList></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><DataControlList><Status code="200">Configuration applied successfully.</Status></DataControlList></Response>' }
            }
        }

        Set-SfosDataControlList -Name 'ExistingList' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Signature>Postal addresses \[Germany\]</Signature>' -and
            $InnerXml -match '<Signature>Postal addresses \[France\]</Signature>'
        }
    }

    It 'Set-SfosDataControlList throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Status>No. of records Zero.</Status></DataControlList></Response>' }
        }

        { Set-SfosDataControlList -Name 'DoesNotExist' -Signature 'Postal addresses [Germany]' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Set-SfosDataControlList -WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature></Signatures></DataControlList></Response>' }
        }

        Set-SfosDataControlList -Name 'ExistingList' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }

    It 'Remove-SfosDataControlList reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature></Signatures></DataControlList></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><DataControlList><Status code="200">Configuration applied successfully.</Status></DataControlList></Response>' }
            }
        }

        Remove-SfosDataControlList -Name 'ExistingList' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<DataControlList>' -and $InnerXml -match '<Name>ExistingList</Name>'
        }
    }

    It 'Remove-SfosDataControlList throws "was not found" for an unknown name, without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Status>No. of records Zero.</Status></DataControlList></Response>' }
        }

        { Remove-SfosDataControlList -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosDataControlList -WhatIf makes the existence-check call but never sends the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DataControlList transactionid=""><Name>ExistingList</Name><Signatures><Signature>Postal addresses [Germany]</Signature></Signatures></DataControlList></Response>' }
        }

        Remove-SfosDataControlList -Name 'ExistingList' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'SPXTemplate - XML generation, RMW and the 545 mode gate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosSPXTemplate sends an add operation with the plural root, escaped Name and the requested fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SPXTemplates><Status code="200">Configuration applied successfully.</Status></SPXTemplates></Response>' }
        }

        New-SfosSPXTemplate -Name 'Partner & Co Template' -OrganizationName 'Example Org' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<SPXTemplates>' -and
            $InnerXml -match '<Name>Partner &amp; Co Template</Name>' -and
            $InnerXml -match '<OrganizationName>Example Org</OrganizationName>' -and
            $InnerXml -match '<PDFEncryption>AES/256</PDFEncryption>' -and
            $InnerXml -match '<PageSize>Letter</PageSize>' -and
            $InnerXml -match '<PasswordType>SpecifiedBySender</PasswordType>'
        }
    }

    It 'New-SfosSPXTemplate throws mentioning the mode on a mocked 545 (MTAModeDisableCheck)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SPXTemplates><Status code="545">Operation failed. MTAModeDisableCheck - this legacy operation requires legacy mode, but MTA mode is currently active.</Status></SPXTemplates></Response>' }
        }

        { New-SfosSPXTemplate -Name 'ModeLocked' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender' @conn -Confirm:$false } |
            Should -Throw '*MTAModeDisableCheck*'
    }

    It 'New-SfosSPXTemplate throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SPXTemplates><Status code="502">Operation failed. Entity having same name already exists.</Status></SPXTemplates></Response>' }
        }

        { New-SfosSPXTemplate -Name 'DupTemplate' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender' @conn -Confirm:$false } |
            Should -Throw '*502*'
    }

    It 'New-SfosSPXTemplate throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SPXTemplates><Status code="501">Configuration parameters validation failed.</Status></SPXTemplates></Response>' }
        }

        { New-SfosSPXTemplate -Name 'BadTemplate' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender' @conn -Confirm:$false } |
            Should -Throw '*501*'
    }

    It 'New-SfosSPXTemplate -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        New-SfosSPXTemplate -Name 'WhatIfTemplate' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosSPXTemplate sends an update, keeping fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Name>ExistingTemplate</Name><Description>old</Description><OrganizationName>Old Org</OrganizationName><PDFEncryption>AES/128</PDFEncryption><PageSize>Letter</PageSize><PasswordType>SpecifiedBySender</PasswordType></SPXTemplates></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SPXTemplates><Status code="200">Configuration applied successfully.</Status></SPXTemplates></Response>' }
            }
        }

        Set-SfosSPXTemplate -Name 'ExistingTemplate' -OrganizationName 'New Org' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<OrganizationName>New Org</OrganizationName>' -and
            $InnerXml -match '<Description>old</Description>' -and
            $InnerXml -match '<PDFEncryption>AES/128</PDFEncryption>' -and
            $InnerXml -match '<PageSize>Letter</PageSize>' -and
            $InnerXml -match '<PasswordType>SpecifiedBySender</PasswordType>'
        }
    }

    It 'Set-SfosSPXTemplate throws "was not found" for an unknown name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Status>No. of records Zero.</Status></SPXTemplates></Response>' }
        }

        { Set-SfosSPXTemplate -Name 'DoesNotExist' -OrganizationName 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Set-SfosSPXTemplate -WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Name>ExistingTemplate</Name><OrganizationName>Org</OrganizationName></SPXTemplates></Response>' }
        }

        Set-SfosSPXTemplate -Name 'ExistingTemplate' -OrganizationName 'New Org' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }

    It 'Remove-SfosSPXTemplate reads first, sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Name>ExistingTemplate</Name><OrganizationName>Org</OrganizationName></SPXTemplates></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SPXTemplates><Status code="200">Configuration applied successfully.</Status></SPXTemplates></Response>' }
            }
        }

        Remove-SfosSPXTemplate -Name 'ExistingTemplate' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<SPXTemplates>' -and $InnerXml -match '<Name>ExistingTemplate</Name>'
        }
    }

    It 'Remove-SfosSPXTemplate throws "was not found" for an unknown name, without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Status>No. of records Zero.</Status></SPXTemplates></Response>' }
        }

        { Remove-SfosSPXTemplate -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosSPXTemplate -WhatIf makes the existence-check call but never sends the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SPXTemplates transactionid=""><Name>ExistingTemplate</Name><OrganizationName>Org</OrganizationName></SPXTemplates></Response>' }
        }

        Remove-SfosSPXTemplate -Name 'ExistingTemplate' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Remove>' }
    }
}

Describe 'SPXConfiguration - RMW singleton' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $script:ExistingSPXConfig = '<Response><Login><status>Authentication Successful</status></Login><SPXConfiguration transactionid=""><SPXGlobalTemplate><DefaultSPXTemplate>Default Template</DefaultSPXTemplate></SPXGlobalTemplate><HostName>None</HostName><AllowedNetworks></AllowedNetworks><Port>8094</Port><KeepUnusedPassFor>30</KeepUnusedPassFor><AllowPassRegistrationFor>10</AllowPassRegistrationFor><SendNotifcationErrorTo>SenderOnly</SendNotifcationErrorTo></SPXConfiguration></Response>'
    }

    It 'Set-SfosSPXConfiguration sends operation=update, keeping fields the caller did not pass' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingSPXConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SPXConfiguration><Status code="200">Configuration applied successfully.</Status></SPXConfiguration></Response>' }
            }
        }

        Set-SfosSPXConfiguration -HostName 'spx.example.com' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SPXConfiguration>' -and
            $InnerXml -match '<HostName>spx\.example\.com</HostName>' -and
            $InnerXml -match '<DefaultSPXTemplate>Default Template</DefaultSPXTemplate>' -and
            $InnerXml -match '<Port>8094</Port>' -and
            $InnerXml -match '<AllowPassRegistrationFor>10</AllowPassRegistrationFor>' -and
            $InnerXml -match '<SendNotifcationErrorTo>SenderOnly</SendNotifcationErrorTo>'
        }
    }

    It 'throws on a field validation error (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingSPXConfig }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><SPXConfiguration><Status code="501">Configuration parameters validation failed.</Status></SPXConfiguration></Response>' }
            }
        }

        { Set-SfosSPXConfiguration -HostName 'spx.example.com' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingSPXConfig }
        }

        Set-SfosSPXConfiguration -HostName 'spx.example.com' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation="update">' }
    }
}

Describe 'SMTPDeploymentMode - the mode switch' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosSMTPDeploymentMode returns a PSCustomObject with MTAMode from the mocked response' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMTPDeploymentMode transactionid=""><MTAMode>ON</MTAMode></SMTPDeploymentMode></Response>' }
        }

        $result = Get-SfosSMTPDeploymentMode @conn

        $result.MTAMode | Should -Be 'ON'
    }

    It 'Set-SfosSMTPDeploymentMode sends operation=update with the requested MTAMode' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SMTPDeploymentMode><Status code="200">Configuration applied successfully.</Status></SMTPDeploymentMode></Response>' }
        }

        Set-SfosSMTPDeploymentMode -MTAMode OFF @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<SMTPDeploymentMode>' -and
            $InnerXml -match '<MTAMode>OFF</MTAMode>'
        }
    }

    It 'Set-SfosSMTPDeploymentMode rejects a value outside ON/OFF before ever reaching the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        { Set-SfosSMTPDeploymentMode -MTAMode 'Maybe' @conn -Confirm:$false -ErrorAction Stop } | Should -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosSMTPDeploymentMode -WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email

        Set-SfosSMTPDeploymentMode -MTAMode ON @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -Times 0 -Exactly
    }

    It 'Set-SfosSMTPDeploymentMode throws on a rejected value (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Email -MockWith {
            [PSCustomObject]@{ Content = '<Response><SMTPDeploymentMode><Status code="501">Configuration parameters validation failed.</Status></SMTPDeploymentMode></Response>' }
        }

        { Set-SfosSMTPDeploymentMode -MTAMode ON @conn -Confirm:$false } | Should -Throw '*501*'
    }
}
