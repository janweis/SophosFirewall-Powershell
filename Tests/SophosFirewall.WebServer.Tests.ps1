#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.WebServer module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 18 exported functions
    with their identifying and connection parameters; inner XML generation (root element,
    operation, name, XML escaping) for every New/Set/Remove cmdlet across the five entities
    RealServers, ProtocolSecurity, ReverseAuthentication, FormTemplate and WAFSlowHTTP; the
    read-modify-write path of every Set-* cmdlet; the RequestSizeLimitMB/bytes conversion on
    ProtocolSecurity, including the round trip that must not reconvert an untouched value; the
    undocumented but mandatory FrontendRealm field on ReverseAuthentication; the binary-vs-XML
    transport branch and the misleading 200-on-nonexistent-object Remove behaviour of
    FormTemplate; the multipart upload of New-/Set-SfosWebServerAuthenticationTemplate,
    including the Assets/Asset XML and the Asset multipart field for multiple files, the
    existence check ahead of Set, and a missing local file failing before any API call; the
    WAFSlowHTTP singleton no-op round trip; -WhatIf suppressing every write call; and the
    shared status-parsing error paths (5xx throws, a failed login with no entity status
    throws, "No. of records Zero." yields an empty array).

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
        Invoke-Pester -Path '.\SophosFirewall.WebServer.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.WebServer\SophosFirewall.WebServer.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.WebServer module should load' {
        Get-Module SophosFirewall.WebServer | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 18 functions' {
        (Get-Module SophosFirewall.WebServer).ExportedFunctions.Count | Should -Be 18
    }

    It 'Manifest FunctionsToExport should list exactly 18 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.WebServer\SophosFirewall.WebServer.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 18
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosWebServer'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosWebServer'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosWebServer'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosWebServer'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosWebServerProtectionPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosWebServerProtectionPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosWebServerProtectionPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosWebServerProtectionPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosWebServerAuthenticationPolicy'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosWebServerAuthenticationPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosWebServerAuthenticationPolicy'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosWebServerAuthenticationPolicy'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosWebServerAuthenticationTemplate'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosWebServerAuthenticationTemplate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosWebServerAuthenticationTemplate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosWebServerAuthenticationTemplate'; IdParam = 'Name'; Mandatory = $true }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with an identifying parameter <IdParam> and the six connection parameters' -TestCases $script:CmdletParameterCases {
        param($Function, $IdParam, $Mandatory)

        $cmd = Get-Command $Function -Module SophosFirewall.WebServer -ErrorAction SilentlyContinue
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

    It 'Exports the WAFSlowHTTP singleton cmdlets with the six connection parameters, no identifying parameter' {
        foreach ($name in 'Get-SfosWebServerSlowHTTPProtectionSettings', 'Set-SfosWebServerSlowHTTPProtectionSettings') {
            $cmd = Get-Command $name -Module SophosFirewall.WebServer -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty -Because "$name should be exported"
            foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
                $cmd.Parameters.Keys | Should -Contain $connParam
            }
        }
    }

    It 'New-SfosWebServerAuthenticationPolicy requires the undocumented FrontendRealm field' {
        $cmd = Get-Command New-SfosWebServerAuthenticationPolicy -Module SophosFirewall.WebServer
        $isMandatory = ($cmd.Parameters['FrontendRealm'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory }) -contains $true
        $isMandatory | Should -Be $true
    }
}

Describe 'RealServers - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosWebServer sends an add operation carrying Name, Host and Port' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><RealServers><Status code="200">Configuration applied successfully.</Status></RealServers></Response>' }
        }

        New-SfosWebServer -Name 'IntranetServer' -HostName 'IntranetServerHost' -PortNumber 8080 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<RealServers>' -and
            $InnerXml -match '<Name>IntranetServer</Name>' -and
            $InnerXml -match '<Host>IntranetServerHost</Host>' -and
            $InnerXml -match '<Port>8080</Port>'
        }
    }

    It 'escapes a Description containing an ampersand and angle brackets' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><RealServers><Status code="200">Configuration applied successfully.</Status></RealServers></Response>' }
        }

        New-SfosWebServer -Name 'Esc' -Description 'Smith & Sons "Test" <ok>' -HostName 'SomeHost' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Description>Smith &amp; Sons &quot;Test&quot; &lt;ok&gt;</Description>'
        }
    }

    It 'Remove-SfosWebServer sends a Remove request carrying the name, after confirming the object exists' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Name>IntranetServer</Name><Description></Description><Host>IntranetServerHost</Host><Type>Plaintext (HTTP)</Type><Port>8080</Port><KeepAlive>Enable</KeepAlive><TimeOut>300</TimeOut><DisableReuse>Disable</DisableReuse></RealServers></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><RealServers><Status code="200">Configuration applied successfully.</Status></RealServers></Response>' }
            }
        }

        Remove-SfosWebServer -Name 'IntranetServer' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<RealServers>' -and
            $InnerXml -match '<Name>IntranetServer</Name>'
        }
    }
}

Describe 'Set-SfosWebServer - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Name>IntranetServer</Name><Description>Old desc</Description><Host>OldHost</Host><Type>Plaintext (HTTP)</Type><Port>80</Port><KeepAlive>Enable</KeepAlive><TimeOut>300</TimeOut><DisableReuse>Disable</DisableReuse></RealServers></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><RealServers><Status code="200">Configuration applied successfully.</Status></RealServers></Response>' }
            }
        }
    }

    It 'sends an update operation carrying the changed field' {
        Set-SfosWebServer -Name 'IntranetServer' -PortNumber 8443 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<RealServers>' -and
            $InnerXml -match '<Name>IntranetServer</Name>' -and
            $InnerXml -match '<Port>8443</Port>'
        }
    }

    It 'keeps every field the caller did not pass' {
        Set-SfosWebServer -Name 'IntranetServer' -PortNumber 8443 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Description>Old desc</Description>' -and
            $InnerXml -match '<Host>OldHost</Host>' -and
            $InnerXml -match '<KeepAlive>Enable</KeepAlive>' -and
            $InnerXml -match '<TimeOut>300</TimeOut>' -and
            $InnerXml -match '<DisableReuse>Disable</DisableReuse>'
        }
    }
}

Describe 'RealServers - error handling and WhatIf' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosWebServer throws a clear message for a raw IP address instead of a Host object name (measured 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><RealServers><Status code="501">Configuration parameters validation failed.</Status><InvalidParams><Params>/RealServers/Host</Params></InvalidParams></RealServers></Response>' }
        }

        { New-SfosWebServer -Name 'BadHost' -HostName '203.0.113.5' @conn -Confirm:$false } |
            Should -Throw '*-HostName must be the name of an existing IPHost or FQDNHost*'
    }

    It 'Remove-SfosWebServer throws "was not found" without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Status>No. of records Zero.</Status></RealServers></Response>' }
        }

        { Remove-SfosWebServer -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }

    It 'Set-SfosWebServer -WhatIf does not send the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Name>IntranetServer</Name><Description></Description><Host>OldHost</Host><Type>Plaintext (HTTP)</Type><Port>80</Port><KeepAlive>Enable</KeepAlive><TimeOut>300</TimeOut><DisableReuse>Disable</DisableReuse></RealServers></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><RealServers><Status code="200">Configuration applied successfully.</Status></RealServers></Response>' }
            }
        }

        Set-SfosWebServer -Name 'IntranetServer' -PortNumber 9999 @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'Remove-SfosWebServer -WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Name>IntranetServer</Name><Description></Description><Host>OldHost</Host><Type>Plaintext (HTTP)</Type><Port>80</Port><KeepAlive>Enable</KeepAlive><TimeOut>300</TimeOut><DisableReuse>Disable</DisableReuse></RealServers></Response>' }
        }

        Remove-SfosWebServer -Name 'IntranetServer' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }
}

Describe 'ProtocolSecurity - XML generation and RequestSizeLimit unit conversion' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosWebServerProtectionPolicy converts -RequestSizeLimitMB to the bytes the wire stores' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><ProtocolSecurity><Status code="200">Configuration applied successfully.</Status></ProtocolSecurity></Response>' }
        }

        New-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Mode Reject -RequestSizeLimitMB 10 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<ProtocolSecurity>' -and
            $InnerXml -match '<Name>IntranetProtection</Name>' -and
            $InnerXml -match '<Mode>Reject</Mode>' -and
            $InnerXml -match '<RequestSizeLimit>10485760</RequestSizeLimit>'
        }
    }

    It 'Get-SfosWebServerProtectionPolicy exposes both the raw bytes and the megabyte value' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ProtocolSecurity transactionid=""><Name>Exchange AutoDiscover</Name><Description>Exchange AutoDiscover</Description><Mode>Reject</Mode><RequestSizeLimit>1048576</RequestSizeLimit></ProtocolSecurity></Response>' }
        }

        $result = Get-SfosWebServerProtectionPolicy @conn

        $result.RequestSizeLimitBytes | Should -Be 1048576
        $result.RequestSizeLimitMB | Should -Be 1
    }
}

Describe 'Set-SfosWebServerProtectionPolicy - read-modify-write and RequestSizeLimitMB round trip' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ProtocolSecurity transactionid=""><Name>IntranetProtection</Name><Description>Old</Description><Mode>Reject</Mode><RequestSizeLimit>1048576</RequestSizeLimit></ProtocolSecurity></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ProtocolSecurity><Status code="200">Configuration applied successfully.</Status></ProtocolSecurity></Response>' }
            }
        }
    }

    It 'does not reconvert the existing byte value when -RequestSizeLimitMB is not passed' {
        Set-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<RequestSizeLimit>1048576</RequestSizeLimit>'
        }
    }

    It 'converts a newly passed -RequestSizeLimitMB to bytes' {
        Set-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -RequestSizeLimitMB 5 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<RequestSizeLimit>5242880</RequestSizeLimit>'
        }
    }

    It 'keeps Mode when only Description is changed' {
        Set-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Description>Updated</Description>' -and
            $InnerXml -match '<Mode>Reject</Mode>'
        }
    }
}

Describe 'ProtocolSecurity - error handling and WhatIf' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosWebServerProtectionPolicy throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><ProtocolSecurity><Status code="502">Operation failed. Entity having same name already exists.</Status></ProtocolSecurity></Response>' }
        }

        { New-SfosWebServerProtectionPolicy -Name 'Exchange General' -Mode Reject -RequestSizeLimitMB 5 @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'Remove-SfosWebServerProtectionPolicy throws "was not found" for a nonexistent policy' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ProtocolSecurity transactionid=""><Status>No. of records Zero.</Status></ProtocolSecurity></Response>' }
        }

        { Remove-SfosWebServerProtectionPolicy -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }

    It 'Set-SfosWebServerProtectionPolicy -WhatIf does not send the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ProtocolSecurity transactionid=""><Name>IntranetProtection</Name><Description></Description><Mode>Reject</Mode><RequestSizeLimit>1048576</RequestSizeLimit></ProtocolSecurity></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ProtocolSecurity><Status code="200">Configuration applied successfully.</Status></ProtocolSecurity></Response>' }
            }
        }

        Set-SfosWebServerProtectionPolicy -Name 'IntranetProtection' -Description 'x' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}

Describe 'ReverseAuthentication - XML generation, including the undocumented FrontendRealm field' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosWebServerAuthenticationPolicy sends an add operation carrying FrontendRealm' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><ReverseAuthentication><Status code="200">Configuration applied successfully.</Status></ReverseAuthentication></Response>' }
        }

        New-SfosWebServerAuthenticationPolicy -Name 'IntranetAuth' -VirtualWebserverMode Basic -FrontendRealm 'intranetrealm' -BasicPrompt 'Please sign in.' -RealWebserverMode Basic -UsernameAffix Basic @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<ReverseAuthentication>' -and
            $InnerXml -match '<Name>IntranetAuth</Name>' -and
            $InnerXml -match '<VirtualWebserverMode>Basic</VirtualWebserverMode>' -and
            $InnerXml -match '<FrontendRealm>intranetrealm</FrontendRealm>' -and
            $InnerXml -match '<RealWebserverMode>Basic</RealWebserverMode>' -and
            $InnerXml -match '<UsernameAffix>Basic</UsernameAffix>'
        }
    }

    It 'throws on the measured 501 when the firewall rejects the FrontendRealm value' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><ReverseAuthentication><Status code="501">Configuration parameters validation failed.</Status><InvalidParams><Params>/ReverseAuthentication/FrontendRealm</Params></InvalidParams></ReverseAuthentication></Response>' }
        }

        { New-SfosWebServerAuthenticationPolicy -Name 'BadAuth' -VirtualWebserverMode Basic -FrontendRealm 'r' -BasicPrompt 'Please sign in.' -RealWebserverMode Basic -UsernameAffix Basic @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It 'New-SfosWebServerAuthenticationPolicy refuses a Basic policy without a prompt before calling the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><ReverseAuthentication><Status code="200">Configuration applied successfully.</Status></ReverseAuthentication></Response>' }
        }

        { New-SfosWebServerAuthenticationPolicy -Name 'NoPrompt' -VirtualWebserverMode Basic -FrontendRealm 'r' -RealWebserverMode Basic -UsernameAffix Basic @conn -Confirm:$false } |
            Should -Throw '*BasicPrompt*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly
    }

    It 'Remove-SfosWebServerAuthenticationPolicy sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ReverseAuthentication transactionid=""><Name>Basic with passthrough</Name><Description></Description><VirtualWebserverMode>Basic</VirtualWebserverMode><FrontendRealm>mdgrtrmozksef</FrontendRealm><RealWebserverMode>Basic</RealWebserverMode><UsernameAffix>Basic</UsernameAffix></ReverseAuthentication></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ReverseAuthentication><Status code="200">Configuration applied successfully.</Status></ReverseAuthentication></Response>' }
            }
        }

        Remove-SfosWebServerAuthenticationPolicy -Name 'Basic with passthrough' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<ReverseAuthentication>' -and
            $InnerXml -match '<Name>Basic with passthrough</Name>'
        }
    }
}

Describe 'Set-SfosWebServerAuthenticationPolicy - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ReverseAuthentication transactionid=""><Name>Form with passthrough</Name><Description>Form with passthrough</Description><VirtualWebserverMode>Form</VirtualWebserverMode><FrontendRealm>uihgxqqtwgndv</FrontendRealm><RealWebserverMode>Basic</RealWebserverMode><SessionTimeout>Enable</SessionTimeout><SessionLifetime>Enable</SessionLifetime><FormTemplate>Default Template</FormTemplate><UsernameAffix>Basic</UsernameAffix><SessionTimeoutLimit>5</SessionTimeoutLimit><SessionTimeoutScope>Minutes</SessionTimeoutScope><SessionLifetimeLimit>8</SessionLifetimeLimit><SessionLifetimeScope>Hours</SessionLifetimeScope></ReverseAuthentication></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ReverseAuthentication><Status code="200">Configuration applied successfully.</Status></ReverseAuthentication></Response>' }
            }
        }
    }

    It 'sends an update operation carrying only the changed field' {
        Set-SfosWebServerAuthenticationPolicy -Name 'Form with passthrough' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ReverseAuthentication>' -and
            $InnerXml -match '<Name>Form with passthrough</Name>' -and
            $InnerXml -match '<Description>Updated</Description>'
        }
    }

    It 'keeps FrontendRealm and the session timeout/lifetime fields the caller did not pass' {
        Set-SfosWebServerAuthenticationPolicy -Name 'Form with passthrough' -Description 'Updated' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<FrontendRealm>uihgxqqtwgndv</FrontendRealm>' -and
            $InnerXml -match '<SessionTimeoutLimit>5</SessionTimeoutLimit>' -and
            $InnerXml -match '<SessionTimeoutScope>Minutes</SessionTimeoutScope>' -and
            $InnerXml -match '<SessionLifetimeLimit>8</SessionLifetimeLimit>' -and
            $InnerXml -match '<SessionLifetimeScope>Hours</SessionLifetimeScope>'
        }
    }

    It 'throws "was not found" for a nonexistent policy' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ReverseAuthentication transactionid=""><Status>No. of records Zero.</Status></ReverseAuthentication></Response>' }
        }

        { Set-SfosWebServerAuthenticationPolicy -Name 'DoesNotExist' -Description 'x' @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'FormTemplate - binary transport and the misleading Remove success' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosWebServerAuthenticationTemplate returns the raw archive when the firewall answers binary' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{
                Content = [byte[]]@(1, 2, 3, 4)
                Headers = @{ 'Content-Type' = 'application/octet-stream' }
            }
        }

        $result = Get-SfosWebServerAuthenticationTemplate -NameLike 'Default' @conn

        $result.RawContent.Count | Should -Be 4
        $result.ContentType | Should -Be 'application/octet-stream'
    }

    It 'Get-SfosWebServerAuthenticationTemplate returns an empty array for "No. of records Zero."' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FormTemplate transactionid=""><Status>No. of records Zero.</Status></FormTemplate></Response>' }
        }

        $result = @(Get-SfosWebServerAuthenticationTemplate -NameLike 'DoesNotExist' @conn)
        $result.Count | Should -Be 0
    }

    It 'Remove-SfosWebServerAuthenticationTemplate throws "was not found" without attempting the Remove call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FormTemplate transactionid=""><Status>No. of records Zero.</Status></FormTemplate></Response>' }
        }

        { Remove-SfosWebServerAuthenticationTemplate -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly
    }

    It 'throws when the firewall reports 200 for a Remove but the object is still present (measured no-op)' {
        $script:FormTemplateGetCount = 0

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                $script:FormTemplateGetCount++
                [PSCustomObject]@{
                    Content = [byte[]]@(1, 2, 3)
                    Headers = @{ 'Content-Type' = 'application/octet-stream' }
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="200">Configuration applied successfully.</Status></FormTemplate></Response>' }
            }
        }

        { Remove-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' @conn -Confirm:$false } | Should -Throw '*still present*'
        $script:FormTemplateGetCount | Should -Be 2
    }

    It '-WhatIf does not send the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{
                Content = [byte[]]@(1, 2, 3)
                Headers = @{ 'Content-Type' = 'application/octet-stream' }
            }
        }

        Remove-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }
}

Describe 'New-SfosWebServerAuthenticationTemplate and Set-SfosWebServerAuthenticationTemplate - multipart upload' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'New-SfosWebServerAuthenticationTemplate sends an add operation carrying the template file name and uploads it via MultipartFile' {
        $templatePath = Join-Path $TestDrive 'login.html'
        Set-Content -LiteralPath $templatePath -Value '<html></html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="200">Configuration applied successfully.</Status></FormTemplate></Response>' }
        }

        New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<FormTemplate>' -and
            $InnerXml -match '<Name>CustomLoginForm</Name>' -and
            $InnerXml -match '<Template>login\.html</Template>' -and
            $MultipartFile.Template -eq $templatePath
        }
    }

    It 'New-SfosWebServerAuthenticationTemplate with multiple -AssetFile paths sends the Assets/Asset XML and an Asset multipart field carrying all paths' {
        $templatePath = Join-Path $TestDrive 'login.html'
        $assetPath1 = Join-Path $TestDrive 'style.css'
        $assetPath2 = Join-Path $TestDrive 'logo.png'
        Set-Content -LiteralPath $templatePath -Value '<html></html>'
        Set-Content -LiteralPath $assetPath1 -Value 'body{}'
        Set-Content -LiteralPath $assetPath2 -Value 'not really a png'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="200">Configuration applied successfully.</Status></FormTemplate></Response>' }
        }

        New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath -AssetFile $assetPath1, $assetPath2 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Assets><Asset>style\.css</Asset><Asset>logo\.png</Asset></Assets>' -and
            $MultipartFile.Asset.Count -eq 2 -and
            $MultipartFile.Asset -contains $assetPath1 -and
            $MultipartFile.Asset -contains $assetPath2
        }
    }

    It 'New-SfosWebServerAuthenticationTemplate throws naming the entity and object for a missing template file, without calling the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer

        { New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile (Join-Path $TestDrive 'missing.html') @conn -Confirm:$false } |
            Should -Throw '*FormTemplate*CustomLoginForm*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly
    }

    It 'New-SfosWebServerAuthenticationTemplate -WhatIf does not send the add' {
        $templatePath = Join-Path $TestDrive 'login.html'
        Set-Content -LiteralPath $templatePath -Value '<html></html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer

        New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly
    }

    It 'New-SfosWebServerAuthenticationTemplate throws on a duplicate name (measured 502)' {
        $templatePath = Join-Path $TestDrive 'login.html'
        Set-Content -LiteralPath $templatePath -Value '<html></html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="502">Operation failed. Entity having same name already exists.</Status></FormTemplate></Response>' }
        }

        { New-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'Set-SfosWebServerAuthenticationTemplate checks the object exists first, then sends an update operation carrying MultipartFile' {
        $templatePath = Join-Path $TestDrive 'login-v2.html'
        Set-Content -LiteralPath $templatePath -Value '<html>v2</html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{
                    Content = [byte[]]@(1, 2, 3)
                    Headers = @{ 'Content-Type' = 'application/octet-stream' }
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="200">Configuration applied successfully.</Status></FormTemplate></Response>' }
            }
        }

        Set-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<FormTemplate>' -and
            $InnerXml -match '<Name>CustomLoginForm</Name>' -and
            $InnerXml -match '<Template>login-v2\.html</Template>' -and
            $MultipartFile.Template -eq $templatePath
        }
    }

    It 'Set-SfosWebServerAuthenticationTemplate throws "was not found" for a nonexistent template and does not send an update' {
        $templatePath = Join-Path $TestDrive 'login-v2.html'
        Set-Content -LiteralPath $templatePath -Value '<html>v2</html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FormTemplate transactionid=""><Status>No. of records Zero.</Status></FormTemplate></Response>' }
        }

        { Set-SfosWebServerAuthenticationTemplate -Name 'DoesNotExist' -TemplateFile $templatePath @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'Set-SfosWebServerAuthenticationTemplate throws naming the entity and object for a missing template file, without sending an update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{
                    Content = [byte[]]@(1, 2, 3)
                    Headers = @{ 'Content-Type' = 'application/octet-stream' }
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="200">Configuration applied successfully.</Status></FormTemplate></Response>' }
            }
        }

        { Set-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile (Join-Path $TestDrive 'missing.html') @conn -Confirm:$false } |
            Should -Throw '*FormTemplate*CustomLoginForm*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'Set-SfosWebServerAuthenticationTemplate -WhatIf does not send the update' {
        $templatePath = Join-Path $TestDrive 'login-v2.html'
        Set-Content -LiteralPath $templatePath -Value '<html>v2</html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{
                    Content = [byte[]]@(1, 2, 3)
                    Headers = @{ 'Content-Type' = 'application/octet-stream' }
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="200">Configuration applied successfully.</Status></FormTemplate></Response>' }
            }
        }

        Set-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }

    It 'Set-SfosWebServerAuthenticationTemplate throws on a 5xx status code' {
        $templatePath = Join-Path $TestDrive 'login-v2.html'
        Set-Content -LiteralPath $templatePath -Value '<html>v2</html>'

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{
                    Content = [byte[]]@(1, 2, 3)
                    Headers = @{ 'Content-Type' = 'application/octet-stream' }
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><FormTemplate><Status code="502">Operation failed. Entity having same name already exists.</Status></FormTemplate></Response>' }
            }
        }

        { Set-SfosWebServerAuthenticationTemplate -Name 'CustomLoginForm' -TemplateFile $templatePath @conn -Confirm:$false } | Should -Throw '*502*'
    }
}

Describe 'WAFSlowHTTP - Get parsing' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'parses the four timeout fields and returns an empty NetworkExceptionHost when the wrapper is absent' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><WAFSlowHTTP transactionid=""><RequestHeaderTimeoutEnabled>Disable</RequestHeaderTimeoutEnabled><RequestHeaderTimeoutSoftLimit>10</RequestHeaderTimeoutSoftLimit><RequestHeaderTimeoutHardLimit>30</RequestHeaderTimeoutHardLimit><RequestHeaderTimeoutExtensionRate>5000</RequestHeaderTimeoutExtensionRate></WAFSlowHTTP></Response>' }
        }

        $result = Get-SfosWebServerSlowHTTPProtectionSettings @conn

        $result.RequestHeaderTimeoutEnabled | Should -Be 'Disable'
        $result.RequestHeaderTimeoutSoftLimit | Should -Be 10
        $result.RequestHeaderTimeoutHardLimit | Should -Be 30
        $result.RequestHeaderTimeoutExtensionRate | Should -Be 5000
        @($result.NetworkExceptionHost).Count | Should -Be 0
    }
}

Describe 'Set-SfosWebServerSlowHTTPProtectionSettings - read-modify-write, round trip, error handling and WhatIf' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><WAFSlowHTTP transactionid=""><RequestHeaderTimeoutEnabled>Disable</RequestHeaderTimeoutEnabled><RequestHeaderTimeoutSoftLimit>10</RequestHeaderTimeoutSoftLimit><RequestHeaderTimeoutHardLimit>30</RequestHeaderTimeoutHardLimit><RequestHeaderTimeoutExtensionRate>5000</RequestHeaderTimeoutExtensionRate></WAFSlowHTTP></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><WAFSlowHTTP><Status code="200">Configuration applied successfully.</Status></WAFSlowHTTP></Response>' }
            }
        }
    }

    It 'a no-op call sends back the exact values it read, unchanged' {
        Set-SfosWebServerSlowHTTPProtectionSettings @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<WAFSlowHTTP>' -and
            $InnerXml -match '<RequestHeaderTimeoutEnabled>Disable</RequestHeaderTimeoutEnabled>' -and
            $InnerXml -match '<RequestHeaderTimeoutSoftLimit>10</RequestHeaderTimeoutSoftLimit>' -and
            $InnerXml -match '<RequestHeaderTimeoutHardLimit>30</RequestHeaderTimeoutHardLimit>' -and
            $InnerXml -match '<RequestHeaderTimeoutExtensionRate>5000</RequestHeaderTimeoutExtensionRate>'
        }
    }

    It 'changes only the field the caller passed' {
        Set-SfosWebServerSlowHTTPProtectionSettings -RequestHeaderTimeoutSoftLimit 15 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -ParameterFilter {
            $InnerXml -match '<RequestHeaderTimeoutSoftLimit>15</RequestHeaderTimeoutSoftLimit>' -and
            $InnerXml -match '<RequestHeaderTimeoutHardLimit>30</RequestHeaderTimeoutHardLimit>' -and
            $InnerXml -match '<RequestHeaderTimeoutEnabled>Disable</RequestHeaderTimeoutEnabled>'
        }
    }

    It 'throws on a 5xx status code' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><WAFSlowHTTP transactionid=""><RequestHeaderTimeoutEnabled>Disable</RequestHeaderTimeoutEnabled><RequestHeaderTimeoutSoftLimit>10</RequestHeaderTimeoutSoftLimit><RequestHeaderTimeoutHardLimit>30</RequestHeaderTimeoutHardLimit><RequestHeaderTimeoutExtensionRate>5000</RequestHeaderTimeoutExtensionRate></WAFSlowHTTP></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><WAFSlowHTTP><Status code="529">Invalid XML request</Status></WAFSlowHTTP></Response>' }
            }
        }

        { Set-SfosWebServerSlowHTTPProtectionSettings -RequestHeaderTimeoutSoftLimit 15 @conn -Confirm:$false } | Should -Throw '*529*'
    }

    It '-WhatIf does not send the update' {
        Set-SfosWebServerSlowHTTPProtectionSettings -RequestHeaderTimeoutSoftLimit 99 @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Status code="529">Invalid XML request</Status></RealServers></Response>' }
        }

        { Get-SfosWebServer @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosWebServer @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.WebServer -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><RealServers transactionid=""><Status>No. of records Zero.</Status></RealServers></Response>' }
        }

        $result = @(Get-SfosWebServer @conn)
        $result.Count | Should -Be 0
    }
}
