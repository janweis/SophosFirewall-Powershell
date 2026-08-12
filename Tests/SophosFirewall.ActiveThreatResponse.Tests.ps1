#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.ActiveThreatResponse module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement; a Get smoke test for both entities
    (ATP singleton, ThirdPartyFeed's "No. of records Zero." empty result); New/Set
    XML-generation checks for New-/Set-SfosThirdPartyFeed across all three Authorization
    modes; read-modify-write checks for Set-SfosATPSettings and Set-SfosThirdPartyFeed;
    the Add-/Remove-*Exception member cmdlets; the module's measured special-case
    behaviours (ThirdPartyFeed's untrustworthy Remove status resolved via a follow-up Get,
    and the "never resend the read-back secret hash" preserve-on-omit behaviour); XML
    escaping; the shared error paths (5xx throws, a failed login with no entity status
    throws, "No. of records Zero." yields @()); and a -WhatIf check against every one of
    the module's 8 write cmdlets.

.NOTES
    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6,
    once loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its
    type data collides with the one PS 5.1 already loaded at startup ("The member
    AuditToString is already present", etc.) - a machine/environment issue, reproducible
    against any test file in this repo, not specific to this suite. Work around it by
    restricting $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.ActiveThreatResponse.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.ActiveThreatResponse\SophosFirewall.ActiveThreatResponse.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.ActiveThreatResponse module should load' {
        Get-Module SophosFirewall.ActiveThreatResponse | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 10 functions' {
        (Get-Module SophosFirewall.ActiveThreatResponse).ExportedFunctions.Count | Should -Be 10
    }

    It 'Manifest FunctionsToExport should list exactly 10 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.ActiveThreatResponse\SophosFirewall.ActiveThreatResponse.psd1'

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

        $manifest.ExportedFunctions.Count | Should -Be 10
    }

    It 'Every documented function exists' {
        $expected = @(
            'Get-SfosATPSettings', 'Set-SfosATPSettings',
            'Add-SfosATPHostException', 'Remove-SfosATPHostException',
            'Add-SfosATPThreatException', 'Remove-SfosATPThreatException',
            'Get-SfosThirdPartyFeed', 'New-SfosThirdPartyFeed',
            'Set-SfosThirdPartyFeed', 'Remove-SfosThirdPartyFeed'
        )
        foreach ($name in $expected) {
            Get-Command $name -Module SophosFirewall.ActiveThreatResponse -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$name should be exported"
        }
    }
}

Describe 'Get-SfosATPSettings' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends Get/ATP and returns the singleton fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
        }

        $result = Get-SfosATPSettings @conn
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>\s*<ATP>\s*</ATP>\s*</Get>'
        }
        $result.ThreatProtectionStatus | Should -Be 'Enable'
        $result.InspectContent | Should -Be 'untrusted'
        $result.Policy | Should -Be 'Log and Drop'
    }

    It 'returns @() for HostExceptionList/ThreatExceptionList when no wrapper element is present' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
        }

        $result = Get-SfosATPSettings @conn
        @($result.HostExceptionList).Count | Should -Be 0
        @($result.ThreatExceptionList).Count | Should -Be 0
    }

    It 'reads HostExceptionList and ThreatExceptionList when present' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>all</InspectContent><Policy>Log Only</Policy><HostException><Host>WebServer01</Host></HostException><ThreatException><Threat>C2/Generic-A</Threat></ThreatException></ATP></Response>' }
        }

        $result = Get-SfosATPSettings @conn
        @($result.HostExceptionList) | Should -Be @('WebServer01')
        @($result.ThreatExceptionList) | Should -Be @('C2/Generic-A')
    }

    It 'throws when the ATP node is missing from the response' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }

        { Get-SfosATPSettings @conn } | Should -Throw '*could not be retrieved*'
    }
}

Describe 'Set-SfosATPSettings - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy><HostException><Host>WebServer01</Host></HostException></ATP></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
            }
        }
    }

    It 'preserves Policy and HostException when only InspectContent changes' {
        Set-SfosATPSettings -InspectContent all @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<InspectContent>all</InspectContent>' -and
            $InnerXml -match '<Policy>Log and Drop</Policy>' -and
            $InnerXml -match '<HostException><Host>WebServer01</Host></HostException>'
        }
    }

    It 'escapes Policy and HostException/ThreatException values' {
        Set-SfosATPSettings -ThreatException @('C2 & "Generic"') @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<ThreatException><Threat>C2 &amp; &quot;Generic&quot;</Threat></ThreatException>'
        }
    }

    It 'clears HostException when an empty array is passed explicitly' {
        Set-SfosATPSettings -HostException @() @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -notmatch '<HostException>'
        }
    }
}

Describe 'Add-/Remove-SfosATPHostException and -SfosATPThreatException' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Add-SfosATPHostException' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
                }
            }
        }

        It 'appends the new host to the existing (empty) HostException list' {
            Add-SfosATPHostException -HostName 'WebServer01' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<HostException><Host>WebServer01</Host></HostException>'
            }
        }

        It 'accepts pipeline input by property name via the Host alias' {
            [PSCustomObject]@{ Host = 'WebServer02' } | Add-SfosATPHostException @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<HostException><Host>WebServer02</Host></HostException>'
            }
        }
    }

    Context 'Remove-SfosATPHostException' {
        It 'throws when the host is not currently listed' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
            }

            { Remove-SfosATPHostException -HostName 'Ghost' @conn -Confirm:$false } | Should -Throw '*was not found*'
            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly
        }

        It 'throws when the host is still present after the write (append-only guard)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                # Every Get - before and after the write - still reports the host, simulating
                # a firewall that silently ignored the removal.
                if ($InnerXml -notmatch '<Get>') {
                    return [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
                }
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy><HostException><Host>WebServer01</Host></HostException></ATP></Response>' }
            }

            { Remove-SfosATPHostException -HostName 'WebServer01' @conn -Confirm:$false } | Should -Throw '*still present*'
        }

        It 'removes the host and completes without throwing when the follow-up Get confirms it is gone' {
            $script:removed = $false
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    $script:removed = $true
                    return [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
                }
                if ($script:removed) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
                }
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy><HostException><Host>WebServer01</Host></HostException></ATP></Response>' }
            }

            { Remove-SfosATPHostException -HostName 'WebServer01' @conn -Confirm:$false } | Should -Not -Throw
        }
    }

    Context 'Add-/Remove-SfosATPThreatException' {
        It 'Add-SfosATPThreatException appends the new threat to the existing list' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
                }
            }

            Add-SfosATPThreatException -Threat 'C2/Generic-A' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<ThreatException><Threat>C2/Generic-A</Threat></ThreatException>'
            }
        }

        It 'Remove-SfosATPThreatException throws when the threat is not currently listed' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
            }

            { Remove-SfosATPThreatException -Threat 'Ghost' @conn -Confirm:$false } | Should -Throw '*was not found*'
        }

        It 'Remove-SfosATPThreatException throws when the threat is still present after the write (append-only guard)' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                # Every Get - before and after the write - still reports the threat, simulating
                # a firewall that silently ignored the removal.
                if ($InnerXml -notmatch '<Get>') {
                    return [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
                }
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy><ThreatException><Threat>C2/Generic-A</Threat></ThreatException></ATP></Response>' }
            }

            { Remove-SfosATPThreatException -Threat 'C2/Generic-A' @conn -Confirm:$false } | Should -Throw '*still present*'
        }

        It 'Remove-SfosATPThreatException removes the threat and completes without throwing when the follow-up Get confirms it is gone' {
            $script:removed = $false
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    $script:removed = $true
                    return [PSCustomObject]@{ Content = '<Response><ATP><Status code="200">Configuration applied successfully.</Status></ATP></Response>' }
                }
                if ($script:removed) {
                    return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy></ATP></Response>' }
                }
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy><ThreatException><Threat>C2/Generic-A</Threat></ThreatException></ATP></Response>' }
            }

            { Remove-SfosATPThreatException -Threat 'C2/Generic-A' @conn -Confirm:$false } | Should -Not -Throw
        }
    }
}

Describe 'Get-SfosThirdPartyFeed' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends Get/ThirdPartyFeed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status>No. of records Zero.</Status></ThirdPartyFeed></Response>' }
        }

        Get-SfosThirdPartyFeed @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>\s*<ThirdPartyFeed>'
        }
    }

    It 'returns @() for "No. of records Zero." without throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status>No. of records Zero.</Status></ThirdPartyFeed></Response>' }
        }

        $result = @(Get-SfosThirdPartyFeed @conn)
        $result.Count | Should -Be 0
    }

    It 'sends the Name filter as a server-side like key and maps hashed secrets to PasswordHash/ValueHash' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>abc-123</Id><Name>VendorIPFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>basicAuthentication</Authorization><Username>feedreader</Username><Password hashform="1">abc123hash</Password><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
        }

        $result = Get-SfosThirdPartyFeed -NameLike 'Vendor' @conn
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Filter><key name="Name" criteria="like">Vendor</key></Filter>'
        }
        $result.Id | Should -Be 'abc-123'
        $result.PasswordHash | Should -Be 'abc123hash'
        $result.Enabled | Should -Be '1'
    }
}

Describe 'New-SfosThirdPartyFeed' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><ThirdPartyFeed><Status code="201">Configuration applied successfully.</Status></ThirdPartyFeed></Response>' }
        }
    }

    It 'builds the expected XML for a noAuthentication feed' {
        New-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Action monitor -IndicatorType ip `
            -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization noAuthentication `
            -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Name>AbuseChIPFeed</Name>' -and
            $InnerXml -match '<Action>monitor</Action>' -and
            $InnerXml -match '<Position>top</Position>' -and
            $InnerXml -match '<IndicatorType>ip</IndicatorType>' -and
            $InnerXml -match '<ExternalURL>https://feeds\.example\.com/blocklist\.txt</ExternalURL>' -and
            $InnerXml -match '<Authorization>noAuthentication</Authorization>' -and
            $InnerXml -match '<ValidateServerCertificate>1</ValidateServerCertificate>' -and
            $InnerXml -match '<PollingInterval>1h</PollingInterval>' -and
            $InnerXml -match '<Enabled>1</Enabled>' -and
            $InnerXml -notmatch '<Username>' -and
            $InnerXml -notmatch '<Key>'
        }
    }

    It 'builds Username/Password for a basicAuthentication feed' {
        $pw = ConvertTo-SecureString 'FeedSecret1!' -AsPlainText -Force
        New-SfosThirdPartyFeed -Name 'VendorIPFeed' -Action monitor -IndicatorType ip `
            -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization basicAuthentication `
            -FeedUsername 'feedreader' -FeedPassword $pw `
            -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Authorization>basicAuthentication</Authorization>' -and
            $InnerXml -match '<Username>feedreader</Username>' -and
            $InnerXml -match '<Password>FeedSecret1!</Password>'
        }
    }

    It 'builds Key/Value/AddTo for an apiKey feed' {
        $key = ConvertTo-SecureString 'MyApiKeyValue123' -AsPlainText -Force
        New-SfosThirdPartyFeed -Name 'PartnerIPFeed' -Action monitor -IndicatorType ip `
            -ExternalURL 'https://feeds.example.com/blocklist.txt' -Authorization apiKey `
            -ApiKeyName 'X-Api-Key' -ApiKeyValue $key -AddTo header `
            -ValidateServerCertificate 1 -PollingInterval 1h -Enabled 1 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Authorization>apiKey</Authorization>' -and
            $InnerXml -match '<Key>X-Api-Key</Key>' -and
            $InnerXml -match '<Value>MyApiKeyValue123</Value>' -and
            $InnerXml -match '<AddTo>header</AddTo>'
        }
    }

    It 'escapes Description' {
        New-SfosThirdPartyFeed -Name 'EscFeed' -ExternalURL 'https://feeds.example.com/x.txt' `
            -Description 'Smith & Sons <blocklist>' -ValidateServerCertificate 1 -PollingInterval 1h @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Description>Smith &amp; Sons &lt;blocklist&gt;</Description>'
        }
    }

    It 'throws client-side when Authorization basicAuthentication is requested without -FeedPassword' {
        { New-SfosThirdPartyFeed -Name 'NoPwFeed' -ExternalURL 'https://feeds.example.com/x.txt' `
                -Authorization basicAuthentication -FeedUsername 'someone' `
                -ValidateServerCertificate 1 -PollingInterval 1h @conn -Confirm:$false } |
            Should -Throw '*FeedPassword*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly
    }

    It 'throws client-side when Authorization apiKey is requested without -ApiKeyValue' {
        { New-SfosThirdPartyFeed -Name 'NoKeyFeed' -ExternalURL 'https://feeds.example.com/x.txt' `
                -Authorization apiKey -ApiKeyName 'X-Api-Key' -AddTo header `
                -ValidateServerCertificate 1 -PollingInterval 1h @conn -Confirm:$false } |
            Should -Throw '*ApiKeyName*ApiKeyValue*AddTo*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly
    }

    It 'rejects a Name containing characters outside the documented pattern' {
        { New-SfosThirdPartyFeed -Name 'Bad Name!' -ExternalURL 'https://feeds.example.com/x.txt' `
                -ValidateServerCertificate 1 -PollingInterval 1h @conn -Confirm:$false } | Should -Throw
    }
}

Describe 'Set-SfosThirdPartyFeed - read-modify-write' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'noAuthentication feed, only Enabled changes' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-1</Id><Name>AbuseChIPFeed</Name><Description>orig</Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ThirdPartyFeed><Status code="200">Configuration applied successfully.</Status></ThirdPartyFeed></Response>' }
                }
            }
        }

        It 'preserves Description, Action and ExternalURL while updating Enabled' {
            Set-SfosThirdPartyFeed -Name 'AbuseChIPFeed' -Enabled 0 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>orig</Description>' -and
                $InnerXml -match '<Action>monitor</Action>' -and
                $InnerXml -match '<ExternalURL>https://feeds\.example\.com/blocklist\.txt</ExternalURL>' -and
                $InnerXml -match '<Enabled>0</Enabled>'
            }
        }
    }

    Context 'basicAuthentication feed, secret omitted - measured preserve-on-omit behaviour' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-2</Id><Name>VendorIPFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>basicAuthentication</Authorization><Username>feedreader</Username><Password hashform="1">storedhash</Password><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ThirdPartyFeed><Status code="200">Configuration applied successfully.</Status></ThirdPartyFeed></Response>' }
                }
            }
        }

        It 'sends Username but never resends the read-back PasswordHash as Password' {
            Set-SfosThirdPartyFeed -Name 'VendorIPFeed' -Description 'updated' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Username>feedreader</Username>' -and
                $InnerXml -notmatch '<Password>' -and
                $InnerXml -notmatch 'storedhash'
            }
        }
    }

    Context 'switching Authorization without the required secret' {
        It 'throws client-side when switching to basicAuthentication without -FeedPassword' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-3</Id><Name>SwitchFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
            }

            { Set-SfosThirdPartyFeed -Name 'SwitchFeed' -Authorization basicAuthentication -FeedUsername 'x' @conn -Confirm:$false } |
                Should -Throw '*basicAuthentication*FeedPassword*'
        }

        It 'throws client-side when switching to apiKey without -ApiKeyValue' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-3b</Id><Name>SwitchFeed2</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
            }

            { Set-SfosThirdPartyFeed -Name 'SwitchFeed2' -Authorization apiKey -ApiKeyName 'X-Api-Key' @conn -Confirm:$false } |
                Should -Throw '*apiKey*ApiKeyName*ApiKeyValue*AddTo*'
        }
    }

    It 'throws "was not found" when the target feed does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status>No. of records Zero.</Status></ThirdPartyFeed></Response>' }
        }

        { Set-SfosThirdPartyFeed -Name 'Ghost' -Enabled 0 @conn -Confirm:$false } | Should -Throw '*was not found*'
    }
}

Describe 'Remove-SfosThirdPartyFeed - untrustworthy delete status resolved via follow-up Get' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'throws "was not found" when the feed does not exist, without sending a Remove request' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status>No. of records Zero.</Status></ThirdPartyFeed></Response>' }
        }

        { Remove-SfosThirdPartyFeed -Name 'Ghost' @conn -Confirm:$false } | Should -Throw '*was not found*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 1 -Exactly
    }

    It 'succeeds when the always-500 remove response is followed by a Get confirming the feed is gone' {
        $script:removed = $false
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            if ($InnerXml -match '<Remove>') {
                $script:removed = $true
                # Measured: this entity always answers 500 on Remove, for a real delete as
                # much as for a nonexistent object - see the module README.
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed><Status code="500">Deleted some configurations. Couldn''t delete all.</Status></ThirdPartyFeed></Response>' }
            }
            if ($script:removed) {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status>No. of records Zero.</Status></ThirdPartyFeed></Response>' }
            }
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-4</Id><Name>AbuseChIPFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
        }

        { Remove-SfosThirdPartyFeed -Name 'AbuseChIPFeed' @conn -Confirm:$false } | Should -Not -Throw
    }

    It 'throws when the same code-500 response is answered but the feed is still present afterwards' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            if ($InnerXml -match '<Remove>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed><Status code="500">Deleted some configurations. Couldn''t delete all.</Status></ThirdPartyFeed></Response>' }
            }
            # Every Get, before and after the Remove, still reports the feed - the failure case.
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-5</Id><Name>StubbornFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
        }

        { Remove-SfosThirdPartyFeed -Name 'StubbornFeed' @conn -Confirm:$false } | Should -Throw '*still present*'
    }

    It 'throws on a login failure even though the entity Remove status would otherwise be ignored' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            if ($InnerXml -match '<Remove>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
            }
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-6</Id><Name>LoginFailFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
        }

        { Remove-SfosThirdPartyFeed -Name 'LoginFailFeed' @conn -Confirm:$false } | Should -Throw '*login failed*'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status code="529">Invalid XML request</Status></ThirdPartyFeed></Response>' }
        }

        { Get-SfosThirdPartyFeed @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosThirdPartyFeed @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Status>No. of records Zero.</Status></ThirdPartyFeed></Response>' }
        }

        $result = @(Get-SfosThirdPartyFeed @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'ShouldProcess - -WhatIf prevents every write cmdlet from sending a write request' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -MockWith {
            if ($InnerXml -notmatch '<Get>') {
                return [PSCustomObject]@{ Content = '<Response><Status code="200">Configuration applied successfully.</Status></Response>' }
            }
            if ($InnerXml -match '<ATP>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ATP transactionid=""><ThreatProtectionStatus>Enable</ThreatProtectionStatus><InspectContent>untrusted</InspectContent><Policy>Log and Drop</Policy><HostException><Host>WebServer01</Host></HostException><ThreatException><Threat>C2/Generic-A</Threat></ThreatException></ATP></Response>' }
            }
            if ($InnerXml -match '<ThirdPartyFeed>') {
                return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ThirdPartyFeed transactionid=""><Id>id-wi</Id><Name>ZZWIFeed</Name><Description></Description><Action>monitor</Action><IndicatorType>ip</IndicatorType><ExternalURL>https://feeds.example.com/blocklist.txt</ExternalURL><Authorization>noAuthentication</Authorization><ValidateServerCertificate>1</ValidateServerCertificate><PollingInterval>1h</PollingInterval><Enabled>1</Enabled></ThirdPartyFeed></Response>' }
            }
            return [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    It 'Set-SfosATPSettings sends no write request under -WhatIf' {
        Set-SfosATPSettings -InspectContent all @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Add-SfosATPHostException sends no write request under -WhatIf' {
        Add-SfosATPHostException -HostName 'WebServer02' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosATPHostException sends no write request under -WhatIf' {
        Remove-SfosATPHostException -HostName 'WebServer01' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Add-SfosATPThreatException sends no write request under -WhatIf' {
        Add-SfosATPThreatException -Threat 'New/Threat' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosATPThreatException sends no write request under -WhatIf' {
        Remove-SfosATPThreatException -Threat 'C2/Generic-A' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'New-SfosThirdPartyFeed sends no write request under -WhatIf' {
        New-SfosThirdPartyFeed -Name 'ZZWIFeed' -ExternalURL 'https://feeds.example.com/blocklist.txt' `
            -ValidateServerCertificate 1 -PollingInterval 1h @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Set-SfosThirdPartyFeed sends no write request under -WhatIf' {
        Set-SfosThirdPartyFeed -Name 'ZZWIFeed' -Enabled 0 @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }

    It 'Remove-SfosThirdPartyFeed sends no write request under -WhatIf' {
        Remove-SfosThirdPartyFeed -Name 'ZZWIFeed' @conn -WhatIf
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.ActiveThreatResponse -Times 0 -Exactly -ParameterFilter { $InnerXml -match '<Set operation=' -or $InnerXml -match '<Remove>' }
    }
}
