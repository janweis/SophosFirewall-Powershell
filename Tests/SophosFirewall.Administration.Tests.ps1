#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Administration module.

.DESCRIPTION
    Tests cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 26 exported
    functions; New-SfosSNMPCommunity XML generation; the measured Name/Location/
    ContactPerson mandatory-field guard on Set-SfosSNMPAgentConfiguration; the partial
    (single-field) update shape of Set-SfosMessages; the shared status-parsing error
    paths (5xx throws, login failure throws, "No. of records Zero." yields @()); and
    the -Session parameter against a named, non-default session.

.NOTES
    Minimum supported PowerShell version: 5.1

    Under Windows PowerShell 5.1 restrict $env:PSModulePath in a child process before
    importing Pester (PowerShell 7's module folders otherwise collide with Pester 6
    type data), then Invoke-Pester on this file.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Administration\SophosFirewall.Administration.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Administration module should load' {
        Get-Module SophosFirewall.Administration | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 26 functions' {
        (Get-Module SophosFirewall.Administration).ExportedFunctions.Count | Should -Be 26
    }

    It 'Manifest FunctionsToExport should list exactly 26 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Administration\SophosFirewall.Administration.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 26
    }

    It 'Every documented function exists' {
        $expected = @(
            'Get-SfosAdminSettings', 'Get-SfosApplianceAccess', 'Get-SfosLocalServiceACL',
            'Get-SfosMessages', 'Get-SfosNotification', 'Get-SfosSNMPAgentConfiguration',
            'Get-SfosSNMPCommunity', 'Get-SfosSNMPv3User', 'Get-SfosTime',
            'New-SfosSNMPCommunity', 'New-SfosSNMPv3User', 'Remove-SfosSNMPCommunity',
            'Remove-SfosSNMPv3User', 'Set-SfosAdminPasswordComplexity', 'Set-SfosApplianceAccess',
            'Set-SfosDefaultLanguage', 'Set-SfosHostname', 'Set-SfosLoginDisclaimer',
            'Set-SfosLoginSecurity', 'Set-SfosMessages', 'Set-SfosNotification',
            'Set-SfosSNMPAgentConfiguration', 'Set-SfosSNMPCommunity', 'Set-SfosSNMPv3User',
            'Set-SfosTime', 'Set-SfosWebAdminSettings'
        )
        foreach ($name in $expected) {
            Get-Command $name -Module SophosFirewall.Administration -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty -Because "$name should be exported"
        }
    }
}

Describe 'New-SfosSNMPCommunity - XML generation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SNMPCommunity><Status code="200">Configuration applied successfully.</Status></SNMPCommunity></Response>' }
        }
    }

    It 'sends an add operation carrying the community name and string' {
        New-SfosSNMPCommunity -Name 'monitoring-ro' -CommunityString (ConvertTo-SecureString 'p4ssStr1ng' -AsPlainText -Force) -AuthorizedHostIpv4 '10.0.0.5' -AcceptQueries True @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<SNMPCommunity>' -and
            $InnerXml -match '<Name>monitoring-ro</Name>' -and
            $InnerXml -match 'p4ssStr1ng'
        }
    }
}

Describe 'Set-SfosSNMPAgentConfiguration - measured mandatory fields' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        # The Set does a read-modify-write; the Get returns the appliance's empty-stored
        # Name/Location/ContactPerson, and the Set answers success.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SNMPAgentConfiguration transactionid=""><Location></Location><Name></Name><ContactPerson></ContactPerson><Description></Description><EnableAgent>false</EnableAgent><AgentPort>161</AgentPort><ManagerPort>162</ManagerPort></SNMPAgentConfiguration></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SNMPAgentConfiguration><Status code="200">Configuration applied successfully.</Status></SNMPAgentConfiguration></Response>' }
            }
        }
    }

    It 'throws when Name/Location/ContactPerson are not all supplied (measured firmware 400)' {
        { Set-SfosSNMPAgentConfiguration -Name 'agent-only' @conn -Confirm:$false } |
            Should -Throw '*Name, Location and ContactPerson*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter { $InnerXml -match '<Set' } -Times 0 -Exactly
    }

    It 'sends the update when all three mandatory fields are supplied' {
        Set-SfosSNMPAgentConfiguration -Name 'lab-agent' -Location 'Rack 4' -ContactPerson 'ops' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Name>lab-agent</Name>' -and
            $InnerXml -match '<Location>Rack 4</Location>' -and
            $InnerXml -match '<ContactPerson>ops</ContactPerson>'
        }
    }
}

Describe 'Set-SfosMessages - partial (single-field) update' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends only the bound field, not the whole message set' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Messages><Status code="200">Configuration applied successfully.</Status></Messages></Response>' }
        }

        Set-SfosMessages -DefaultSMS 'Your code is %code%' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $InnerXml -match '<DefaultSMS>Your code is %code%</DefaultSMS>' -and
            $InnerXml -notmatch '<SXLRejection>'
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SNMPCommunity transactionid=""><Status code="529">Invalid XML request</Status></SNMPCommunity></Response>' }
        }

        { Get-SfosSNMPCommunity @conn } | Should -Throw '*529*'
    }

    It 'throws when the login failed, even with no entity status present at all' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Failed. Invalid Username/Password.</status></Login></Response>' }
        }

        { Get-SfosSNMPCommunity @conn } | Should -Throw '*login failed*'
    }

    It '"No. of records Zero." yields an empty array rather than throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SNMPCommunity transactionid=""><Status>No. of records Zero.</Status></SNMPCommunity></Response>' }
        }

        $result = @(Get-SfosSNMPCommunity @conn)
        $result.Count | Should -Be 0
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SNMPCommunity transactionid=""><Status>No. of records Zero.</Status></SNMPCommunity></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default' {
        Get-SfosSNMPCommunity -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosSNMPCommunity | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosSNMPCommunity -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -Times 0 -Exactly
    }
}
