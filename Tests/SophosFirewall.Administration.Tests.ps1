#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Administration module.

.DESCRIPTION
    Tests cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage: module loading/manifest agreement and existence of all 32 exported
    functions; New-SfosSNMPCommunity XML generation; New-SfosLocalServiceACL XML
    generation; the Name/Location/ContactPerson mandatory-field guard on
    Set-SfosSNMPAgentConfiguration; the partial (single-field) update shape of
    Set-SfosMessages; Get-/Set-SfosNetFlowConfiguration (parallel-array parsing,
    read-modify-write, the single repeating <Server> wrapper, clearing the list,
    the array-length guard); Set-SfosAdminPassword XML generation and its error
    path; the shared status-parsing error paths (5xx throws, login failure throws,
    "No. of records Zero." yields @()); and the -Session parameter against a
    named, non-default session.

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

    It 'Should export exactly 32 functions' {
        (Get-Module SophosFirewall.Administration).ExportedFunctions.Count | Should -Be 32
    }

    It 'Manifest FunctionsToExport should list exactly 32 functions, matching the loaded module' {
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

        $manifest.ExportedFunctions.Count | Should -Be 32
    }

    It 'Every documented function exists' {
        $expected = @(
            'Get-SfosAdminSettings', 'Get-SfosApplianceAccess', 'Get-SfosLocalServiceACL',
            'Get-SfosMessages', 'Get-SfosNetFlowConfiguration', 'Get-SfosNotification',
            'Get-SfosSNMPAgentConfiguration',
            'Get-SfosSNMPCommunity', 'Get-SfosSNMPv3User', 'Get-SfosTime',
            'New-SfosLocalServiceACL', 'New-SfosSNMPCommunity', 'New-SfosSNMPv3User',
            'Remove-SfosLocalServiceACL', 'Remove-SfosSNMPCommunity',
            'Remove-SfosSNMPv3User', 'Reset-SfosToFactoryDefaults',
            'Set-SfosAdminPassword',
            'Set-SfosAdminPasswordComplexity', 'Set-SfosApplianceAccess',
            'Set-SfosHostname', 'Set-SfosLocalServiceACL',
            'Set-SfosLoginDisclaimer', 'Set-SfosLoginSecurity', 'Set-SfosMessages',
            'Set-SfosNetFlowConfiguration', 'Set-SfosNotification',
            'Set-SfosSNMPAgentConfiguration', 'Set-SfosSNMPCommunity',
            'Set-SfosSNMPv3User', 'Set-SfosTime', 'Set-SfosWebAdminSettings'
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

Describe 'New-SfosLocalServiceACL - XML generation' {

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
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><LocalServiceACL><Status code="200">Configuration applied successfully.</Status></LocalServiceACL></Response>' }
        }
    }

    It 'sends an add operation carrying the rule name and service' {
        New-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Service HTTPS -SourceZone 'LAN' -Action accept @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<LocalServiceACL>' -and
            $InnerXml -match '<RuleName>AllowLANHttps</RuleName>' -and
            $InnerXml -match '<Services><Service>HTTPS</Service></Services>' -and
            $InnerXml -match '<SourceZone>LAN</SourceZone>' -and
            $InnerXml -match '<Action>accept</Action>'
        }
    }

    It 'throws client-side when no -Service is supplied' {
        { New-SfosLocalServiceACL -RuleName 'NoService' -Service @() @conn -Confirm:$false } |
            Should -Throw '*empty array*'
    }
}

Describe 'Set-SfosSNMPAgentConfiguration - mandatory fields' {

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

    It 'throws when Name/Location/ContactPerson are not all supplied (firmware answers 400)' {
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

Describe 'Get-/Set-SfosNetFlowConfiguration' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosNetFlowConfiguration exists with the documented parameters' {
        $cmd = Get-Command Get-SfosNetFlowConfiguration -Module SophosFirewall.Administration
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'AsXml'
        $cmd.Parameters.Keys | Should -Contain 'Session'
    }

    It 'Set-SfosNetFlowConfiguration exists with the documented parameters' {
        $cmd = Get-Command Set-SfosNetFlowConfiguration -Module SophosFirewall.Administration
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'ServerName'
        $cmd.Parameters.Keys | Should -Contain 'NetflowServer'
        $cmd.Parameters.Keys | Should -Contain 'NetflowServerPort'
        $cmd.Parameters['ServerName'].ParameterType | Should -Be ([string[]])
        $cmd.Parameters['NetflowServerPort'].ParameterType | Should -Be ([int[]])
    }

    It 'Get-* returns an empty array when no NetFlowConfiguration server is present' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration transactionid=""><Status code="200">Configuration applied successfully.</Status></NetFlowConfiguration></Response>' }
        }

        $result = @(Get-SfosNetFlowConfiguration @conn)
        $result.Count | Should -Be 0
    }

    It 'Get-* parses a single <Server> wrapper with two parallel sets of fields into two objects' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration transactionid=""><Server><ServerName>A</ServerName><ServerName>B</ServerName><NetflowServer>192.0.2.10</NetflowServer><NetflowServer>192.0.2.11</NetflowServer><NetflowServerPort>2055</NetflowServerPort><NetflowServerPort>2056</NetflowServerPort></Server></NetFlowConfiguration></Response>' }
        }

        $result = @(Get-SfosNetFlowConfiguration @conn)
        $result.Count | Should -Be 2
        $result[0].ServerName | Should -Be 'A'
        $result[0].NetflowServer | Should -Be '192.0.2.10'
        $result[0].NetflowServerPort | Should -Be '2055'
        $result[1].ServerName | Should -Be 'B'
        $result[1].NetflowServer | Should -Be '192.0.2.11'
        $result[1].NetflowServerPort | Should -Be '2056'
    }

    It 'Set-* sends exactly one <Server> wrapper with the fields repeated in parallel' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration transactionid=""><Status code="200">Configuration applied successfully.</Status></NetFlowConfiguration></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration><Status code="200">Configuration applied successfully.</Status></NetFlowConfiguration></Response>' }
            }
        }

        Set-SfosNetFlowConfiguration -ServerName 'Collector1', 'Collector2' -NetflowServer '10.0.0.50', '10.0.0.51' -NetflowServerPort 2055, 2056 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            ([regex]::Matches($InnerXml, '<Server>').Count -eq 1) -and
            $InnerXml -match '<ServerName>Collector1</ServerName><ServerName>Collector2</ServerName>' -and
            $InnerXml -match '<NetflowServer>10\.0\.0\.50</NetflowServer><NetflowServer>10\.0\.0\.51</NetflowServer>' -and
            $InnerXml -match '<NetflowServerPort>2055</NetflowServerPort><NetflowServerPort>2056</NetflowServerPort>'
        }
    }

    It 'Set-* with only -NetflowServerPort keeps the names and addresses from the current configuration' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration transactionid=""><Server><ServerName>Collector1</ServerName><NetflowServer>10.0.0.50</NetflowServer><NetflowServerPort>2055</NetflowServerPort></Server></NetFlowConfiguration></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration><Status code="200">Configuration applied successfully.</Status></NetFlowConfiguration></Response>' }
            }
        }

        Set-SfosNetFlowConfiguration -NetflowServerPort 2099 @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<ServerName>Collector1</ServerName>' -and
            $InnerXml -match '<NetflowServer>10\.0\.0\.50</NetflowServer>' -and
            $InnerXml -match '<NetflowServerPort>2099</NetflowServerPort>'
        }
    }

    It 'Set-* with all three arrays empty clears the server list' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration transactionid=""><Server><ServerName>Collector1</ServerName><NetflowServer>10.0.0.50</NetflowServer><NetflowServerPort>2055</NetflowServerPort></Server></NetFlowConfiguration></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration><Status code="200">Configuration applied successfully.</Status></NetFlowConfiguration></Response>' }
            }
        }

        Set-SfosNetFlowConfiguration -ServerName @() -NetflowServer @() -NetflowServerPort @() @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<NetFlowConfiguration>' -and
            $InnerXml -notmatch '<Server>'
        }
    }

    It 'throws an entity-naming error when the three arrays have different lengths' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><NetFlowConfiguration transactionid=""><Status code="200">Configuration applied successfully.</Status></NetFlowConfiguration></Response>' }
        }

        { Set-SfosNetFlowConfiguration -ServerName 'Collector1', 'Collector2' -NetflowServer '10.0.0.50' -NetflowServerPort 2055 @conn -Confirm:$false } |
            Should -Throw '*NetFlowConfiguration*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -ParameterFilter { $InnerXml -match '<Set' } -Times 0 -Exactly
    }
}

Describe 'Set-SfosAdminPassword' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $currentPw = ConvertTo-SecureString 'current-placeholder-pw' -AsPlainText -Force
        $newPw = ConvertTo-SecureString 'new-placeholder-pw' -AsPlainText -Force
    }

    It 'exists with -CurrentPassword and -NewPassword as mandatory SecureString parameters' {
        $cmd = Get-Command Set-SfosAdminPassword -Module SophosFirewall.Administration
        $cmd | Should -Not -BeNullOrEmpty

        $cmd.Parameters['CurrentPassword'].ParameterType | Should -Be ([SecureString])
        $cmd.Parameters['CurrentPassword'].Attributes.Mandatory | Should -Contain $true

        $cmd.Parameters['NewPassword'].ParameterType | Should -Be ([SecureString])
        $cmd.Parameters['NewPassword'].Attributes.Mandatory | Should -Contain $true
    }

    It 'has no functional parameter besides CurrentPassword and NewPassword (no account-name parameter)' {
        $cmd = Get-Command Set-SfosAdminPassword -Module SophosFirewall.Administration
        $connectionAndCommonParams = @(
            'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session',
            'Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction',
            'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable',
            'OutBuffer', 'PipelineVariable', 'WhatIf', 'Confirm', 'ProgressAction'
        )
        $functionalParams = $cmd.Parameters.Keys | Where-Object { $_ -notin $connectionAndCommonParams }
        ($functionalParams | Sort-Object) | Should -Be @('CurrentPassword', 'NewPassword')
    }

    It 'sends an update operation carrying both passwords' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdminPassword><Status code="200">Configuration applied successfully.</Status></AdminPassword></Response>' }
        }

        Set-SfosAdminPassword -CurrentPassword $currentPw -NewPassword $newPw @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<AdminPassword>' -and
            $InnerXml -match '<CurrentPassword>current-placeholder-pw</CurrentPassword>' -and
            $InnerXml -match '<NewPassword>new-placeholder-pw</NewPassword>'
        }
    }

    It 'throws on a 510 status under /Response/AdminPassword/Status rather than reporting success' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Administration -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdminPassword><Status code="510">Operation failed. Deleting entity referred by another entity</Status></AdminPassword></Response>' }
        }

        { Set-SfosAdminPassword -CurrentPassword $currentPw -NewPassword $newPw @conn -Confirm:$false } |
            Should -Throw '*510*'
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
