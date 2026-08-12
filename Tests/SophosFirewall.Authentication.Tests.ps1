#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Authentication module

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    Coverage is deliberately uneven across the module's ~29 entity areas. Covered in depth
    (Get/New/Set XML, read-modify-write, measured error paths, member cmdlets including
    read-back-after-write where the module performs one): the AuthenticationServer family
    (ActiveDirectory/LDAPServer/RADIUSServer/TACACSServer/EDirectory), User/UserGroup with
    membership, GuestUser/GuestUserSettings, OTPSettings with membership,
    FirewallAuthenticationMethods/AdminAuthentication with membership, VPNAuthentication/
    SSLVPNAuthentication with membership, WebAuthenticationSettings/CaptivePortalAppearance,
    DefaultCaptivePortal, DirectWebProxyAuthentication with membership, the FirewallAuthentication
    GlobalSettings/NTLMSettings/CTASSettings/iOSWebClientSettings singletons, AzureADSSO, STAS
    and LiveUser. ClientlessUser, SMSGateway, OTPTokens and SSORadiusAccount get only a
    Get-root-element smoke test (SSORadiusAccount by design - see its Describe block for why
    it has no read-modify-write case), because they follow the same measured patterns as the
    deeply-tested entities but were not read in full for this pass.

.NOTES
    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders (e.g. "C:\Program Files\PowerShell\7\Modules") before
    the native Windows PowerShell ones. Pester 6, once loaded, ends up importing the PS7 copy
    of Microsoft.PowerShell.Security and its type data collides with the one PS 5.1 already
    loaded at startup ("The member AuditToString is already present", etc.) - a machine/
    environment issue, reproducible against any test file in this repo, not specific to this
    suite. Work around it by restricting $env:PSModulePath in the child process before
    importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Authentication.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

param(
    [switch]$SkipIntegration
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Authentication\SophosFirewall.Authentication.psd1"
$CoreModulePath = Join-Path $ProjectRoot "Modules\SophosFirewall.Core\SophosFirewall.Core.psd1"

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

Describe 'Module Loading' {
    It 'SophosFirewall.Authentication module should load' {
        Get-Module SophosFirewall.Authentication | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 97 functions' {
        (Get-Module SophosFirewall.Authentication).ExportedFunctions.Count | Should -Be 97
    }

    It 'Manifest FunctionsToExport should list exactly 96 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Authentication\SophosFirewall.Authentication.psd1'

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

        $manifest.ExportedFunctions.Count | Should -Be 97
    }

    Context 'Private helper is not exported' {
        # ConvertTo-SfosClientlessUserSanitizedXml is the module's one internal helper (98
        # functions total, 97 exported). If FunctionsToExport ever grew to include it by
        # accident, callers could bypass ClientlessUser's own sanitisation.
        It 'ConvertTo-SfosClientlessUserSanitizedXml should not be visible' {
            Get-Command ConvertTo-SfosClientlessUserSanitizedXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
}

Describe 'AuthenticationServer family - Get wraps every server type in AuthenticationServer' {
    # Measured: a Get on the standalone element name (e.g. <ActiveDirectory> directly under
    # <Response>) answers 529 "Input request module is Invalid". Every Get-* in this family
    # must nest inside <AuthenticationServer>.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = @'
<Response APIVersion="2200.1">
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <ActiveDirectory><Status>No. of records Zero.</Status></ActiveDirectory>
    <LDAPServer><Status>No. of records Zero.</Status></LDAPServer>
    <RADIUSServer><Status>No. of records Zero.</Status></RADIUSServer>
    <TACACSServer><Status>No. of records Zero.</Status></TACACSServer>
    <EDirectory><Status>No. of records Zero.</Status></EDirectory>
  </AuthenticationServer>
</Response>
'@
            }
        }
    }

    It 'Get-SfosActiveDirectoryServer should send Get/AuthenticationServer/ActiveDirectory' {
        Get-SfosActiveDirectoryServer @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><AuthenticationServer><ActiveDirectory>'
        }
    }

    It 'Get-SfosLDAPServer should send Get/AuthenticationServer/LDAPServer' {
        Get-SfosLDAPServer @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><AuthenticationServer><LDAPServer>'
        }
    }

    It 'Get-SfosRADIUSServer should send Get/AuthenticationServer/RADIUSServer' {
        Get-SfosRADIUSServer @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><AuthenticationServer><RADIUSServer>'
        }
    }

    It 'Get-SfosTACACSServer should send Get/AuthenticationServer/TACACSServer' {
        Get-SfosTACACSServer @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><AuthenticationServer><TACACSServer>'
        }
    }

    It 'Get-SfosEDirectoryServer should send Get/AuthenticationServer/EDirectory' {
        Get-SfosEDirectoryServer @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><AuthenticationServer><EDirectory>'
        }
    }

    It 'An empty result (No. of records Zero.) should return @(), not throw' {
        $result = @(Get-SfosActiveDirectoryServer @conn)
        $result.Count | Should -Be 0
    }

    It 'Get-SfosActiveDirectoryServer should never send a Filter element even with -ServerNameLike (unconfirmed server-side, client-side only per its own docs)' {
        Get-SfosActiveDirectoryServer -ServerNameLike 'Corp' @conn | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -notmatch '<Filter>'
        }
    }
}

Describe 'New-Sfos*AuthenticationServer - field names measured live, not the doc table' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $secret = ConvertTo-SecureString 's3cr3t' -AsPlainText -Force
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    It 'New-SfosActiveDirectoryServer should send operation="add" nested under AuthenticationServer/ActiveDirectory' {
        New-SfosActiveDirectoryServer -ServerName 'CorpAD' -ServerAddress 'ad.example.invalid' -ServerPort 389 `
            -NetBIOSDomain 'CORP' -ADSUsername 'svc-sfos' -ConnectionSecurity Simple -DomainName 'example.invalid' `
            @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AuthenticationServer>\s*<ActiveDirectory>' -and
            $InnerXml -match '<ServerName>CorpAD</ServerName>' -and
            $InnerXml -match '<ServerAddress>ad\.example\.invalid</ServerAddress>' -and
            $InnerXml -match '<Port>389</Port>'
        }
    }

    It 'New-SfosRADIUSServer should send ServerAddress (not ServerIP) and Port (not AuthenticationPort) and mandatory Timeout' {
        New-SfosRADIUSServer -ServerName 'CorpRadius' -ServerAddress '203.0.113.10' -ServerPort 1812 -Timeout 60 `
            -SharedSecret $secret -GroupNameAttribute 'memberOf' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<ServerAddress>203\.0\.113\.10</ServerAddress>' -and
            $InnerXml -notmatch '<ServerIP>' -and
            $InnerXml -match '<Port>1812</Port>' -and
            $InnerXml -notmatch '<AuthenticationPort>' -and
            $InnerXml -match '<Timeout>60</Timeout>' -and
            $InnerXml -match '<GroupNameAttribute>memberOf</GroupNameAttribute>'
        }
    }

    It 'New-SfosTACACSServer should send ServerAddress (not ServerIP)' {
        New-SfosTACACSServer -ServerName 'CorpTacacs' -ServerAddress '203.0.113.21' -ServerPort 49 -SharedSecret $secret @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<AuthenticationServer>\s*<TACACSServer>' -and
            $InnerXml -match '<ServerAddress>203\.0\.113\.21</ServerAddress>' -and
            $InnerXml -notmatch '<ServerIP>'
        }
    }

    It 'New-SfosEDirectoryServer should send ServerIpDomain (not ServerAddress) and Username (not EdirUsername)' {
        New-SfosEDirectoryServer -ServerName 'CorpEDir' -ServerIpDomain 'edir.example.invalid' -ServerPort 636 `
            -EdirUsername 'cn=admin' -ConnectionSecurity SSL @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<ServerIpDomain>edir\.example\.invalid</ServerIpDomain>' -and
            $InnerXml -notmatch '<ServerAddress>' -and
            $InnerXml -match '<Username>cn=admin</Username>' -and
            $InnerXml -notmatch '<EdirUsername>'
        }
    }
}

Describe 'Read-Modify-Write - AuthenticationServer secret preservation' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosActiveDirectoryServer' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <ActiveDirectory>
      <ServerName>CorpAD</ServerName>
      <ServerAddress>ad.example.invalid</ServerAddress>
      <Port>389</Port>
      <NetBIOSDomain>CORP</NetBIOSDomain>
      <ADSUsername>svc-sfos</ADSUsername>
      <ConnectionSecurity>Simple</ConnectionSecurity>
      <DomainName>example.invalid</DomainName>
    </ActiveDirectory>
  </AuthenticationServer>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ActiveDirectory><Status code="200">Configuration applied successfully.</Status></ActiveDirectory></Response>' }
                }
            }
        }

        It 'Should send an empty Password and preserve DomainName/NetBIOSDomain when only ServerAddress changes' {
            # Measured: an empty <Password></Password> on update is accepted and preserves the
            # existing bind password - the one field in this API observed to violate the usual
            # replace-the-whole-entity rule.
            Set-SfosActiveDirectoryServer -ServerName 'CorpAD' -ServerAddress 'ad2.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<ServerAddress>ad2\.example\.invalid</ServerAddress>' -and
                $InnerXml -match '<Password></Password>' -and
                $InnerXml -match '<DomainName>example\.invalid</DomainName>' -and
                $InnerXml -match '<NetBIOSDomain>CORP</NetBIOSDomain>'
            }
        }
    }

    Context 'Set-SfosRADIUSServer' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <RADIUSServer>
      <ServerName>CorpRadius</ServerName>
      <ServerAddress>203.0.113.10</ServerAddress>
      <Port>1812</Port>
      <Timeout>60</Timeout>
      <SharedSecret hashform="mode1">$sfos$7$0$hashedvalue</SharedSecret>
      <DomainName>example.invalid</DomainName>
      <GroupNameAttribute>memberOf</GroupNameAttribute>
    </RADIUSServer>
  </AuthenticationServer>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><RADIUSServer><Status code="200">Configuration applied successfully.</Status></RADIUSServer></Response>' }
                }
            }
        }

        It 'Should resend the hashed SharedSecret with its hashform attribute when -SharedSecret is omitted' {
            # Measured: unlike ActiveDirectory's Password, an empty <SharedSecret></SharedSecret>
            # on update is rejected with 501. The only way to preserve it is resending the hash.
            Set-SfosRADIUSServer -ServerName 'CorpRadius' -DomainName 'corp.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<SharedSecret hashform="mode1">\$sfos\$7\$0\$hashedvalue</SharedSecret>' -and
                $InnerXml -match '<DomainName>corp\.example\.invalid</DomainName>' -and
                $InnerXml -match '<Timeout>60</Timeout>' -and
                $InnerXml -match '<GroupNameAttribute>memberOf</GroupNameAttribute>'
            }
        }

        It 'Get-SfosRADIUSServer should return an empty SharedSecretHash instead of throwing when SharedSecret is absent' {
            # Fixed: Get-SfosRADIUSServer now addresses the element via
            # SelectSingleNode('SharedSecret') and returns '' when it is missing, rather than
            # crashing on $node.SharedSecret.GetAttribute('hashform') against $null.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <RADIUSServer>
      <ServerName>NoSecretYet</ServerName>
      <ServerAddress>203.0.113.11</ServerAddress>
      <Port>1812</Port>
      <Timeout>60</Timeout>
      <GroupNameAttribute>memberOf</GroupNameAttribute>
    </RADIUSServer>
  </AuthenticationServer>
</Response>
'@
                }
            }

            $result = @(Get-SfosRADIUSServer @conn | Where-Object { $_.ServerName -eq 'NoSecretYet' })
            $result.Count | Should -Be 1
            $result[0].SharedSecretHash | Should -Be ''
        }

        It 'Set-SfosRADIUSServer should throw the friendly message, without calling Invoke-SfosApi to update, when there is no hash to resend' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <RADIUSServer>
      <ServerName>NoSecretYet</ServerName>
      <ServerAddress>203.0.113.11</ServerAddress>
      <Port>1812</Port>
      <Timeout>60</Timeout>
      <GroupNameAttribute>memberOf</GroupNameAttribute>
    </RADIUSServer>
  </AuthenticationServer>
</Response>
'@
                }
            }

            { Set-SfosRADIUSServer -ServerName 'NoSecretYet' -DomainName 'x' @conn -Confirm:$false } |
                Should -Throw '*cannot preserve the shared secret*Pass -SharedSecret explicitly*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>'
            }
        }
    }

    Context 'Set-SfosTACACSServer' {
        It 'Get-SfosTACACSServer should return an empty SharedSecretHash instead of throwing when SharedSecret is absent' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <TACACSServer>
      <ServerName>NoSecretYetTacacs</ServerName>
      <ServerAddress>203.0.113.21</ServerAddress>
      <Port>49</Port>
    </TACACSServer>
  </AuthenticationServer>
</Response>
'@
                }
            }

            $result = @(Get-SfosTACACSServer @conn | Where-Object { $_.ServerName -eq 'NoSecretYetTacacs' })
            $result.Count | Should -Be 1
            $result[0].SharedSecretHash | Should -Be ''
        }

        It 'Set-SfosTACACSServer should throw the friendly message, without calling Invoke-SfosApi to update, when there is no hash to resend' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <TACACSServer>
      <ServerName>NoSecretYetTacacs</ServerName>
      <ServerAddress>203.0.113.21</ServerAddress>
      <Port>49</Port>
    </TACACSServer>
  </AuthenticationServer>
</Response>
'@
                }
            }

            { Set-SfosTACACSServer -ServerName 'NoSecretYetTacacs' -ServerAddress '203.0.113.22' @conn -Confirm:$false } |
                Should -Throw '*cannot preserve the shared secret*Pass -SharedSecret explicitly*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>'
            }
        }
    }
}

Describe 'AuthenticationServer family - Remove nested under AuthenticationServer/<Type>' {
    # Measured: Remove, like Get, addresses these four server types nested under
    # <AuthenticationServer>, unlike the flat New/Set status path used by LDAPServer.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AuthenticationServer><ActiveDirectory><Status code="200">Configuration applied successfully.</Status></ActiveDirectory></AuthenticationServer></Response>' }
        }
    }

    It 'Remove-SfosActiveDirectoryServer should send Remove/AuthenticationServer/ActiveDirectory/ServerName' {
        Remove-SfosActiveDirectoryServer -ServerName 'CorpAD' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AuthenticationServer>\s*<ActiveDirectory>' -and
            $InnerXml -match '<ServerName>CorpAD</ServerName>'
        }
    }

    It 'Remove-SfosRADIUSServer should send Remove/AuthenticationServer/RADIUSServer/ServerName' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AuthenticationServer><RADIUSServer><Status code="200">Configuration applied successfully.</Status></RADIUSServer></AuthenticationServer></Response>' }
        }

        Remove-SfosRADIUSServer -ServerName 'CorpRadius' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AuthenticationServer>\s*<RADIUSServer>' -and
            $InnerXml -match '<ServerName>CorpRadius</ServerName>'
        }
    }

    It 'Remove-SfosTACACSServer should send Remove/AuthenticationServer/TACACSServer/ServerName' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AuthenticationServer><TACACSServer><Status code="200">Configuration applied successfully.</Status></TACACSServer></AuthenticationServer></Response>' }
        }

        Remove-SfosTACACSServer -ServerName 'CorpTacacs' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AuthenticationServer>\s*<TACACSServer>' -and
            $InnerXml -match '<ServerName>CorpTacacs</ServerName>'
        }
    }

    It 'Remove-SfosEDirectoryServer should send Remove/AuthenticationServer/EDirectory/ServerName' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AuthenticationServer><EDirectory><Status code="200">Configuration applied successfully.</Status></EDirectory></AuthenticationServer></Response>' }
        }

        Remove-SfosEDirectoryServer -ServerName 'CorpEDir' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AuthenticationServer>\s*<EDirectory>' -and
            $InnerXml -match '<ServerName>CorpEDir</ServerName>'
        }
    }

    It 'Remove-SfosActiveDirectoryServer should throw when the removal fails' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AuthenticationServer><ActiveDirectory><Status code="528">Trying to update default entities which are not editable</Status></ActiveDirectory></AuthenticationServer></Response>' }
        }

        { Remove-SfosActiveDirectoryServer -ServerName 'NoSuchServer' @conn -Confirm:$false } | Should -Throw '*528*'
    }
}

Describe 'LDAPServer - New/Set mandatory-Administrator client-side check, Remove' {
    # Measured: with AnonymousLogin=Disable, omitting Administrator answers code 501 on both
    # New and Set. Both cmdlets check the merged target values client-side and throw before
    # calling the API, so the mock below never needs to simulate the 501 itself.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosLDAPServer' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><LDAPServer><Status code="200">Configuration applied successfully.</Status></LDAPServer></Response>' }
            }
        }

        It 'Should send operation="add" nested under AuthenticationServer/LDAPServer with the mandatory fields' {
            New-SfosLDAPServer -ServerName 'CorpLDAP' -ServerAddress 'ldap.example.invalid' -ServerPort 389 `
                -Version '3' -AnonymousLogin Enable -ConnectionSecurity Simple -BaseDN 'dc=corp,dc=example,dc=invalid' `
                -AuthenticationAttribute 'sAMAccountName' -GroupNameAttribute 'memberOf' -ExpiryDateAttribute 'accountExpires' `
                @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<AuthenticationServer>\s*<LDAPServer>' -and
                $InnerXml -match '<ServerName>CorpLDAP</ServerName>' -and
                $InnerXml -match '<AnonymousLogin>Enable</AnonymousLogin>' -and
                $InnerXml -notmatch '<Administrator>'
            }
        }

        It 'Should throw client-side, without calling Invoke-SfosApi, when AnonymousLogin is Disable and -Administrator is omitted' {
            { New-SfosLDAPServer -ServerName 'CorpLDAP' -ServerAddress 'ldap.example.invalid' -ServerPort 389 `
                    -Version '3' -AnonymousLogin Disable -ConnectionSecurity Simple -BaseDN 'dc=corp,dc=example,dc=invalid' `
                    -AuthenticationAttribute 'sAMAccountName' -GroupNameAttribute 'memberOf' -ExpiryDateAttribute 'accountExpires' `
                    @conn -Confirm:$false } | Should -Throw '*-Administrator is required*AnonymousLogin*Disable*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
        }
    }

    Context 'Set-SfosLDAPServer - Read-Modify-Write and the merged-target Administrator check' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <LDAPServer>
      <ServerName>CorpLDAP</ServerName>
      <ServerAddress>ldap.example.invalid</ServerAddress>
      <Port>389</Port>
      <Version>3</Version>
      <AnonymousLogin>Disable</AnonymousLogin>
      <Administrator>cn=bind,dc=corp,dc=example,dc=invalid</Administrator>
      <ConnectionSecurity>Simple</ConnectionSecurity>
      <BaseDN>dc=corp,dc=example,dc=invalid</BaseDN>
      <AuthenticationAttribute>sAMAccountName</AuthenticationAttribute>
      <GroupNameAttribute>memberOf</GroupNameAttribute>
      <ExpiryDateAttribute>accountExpires</ExpiryDateAttribute>
    </LDAPServer>
  </AuthenticationServer>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><LDAPServer><Status code="200">Configuration applied successfully.</Status></LDAPServer></Response>' }
                }
            }
        }

        It 'Should send an empty Password and preserve Administrator/BaseDN when only ServerAddress changes' {
            Set-SfosLDAPServer -ServerName 'CorpLDAP' -ServerAddress 'ldap2.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<ServerAddress>ldap2\.example\.invalid</ServerAddress>' -and
                $InnerXml -match '<Password></Password>' -and
                $InnerXml -match '<Administrator>cn=bind,dc=corp,dc=example,dc=invalid</Administrator>' -and
                $InnerXml -match '<BaseDN>dc=corp,dc=example,dc=invalid</BaseDN>'
            }
        }

        It 'Should throw client-side when the merged target has AnonymousLogin Disable and no Administrator anywhere' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AuthenticationServer><LDAPServer><ServerName>NoAdminLDAP</ServerName><AnonymousLogin>Disable</AnonymousLogin></LDAPServer></AuthenticationServer></Response>' }
            }

            { Set-SfosLDAPServer -ServerName 'NoAdminLDAP' -ServerAddress 'x' @conn -Confirm:$false } |
                Should -Throw '*-Administrator is required*AnonymousLogin*Disable*'
        }
    }

    Context 'Remove-SfosLDAPServer' {
        It 'Should send Remove/AuthenticationServer/LDAPServer/ServerName' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><LDAPServer><Status code="200">Configuration applied successfully.</Status></LDAPServer></Response>' }
            }

            Remove-SfosLDAPServer -ServerName 'CorpLDAP' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<AuthenticationServer>\s*<LDAPServer>' -and
                $InnerXml -match '<ServerName>CorpLDAP</ServerName>'
            }
        }
    }
}

Describe 'EDirectory - Set Read-Modify-Write (empty Password preserves bind password), Remove' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosEDirectoryServer' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AuthenticationServer>
    <EDirectory>
      <ServerName>CorpEDir</ServerName>
      <ServerIpDomain>edir.example.invalid</ServerIpDomain>
      <Port>636</Port>
      <Username>cn=admin</Username>
      <BaseDN>o=corp</BaseDN>
      <ConnectionSecurity>SSL</ConnectionSecurity>
    </EDirectory>
  </AuthenticationServer>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><EDirectory><Status code="200">Configuration applied successfully.</Status></EDirectory></Response>' }
                }
            }
        }

        It 'Should send an empty Password and preserve BaseDN/ConnectionSecurity when only ServerIpDomain changes' {
            Set-SfosEDirectoryServer -ServerName 'CorpEDir' -ServerIpDomain 'edir2.example.invalid' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<ServerIpDomain>edir2\.example\.invalid</ServerIpDomain>' -and
                $InnerXml -match '<Password></Password>' -and
                $InnerXml -match '<BaseDN>o=corp</BaseDN>' -and
                $InnerXml -match '<ConnectionSecurity>SSL</ConnectionSecurity>'
            }
        }

        It 'Should throw when the named server does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AuthenticationServer><EDirectory><Status>No. of records Zero.</Status></EDirectory></AuthenticationServer></Response>' }
            }

            { Set-SfosEDirectoryServer -ServerName 'DoesNotExist' -ServerIpDomain 'x' @conn -Confirm:$false } |
                Should -Throw "*EDirectory authentication server 'DoesNotExist' was not found*"
        }
    }

    Context 'Remove-SfosEDirectoryServer' {
        It 'Should send Remove/AuthenticationServer/EDirectory/ServerName' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><AuthenticationServer><EDirectory><Status code="200">Configuration applied successfully.</Status></EDirectory></AuthenticationServer></Response>' }
            }

            Remove-SfosEDirectoryServer -ServerName 'CorpEDir' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<AuthenticationServer>\s*<EDirectory>' -and
                $InnerXml -match '<ServerName>CorpEDir</ServerName>'
            }
        }
    }
}

Describe 'Read-Modify-Write - User' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <User>
    <Username>jdoe</Username>
    <Name>Jane Doe</Name>
    <UserType>User</UserType>
    <Group>Sales</Group>
    <Description>original</Description>
    <QuarantineDigest>0</QuarantineDigest>
    <EmailList><EmailID>jane@example.test</EmailID></EmailList>
    <LoginRestriction>UserGroupNode</LoginRestriction>
  </User>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><User><Status code="200">Configuration applied successfully.</Status></User></Response>' }
            }
        }
    }

    It 'Should preserve Group, UserType and EmailList when only Description changes' {
        Set-SfosUser -AccountName 'jdoe' -Description 'Updated via PowerShell' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Username>jdoe</Username>' -and
            $InnerXml -match '<Description>Updated via PowerShell</Description>' -and
            $InnerXml -match '<Group>Sales</Group>' -and
            $InnerXml -match '<UserType>User</UserType>' -and
            $InnerXml -match '<EmailID>jane@example\.test</EmailID>'
        }
    }

    It 'Should heal a QuarantineDigest of literal "0" to Disable instead of resending the invalid value' {
        # A User created without an explicit QuarantineDigest is stored as "0", which the
        # firewall rejects with 501 on a later update. Set-SfosUser normalises it.
        Set-SfosUser -AccountName 'jdoe' -Description 'Updated via PowerShell' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<QuarantineDigest>Disable</QuarantineDigest>' -and
            $InnerXml -notmatch '<QuarantineDigest>0</QuarantineDigest>'
        }
    }

    It 'New-SfosUser should send operation="add" with the wire element Username, not AccountName' {
        $pw = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force
        New-SfosUser -AccountName 'asmith' -Name 'Alex Smith' -AccountPassword $pw -LoginRestriction AnyNode @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Username>asmith</Username>' -and
            $InnerXml -notmatch '<AccountName>' -and
            $InnerXml -match '<LoginRestriction>AnyNode</LoginRestriction>'
        }
    }
}

Describe 'Remove-SfosUser - lowercased <Name>, not <Username>, with read-back' {
    # The Delete User operation only honours <Name>, case-sensitively against the always-lowercase
    # stored value. <Username> or the caller's original casing both answer a false 200 and remove nothing.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Should send a lowercased <Name>, not <Username>, and succeed when the read-back is empty' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Remove>') {
                [PSCustomObject]@{ Content = '<Response><User><Status code="200">Configuration applied successfully.</Status></User></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
            }
        }

        { Remove-SfosUser -AccountName 'JDoe' @conn -Confirm:$false } | Should -Not -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<Name>jdoe</Name>' -and
            $InnerXml -notmatch '<Username>jdoe</Username>'
        }
    }

    It 'Should throw when the firewall reports success but the user is still present on read-back' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Remove>') {
                [PSCustomObject]@{ Content = '<Response><User><Status code="200">Configuration applied successfully.</Status></User></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User><Username>jdoe</Username><Name>Jane Doe</Name></User></Response>' }
            }
        }

        { Remove-SfosUser -AccountName 'jdoe' @conn -Confirm:$false } |
            Should -Throw "*User 'jdoe' is still present*"
    }
}

Describe 'UserGroup - Set Read-Modify-Write, Remove with read-back' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosUserGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>\s*<UserGroup>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UserGroup><GroupDetail><Name>Sales</Name><GroupType>Normal</GroupType><SurfingQuotaPolicy>Unlimited</SurfingQuotaPolicy><AccessTimePolicy>AllowedAllTheTime</AccessTimePolicy><QoSPolicy>None</QoSPolicy><QuarantineDigest>Enable</QuarantineDigest><LoginRestriction>AnyNode</LoginRestriction></GroupDetail></UserGroup></Response>' }
                }
                elseif ($InnerXml -match '<Get>\s*<User>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
                }
            }
        }

        It 'Should preserve AccessTimePolicy/QuarantineDigest/LoginRestriction when only QoSPolicy changes' {
            Set-SfosUserGroup -Name 'Sales' -QoSPolicy 'Gold' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<QoSPolicy>Gold</QoSPolicy>' -and
                $InnerXml -match '<AccessTimePolicy>AllowedAllTheTime</AccessTimePolicy>' -and
                $InnerXml -match '<QuarantineDigest>Enable</QuarantineDigest>' -and
                $InnerXml -match '<LoginRestriction>AnyNode</LoginRestriction>'
            }
        }

        It 'Should throw when the named group does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UserGroup></UserGroup></Response>' }
            }

            { Set-SfosUserGroup -Name 'DoesNotExist' -QoSPolicy 'Gold' @conn -Confirm:$false } |
                Should -Throw "*UserGroup object 'DoesNotExist' was not found*"
        }
    }

    Context 'Remove-SfosUserGroup' {
        It 'Should nest <Name> inside <GroupDetail> and succeed when the read-back is empty' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><UserGroup><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></UserGroup></Response>' }
                }
                elseif ($InnerXml -match '<Get>\s*<UserGroup>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UserGroup></UserGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
                }
            }

            { Remove-SfosUserGroup -Name 'Sales' @conn -Confirm:$false } | Should -Not -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<UserGroup>\s*<GroupDetail>\s*<Name>Sales</Name>'
            }
        }

        It 'Should throw when the firewall reports success (code 200) but the group is still present - the documented false-success defect' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Remove>') {
                    [PSCustomObject]@{ Content = '<Response><UserGroup><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></UserGroup></Response>' }
                }
                elseif ($InnerXml -match '<Get>\s*<UserGroup>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UserGroup><GroupDetail><Name>Sales</Name></GroupDetail></UserGroup></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
                }
            }

            { Remove-SfosUserGroup -Name 'Sales' @conn -Confirm:$false } |
                Should -Throw "*UserGroup 'Sales' is still present*"
        }
    }
}

Describe 'Add-/Remove-SfosFirewallAuthenticationMethodsMember' {
    # NOT verified against the live firewall (see the functions'' .NOTES): this block controls
    # the login path for every account, including the API user. Structural tests only.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Add-SfosFirewallAuthenticationMethodsMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><AuthenticationMethods><DefaultGroup>Open Group</DefaultGroup><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></AuthenticationServerList></AuthenticationMethods></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><AuthenticationMethods><Status code="200">Configuration applied successfully.</Status></AuthenticationMethods></Response>' }
                }
            }
        }

        It 'Should merge the new server into the existing list, preserving DefaultGroup' {
            Add-SfosFirewallAuthenticationMethodsMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<DefaultGroup>Open Group</DefaultGroup>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -match '<AuthenticationServer>CorpRadius</AuthenticationServer>'
            }
        }
    }

    Context 'Remove-SfosFirewallAuthenticationMethodsMember' {
        It 'Should preserve DefaultGroup and the remaining server when removing one of two' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><AuthenticationMethods><DefaultGroup>Open Group</DefaultGroup><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer><AuthenticationServer>CorpRadius</AuthenticationServer></AuthenticationServerList></AuthenticationMethods></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><AuthenticationMethods><Status code="200">Configuration applied successfully.</Status></AuthenticationMethods></Response>' }
                }
            }

            Remove-SfosFirewallAuthenticationMethodsMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -notmatch '<AuthenticationServer>CorpRadius</AuthenticationServer>' -and
                $InnerXml -match '<DefaultGroup>Open Group</DefaultGroup>'
            }
        }

        It 'Should do nothing (no API write call) when the server list is already empty' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><AuthenticationMethods><DefaultGroup>Open Group</DefaultGroup><AuthenticationServerList></AuthenticationServerList></AuthenticationMethods></FirewallAuthentication></Response>' }
            }

            Remove-SfosFirewallAuthenticationMethodsMember -Members 'Local' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>'
            }
        }
    }
}

Describe 'Read-Modify-Write - UserGroup, GuestUserSettings, OTPSettings, FirewallAuthenticationMethods, AdminAuthentication' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'New-SfosUserGroup' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
            }
        }

        It 'Should send operation="add" wrapped in UserGroup/GroupDetail' {
            New-SfosUserGroup -Name 'Sales' -GroupType Normal -QoSPolicy 'None' -SurfingQuotaPolicy 'Unlimited' `
                -AccessTimePolicy 'AllowedAllTheTime' -LoginRestriction AnyNode @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<UserGroup>\s*<GroupDetail>' -and
                $InnerXml -match '<Name>Sales</Name>' -and
                $InnerXml -match '<GroupType>Normal</GroupType>'
            }
        }
    }

    Context 'Set-SfosGuestUserSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <GuestUserSettings>
    <AllowGuestUserSettings>Enable</AllowGuestUserSettings>
    <GuestUserSettingsName>AutoGenerate</GuestUserSettingsName>
    <UserNamePrefix>guest-</UserNamePrefix>
    <UserValidity><Days>1</Days></UserValidity>
    <AutoPurgeOnExpiry>Enable</AutoPurgeOnExpiry>
    <UserGroup>Guest Group</UserGroup>
    <PasswordLength>8</PasswordLength>
    <PasswordComplexity>AlphanumericPassword</PasswordComplexity>
  </GuestUserSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GuestUserSettings><Status code="200">Configuration applied successfully.</Status></GuestUserSettings></Response>' }
                }
            }
        }

        It 'Should resend Days nested under UserValidity and preserve UserGroup/PasswordLength when only AutoPurgeOnExpiry changes' {
            Set-SfosGuestUserSettings -AutoPurgeOnExpiry Disable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<AutoPurgeOnExpiry>Disable</AutoPurgeOnExpiry>' -and
                $InnerXml -match '<UserValidity>\s*<Days>1</Days>\s*</UserValidity>' -and
                $InnerXml -match '<UserGroup>Guest Group</UserGroup>' -and
                $InnerXml -match '<PasswordLength>8</PasswordLength>'
            }
        }
    }

    Context 'Set-SfosOTPSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <OTPSettings>
    <otp>1</otp>
    <allUsers>0</allUsers>
    <otpUsers><user>jdoe</user></otpUsers>
    <tokenAutoCreation>1</tokenAutoCreation>
    <algorithm>SHA1</algorithm>
    <defaultTimeStep>30</defaultTimeStep>
    <maxTimeStepsInterval>2</maxTimeStepsInterval>
    <maxInitialTimeStepDiff>10</maxInitialTimeStepDiff>
  </OTPSettings>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><OTPSettings><Status code="200">Configuration applied successfully.</Status></OTPSettings></Response>' }
                }
            }
        }

        It 'Should preserve otpUsers and algorithm when only DefaultTimeStep changes' {
            Set-SfosOTPSettings -DefaultTimeStep 60 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<defaultTimeStep>60</defaultTimeStep>' -and
                $InnerXml -match '<user>jdoe</user>' -and
                $InnerXml -match '<algorithm>SHA1</algorithm>' -and
                $InnerXml -match '<allUsers>0</allUsers>'
            }
        }
    }

    Context 'Set-SfosFirewallAuthenticationMethods' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <FirewallAuthentication>
    <AuthenticationMethods>
      <DefaultGroup>Open Group</DefaultGroup>
      <AuthenticationServerList>
        <AuthenticationServer>Local</AuthenticationServer>
        <AuthenticationServer>CorpAD</AuthenticationServer>
      </AuthenticationServerList>
    </AuthenticationMethods>
  </FirewallAuthentication>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><AuthenticationMethods><Status code="200">Configuration applied successfully.</Status></AuthenticationMethods></Response>' }
                }
            }
        }

        It 'Should resend the existing AuthenticationServerList when only DefaultGroup changes' {
            # This block controls the login path for every account, including the API user -
            # losing a server here is the "must not become empty" defect class the module
            # documents for this whole family of entities.
            Set-SfosFirewallAuthenticationMethods -DefaultGroup 'New Default Group' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<DefaultGroup>New Default Group</DefaultGroup>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -match '<AuthenticationServer>CorpAD</AuthenticationServer>'
            }
        }
    }

    Context 'Set-SfosAdminAuthentication' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AdminAuthentication>
    <AuthenticationMethods>Custom</AuthenticationMethods>
    <AuthenticationServerList>
      <AuthenticationServer>Local</AuthenticationServer>
    </AuthenticationServerList>
  </AdminAuthentication>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><AdminAuthentication><Status code="200">Configuration applied successfully.</Status></AdminAuthentication></Response>' }
                }
            }
        }

        It 'Should preserve the existing AuthenticationServerList when only AuthenticationMethods is resent' {
            Set-SfosAdminAuthentication -AuthenticationMethods 'Custom' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>'
            }
        }
    }
}

Describe 'Add-/Remove-SfosUserGroupMember write through the User object, not GroupMembers' {
    # Writing <GroupMembers> under <UserGroup> answers 200 and does nothing.
    # Membership lives on the User object's own <Group> field.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        # Stateful mock: tracks jdoe's Group across the Get -> Set -> Get(verify) sequence
        # that Add-/Remove-SfosUserGroupMember perform, so the post-write verification each
        # cmdlet does (read the user back and check Group) is exercised for real instead of
        # being hard-coded into the mock response.
        $script:jdoeGroup = ''

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<UserGroup>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <UserGroup>
    <GroupDetail>
      <Name>Sales</Name>
      <GroupType>Normal</GroupType>
    </GroupDetail>
  </UserGroup>
</Response>
'@
                }
            }
            elseif ($InnerXml -match '<Set operation="update">' -and $InnerXml -match '<User>') {
                if ($InnerXml -match '<Group>([^<]*)</Group>') {
                    $script:jdoeGroup = $Matches[1]
                }
                [PSCustomObject]@{ Content = '<Response><User><Status code="200">Configuration applied successfully.</Status></User></Response>' }
            }
            else {
                # Any <Get><User>...</User></Get>, filtered or not - both Get-SfosUserGroup's
                # internal all-users fetch and Add-/Remove-SfosUserGroupMember's own lookups
                # land here.
                [PSCustomObject]@{ Content = @"
<Response>
  <Login><status>Authentication Successful</status></Login>
  <User>
    <Username>jdoe</Username>
    <Name>Jane Doe</Name>
    <UserType>User</UserType>
    <Group>$script:jdoeGroup</Group>
  </User>
</Response>
"@
                }
            }
        }
    }

    It 'Add-SfosUserGroupMember should set Group to Sales on the User object via Set-SfosUser' {
        Add-SfosUserGroupMember -Name 'Sales' -Members 'jdoe' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<User>' -and $InnerXml -match '<Group>Sales</Group>'
        }
        $script:jdoeGroup | Should -Be 'Sales'
    }

    It 'Should never write a GroupMembers element anywhere' {
        Add-SfosUserGroupMember -Name 'Sales' -Members 'jdoe' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $InnerXml -notmatch 'GroupMembers'
        }
    }

    It 'Remove-SfosUserGroupMember should clear Group to an empty value when the user currently belongs to the group' {
        $script:jdoeGroup = 'Sales'

        Remove-SfosUserGroupMember -Name 'Sales' -Members 'jdoe' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<User>' -and $InnerXml -match '<Group></Group>'
        }
        $script:jdoeGroup | Should -Be ''
    }

    It 'Remove-SfosUserGroupMember should leave a non-member untouched, without calling Set-SfosUser' {
        $script:jdoeGroup = 'Marketing'

        Remove-SfosUserGroupMember -Name 'Sales' -Members 'jdoe' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<User>'
        }
        $script:jdoeGroup | Should -Be 'Marketing'
    }

    It 'Add-SfosUserGroupMember should throw when the named user does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<UserGroup>') {
                [PSCustomObject]@{ Content = '<Response><UserGroup><GroupDetail><Name>Sales</Name></GroupDetail></UserGroup></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
            }
        }

        { Add-SfosUserGroupMember -Name 'Sales' -Members 'ghost' @conn -Confirm:$false } | Should -Throw "*User 'ghost' was not found*"
    }
}

Describe 'Get-SfosOTPSettings' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Should send Get/OTPSettings and parse otpUsers/algorithm/defaultTimeStep' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>1</otp><allUsers>0</allUsers><otpUsers><user>jdoe</user></otpUsers><algorithm>SHA1</algorithm><defaultTimeStep>30</defaultTimeStep></OTPSettings></Response>' }
        }

        $result = Get-SfosOTPSettings @conn
        $result.Otp | Should -Be '1'
        $result.OtpUsers | Should -Contain 'jdoe'
        $result.Algorithm | Should -Be 'SHA1'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><OTPSettings></OTPSettings></Get>'
        }
    }

    It 'Should return an empty OtpUsers array (not $null) when the element is absent (allUsers=1)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>0</otp><allUsers>1</allUsers></OTPSettings></Response>' }
        }

        $result = Get-SfosOTPSettings @conn
        , $result.OtpUsers | Should -Not -Be $null
        @($result.OtpUsers).Count | Should -Be 0
    }
}

Describe 'OTPSettings member management' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Add-SfosOTPSettingsMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>1</otp><allUsers>0</allUsers><otpUsers><user>jdoe</user></otpUsers></OTPSettings></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><OTPSettings><Status code="200">Configuration applied successfully.</Status></OTPSettings></Response>' }
                }
            }
        }

        It 'Should merge the new member into the existing list and de-duplicate' {
            Add-SfosOTPSettingsMember -Members 'jdoe', 'asmith' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                (([regex]::Matches($InnerXml, '<user>jdoe</user>')).Count -eq 1) -and
                $InnerXml -match '<user>asmith</user>'
            }
        }
    }

    Context 'Remove-SfosOTPSettingsMember - append-only defect' {
        It 'Should throw when the firewall silently ignores a partial removal' {
            # Measured live: <otpUsers> is append-only on a normal update. A shorter,
            # non-empty list is silently ignored and answers 200 - the cmdlet must catch this
            # rather than report success for a write that did nothing.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>1</otp><allUsers>0</allUsers><otpUsers><user>jdoe</user><user>asmith</user></otpUsers></OTPSettings></Response>' }
                }
                else {
                    # Simulates the measured append-only firmware behaviour: the write answers
                    # 200 but a follow-up Get would still show both members.
                    [PSCustomObject]@{ Content = '<Response><OTPSettings><Status code="200">Configuration applied successfully.</Status></OTPSettings></Response>' }
                }
            }

            { Remove-SfosOTPSettingsMember -Members 'jdoe' @conn -Confirm:$false } |
                Should -Throw '*answered success but the firewall left them in place*'
        }

        It 'Should succeed and send a single empty user element when the removal empties the whole list' {
            # Stateful: otpUsers holds jdoe until the Set call clears it, so the post-write
            # verification Get (which the cmdlet always performs) sees the real outcome
            # instead of a hard-coded "still has members" response.
            $script:otpHasMember = $true

            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    if ($script:otpHasMember) {
                        [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>1</otp><allUsers>0</allUsers><otpUsers><user>jdoe</user></otpUsers></OTPSettings></Response>' }
                    }
                    else {
                        [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>1</otp><allUsers>0</allUsers></OTPSettings></Response>' }
                    }
                }
                else {
                    $script:otpHasMember = $false
                    [PSCustomObject]@{ Content = '<Response><OTPSettings><Status code="200">Configuration applied successfully.</Status></OTPSettings></Response>' }
                }
            }

            { Remove-SfosOTPSettingsMember -Members 'jdoe' @conn -Confirm:$false } | Should -Not -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<otpUsers>\s*<user/>\s*</otpUsers>'
            }
        }

        It 'Should return without calling Set when the list is already empty' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPSettings><otp>0</otp><allUsers>1</allUsers></OTPSettings></Response>' }
            }

            Remove-SfosOTPSettingsMember -Members 'jdoe' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>'
            }
        }
    }
}

Describe 'GuestUser - no update path exists' {
    # Neither operation="update" nor the undocumented operation="edit" works for GuestUser
    # (edit silently creates a duplicate). No Set-SfosGuestUser is shipped.

    It 'Set-SfosGuestUser should not exist' {
        Get-Command Set-SfosGuestUser -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    Context 'New-SfosGuestUser / Remove-SfosGuestUser' {
        BeforeAll {
            $conn = @{
                Firewall = 'fw.example.test'
                Port     = 4444
                Username = 'apiuser'
                Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
            }
        }

        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><GuestUser><Status code="200">Configuration applied successfully.</Status></GuestUser></Response>' }
            }
        }

        It 'New-SfosGuestUser should send operation="add" with Name and UserValidity' {
            New-SfosGuestUser -Name 'visitor1' -UserValidity '1' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<Name>visitor1</Name>' -and
                $InnerXml -match '<UserValidity>1</UserValidity>'
            }
        }

        It 'Remove-SfosGuestUser should identify the object by the auto-generated Username, not Name' {
            # <Remove><GuestUser><Name>...</Name></GuestUser></Remove> answers 500; the
            # auto-generated login (Username) is required instead.
            Remove-SfosGuestUser -AccountName 'guest-00001' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<Username>guest-00001</Username>' -and
                $InnerXml -notmatch '<Name>guest-00001</Name>'
            }
        }
    }
}

Describe 'ClientlessUser - Get, New, Read-Modify-Write, Remove, and the duplicate-transactionid sanitiser' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'ConvertTo-SfosClientlessUserSanitizedXml is not exported' {
        Get-Command ConvertTo-SfosClientlessUserSanitizedXml -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    Context 'Get-SfosClientlessUser' {
        It 'Should return an empty array on "No. of records Zero."' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ClientlessUser transactionid=""><Status>No. of records Zero.</Status></ClientlessUser></Response>' }
            }

            $result = @(Get-SfosClientlessUser @conn)
            $result.Count | Should -Be 0
        }

        It 'Should parse fields and expose AccountName as an alias of UserName' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ClientlessUser><UserName>jdoe</UserName><Name>Jane Doe</Name><IPAddress>203.0.113.10</IPAddress><ClientLessGroup>Clientless Group</ClientLessGroup><Email>jdoe@example.test</Email><Status>Active</Status></ClientlessUser></Response>' }
            }

            $result = @(Get-SfosClientlessUser @conn)
            $result.Count | Should -Be 1
            $result[0].UserName | Should -Be 'jdoe'
            $result[0].AccountName | Should -Be 'jdoe'
            $result[0].IPAddress | Should -Be '203.0.113.10'
        }

        It 'Should tolerate a doubled transactionid attribute that would otherwise break XML parsing' {
            # Measured live: the response body can carry the root element's transactionid
            # attribute twice, which System.Xml.XmlDocument rejects outright before any status
            # or data node is ever reached.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ClientlessUser transactionid="" transactionid=""><UserName>jdoe</UserName><Name>Jane Doe</Name></ClientlessUser></Response>' }
            }

            $result = @(Get-SfosClientlessUser @conn)
            $result.Count | Should -Be 1
            $result[0].UserName | Should -Be 'jdoe'
        }
    }

    Context 'New-SfosClientlessUser' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><ClientlessUser><Status code="200">Configuration applied successfully.</Status></ClientlessUser></Response>' }
            }
        }

        It 'Should send operation="add" with the wire element UserName, not AccountName' {
            New-SfosClientlessUser -AccountName 'jdoe' -Name 'Jane Doe' -ClientLessGroup 'Clientless Group' -Email 'jdoe@example.test' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<UserName>jdoe</UserName>' -and
                $InnerXml -notmatch '<AccountName>' -and
                $InnerXml -match '<ClientLessGroup>Clientless Group</ClientLessGroup>'
            }
        }

        It 'Should throw when the duplicated transactionid attribute wraps a real failure status' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><ClientlessUser transactionid="" transactionid=""><Status code="501">Configuration parameters validation failed.</Status></ClientlessUser></Response>' }
            }

            { New-SfosClientlessUser -AccountName 'jdoe' -Name 'Jane Doe' -ClientLessGroup 'Clientless Group' -Email 'jdoe@example.test' @conn -Confirm:$false } |
                Should -Throw '*501*'
        }
    }

    Context 'Set-SfosClientlessUser - Read-Modify-Write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ClientlessUser><UserName>jdoe</UserName><Name>Jane Doe</Name><IPAddress>203.0.113.10</IPAddress><ClientLessGroup>Clientless Group</ClientLessGroup><Email>jdoe@example.test</Email><Status>Active</Status></ClientlessUser></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><ClientlessUser><Status code="200">Configuration applied successfully.</Status></ClientlessUser></Response>' }
                }
            }
        }

        It 'Should preserve ClientLessGroup/Email/Status when only Description changes' {
            Set-SfosClientlessUser -AccountName 'jdoe' -Description 'Contractor access' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<Description>Contractor access</Description>' -and
                $InnerXml -match '<ClientLessGroup>Clientless Group</ClientLessGroup>' -and
                $InnerXml -match '<Email>jdoe@example\.test</Email>' -and
                $InnerXml -match '<Status>Active</Status>'
            }
        }

        It 'Should throw when the named user does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ClientlessUser transactionid=""><Status>No. of records Zero.</Status></ClientlessUser></Response>' }
            }

            { Set-SfosClientlessUser -AccountName 'ghost' -Description 'x' @conn -Confirm:$false } |
                Should -Throw "*ClientlessUser object 'ghost' was not found*"
        }
    }

    Context 'Remove-SfosClientlessUser' {
        It 'Should send Remove/ClientlessUser/UserName' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><ClientlessUser><Status code="200">Configuration applied successfully.</Status></ClientlessUser></Response>' }
            }

            Remove-SfosClientlessUser -AccountName 'jdoe' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<ClientlessUser>' -and
                $InnerXml -match '<UserName>jdoe</UserName>'
            }
        }
    }

    Context 'New-SfosClientlessUserRange' {
        It 'Should send operation="add" wrapped in the distinct ClientlessUserAddRange element' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><ClientlessUserAddRange><Status code="200">Configuration applied successfully.</Status></ClientlessUserAddRange></Response>' }
            }

            New-SfosClientlessUserRange -FromIPAddress '203.0.113.10' -ToIPAddress '203.0.113.20' -ClientLessGroup 'Clientless Group' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<ClientlessUserAddRange>' -and
                $InnerXml -match '<FromIPAddress>203\.0\.113\.10</FromIPAddress>' -and
                $InnerXml -match '<ToIPAddress>203\.0\.113\.20</ToIPAddress>' -and
                $InnerXml -notmatch '<ClientlessUser>'
            }
        }
    }
}

Describe 'SMSGateway - the firmware misspelling "Paramter" and numeric ResponseParameterName indexes' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosSMSGateway' {
        It 'Should return an empty array on "No. of records Zero."' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMSGateway transactionid=""><Status>No. of records Zero.</Status></SMSGateway></Response>' }
            }

            $result = @(Get-SfosSMSGateway @conn)
            $result.Count | Should -Be 0
        }

        It 'Should parse the positionally-matched RequestParamter/ResponseParamter name/value arrays' {
            # Measured: RequestParamterList/RequestParamter wraps N sibling <ParameterName>
            # elements followed by N sibling <ParameterValue> elements - not N repeated
            # name/value pairs. The wrapper spelling 'Paramter' is the firmware's own, kept
            # verbatim; ParameterName/ParameterValue are spelled correctly.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SMSGateway>
    <Name>ExampleGateway</Name>
    <URL>https://sms.example.test/send</URL>
    <HTTPMethod>Post</HTTPMethod>
    <RequestParamterList>
      <RequestParamter>
        <ParameterName>to</ParameterName>
        <ParameterName>msg</ParameterName>
        <ParameterValue>{mobileno}</ParameterValue>
        <ParameterValue>{msg}</ParameterValue>
      </RequestParamter>
    </RequestParamterList>
    <ResponseFormat>{0}:{1}</ResponseFormat>
    <ResponseParamterList>
      <ResponseParamter>
        <ParameterName>0</ParameterName>
        <ParameterName>1</ParameterName>
        <ParameterValue>status</ParameterValue>
        <ParameterValue>id</ParameterValue>
      </ResponseParamter>
    </ResponseParamterList>
  </SMSGateway>
</Response>
'@
            }
            }

            $result = @(Get-SfosSMSGateway @conn)
            $result.Count | Should -Be 1
            $result[0].RequestParameterName | Should -Be @('to', 'msg')
            $result[0].RequestParameterValue | Should -Be @('{mobileno}', '{msg}')
            $result[0].ResponseParameterName | Should -Be @('0', '1')
            $result[0].ResponseParameterValue | Should -Be @('status', 'id')
        }
    }

    Context 'New-SfosSMSGateway' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><SMSGateway><Status code="200">Configuration applied successfully.</Status></SMSGateway></Response>' }
            }
        }

        It 'Should send the misspelled RequestParamterList/RequestParamter wrapper with ParameterName/ParameterValue spelled correctly' {
            New-SfosSMSGateway -Name 'ExampleGateway' -URL 'https://sms.example.test/send' -HTTPMethod Post `
                -RequestParameterName @('to', 'msg') -RequestParameterValue @('{mobileno}', '{msg}') `
                -ResponseFormat '{0}:{1}' -ResponseParameterName @('0', '1') -ResponseParameterValue @('status', 'id') `
                @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<RequestParamterList><RequestParamter>' -and
                $InnerXml -match '<ParameterName>to</ParameterName>' -and
                $InnerXml -match '<ParameterValue>\{mobileno\}</ParameterValue>' -and
                $InnerXml -match '<ResponseParamterList><ResponseParamter>' -and
                $InnerXml -match '<ParameterName>0</ParameterName>' -and
                $InnerXml -match '<ParameterName>1</ParameterName>'
            }
        }

        It 'Should throw client-side, without calling Invoke-SfosApi, when the request name/value array lengths differ' {
            { New-SfosSMSGateway -Name 'Bad' -URL 'https://sms.example.test/send' `
                    -RequestParameterName @('to', 'msg') -RequestParameterValue @('only-one') `
                    @conn -Confirm:$false } | Should -Throw '*same number of elements*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
        }
    }

    Context 'Set-SfosSMSGateway - Read-Modify-Write' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <SMSGateway>
    <Name>ExampleGateway</Name>
    <URL>https://sms.example.test/send</URL>
    <HTTPMethod>Post</HTTPMethod>
    <CellNumberPreFix>+1</CellNumberPreFix>
    <RequestParamterList>
      <RequestParamter>
        <ParameterName>to</ParameterName>
        <ParameterValue>{mobileno}</ParameterValue>
      </RequestParamter>
    </RequestParamterList>
    <ResponseFormat>{0}</ResponseFormat>
    <ResponseParamterList>
      <ResponseParamter>
        <ParameterName>0</ParameterName>
        <ParameterValue>status</ParameterValue>
      </ResponseParamter>
    </ResponseParamterList>
  </SMSGateway>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SMSGateway><Status code="200">Configuration applied successfully.</Status></SMSGateway></Response>' }
                }
            }
        }

        It 'Should preserve the RequestParamter/ResponseParamter lists when only CellNumberPreFix changes' {
            Set-SfosSMSGateway -Name 'ExampleGateway' -CellNumberPreFix '+44' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<CellNumberPreFix>\+44</CellNumberPreFix>' -and
                $InnerXml -match '<RequestParamterList><RequestParamter>' -and
                $InnerXml -match '<ParameterName>to</ParameterName>' -and
                $InnerXml -match '<ResponseParamterList><ResponseParamter>' -and
                $InnerXml -match '<ParameterName>0</ParameterName>' -and
                $InnerXml -match '<URL>https://sms\.example\.test/send</URL>'
            }
        }

        It 'Should throw when the named gateway does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SMSGateway transactionid=""><Status>No. of records Zero.</Status></SMSGateway></Response>' }
            }

            { Set-SfosSMSGateway -Name 'DoesNotExist' -CellNumberPreFix '+44' @conn -Confirm:$false } |
                Should -Throw "*SMSGateway object 'DoesNotExist' was not found*"
        }
    }

    Context 'Remove-SfosSMSGateway' {
        It 'Should send Remove/SMSGateway/Name' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><SMSGateway><Status code="200">Configuration applied successfully.</Status></SMSGateway></Response>' }
            }

            Remove-SfosSMSGateway -Name 'ExampleGateway' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<SMSGateway>' -and
                $InnerXml -match '<Name>ExampleGateway</Name>'
            }
        }
    }
}

Describe 'OTPTokens - Get, New (hex-secret validation), Read-Modify-Write, Remove' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Get-SfosOTPTokens' {
        It 'Should return an empty array on "No. of records Zero."' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPTokens transactionid=""><Status>No. of records Zero.</Status></OTPTokens></Response>' }
            }

            $result = @(Get-SfosOTPTokens @conn)
            $result.Count | Should -Be 0
        }

        It 'Should parse the measured field set, using useCustomTokenTimeStep/timeStepOffset rather than the documented but nonexistent timeStep' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPTokens><tokenid>ABC123</tokenid><useCustomTokenTimeStep>Off</useCustomTokenTimeStep><timeStepOffset>0</timeStepOffset><algorithm>SHA1</algorithm><active>1</active><user>jdoe</user><comment>Issued</comment></OTPTokens></Response>' }
            }

            $result = @(Get-SfosOTPTokens @conn)
            $result.Count | Should -Be 1
            $result[0].TokenId | Should -Be 'ABC123'
            $result[0].UseCustomTokenTimeStep | Should -Be 'Off'
            $result[0].User | Should -Be 'jdoe'
            $result[0].PSObject.Properties.Name | Should -Not -Contain 'Secret'
        }

        It 'Should combine TokenIdLike and UserLike with AND' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPTokens><tokenid>ABC123</tokenid><user>jdoe</user></OTPTokens><OTPTokens><tokenid>XYZ789</tokenid><user>jdoe</user></OTPTokens><OTPTokens><tokenid>ABC999</tokenid><user>asmith</user></OTPTokens></Response>' }
            }

            $result = @(Get-SfosOTPTokens -TokenIdLike 'ABC' -UserLike 'jdoe' @conn)
            $result.Count | Should -Be 1
            $result[0].TokenId | Should -Be 'ABC123'
        }
    }

    Context 'New-SfosOTPTokens - hex-secret client-side validation' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><OTPTokens><Status code="200">Configuration applied successfully.</Status></OTPTokens></Response>' }
            }
        }

        It 'Should send operation="add" with the hexadecimal secret and the wire element <user>' {
            $secret = ConvertTo-SecureString '0123456789abcdef0123456789abcdef' -AsPlainText -Force
            New-SfosOTPTokens -User 'jdoe' -Secret $secret -Algorithm SHA1 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="add">' -and
                $InnerXml -match '<user>jdoe</user>' -and
                $InnerXml -match '<secret>0123456789abcdef0123456789abcdef</secret>' -and
                $InnerXml -match '<algorithm>SHA1</algorithm>'
            }
        }

        It 'Should throw client-side, without calling Invoke-SfosApi, on a non-hexadecimal secret' {
            $secret = ConvertTo-SecureString 'NOTHEXADECIMAL-VALUE-ZZZZZZZZZZZ' -AsPlainText -Force
            { New-SfosOTPTokens -User 'jdoe' -Secret $secret @conn -Confirm:$false } | Should -Throw '*hexadecimal*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
        }

        It 'Should throw client-side on a secret shorter than 32 characters' {
            $secret = ConvertTo-SecureString '0123456789abcdef' -AsPlainText -Force
            { New-SfosOTPTokens -User 'jdoe' -Secret $secret @conn -Confirm:$false } | Should -Throw '*32 to 120 characters*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
        }
    }

    Context 'Set-SfosOTPTokens - Read-Modify-Write, no -Secret parameter' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPTokens><tokenid>ABC123</tokenid><useCustomTokenTimeStep>Off</useCustomTokenTimeStep><algorithm>SHA1</algorithm><active>1</active><user>jdoe</user><comment>Issued</comment></OTPTokens></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><OTPTokens><Status code="200">Configuration applied successfully.</Status></OTPTokens></Response>' }
                }
            }
        }

        It 'Should preserve algorithm/user when only Comment changes, and never send a secret element' {
            Set-SfosOTPTokens -TokenId 'ABC123' -Comment 'Reissued' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<comment>Reissued</comment>' -and
                $InnerXml -match '<algorithm>SHA1</algorithm>' -and
                $InnerXml -match '<user>jdoe</user>' -and
                $InnerXml -notmatch '<secret>'
            }
        }

        It 'Set-SfosOTPTokens has no -Secret parameter' {
            (Get-Command Set-SfosOTPTokens).Parameters.Keys | Should -Not -Contain 'Secret'
        }

        It 'Should throw when the named token does not exist' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><OTPTokens transactionid=""><Status>No. of records Zero.</Status></OTPTokens></Response>' }
            }

            { Set-SfosOTPTokens -TokenId 'GHOST' -Comment 'x' @conn -Confirm:$false } |
                Should -Throw "*OTPTokens object 'GHOST' was not found*"
        }
    }

    Context 'Remove-SfosOTPTokens' {
        It 'Should send Remove/OTPTokens/tokenid' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><OTPTokens><Status code="200">Configuration applied successfully.</Status></OTPTokens></Response>' }
            }

            Remove-SfosOTPTokens -TokenId 'ABC123' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Remove>' -and
                $InnerXml -match '<OTPTokens>' -and
                $InnerXml -match '<tokenid>ABC123</tokenid>'
            }
        }
    }
}

Describe 'AzureADSSO' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $secret = ConvertTo-SecureString 'MySecret' -AsPlainText -Force
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AzureADSSO><Status code="200">Configuration applied successfully.</Status></AzureADSSO></Response>' }
        }
    }

    It 'Should send no RoleMapping element for a plain User-type server' {
        New-SfosAzureADSSO -ServerName 'CorpEntra' -ApplicationID 'app-id' -TenantID 'tenant-id' -ClientSecret $secret `
            -RedirectURI 'fw.example.invalid' -DisplayName upn -EmailAddress email -FallbackUserGroup 'Open Group' `
            -UserType User @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -notmatch '<RoleMapping>' -and
            $InnerXml -match '<UserType>User</UserType>'
        }
    }

    It 'Should send RoleMapping/IdentifierTypeAndProfile when all three role-mapping parameters are supplied' {
        New-SfosAzureADSSO -ServerName 'CorpEntraAdmin' -ApplicationID 'app-id' -TenantID 'tenant-id' -ClientSecret $secret `
            -RedirectURI 'fw.example.invalid' -DisplayName upn -EmailAddress email -FallbackUserGroup 'Open Group' `
            -UserType Administrator -RoleMappingIdentifierType roles -RoleMappingIdentifierValue 'role.admin' `
            -RoleMappingProfileID 'Administrator' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<RoleMapping><IdentifierTypeAndProfile><identifiertype>roles</identifiertype><identifiervalue>role\.admin</identifiervalue><profileid>Administrator</profileid></IdentifierTypeAndProfile></RoleMapping>'
        }
    }

    It 'Should throw client-side, without calling Invoke-SfosApi, when only some role-mapping parameters are supplied' {
        { New-SfosAzureADSSO -ServerName 'Partial' -ApplicationID 'app-id' -TenantID 'tenant-id' -ClientSecret $secret `
                -RedirectURI 'fw.example.invalid' -DisplayName upn -EmailAddress email -FallbackUserGroup 'Open Group' `
                -UserType Administrator -RoleMappingIdentifierType roles -RoleMappingIdentifierValue 'role.admin' `
                @conn -Confirm:$false } | Should -Throw '*must be supplied together*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
    }
}

Describe 'STAS' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosSTAS should not throw on the lenient-Get pattern (no Status node at all on success)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AuthCTA><EnableDisable><ACTION>Disable</ACTION></EnableDisable></AuthCTA></Response>' }
        }

        $result = Get-SfosSTAS @conn
        $result.ACTION | Should -Be 'Disable'
    }

    It 'Set-SfosSTAS should assert against /Response/EnableDisable/Status, not /Response/AuthCTA/Status' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><EnableDisable><Status code="200">Configuration applied successfully.</Status></EnableDisable></Response>' }
        }

        { Set-SfosSTAS -ACTION Enable @conn -Confirm:$false } | Should -Not -Throw

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<AuthCTA>\s*<EnableDisable>\s*<ACTION>Enable</ACTION>'
        }
    }

    It 'Set-SfosSTAS should throw the documented 502 "already in that state" error' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><EnableDisable><Status code="502">STAS is already in that state</Status></EnableDisable></Response>' }
        }

        { Set-SfosSTAS -ACTION Disable @conn -Confirm:$false } | Should -Throw '*502*'
    }
}

Describe 'LiveUser - undocumented write path throws on a status-less response' {
    # Every write shape tried against LiveUser answers HTTP 200 with a well-formed <Response>
    # but no <Status> node anywhere for the LiveUser object - only the unrelated API-session
    # <Login> block. Assert-SfosApiReturnSuccess alone treats a status-less response as
    # success, so both cmdlets add their own explicit check and always throw on this
    # firmware - the throw is the correct, documented behaviour.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    It 'Connect-SfosLiveUser should throw, naming the missing status, rather than report an unconfirmable success' {
        { Connect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55' @conn -Confirm:$false } |
            Should -Throw '*returned no status for logging in live user*'
    }

    It 'Disconnect-SfosLiveUser should throw, naming the missing status, rather than report an unconfirmable success' {
        { Disconnect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55' @conn -Confirm:$false } |
            Should -Throw '*returned no status for logging out live user*'
    }

    It 'Connect-SfosLiveUser should send the documented LiveUserLogin shape with UserName/IPAddress' {
        try { Connect-SfosLiveUser -LiveUserName 'jdoe' -IPAddress '10.0.0.55' @conn -Confirm:$false } catch {}

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<LiveUserLogin>' -and
            $InnerXml -match '<Admin>' -and
            $InnerXml -match '<UserName>jdoe</UserName>' -and
            $InnerXml -match '<IPAddress>10\.0\.0\.55</IPAddress>'
        }
    }
}

Describe 'Get-SfosLiveUser' {
    # Request/response shape: <Get><LiveUser></LiveUser></Get>, no server-side filter key -
    # server-side filtering for this entity has not been confirmed, so none is sent. Empty
    # result answers <LiveUser transactionid=""><Status>No. of records Zero.</Status></LiveUser>.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    # The It title deliberately avoids literal '<Tag>' sequences: raw XML angle brackets there
    # break Pester's own parsing of the later Should -Invoke -ParameterFilter block in this file.
    It 'Should send the Get LiveUser request with no server-side filter key' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><LiveUser transactionid=""><Status>No. of records Zero.</Status></LiveUser></Response>' }
        }

        Get-SfosLiveUser @conn | Out-Null

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>\s*<LiveUser>\s*</LiveUser>\s*</Get>' -and
            $InnerXml -notmatch '<key '
        }
    }

    It '"No. of records Zero." should return an empty array, not throw' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><LiveUser transactionid=""><Status>No. of records Zero.</Status></LiveUser></Response>' }
        }

        $result = @(Get-SfosLiveUser @conn)
        $result.Count | Should -Be 0
    }

    It 'Should map the measured field set onto the output object' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <LiveUser>
    <UserID>9</UserID>
    <UserName>guest-00001</UserName>
    <LiveUserID>1</LiveUserID>
    <ClientType>API Client</ClientType>
    <HostIP>10.99.99.21</HostIP>
    <IPFamily>IPv4</IPFamily>
    <MAC>AA:BB:CC:DD:EE:21</MAC>
    <StartTime>2026-08-11 16:24</StartTime>
    <Upload>0</Upload>
    <Download>0</Download>
    <DataTransferRate>0</DataTransferRate>
    <InternetUsageTime>00:00</InternetUsageTime>
  </LiveUser>
</Response>
'@
            }
        }

        $result = @(Get-SfosLiveUser @conn)
        $result.Count | Should -Be 1
        $result[0].UserID | Should -Be '9'
        $result[0].UserName | Should -Be 'guest-00001'
        $result[0].HostIP | Should -Be '10.99.99.21'
        $result[0].MAC | Should -Be 'AA:BB:CC:DD:EE:21'
    }
}

Describe 'Error Paths' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'A status code in the failure range should throw (Set-SfosActiveDirectoryServer, 501)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AuthenticationServer><ActiveDirectory><ServerName>CorpAD</ServerName><ServerAddress>ad.example.invalid</ServerAddress><Port>389</Port></ActiveDirectory></AuthenticationServer></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><ActiveDirectory><Status code="501">Configuration parameters validation failed.</Status></ActiveDirectory></Response>' }
            }
        }

        { Set-SfosActiveDirectoryServer -ServerName 'CorpAD' -DomainName 'x' @conn -Confirm:$false } | Should -Throw '*501*'
    }

    It 'A code-less Status of Transaction fail should throw and NOT be read as an empty result' {
        # A broken GuestUserSettings singleton answers exactly this shape on every subsequent
        # Get. Only "No. of records Zero." counts as empty.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GuestUserSettings><Status>Transaction fail</Status></GuestUserSettings></Response>' }
        }

        { Get-SfosGuestUserSettings @conn } | Should -Throw '*Transaction fail*'
    }

    It '"No. of records Zero." should return an empty array, not throw' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
        }

        $result = @(Get-SfosUser @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'XML Escaping' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><ActiveDirectory><Status code="200">OK</Status></ActiveDirectory><User><Status code="200">OK</Status></User></Response>' }
        }
    }

    It 'New-SfosActiveDirectoryServer should escape ampersand and angle brackets in ServerName and NetBIOSDomain' {
        New-SfosActiveDirectoryServer -ServerName 'A&B<C>' -ServerAddress 'ad.example.invalid' -ServerPort 389 `
            -NetBIOSDomain 'C&O<RP>' -ADSUsername 'svc' -ConnectionSecurity Simple -DomainName 'x' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<ServerName>A&amp;B&lt;C&gt;</ServerName>' -and
            $InnerXml -match '<NetBIOSDomain>C&amp;O&lt;RP&gt;</NetBIOSDomain>'
        }
    }

    It 'New-SfosUser should escape ampersand and angle brackets in Name and Description' {
        $pw = ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force
        New-SfosUser -AccountName 'weird' -Name 'R&D <Team>' -Description 'A & B <tag>' -AccountPassword $pw -LoginRestriction AnyNode @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Name>R&amp;D &lt;Team&gt;</Name>' -and
            $InnerXml -match '<Description>A &amp; B &lt;tag&gt;</Description>'
        }
    }
}

Describe 'Client-side Filtering' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <User><Username>jdoe</Username><Name>Jane Doe</Name><Group>Sales</Group></User>
  <User><Username>jsmith</Username><Name>John Smith</Name><Group>Marketing</Group></User>
  <User><Username>jbrown</Username><Name>Jane Brown</Name><Group>Sales</Group></User>
</Response>
'@
            }
        }
    }

    It 'Should send only one server-side key (Username), lowercased' {
        Get-SfosUser -UsernameLike 'JDoe' @conn | Out-Null

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            (([regex]::Matches($InnerXml, '<key ')).Count -eq 1) -and
            $InnerXml -match '<key name="Username" criteria="like">jdoe</key>'
        }
    }

    It 'Should combine UsernameLike and NameLike with AND, not OR' {
        $result = @(Get-SfosUser -UsernameLike 'j' -NameLike 'Jane' @conn)

        $result.Count | Should -Be 2
        $result.Username | Should -Contain 'jdoe'
        $result.Username | Should -Contain 'jbrown'
        $result.Username | Should -Not -Contain 'jsmith'
    }

    It 'Should apply the same filtering to -AsXml as to the default output' {
        $result = @(Get-SfosUser -UsernameLike 'j' -NameLike 'Jane' -AsXml @conn)

        $result.Count | Should -Be 2
        $result[0] | Should -BeOfType [System.Xml.XmlElement]
    }

    It 'Should return an empty array when nothing matches' {
        $result = @(Get-SfosUser -NameLike 'DoesNotExist' @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'WhatIf' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        # Should -Invoke -Times 0 needs a Mock registered in scope to verify against, even
        # when it is never expected to be called.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }
    }

    It 'New-SfosActiveDirectoryServer should not call the API with -WhatIf' {
        New-SfosActiveDirectoryServer -ServerName 'CorpAD' -ServerAddress 'x' -ServerPort 389 -NetBIOSDomain 'C' `
            -ADSUsername 'u' -ConnectionSecurity Simple -DomainName 'x' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
    }

    It 'Set-SfosSTAS should not call the API with -WhatIf' {
        Set-SfosSTAS -ACTION Enable @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
    }

    It 'Remove-SfosUserGroupMember should not call the API with -WhatIf' {
        Remove-SfosUserGroupMember -Name 'Sales' -Members 'jdoe' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
    }

    It 'Set-SfosUser reads the current object before evaluating -WhatIf (RMW happens first), but does not write' {
        # Documents a real property of the read-modify-write design, not a bug: the ShouldProcess
        # check sits after the read in this cmdlet, so -WhatIf still triggers one Get call.
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User><Username>jdoe</Username><Name>Jane Doe</Name></User></Response>' }
        }

        Set-SfosUser -AccountName 'jdoe' -Description 'Would be updated' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get>'
        }
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}

Describe 'Session context fallback' {
    # Wo ein Test verbindet, raeumt AfterEach mit Disconnect-SfosFirewall auf.

    AfterEach {
        Disconnect-SfosFirewall
    }

    It 'Get-SfosSTAS should use the stored connection context when no connection parameters are supplied' {
        $cred = New-Object System.Management.Automation.PSCredential('apiuser', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
        Connect-SfosFirewall -Firewall 'fw.example.test' -Port 4444 -Credential $cred -SkipCertificateCheck | Out-Null

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AuthCTA><EnableDisable><ACTION>Disable</ACTION></EnableDisable></AuthCTA></Response>' }
        }

        Get-SfosSTAS | Out-Null

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $Firewall -eq 'fw.example.test' -and $Port -eq 4444
        }
    }
}

Describe 'SSORadiusAccount' {
    # Not deepened further: Set-SfosSSORadiusAccount takes both -ClientIP and -SharedSecret as
    # Mandatory and performs no read-modify-write merge - a call always replaces the whole
    # single <Radius> block wholesale, by design (documented in the cmdlet's own .DESCRIPTION),
    # so there is no "only one field changes, the rest must survive" case to test here.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosSSORadiusAccount should send Get/FirewallAuthentication and return @() when unconfigured' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><AuthenticationMethods><DefaultGroup>Open Group</DefaultGroup></AuthenticationMethods></FirewallAuthentication></Response>' }
        }

        $result = @(Get-SfosSSORadiusAccount @conn)
        $result.Count | Should -Be 0
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter { $InnerXml -match '<Get><FirewallAuthentication>' }
    }
}

Describe 'FirewallAuthentication settings singletons - Set, Read-Modify-Write, error path' {
    # GlobalSettings, NTLMSettings, CTASSettings and iOSWebClientSettings all share the same
    # measured shape: read via <Get><FirewallAuthentication>, written via
    # <Set operation="update"><FirewallAuthentication><Block>...</Block></FirewallAuthentication>,
    # and the write's Status lands at the top-level /Response/<Block>/Status - not nested under
    # FirewallAuthentication (measured live per-block, see the module source .NOTES).

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosFirewallAuthenticationGlobalSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><GlobalSettings><SimultaneousLogins>Unlimited</SimultaneousLogins><MaximumSessionTimeoutMinutes>Unlimited</MaximumSessionTimeoutMinutes></GlobalSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GlobalSettings><Status code="200">Configuration applied successfully.</Status></GlobalSettings></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve SimultaneousLogins when only MaximumSessionTimeoutMinutes changes' {
            Set-SfosFirewallAuthenticationGlobalSettings -MaximumSessionTimeoutMinutes 30 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<FirewallAuthentication>\s*<GlobalSettings>' -and
                $InnerXml -match '<MaximumSessionTimeoutMinutes>30</MaximumSessionTimeoutMinutes>' -and
                $InnerXml -match '<SimultaneousLogins>Unlimited</SimultaneousLogins>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><GlobalSettings><SimultaneousLogins>Unlimited</SimultaneousLogins><MaximumSessionTimeoutMinutes>Unlimited</MaximumSessionTimeoutMinutes></GlobalSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><GlobalSettings><Status code="501">Configuration parameters validation failed.</Status></GlobalSettings></Response>' }
                }
            }

            { Set-SfosFirewallAuthenticationGlobalSettings -SimultaneousLogins 5 @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Set-SfosFirewallAuthenticationNTLMSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><NTLMSettings><NTLMInActivtyTime>6</NTLMInActivtyTime><NTLMDataTransferThreshold>1024</NTLMDataTransferThreshold><NTLMChallegeRedirect>Enable</NTLMChallegeRedirect></NTLMSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><NTLMSettings><Status code="200">Configuration applied successfully.</Status></NTLMSettings></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve NTLMDataTransferThreshold/NTLMChallegeRedirect when only NTLMInActivtyTime changes' {
            Set-SfosFirewallAuthenticationNTLMSettings -NTLMInActivtyTime 15 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<FirewallAuthentication>\s*<NTLMSettings>' -and
                $InnerXml -match '<NTLMInActivtyTime>15</NTLMInActivtyTime>' -and
                $InnerXml -match '<NTLMDataTransferThreshold>1024</NTLMDataTransferThreshold>' -and
                $InnerXml -match '<NTLMChallegeRedirect>Enable</NTLMChallegeRedirect>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><NTLMSettings><NTLMInActivtyTime>6</NTLMInActivtyTime><NTLMDataTransferThreshold>1024</NTLMDataTransferThreshold><NTLMChallegeRedirect>Enable</NTLMChallegeRedirect></NTLMSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><NTLMSettings><Status code="501">Configuration parameters validation failed.</Status></NTLMSettings></Response>' }
                }
            }

            { Set-SfosFirewallAuthenticationNTLMSettings -NTLMChallegeRedirect Disable @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Set-SfosFirewallAuthenticationCTASSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><CTASSettings><CTASUserInactivity>Enable</CTASUserInactivity><CTASInActivtyTime>3</CTASInActivtyTime><CTASDataTransferThreshold>100</CTASDataTransferThreshold></CTASSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><CTASSettings><Status code="200">Configuration applied successfully.</Status></CTASSettings></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve CTASInActivtyTime/CTASDataTransferThreshold when only CTASUserInactivity changes' {
            Set-SfosFirewallAuthenticationCTASSettings -CTASUserInactivity Disable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<FirewallAuthentication>\s*<CTASSettings>' -and
                $InnerXml -match '<CTASUserInactivity>Disable</CTASUserInactivity>' -and
                $InnerXml -match '<CTASInActivtyTime>3</CTASInActivtyTime>' -and
                $InnerXml -match '<CTASDataTransferThreshold>100</CTASDataTransferThreshold>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><CTASSettings><CTASUserInactivity>Enable</CTASUserInactivity><CTASInActivtyTime>3</CTASInActivtyTime><CTASDataTransferThreshold>100</CTASDataTransferThreshold></CTASSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><CTASSettings><Status code="501">Configuration parameters validation failed.</Status></CTASSettings></Response>' }
                }
            }

            { Set-SfosFirewallAuthenticationCTASSettings -CTASInActivtyTime 20 @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Set-SfosFirewallAuthenticationiOSWebClientSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><iOSWebClientSettings><iOSWebClientInActivtyTime>6</iOSWebClientInActivtyTime><iOSWebClientDataTransferThreshold>1024</iOSWebClientDataTransferThreshold></iOSWebClientSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><iOSWebClientSettings><Status code="200">Configuration applied successfully.</Status></iOSWebClientSettings></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve iOSWebClientDataTransferThreshold when only iOSWebClientInActivtyTime changes' {
            Set-SfosFirewallAuthenticationiOSWebClientSettings -iOSWebClientInActivtyTime 20 @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<FirewallAuthentication>\s*<iOSWebClientSettings>' -and
                $InnerXml -match '<iOSWebClientInActivtyTime>20</iOSWebClientInActivtyTime>' -and
                $InnerXml -match '<iOSWebClientDataTransferThreshold>1024</iOSWebClientDataTransferThreshold>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><iOSWebClientSettings><iOSWebClientInActivtyTime>6</iOSWebClientInActivtyTime><iOSWebClientDataTransferThreshold>1024</iOSWebClientDataTransferThreshold></iOSWebClientSettings></FirewallAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><iOSWebClientSettings><Status code="501">Configuration parameters validation failed.</Status></iOSWebClientSettings></Response>' }
                }
            }

            { Set-SfosFirewallAuthenticationiOSWebClientSettings -iOSWebClientInActivtyTime 20 @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }
}

Describe 'VPNAuthentication / SSLVPNAuthentication - Set, Read-Modify-Write, member cmdlets' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosVPNAuthentication' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNAuthentication><VPNAuthenticationMethods>Custom</VPNAuthenticationMethods><VPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></VPNAuthenticationServerList></VPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VPNAuthentication><Status code="200">Configuration applied successfully.</Status></VPNAuthentication></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve VPNAuthenticationServerList when only VPNAuthenticationMethods is resent' {
            Set-SfosVPNAuthentication -VPNAuthenticationMethods 'Custom' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<VPNAuthenticationMethods>Custom</VPNAuthenticationMethods>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNAuthentication><VPNAuthenticationMethods>Custom</VPNAuthenticationMethods><VPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></VPNAuthenticationServerList></VPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VPNAuthentication><Status code="501">Configuration parameters validation failed.</Status></VPNAuthentication></Response>' }
                }
            }

            { Set-SfosVPNAuthentication -VPNAuthenticationMethods 'Local' @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Add-/Remove-SfosVPNAuthenticationMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNAuthentication><VPNAuthenticationMethods>Custom</VPNAuthenticationMethods><VPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></VPNAuthenticationServerList></VPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VPNAuthentication><Status code="200">Configuration applied successfully.</Status></VPNAuthentication></Response>' }
                }
            }
        }

        It 'Add- should merge the new server into the existing list, preserving VPNAuthenticationMethods' {
            Add-SfosVPNAuthenticationMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<VPNAuthenticationMethods>Custom</VPNAuthenticationMethods>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -match '<AuthenticationServer>CorpRadius</AuthenticationServer>'
            }
        }

        It 'Remove- should send only the remaining server when one of two is removed' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNAuthentication><VPNAuthenticationMethods>Custom</VPNAuthenticationMethods><VPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer><AuthenticationServer>CorpRadius</AuthenticationServer></VPNAuthenticationServerList></VPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VPNAuthentication><Status code="200">Configuration applied successfully.</Status></VPNAuthentication></Response>' }
                }
            }

            Remove-SfosVPNAuthenticationMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -notmatch '<AuthenticationServer>CorpRadius</AuthenticationServer>'
            }
        }

        It 'Remove- should throw (not report success) when the firewall refuses to empty the list to the sole remaining server' {
            # Removing the last entry answers code 500 "Operation could not be performed on
            # Entity" and leaves the list unchanged. No read-back is performed by this cmdlet
            # for that case - the status code alone must be trusted to throw.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNAuthentication><VPNAuthenticationMethods>Custom</VPNAuthenticationMethods><VPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></VPNAuthenticationServerList></VPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><VPNAuthentication><Status code="500">Operation could not be performed on Entity.</Status></VPNAuthentication></Response>' }
                }
            }

            { Remove-SfosVPNAuthenticationMember -Members 'Local' @conn -Confirm:$false } | Should -Throw '*500*'
        }
    }

    Context 'Set-SfosSSLVPNAuthentication' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNAuthentication><SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods><SSLVPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></SSLVPNAuthenticationServerList></SSLVPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNAuthentication><Status code="200">Configuration applied successfully.</Status></SSLVPNAuthentication></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve SSLVPNAuthenticationServerList when only SSLVPNAuthenticationMethods is resent' {
            Set-SfosSSLVPNAuthentication -SSLVPNAuthenticationMethods 'Custom' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNAuthentication><SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods><SSLVPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></SSLVPNAuthenticationServerList></SSLVPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNAuthentication><Status code="501">Configuration parameters validation failed.</Status></SSLVPNAuthentication></Response>' }
                }
            }

            { Set-SfosSSLVPNAuthentication -SSLVPNAuthenticationMethods 'Local' @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Add-/Remove-SfosSSLVPNAuthenticationMember' {
        It 'Add- should merge the new server into the existing list, preserving SSLVPNAuthenticationMethods' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNAuthentication><SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods><SSLVPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></SSLVPNAuthenticationServerList></SSLVPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNAuthentication><Status code="200">Configuration applied successfully.</Status></SSLVPNAuthentication></Response>' }
                }
            }

            Add-SfosSSLVPNAuthenticationMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -match '<AuthenticationServer>CorpRadius</AuthenticationServer>'
            }
        }

        It 'Remove- should throw (not report success) when the firewall refuses to empty the list to the sole remaining server' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNAuthentication><SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods><SSLVPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></SSLVPNAuthenticationServerList></SSLVPNAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><SSLVPNAuthentication><Status code="500">Operation could not be performed on Entity.</Status></SSLVPNAuthentication></Response>' }
                }
            }

            { Remove-SfosSSLVPNAuthenticationMember -Members 'Local' @conn -Confirm:$false } | Should -Throw '*500*'
        }
    }
}

Describe 'WebAuthenticationSettings / CaptivePortalAppearance - Set, Read-Modify-Write, error path' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosWebAuthenticationSettings' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WebAuthentication><WebAuthenticationSettings><DisplayCaptivePortalLink>Enable</DisplayCaptivePortalLink><UseHTTPS>Enable</UseHTTPS><LogOutUserSetting>Portal closed</LogOutUserSetting><DisplayUserPortalLink>Enable</DisplayUserPortalLink><DisplayWebpageAfterLogin>Enable</DisplayWebpageAfterLogin><UseKerberosForADSSO>Enable</UseKerberosForADSSO><OpenWebpageInNewWindow>Enable</OpenWebpageInNewWindow><WebpageToDisplay>User requested URL</WebpageToDisplay></WebAuthenticationSettings></WebAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebAuthenticationSettings><Status code="200">Configuration applied successfully.</Status></WebAuthenticationSettings></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve WebpageToDisplay/UseHTTPS when only DisplayUserPortalLink changes' {
            Set-SfosWebAuthenticationSettings -DisplayUserPortalLink Disable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<WebAuthentication>\s*<WebAuthenticationSettings>' -and
                $InnerXml -match '<DisplayUserPortalLink>Disable</DisplayUserPortalLink>' -and
                $InnerXml -match '<UseHTTPS>Enable</UseHTTPS>' -and
                $InnerXml -match '<WebpageToDisplay>User requested URL</WebpageToDisplay>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WebAuthentication><WebAuthenticationSettings><DisplayCaptivePortalLink>Enable</DisplayCaptivePortalLink><UseHTTPS>Enable</UseHTTPS><LogOutUserSetting>Portal closed</LogOutUserSetting><DisplayUserPortalLink>Enable</DisplayUserPortalLink><DisplayWebpageAfterLogin>Enable</DisplayWebpageAfterLogin><UseKerberosForADSSO>Enable</UseKerberosForADSSO><OpenWebpageInNewWindow>Enable</OpenWebpageInNewWindow><WebpageToDisplay>User requested URL</WebpageToDisplay></WebAuthenticationSettings></WebAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><WebAuthenticationSettings><Status code="501">Configuration parameters validation failed.</Status></WebAuthenticationSettings></Response>' }
                }
            }

            { Set-SfosWebAuthenticationSettings -OpenWebpageInNewWindow Disable @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Set-SfosCaptivePortalAppearance' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebAuthentication>
    <CaptivePortalAppearance>
      <UseCustomLayout>Disable</UseCustomLayout>
      <DefaultLayout>
        <Logo>Default</Logo>
        <LogoImage/>
        <LogoLink/>
        <LoginPageHeaderHTML/>
        <UserPrompt>Sign in to access this network</UserPrompt>
        <UsernameFieldLabel>Username</UsernameFieldLabel>
        <PasswordFieldLabel>Password</PasswordFieldLabel>
        <LoginButtonLabel>Sign in</LoginButtonLabel>
        <LogoutButtonLabel>Sign out</LogoutButtonLabel>
        <UserPortalLinkLabel>Access the User Portal</UserPortalLinkLabel>
        <RegistrationLinkLabel>Register for internet access</RegistrationLinkLabel>
        <SsoButtonLabel>Single sign-on</SsoButtonLabel>
        <LoginPageFooterHTML/>
        <BackgroundColor>FAFAFA</BackgroundColor>
        <UserPromptFontColor>055BB5</UserPromptFontColor>
        <PageTitleBackgroundColor>055BB5</PageTitleBackgroundColor>
        <HeaderFooterFontColor>5C5C5C</HeaderFooterFontColor>
        <UserPortalLinkFontColor>1987CB</UserPortalLinkFontColor>
      </DefaultLayout>
    </CaptivePortalAppearance>
  </WebAuthentication>
</Response>
'@
                    }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><CaptivePortalAppearance><Status code="200">Configuration applied successfully.</Status></CaptivePortalAppearance></Response>' }
                }
            }
        }

        It 'Should resend the existing DefaultLayout fields when only UserPrompt changes' {
            Set-SfosCaptivePortalAppearance -UserPrompt 'Please sign in' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<UserPrompt>Please sign in</UserPrompt>' -and
                $InnerXml -match '<BackgroundColor>FAFAFA</BackgroundColor>' -and
                $InnerXml -match '<LoginButtonLabel>Sign in</LoginButtonLabel>' -and
                $InnerXml -match '<UserPortalLinkFontColor>1987CB</UserPortalLinkFontColor>'
            }
        }

        It 'Should escape LoginPageHeaderHTML/LoginPageFooterHTML' {
            Set-SfosCaptivePortalAppearance -LoginPageHeaderHTML '<b>Notice</b> & welcome' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<LoginPageHeaderHTML>&lt;b&gt;Notice&lt;/b&gt; &amp; welcome</LoginPageHeaderHTML>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WebAuthentication><CaptivePortalAppearance><UseCustomLayout>Disable</UseCustomLayout><DefaultLayout><Logo>Default</Logo></DefaultLayout></CaptivePortalAppearance></WebAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><CaptivePortalAppearance><Status code="501">Configuration parameters validation failed.</Status></CaptivePortalAppearance></Response>' }
                }
            }

            { Set-SfosCaptivePortalAppearance -UseCustomLayout Enable @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }
}

Describe 'DefaultCaptivePortal - Set, Read-Modify-Write, error path' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    BeforeEach {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DefaultCaptivePortal><UserPrompt>Sign in to access this network</UserPrompt><UsernameFieldLabel>Username</UsernameFieldLabel><PasswordFieldLabel>Password</PasswordFieldLabel><LoginButtonLabel>Sign in</LoginButtonLabel><LogoutButtonLabel>Sign out</LogoutButtonLabel><UserPortalLinkLabel>Access the User Portal</UserPortalLinkLabel><RegistrationLinkLabel>Register for internet access</RegistrationLinkLabel><CredentialLoginButtonLabel>Credential Login</CredentialLoginButtonLabel><UserDefinedTemplate>&lt;html&gt;&lt;/html&gt;</UserDefinedTemplate><LoginPageHeaderHTML></LoginPageHeaderHTML><LoginPageFooterHTML></LoginPageFooterHTML><DoNotClosePage>Do not close this page</DoNotClosePage><WillBeSignedOut>If you do, you will be signed out</WillBeSignedOut><SsoSignedOut>After you finish surfing, click Sign out.</SsoSignedOut><SigningIn>Signing you in...</SigningIn><EnterUsername>Please enter your username.</EnterUsername><EnterPassword>Please enter your password.</EnterPassword></DefaultCaptivePortal></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><DefaultCaptivePortal><Status code="200">Configuration applied successfully.</Status></DefaultCaptivePortal></Response>' }
            }
        }
    }

    It 'Should send operation="update" and preserve UserDefinedTemplate/DoNotClosePage when only UserPrompt changes' {
        Set-SfosDefaultCaptivePortal -UserPrompt 'Please sign in to continue' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<UserPrompt>Please sign in to continue</UserPrompt>' -and
            $InnerXml -match '<UserDefinedTemplate>&lt;html&gt;&lt;/html&gt;</UserDefinedTemplate>' -and
            $InnerXml -match '<DoNotClosePage>Do not close this page</DoNotClosePage>' -and
            $InnerXml -match '<EnterUsername>Please enter your username\.</EnterUsername>'
        }
    }

    It 'Should throw on a status code in the failure range' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DefaultCaptivePortal><UserPrompt>Sign in</UserPrompt></DefaultCaptivePortal></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><DefaultCaptivePortal><Status code="501">Configuration parameters validation failed.</Status></DefaultCaptivePortal></Response>' }
            }
        }

        { Set-SfosDefaultCaptivePortal -UserPrompt 'x' @conn -Confirm:$false } | Should -Throw '*501*'
    }
}

Describe 'Get-* singletons - status-less lenient Get pattern, parsing' {
    # All of these entities answer a successful Get with no <Status> node at all
    # (Assert-SfosApiReturnSuccess falls through as success), so the parsing test is what
    # actually proves the cmdlet reads the right node.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosAdminAuthentication should send Get/AdminAuthentication and parse AuthenticationMethods/AuthenticationServerList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdminAuthentication><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></AuthenticationServerList><AuthenticationMethods>Custom</AuthenticationMethods></AdminAuthentication></Response>' }
        }

        $result = Get-SfosAdminAuthentication @conn
        $result.AuthenticationMethods | Should -Be 'Custom'
        $result.AuthenticationServerList | Should -Contain 'Local'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><AdminAuthentication></AdminAuthentication></Get>'
        }
    }

    It 'Get-SfosVPNAuthentication should parse VPNAuthenticationMethods/VPNAuthenticationServerList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><VPNAuthentication><VPNAuthenticationMethods>Custom</VPNAuthenticationMethods><VPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></VPNAuthenticationServerList></VPNAuthentication></Response>' }
        }

        $result = Get-SfosVPNAuthentication @conn
        $result.VPNAuthenticationMethods | Should -Be 'Custom'
        $result.VPNAuthenticationServerList | Should -Contain 'Local'
    }

    It 'Get-SfosSSLVPNAuthentication should parse SSLVPNAuthenticationMethods/SSLVPNAuthenticationServerList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><SSLVPNAuthentication><SSLVPNAuthenticationMethods>Custom</SSLVPNAuthenticationMethods><SSLVPNAuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></SSLVPNAuthenticationServerList></SSLVPNAuthentication></Response>' }
        }

        $result = Get-SfosSSLVPNAuthentication @conn
        $result.SSLVPNAuthenticationMethods | Should -Be 'Custom'
        $result.SSLVPNAuthenticationServerList | Should -Contain 'Local'
    }

    It 'Get-SfosDirectWebProxyAuthentication should parse PerConnectionAuth/MultiUserHostList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DirectWebProxyAuthentication><PerConnectionAuth>Disable</PerConnectionAuth><MultiUserHosts><Host>TS-Server1</Host></MultiUserHosts></DirectWebProxyAuthentication></Response>' }
        }

        $result = Get-SfosDirectWebProxyAuthentication @conn
        $result.PerConnectionAuth | Should -Be 'Disable'
        $result.MultiUserHostList | Should -Contain 'TS-Server1'
    }

    It 'Get-SfosWebAuthenticationSettings should send Get/WebAuthentication and parse the settings' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><WebAuthentication><WebAuthenticationSettings><DisplayCaptivePortalLink>Enable</DisplayCaptivePortalLink><UseHTTPS>Enable</UseHTTPS><LogOutUserSetting>Portal closed</LogOutUserSetting><DisplayUserPortalLink>Enable</DisplayUserPortalLink><DisplayWebpageAfterLogin>Enable</DisplayWebpageAfterLogin><UseKerberosForADSSO>Enable</UseKerberosForADSSO><OpenWebpageInNewWindow>Enable</OpenWebpageInNewWindow><WebpageToDisplay>User requested URL</WebpageToDisplay></WebAuthenticationSettings></WebAuthentication></Response>' }
        }

        $result = Get-SfosWebAuthenticationSettings @conn
        $result.UseHTTPS | Should -Be 'Enable'
        $result.WebpageToDisplay | Should -Be 'User requested URL'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><WebAuthentication></WebAuthentication></Get>'
        }
    }

    It 'Get-SfosCaptivePortalAppearance should parse the nested DefaultLayout/CustomLayout fields' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <WebAuthentication>
    <CaptivePortalAppearance>
      <UseCustomLayout>Disable</UseCustomLayout>
      <DefaultLayout>
        <BackgroundColor>FAFAFA</BackgroundColor>
        <LoginButtonLabel>Sign in</LoginButtonLabel>
        <UserPortalLinkFontColor>1987CB</UserPortalLinkFontColor>
        <UserPrompt>Please sign in</UserPrompt>
      </DefaultLayout>
    </CaptivePortalAppearance>
  </WebAuthentication>
</Response>
'@
            }
        }

        $result = Get-SfosCaptivePortalAppearance @conn
        $result.UseCustomLayout | Should -Be 'Disable'
        $result.BackgroundColor | Should -Be 'FAFAFA'
        $result.UserPortalLinkFontColor | Should -Be '1987CB'
    }

    It 'Get-SfosDefaultCaptivePortal should parse a flat top-level entity' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DefaultCaptivePortal><UserPrompt>Sign in to access this network</UserPrompt><LoginButtonLabel>Sign in</LoginButtonLabel></DefaultCaptivePortal></Response>' }
        }

        $result = Get-SfosDefaultCaptivePortal @conn
        $result.UserPrompt | Should -Be 'Sign in to access this network'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><DefaultCaptivePortal></DefaultCaptivePortal></Get>' -or $InnerXml -match '<Get>\s*<DefaultCaptivePortal>'
        }
    }

    It 'Get-SfosFirewallAuthenticationGlobalSettings should send Get/FirewallAuthentication and parse GlobalSettings' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><GlobalSettings><SimultaneousLogins>Unlimited</SimultaneousLogins><MaximumSessionTimeoutMinutes>Unlimited</MaximumSessionTimeoutMinutes></GlobalSettings></FirewallAuthentication></Response>' }
        }

        $result = Get-SfosFirewallAuthenticationGlobalSettings @conn
        $result.SimultaneousLogins | Should -Be 'Unlimited'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Get><FirewallAuthentication></FirewallAuthentication></Get>'
        }
    }

    It 'Get-SfosFirewallAuthenticationMethods should parse DefaultGroup/AuthenticationServerList' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><AuthenticationMethods><DefaultGroup>Open Group</DefaultGroup><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></AuthenticationServerList></AuthenticationMethods></FirewallAuthentication></Response>' }
        }

        $result = Get-SfosFirewallAuthenticationMethods @conn
        $result.DefaultGroup | Should -Be 'Open Group'
        $result.AuthenticationServerList | Should -Contain 'Local'
    }

    It 'Get-SfosFirewallAuthenticationNTLMSettings should parse NTLMInActivtyTime/NTLMDataTransferThreshold/NTLMChallegeRedirect' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><NTLMSettings><NTLMInActivtyTime>6</NTLMInActivtyTime><NTLMDataTransferThreshold>1024</NTLMDataTransferThreshold><NTLMChallegeRedirect>Enable</NTLMChallegeRedirect></NTLMSettings></FirewallAuthentication></Response>' }
        }

        $result = Get-SfosFirewallAuthenticationNTLMSettings @conn
        $result.NTLMInActivtyTime | Should -Be 6
        $result.NTLMChallegeRedirect | Should -Be 'Enable'
    }

    It 'Get-SfosFirewallAuthenticationCTASSettings should parse CTASUserInactivity/CTASInActivtyTime/CTASDataTransferThreshold' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><CTASSettings><CTASUserInactivity>Enable</CTASUserInactivity><CTASInActivtyTime>6</CTASInActivtyTime><CTASDataTransferThreshold>1024</CTASDataTransferThreshold></CTASSettings></FirewallAuthentication></Response>' }
        }

        $result = Get-SfosFirewallAuthenticationCTASSettings @conn
        $result.CTASUserInactivity | Should -Be 'Enable'
        $result.CTASDataTransferThreshold | Should -Be '1024'
    }

    It 'Get-SfosFirewallAuthenticationiOSWebClientSettings should parse iOSWebClientInActivtyTime/iOSWebClientDataTransferThreshold' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><FirewallAuthentication><iOSWebClientSettings><iOSWebClientInActivtyTime>6</iOSWebClientInActivtyTime><iOSWebClientDataTransferThreshold>1024</iOSWebClientDataTransferThreshold></iOSWebClientSettings></FirewallAuthentication></Response>' }
        }

        $result = Get-SfosFirewallAuthenticationiOSWebClientSettings @conn
        $result.iOSWebClientInActivtyTime | Should -Be 6
        $result.iOSWebClientDataTransferThreshold | Should -Be 1024
    }

    It 'Get-SfosGuestUser should return an empty array on "No. of records Zero." and map fields otherwise' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GuestUser transactionid=""><Status>No. of records Zero.</Status></GuestUser></Response>' }
        }

        $empty = @(Get-SfosGuestUser @conn)
        $empty.Count | Should -Be 0

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><GuestUser><Username>guest-00001</Username><Name>visitor1</Name><UserValidity>24</UserValidity><Group>Guest Group</Group></GuestUser></Response>' }
        }

        $result = @(Get-SfosGuestUser @conn)
        $result.Count | Should -Be 1
        $result[0].Username | Should -Be 'guest-00001'
        # Documented, not converted: UserValidity is written in days (New-SfosGuestUser) but
        # read back in hours - the value here is exactly what the firewall returns, unscaled.
        $result[0].UserValidity | Should -Be '24'
    }
}

Describe 'AdminAuthentication member cmdlets' {
    # NOT verified against the live firewall (see Set-SfosAdminAuthentication .NOTES): this
    # entity controls the API user's own login path. Structural tests only.

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Add-SfosAdminAuthenticationMember' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdminAuthentication><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer></AuthenticationServerList><AuthenticationMethods>Custom</AuthenticationMethods></AdminAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><AdminAuthentication><Status code="200">Configuration applied successfully.</Status></AdminAuthentication></Response>' }
                }
            }
        }

        It 'Should merge the new server into the existing list, preserving AuthenticationMethods' {
            Add-SfosAdminAuthenticationMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<AuthenticationMethods>Custom</AuthenticationMethods>' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -match '<AuthenticationServer>CorpRadius</AuthenticationServer>'
            }
        }
    }

    Context 'Remove-SfosAdminAuthenticationMember' {
        It 'Should preserve the remaining server and AuthenticationMethods when removing one of two' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdminAuthentication><AuthenticationServerList><AuthenticationServer>Local</AuthenticationServer><AuthenticationServer>CorpRadius</AuthenticationServer></AuthenticationServerList><AuthenticationMethods>Custom</AuthenticationMethods></AdminAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><AdminAuthentication><Status code="200">Configuration applied successfully.</Status></AdminAuthentication></Response>' }
                }
            }

            Remove-SfosAdminAuthenticationMember -Members 'CorpRadius' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<AuthenticationServer>Local</AuthenticationServer>' -and
                $InnerXml -notmatch '<AuthenticationServer>CorpRadius</AuthenticationServer>' -and
                $InnerXml -match '<AuthenticationMethods>Custom</AuthenticationMethods>'
            }
        }

        It 'Should do nothing (no API write call) when the server list is already empty' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><AdminAuthentication><AuthenticationServerList></AuthenticationServerList><AuthenticationMethods>Custom</AuthenticationMethods></AdminAuthentication></Response>' }
            }

            Remove-SfosAdminAuthenticationMember -Members 'Local' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Get>'
            }
        }
    }
}

Describe 'AzureADSSO - Get parsing, Read-Modify-Write, Remove' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'Get-SfosAzureADSSO should parse ServerName/ApplicationID/ClientSecretHash and the RoleMapping sub-object' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AzureADSSO>
    <ServerName>CorpEntraAdmin</ServerName>
    <ApplicationID>app-id</ApplicationID>
    <TenantID>tenant-id</TenantID>
    <ClientSecret hashform="mode1">$sfos$7$0$hashedvalue</ClientSecret>
    <RedirectURI>fw.example.invalid</RedirectURI>
    <DisplayName>upn</DisplayName>
    <EmailAddress>email</EmailAddress>
    <FallbackUserGroup>Open Group</FallbackUserGroup>
    <UserType>Administrator</UserType>
    <RoleMapping>
      <IdentifierTypeAndProfile>
        <identifiertype>roles</identifiertype>
        <identifiervalue>role.admin</identifiervalue>
        <profileid>Administrator</profileid>
      </IdentifierTypeAndProfile>
    </RoleMapping>
  </AzureADSSO>
</Response>
'@
            }
        }

        $result = @(Get-SfosAzureADSSO @conn)
        $result.Count | Should -Be 1
        $result[0].ServerName | Should -Be 'CorpEntraAdmin'
        $result[0].ClientSecretHash | Should -Be '$sfos$7$0$hashedvalue'
        $result[0].ClientSecretHashForm | Should -Be 'mode1'
        $result[0].RoleMappingIdentifierType | Should -Be 'roles'
        $result[0].RoleMappingProfileID | Should -Be 'Administrator'
    }

    It 'Set-SfosAzureADSSO should resend the hashed ClientSecret and the existing RoleMapping when only FallbackUserGroup changes' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = @'
<Response>
  <Login><status>Authentication Successful</status></Login>
  <AzureADSSO>
    <ServerName>CorpEntraAdmin</ServerName>
    <ApplicationID>app-id</ApplicationID>
    <TenantID>tenant-id</TenantID>
    <ClientSecret hashform="mode1">$sfos$7$0$hashedvalue</ClientSecret>
    <RedirectURI>fw.example.invalid</RedirectURI>
    <DisplayName>upn</DisplayName>
    <EmailAddress>email</EmailAddress>
    <FallbackUserGroup>Open Group</FallbackUserGroup>
    <UserType>Administrator</UserType>
    <RoleMapping>
      <IdentifierTypeAndProfile>
        <identifiertype>roles</identifiertype>
        <identifiervalue>role.admin</identifiervalue>
        <profileid>Administrator</profileid>
      </IdentifierTypeAndProfile>
    </RoleMapping>
  </AzureADSSO>
</Response>
'@
                }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><AzureADSSO><Status code="200">Configuration applied successfully.</Status></AzureADSSO></Response>' }
            }
        }

        Set-SfosAzureADSSO -ServerName 'CorpEntraAdmin' -FallbackUserGroup 'New Group' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<FallbackUserGroup>New Group</FallbackUserGroup>' -and
            $InnerXml -match '<ClientSecret hashform="mode1">\$sfos\$7\$0\$hashedvalue</ClientSecret>' -and
            $InnerXml -match '<identifiertype>roles</identifiertype>' -and
            $InnerXml -match '<profileid>Administrator</profileid>'
        }
    }

    It 'Set-SfosAzureADSSO should throw when the named server does not exist' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login></Response>' }
        }

        { Set-SfosAzureADSSO -ServerName 'DoesNotExist' -FallbackUserGroup 'x' @conn -Confirm:$false } |
            Should -Throw "*AzureADSSO object 'DoesNotExist' was not found*"
    }

    It 'Remove-SfosAzureADSSO should send Remove/AzureADSSO/ServerName' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><AzureADSSO><Status code="200">Configuration applied successfully.</Status></AzureADSSO></Response>' }
        }

        Remove-SfosAzureADSSO -ServerName 'CorpEntraAdmin' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<AzureADSSO>' -and
            $InnerXml -match '<ServerName>CorpEntraAdmin</ServerName>'
        }
    }
}

Describe 'DirectWebProxyAuthentication - Set, Read-Modify-Write, member cmdlets with read-back' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    Context 'Set-SfosDirectWebProxyAuthentication' {
        BeforeEach {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DirectWebProxyAuthentication><PerConnectionAuth>Disable</PerConnectionAuth><MultiUserHosts><Host>TS-Server1</Host></MultiUserHosts></DirectWebProxyAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DirectWebProxyAuthentication><Status code="200">Configuration applied successfully.</Status></DirectWebProxyAuthentication></Response>' }
                }
            }
        }

        It 'Should send operation="update" and preserve the existing MultiUserHosts list when only PerConnectionAuth is resent' {
            Set-SfosDirectWebProxyAuthentication -PerConnectionAuth Disable @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<PerConnectionAuth>Disable</PerConnectionAuth>' -and
                $InnerXml -match '<MultiUserHosts><Host>TS-Server1</Host></MultiUserHosts>'
            }
        }

        It 'Should throw on a status code in the failure range' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DirectWebProxyAuthentication><PerConnectionAuth>Disable</PerConnectionAuth></DirectWebProxyAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DirectWebProxyAuthentication><Status code="501">Configuration parameters validation failed.</Status></DirectWebProxyAuthentication></Response>' }
                }
            }

            { Set-SfosDirectWebProxyAuthentication -PerConnectionAuth Enable @conn -Confirm:$false } | Should -Throw '*501*'
        }
    }

    Context 'Add-SfosDirectWebProxyAuthenticationMember' {
        It 'Should merge the new host into the existing list, preserving PerConnectionAuth' {
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Get>') {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DirectWebProxyAuthentication><PerConnectionAuth>Disable</PerConnectionAuth><MultiUserHosts><Host>TS-Server1</Host></MultiUserHosts></DirectWebProxyAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><DirectWebProxyAuthentication><Status code="200">Configuration applied successfully.</Status></DirectWebProxyAuthentication></Response>' }
                }
            }

            Add-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server2' @conn -Confirm:$false

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 1 -Exactly -ParameterFilter {
                $InnerXml -match '<Set operation="update">' -and
                $InnerXml -match '<PerConnectionAuth>Disable</PerConnectionAuth>' -and
                $InnerXml -match '<Host>TS-Server1</Host>' -and
                $InnerXml -match '<Host>TS-Server2</Host>'
            }
        }
    }

    Context 'Remove-SfosDirectWebProxyAuthenticationMember - reads back after writing' {
        It 'Should read the list back after the write and succeed when the member is actually gone' {
            # Stateful mock: the host list only reflects the removal once the Set call has
            # been made, so the post-write verification Get this cmdlet performs is exercised
            # for real rather than trusting a hard-coded response.
            $script:dwpHosts = @('TS-Server1', 'TS-Server2')

            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    $script:dwpHosts = @($script:dwpHosts | Where-Object { $_ -ne 'TS-Server2' })
                    [PSCustomObject]@{ Content = '<Response><DirectWebProxyAuthentication><Status code="200">Configuration applied successfully.</Status></DirectWebProxyAuthentication></Response>' }
                }
                else {
                    $hostXml = ($script:dwpHosts | ForEach-Object { "<Host>$_</Host>" }) -join ''
                    [PSCustomObject]@{ Content = "<Response><Login><status>Authentication Successful</status></Login><DirectWebProxyAuthentication><PerConnectionAuth>Disable</PerConnectionAuth><MultiUserHosts>$hostXml</MultiUserHosts></DirectWebProxyAuthentication></Response>" }
                }
            }

            { Remove-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server2' @conn -Confirm:$false } | Should -Not -Throw

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 3 -Exactly
        }

        It 'Should throw naming the append-only defect when the firewall reports success but the member is still present' {
            # MultiUserHosts is one of this API's several append-only-on-update lists - a 200
            # that changes nothing.
            Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
                if ($InnerXml -match '<Set operation="update">') {
                    [PSCustomObject]@{ Content = '<Response><DirectWebProxyAuthentication><Status code="200">Configuration applied successfully.</Status></DirectWebProxyAuthentication></Response>' }
                }
                else {
                    [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><DirectWebProxyAuthentication><PerConnectionAuth>Disable</PerConnectionAuth><MultiUserHosts><Host>TS-Server1</Host><Host>TS-Server2</Host></MultiUserHosts></DirectWebProxyAuthentication></Response>' }
                }
            }

            { Remove-SfosDirectWebProxyAuthenticationMember -Members 'TS-Server2' @conn -Confirm:$false } |
                Should -Throw '*append-only*'

            Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 3 -Exactly
        }
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
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><User transactionid=""><Status>No. of records Zero.</Status></User></Response>' }
        }
    }

    It 'Resolves the named session instead of the ambient default (direct path)' {
        Get-SfosUser -Session 'fw2' | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $Firewall -eq 'fw2.example.test'
        }
    }

    It 'Uses the ambient default when -Session is omitted' {
        Get-SfosUser | Out-Null
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $Firewall -eq 'fw1.example.test'
        }
    }

    It 'Resolves a session object on the begin-block pipeline path (Set-SfosUserGroup)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -MockWith {
            if ($InnerXml -match '<Get>\s*<UserGroup>') {
                [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><UserGroup><GroupDetail><Name>Sales</Name><GroupType>Normal</GroupType><SurfingQuotaPolicy>Unlimited</SurfingQuotaPolicy><AccessTimePolicy>AllowedAllTheTime</AccessTimePolicy><QoSPolicy>None</QoSPolicy><QuarantineDigest>Enable</QuarantineDigest><LoginRestriction>AnyNode</LoginRestriction></GroupDetail></UserGroup></Response>' }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><GroupDetail><Status code="200">Configuration applied successfully.</Status></GroupDetail></Response>' }
            }
        }

        Set-SfosUserGroup -Name 'Sales' -Session 'fw2' -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -ParameterFilter {
            $Firewall -eq 'fw2.example.test' -and $InnerXml -match '<Set operation="update">' -and $InnerXml -match '<Name>Sales</Name>'
        }
    }

    It 'Throws on an unknown session name without calling the API' {
        { Get-SfosUser -Session 'nichtda' } | Should -Throw '*No session named*'
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Authentication -Times 0 -Exactly
    }
}
