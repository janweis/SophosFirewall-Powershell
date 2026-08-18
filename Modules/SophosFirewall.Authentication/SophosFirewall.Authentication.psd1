@{
    RootModule           = 'SophosFirewall.Authentication.psm1'
    ModuleVersion        = '1.3.5'
    GUID                 = '3c25abfe-0eba-4bc1-831a-d35445a2fd9f'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing authentication servers, users, groups, guest users, one-time passwords, captive portal and SSO on Sophos XGS / SFOS 22.0 firewalls via API.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.5'
        }
    )

    FunctionsToExport    = @(
        'Add-SfosAdminAuthenticationMember',
        'Add-SfosDirectWebProxyAuthenticationMember',
        'Add-SfosFirewallAuthenticationMethodsMember',
        'Add-SfosOTPSettingsMember',
        'Add-SfosSSLVPNAuthenticationMember',
        'Add-SfosUserGroupMember',
        'Add-SfosVPNAuthenticationMember',
        'Connect-SfosLiveUser',
        'Disconnect-SfosLiveUser',
        'Get-SfosActiveDirectoryServer',
        'Get-SfosAdminAuthentication',
        'Get-SfosAzureADSSO',
        'Get-SfosCaptivePortalAppearance',
        'Get-SfosClientlessUser',
        'Get-SfosDefaultCaptivePortal',
        'Get-SfosDirectWebProxyAuthentication',
        'Get-SfosEDirectoryServer',
        'Get-SfosFirewallAuthenticationCTASSettings',
        'Get-SfosFirewallAuthenticationGlobalSettings',
        'Get-SfosFirewallAuthenticationiOSWebClientSettings',
        'Get-SfosFirewallAuthenticationMethods',
        'Get-SfosFirewallAuthenticationNTLMSettings',
        'Get-SfosGuestUser',
        'Get-SfosGuestUserSettings',
        'Get-SfosLDAPServer',
        'Get-SfosLiveUser',
        'Get-SfosOTPSettings',
        'Get-SfosOTPTokens',
        'Get-SfosRADIUSServer',
        'Get-SfosSMSGateway',
        'Get-SfosSSLVPNAuthentication',
        'Get-SfosSSORadiusAccount',
        'Get-SfosSTAS',
        'Get-SfosTACACSServer',
        'Get-SfosUser',
        'Get-SfosUserGroup',
        'Get-SfosVPNAuthentication',
        'Get-SfosWebAuthenticationSettings',
        'New-SfosActiveDirectoryServer',
        'New-SfosAzureADSSO',
        'New-SfosClientlessUser',
        'New-SfosClientlessUserRange',
        'New-SfosEDirectoryServer',
        'New-SfosGuestUser',
        'New-SfosLDAPServer',
        'New-SfosOTPTokens',
        'New-SfosRADIUSServer',
        'New-SfosSMSGateway',
        'New-SfosTACACSServer',
        'New-SfosUser',
        'New-SfosUserGroup',
        'Remove-SfosActiveDirectoryServer',
        'Remove-SfosAdminAuthenticationMember',
        'Remove-SfosAzureADSSO',
        'Remove-SfosClientlessUser',
        'Remove-SfosDirectWebProxyAuthenticationMember',
        'Remove-SfosEDirectoryServer',
        'Remove-SfosFirewallAuthenticationMethodsMember',
        'Remove-SfosGuestUser',
        'Remove-SfosLDAPServer',
        'Remove-SfosOTPSettingsMember',
        'Remove-SfosOTPTokens',
        'Remove-SfosRADIUSServer',
        'Remove-SfosSMSGateway',
        'Remove-SfosSSLVPNAuthenticationMember',
        'Remove-SfosTACACSServer',
        'Remove-SfosUser',
        'Remove-SfosUserGroup',
        'Remove-SfosUserGroupMember',
        'Remove-SfosVPNAuthenticationMember',
        'Set-SfosActiveDirectoryServer',
        'Set-SfosAdminAuthentication',
        'Set-SfosAzureADSSO',
        'Set-SfosCaptivePortalAppearance',
        'Set-SfosClientlessUser',
        'Set-SfosDefaultCaptivePortal',
        'Set-SfosDirectWebProxyAuthentication',
        'Set-SfosEDirectoryServer',
        'Set-SfosFirewallAuthenticationCTASSettings',
        'Set-SfosFirewallAuthenticationGlobalSettings',
        'Set-SfosFirewallAuthenticationiOSWebClientSettings',
        'Set-SfosFirewallAuthenticationMethods',
        'Set-SfosFirewallAuthenticationNTLMSettings',
        'Set-SfosGuestUserSettings',
        'Set-SfosLDAPServer',
        'Set-SfosOTPSettings',
        'Set-SfosOTPTokens',
        'Set-SfosRADIUSServer',
        'Set-SfosSMSGateway',
        'Set-SfosSSLVPNAuthentication',
        'Set-SfosSSORadiusAccount',
        'Set-SfosSTAS',
        'Set-SfosTACACSServer',
        'Set-SfosUser',
        'Set-SfosUserGroup',
        'Set-SfosVPNAuthentication',
        'Set-SfosWebAuthenticationSettings'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Authentication', 'LDAP', 'RADIUS', 'OTP', 'SSO')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Authentication/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Authentication'
            ReleaseNotes = 'Documentation revised for production use: rewritten cmdlet help, module description and README. Set-SfosGuestUserSettings now asks for confirmation before it writes.'
        }
    }
}
