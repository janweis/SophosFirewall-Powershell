@{
    RootModule           = 'SophosFirewall.VPN.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = '2d774502-71be-403a-987f-12fad7d243b9'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing VPN on Sophos XGS / SFOS 22.0 firewalls via API: IPsec connections, SSL VPN, L2TP, PPTP, VPN profiles and failover groups.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.0'
        }
    )

    FunctionsToExport    = @(
        'Add-SfosL2TPConfigurationMember',
        'Add-SfosPPTPConfigurationMember',
        'Add-SfosSSLBookmarkGroupMember',
        'Add-SfosVPNFailoverGroupMember',
        'Get-SfosIPsecConnection',
        'Get-SfosL2TPConfiguration',
        'Get-SfosL2TPConnection',
        'Get-SfosPPTPConfiguration',
        'Get-SfosSiteToSiteClient',
        'Get-SfosSiteToSiteServer',
        'Get-SfosSophosConnectClient',
        'Get-SfosSSLBookmark',
        'Get-SfosSSLBookmarkGroup',
        'Get-SfosSSLTunnelAccessSettings',
        'Get-SfosSSLVPNPolicy',
        'Get-SfosVPNFailoverGroup',
        'Get-SfosVPNProfile',
        'New-SfosIPsecConnection',
        'New-SfosL2TPConnection',
        'New-SfosSiteToSiteClient',
        'New-SfosSiteToSiteServer',
        'New-SfosSSLBookmark',
        'New-SfosSSLBookmarkGroup',
        'New-SfosSSLVPNPolicy',
        'New-SfosVPNFailoverGroup',
        'New-SfosVPNProfile',
        'Remove-SfosIPsecConnection',
        'Remove-SfosL2TPConfigurationMember',
        'Remove-SfosL2TPConnection',
        'Remove-SfosPPTPConfigurationMember',
        'Remove-SfosSiteToSiteClient',
        'Remove-SfosSiteToSiteServer',
        'Remove-SfosSSLBookmark',
        'Remove-SfosSSLBookmarkGroup',
        'Remove-SfosSSLBookmarkGroupMember',
        'Remove-SfosSSLVPNPolicy',
        'Remove-SfosVPNFailoverGroup',
        'Remove-SfosVPNFailoverGroupMember',
        'Remove-SfosVPNProfile',
        'Set-SfosIPsecConnection',
        'Set-SfosL2TPConfiguration',
        'Set-SfosL2TPConnection',
        'Set-SfosPPTPConfiguration',
        'Set-SfosSiteToSiteClient',
        'Set-SfosSiteToSiteServer',
        'Set-SfosSSLBookmark',
        'Set-SfosSSLBookmarkGroup',
        'Set-SfosSSLTunnelAccessSettings',
        'Set-SfosSSLVPNPolicy',
        'Set-SfosVPNFailoverGroup',
        'Set-SfosVPNProfile'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'VPN', 'IPsec', 'SSLVPN', 'L2TP')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.VPN/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.VPN'
            ReleaseNotes = '1.1.0: Adds the -Session parameter to all 51 cmdlets for multi-session use (requires SophosFirewall.Core 1.3.0). 1.0.1: New-/Set-SfosL2TPConnection no longer fail open (write status is asserted at the measured flat path); ConfirmImpact High on Set-SfosL2TP-/PPTPConfiguration; measured docs updated.'
        }
    }
}