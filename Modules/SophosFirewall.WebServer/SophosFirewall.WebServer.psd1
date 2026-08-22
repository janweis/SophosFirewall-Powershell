@{
    RootModule           = 'SophosFirewall.WebServer.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = '47b5f07d-b08f-426d-bafc-ae25f1cd10ea'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing Web Server Protection (WAF) on Sophos XGS / SFOS 22.0 firewalls via API: web servers, protection policies, authentication policies and templates, slow HTTP protection settings.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.4.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosWebServer',
        'Get-SfosWebServerAuthenticationPolicy',
        'Get-SfosWebServerAuthenticationTemplate',
        'Get-SfosWebServerProtectionPolicy',
        'Get-SfosWebServerSlowHTTPProtectionSettings',
        'New-SfosWebServer',
        'New-SfosWebServerAuthenticationPolicy',
        'New-SfosWebServerAuthenticationTemplate',
        'New-SfosWebServerProtectionPolicy',
        'Remove-SfosWebServer',
        'Remove-SfosWebServerAuthenticationPolicy',
        'Remove-SfosWebServerAuthenticationTemplate',
        'Remove-SfosWebServerProtectionPolicy',
        'Set-SfosWebServer',
        'Set-SfosWebServerAuthenticationPolicy',
        'Set-SfosWebServerAuthenticationTemplate',
        'Set-SfosWebServerProtectionPolicy',
        'Set-SfosWebServerSlowHTTPProtectionSettings'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'WAF', 'WebServer', 'ReverseProxy')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.WebServer/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.WebServer'
            ReleaseNotes = '1.4.0: No functional change in this module. The version numbers of the module collection are aligned, and this module now requires SophosFirewall.Core 1.4.0.'
        }
    }
}
