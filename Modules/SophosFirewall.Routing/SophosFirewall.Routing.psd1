@{
    RootModule           = 'SophosFirewall.Routing.psm1'
    ModuleVersion        = '1.3.1'
    GUID                 = '6baa7e3d-24b6-46b1-b49c-9f0f71e04bc4'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing routing on Sophos XGS / SFOS 22.0 firewalls via API: gateways, health checks, SD-WAN profiles and routes, unicast and multicast routing.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.1'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosGatewayHost',
        'Get-SfosHealthCheckProfile',
        'Get-SfosHealthCheckProfileStatus',
        'Get-SfosMulticastConfiguration',
        'Get-SfosMulticastRoute',
        'Get-SfosPIMDynamicRouting',
        'Get-SfosSDWANPolicyRoute',
        'Get-SfosSDWANPolicyRouteStatus',
        'Get-SfosSDWANProfile',
        'Get-SfosUnicastRoute',
        'New-SfosGatewayHost',
        'New-SfosHealthCheckProfile',
        'New-SfosMulticastRoute',
        'New-SfosSDWANPolicyRoute',
        'New-SfosSDWANProfile',
        'New-SfosUnicastRoute',
        'Remove-SfosGatewayHost',
        'Remove-SfosHealthCheckProfile',
        'Remove-SfosMulticastRoute',
        'Remove-SfosSDWANPolicyRoute',
        'Remove-SfosSDWANProfile',
        'Remove-SfosUnicastRoute',
        'Set-SfosGatewayHost',
        'Set-SfosHealthCheckProfile',
        'Set-SfosHealthCheckProfileStatus',
        'Set-SfosMulticastRoute',
        'Set-SfosPIMDynamicRouting',
        'Set-SfosSDWANPolicyRoute',
        'Set-SfosSDWANPolicyRouteStatus',
        'Set-SfosSDWANProfile',
        'Set-SfosUnicastRoute'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Routing', 'SDWAN', 'Gateway', 'Multicast')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Routing/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Routing'
            ReleaseNotes = 'Documentation revised for production use: rewritten cmdlet help, module description and README.'
        }
    }
}