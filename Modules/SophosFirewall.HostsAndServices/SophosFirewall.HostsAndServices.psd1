@{
    RootModule           = 'SophosFirewall.HostsAndServices.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = '1c2a45f5-8215-4035-a691-2be3ef0e8191'
    Author               = 'Jan Weis'
    Description          = 'Manages IP hosts, FQDN hosts, MAC hosts, host groups, services and service groups on a Sophos XGS / SFOS 22.0 firewall via the management API.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosIPHost',
        'New-SfosIPHost',
        'Set-SfosIPHost',
        'Remove-SfosIPHost',
        'Export-SfosIPHosts',
        'Import-SfosIPHosts',
        'Get-SfosIPHostGroup',
        'New-SfosIPHostGroup',
        'Set-SfosIPHostGroup',
        'Remove-SfosIPHostGroup',
        'Add-SfosIPHostGroupMember',
        'Remove-SfosIPHostGroupMember',
        'Export-SfosIPHostGroups',
        'Import-SfosIPHostGroups',
        'Get-SfosFQDNHost',
        'New-SfosFQDNHost',
        'Set-SfosFQDNHost',
        'Remove-SfosFQDNHost',
        'Remove-SfosFQDNHostMass',
        'Export-SfosFQDNHosts',
        'Import-SfosFQDNHosts',
        'Get-SfosFQDNHostGroup',
        'New-SfosFQDNHostGroup',
        'Set-SfosFQDNHostGroup',
        'Remove-SfosFQDNHostGroup',
        'Add-SfosFQDNHostGroupMember',
        'Remove-SfosFQDNHostGroupMember',
        'Export-SfosFQDNHostGroups',
        'Import-SfosFQDNHostGroups',
        'Get-SfosMACHost',
        'New-SfosMACHost',
        'Set-SfosMACHost',
        'Remove-SfosMACHost',
        'Export-SfosMACHosts',
        'Import-SfosMACHosts',
        'Get-SfosCountryGroup',
        'New-SfosCountryGroup',
        'Set-SfosCountryGroup',
        'Remove-SfosCountryGroup',
        'Get-SfosService',
        'New-SfosService',
        'Set-SfosService',
        'Remove-SfosService',
        'Export-SfosServices',
        'Import-SfosServices',
        'Get-SfosServiceGroup',
        'New-SfosServiceGroup',
        'Set-SfosServiceGroup',
        'Remove-SfosServiceGroup',
        'Add-SfosServiceGroupMember',
        'Remove-SfosServiceGroupMember',
        'Export-SfosServiceGroups',
        'Import-SfosServiceGroups'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Network', 'Security')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.HostsAndServices/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.HostsAndServices'
        }
    }
}
