@{
    RootModule           = 'SophosFirewall.SophosCentral.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = 'cecf576f-4bbc-4903-8626-5fc79e8adef3'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for the SYSTEM > Sophos Central area of Sophos XGS / SFOS 22.0 firewalls via API: the cloud central management switches for reporting, management and configuration backup.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.4.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosCentralManagement',
        'Set-SfosCentralManagement'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'SophosCentral', 'CentralManagement', 'Registration')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.SophosCentral/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.SophosCentral'
            ReleaseNotes = '1.4.0: No functional change in this module. The version numbers of the module collection are aligned, and this module now requires SophosFirewall.Core 1.4.0.'
        }
    }
}
