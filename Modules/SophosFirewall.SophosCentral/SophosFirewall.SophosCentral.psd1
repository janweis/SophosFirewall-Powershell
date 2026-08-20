@{
    RootModule           = 'SophosFirewall.SophosCentral.psm1'
    ModuleVersion        = '1.3.5'
    GUID                 = 'cecf576f-4bbc-4903-8626-5fc79e8adef3'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for the SYSTEM > Sophos Central area of Sophos XGS / SFOS 22.0 firewalls via API: the cloud central management switches for reporting, management and configuration backup.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.5'
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
            ReleaseNotes = 'First release. Adds read and update access to the Sophos Central cloud management switches (EnableCloudCentralManagement), including a read-back check for the case where the firewall reports success without applying the change.'
        }
    }
}
