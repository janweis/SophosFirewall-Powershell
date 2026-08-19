@{
    RootModule           = 'SophosFirewall.ZeroDayProtection.psm1'
    ModuleVersion        = '1.3.5'
    GUID                 = 'd37b892a-114a-4ba1-be66-15c102028706'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing zero-day protection settings on Sophos XGS / SFOS 22.0 firewalls via API: the sandbox analysis datacenter and excluded file types.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.5'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosZeroDayProtectionSettings',
        'Set-SfosZeroDayProtectionSettings'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'ZeroDayProtection', 'Sandbox')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.ZeroDayProtection/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.ZeroDayProtection'
            ReleaseNotes = 'First release. Adds read and update access to the zero-day protection settings singleton: analysis datacenter location and excluded file types.'
        }
    }
}
