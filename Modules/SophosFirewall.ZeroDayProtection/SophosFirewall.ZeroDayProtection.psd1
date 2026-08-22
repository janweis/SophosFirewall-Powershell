@{
    RootModule           = 'SophosFirewall.ZeroDayProtection.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = 'd37b892a-114a-4ba1-be66-15c102028706'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing zero-day protection settings on Sophos XGS / SFOS 22.0 firewalls via API: the sandbox analysis datacenter and excluded file types.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.4.0'
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
            ReleaseNotes = '1.4.0: No functional change in this module. The version numbers of the module collection are aligned, and this module now requires SophosFirewall.Core 1.4.0.'
        }
    }
}
