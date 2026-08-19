@{
    RootModule           = 'SophosFirewall.Diagnostics.psm1'
    ModuleVersion        = '1.3.5'
    GUID                 = '799d548b-6bac-4c7a-931d-bfd62e10bee3'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for the MONITOR & ANALYZE > Diagnostics area of Sophos XGS / SFOS 22.0 firewalls via API: remote support access.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.5'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosSupportAccess',
        'Set-SfosSupportAccess'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Diagnostics', 'SupportAccess')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Diagnostics/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Diagnostics'
            ReleaseNotes = 'First release. Adds read and update access to remote support access (SupportAccess).'
        }
    }
}
