@{
    RootModule           = 'SophosFirewall.Profiles.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = 'cadd6557-33e8-43e1-8169-516eac60dfdb'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing System > Profiles on Sophos XGS / SFOS 22.0 firewalls via API: schedules, access time policies, data transfer policies, decryption profiles and administrator role profiles.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.4.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosAccessTimePolicy',
        'Get-SfosAdministrationProfile',
        'Get-SfosDataTransferPolicy',
        'Get-SfosDecryptionProfile',
        'Get-SfosSchedule',
        'New-SfosAccessTimePolicy',
        'New-SfosAdministrationProfile',
        'New-SfosDataTransferPolicy',
        'New-SfosDecryptionProfile',
        'New-SfosSchedule',
        'Remove-SfosAccessTimePolicy',
        'Remove-SfosAdministrationProfile',
        'Remove-SfosDataTransferPolicy',
        'Remove-SfosDecryptionProfile',
        'Remove-SfosSchedule',
        'Set-SfosAccessTimePolicy',
        'Set-SfosAdministrationProfile',
        'Set-SfosDataTransferPolicy',
        'Set-SfosDecryptionProfile',
        'Set-SfosSchedule'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Profiles', 'Schedule', 'Decryption')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Profiles/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Profiles'
            ReleaseNotes = '1.4.0: No functional change in this module. The version numbers of the module collection are aligned, and this module now requires SophosFirewall.Core 1.4.0.'
        }
    }
}
