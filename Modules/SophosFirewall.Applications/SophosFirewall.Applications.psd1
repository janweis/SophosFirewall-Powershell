@{
    RootModule           = 'SophosFirewall.Applications.psm1'
    ModuleVersion        = '1.3.1'
    GUID                 = 'ebbadd35-0d7a-45a6-a2ad-15f0609e65c3'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing application control on Sophos XGS / SFOS 22.0 firewalls via API: application filter policies and rules, application objects, application categories with QoS assignment, application classification.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.1'
        }
    )

    FunctionsToExport    = @(
        'Add-SfosApplicationFilterCategoryMember',
        'Add-SfosApplicationFilterPolicyRule',
        'Get-SfosApplicationClassification',
        'Get-SfosApplicationClassificationAssignment',
        'Get-SfosApplicationFilterCategory',
        'Get-SfosApplicationFilterPolicy',
        'Get-SfosApplicationObject',
        'New-SfosApplicationFilterPolicy',
        'New-SfosApplicationFilterPolicyRule',
        'New-SfosApplicationObject',
        'Remove-SfosApplicationFilterCategoryMember',
        'Remove-SfosApplicationFilterPolicy',
        'Remove-SfosApplicationFilterPolicyRule',
        'Remove-SfosApplicationObject',
        'Set-SfosApplicationClassification',
        'Set-SfosApplicationClassificationAssignment',
        'Set-SfosApplicationClassificationAssignmentBatch',
        'Set-SfosApplicationFilterCategory',
        'Set-SfosApplicationFilterPolicy',
        'Set-SfosApplicationObject'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Applications', 'AppControl', 'QoS')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Applications/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Applications'
            ReleaseNotes = 'Documentation revised for production use: rewritten cmdlet help, module description and README.'
        }
    }
}
