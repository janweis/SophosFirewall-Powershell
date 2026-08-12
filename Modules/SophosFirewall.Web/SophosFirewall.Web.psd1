@{
    RootModule           = 'SophosFirewall.Web.psm1'
    ModuleVersion        = '1.0.2'
    GUID                 = '77a63a21-54db-4f49-a7c7-632f520bd61b'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing the web protection area of Sophos XGS / SFOS 22.0 firewalls via API.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.1.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosWebFilterURLGroup',
        'New-SfosWebFilterURLGroup',
        'Set-SfosWebFilterURLGroup',
        'Remove-SfosWebFilterURLGroup',
        'Add-SfosWebFilterURLGroupMember',
        'Remove-SfosWebFilterURLGroupMember',
        'Get-SfosFileType',
        'New-SfosFileType',
        'Set-SfosFileType',
        'Remove-SfosFileType',
        'Get-SfosWebFilterCategory',
        'New-SfosWebFilterCategory',
        'Set-SfosWebFilterCategory',
        'Remove-SfosWebFilterCategory',
        'Get-SfosUserActivity',
        'New-SfosUserActivity',
        'Set-SfosUserActivity',
        'Remove-SfosUserActivity',
        'Add-SfosUserActivityMember',
        'Remove-SfosUserActivityMember',
        'Get-SfosWebFilterException',
        'New-SfosWebFilterException',
        'Set-SfosWebFilterException',
        'Remove-SfosWebFilterException',
        'Get-SfosWebFilterPolicy',
        'New-SfosWebFilterPolicy',
        'Set-SfosWebFilterPolicy',
        'Remove-SfosWebFilterPolicy',
        'New-SfosWebFilterPolicyCategory',
        'New-SfosWebFilterPolicyRule',
        'Add-SfosWebFilterPolicyRule',
        'Remove-SfosWebFilterPolicyRule',
        'Get-SfosSurfingQuotaPolicy',
        'New-SfosSurfingQuotaPolicy',
        'Set-SfosSurfingQuotaPolicy',
        'Remove-SfosSurfingQuotaPolicy',
        'Get-SfosContentConditionList',
        'New-SfosContentConditionList',
        'Set-SfosContentConditionList',
        'Remove-SfosContentConditionList',
        'Add-SfosContentConditionListMember',
        'Remove-SfosContentConditionListMember',
        'Get-SfosMalwareProtection',
        'Set-SfosMalwareProtection',
        'Get-SfosWebFilterSettings',
        'Set-SfosWebFilterSettings',
        'Get-SfosWebFilterProtectionSettings',
        'Set-SfosWebFilterProtectionSettings',
        'Get-SfosWebFilterAdvancedSettings',
        'Set-SfosWebFilterAdvancedSettings',
        'Get-SfosDefaultWebFilterNotificationSettings',
        'Set-SfosDefaultWebFilterNotificationSettings'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Web', 'WebFilter', 'Security')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Web/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Web'
            ReleaseNotes = '1.0.2: Get-SfosWebFilterCategory returns @() for absent Keyword/URL lists as documented; if/else array-unwrap hardening.'
        }
    }
}
