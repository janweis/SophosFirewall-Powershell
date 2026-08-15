@{
    RootModule           = 'SophosFirewall.Administration.psm1'
    ModuleVersion        = '1.3.1'
    GUID                 = 'ee6ef0e0-5bdf-4032-a8c8-70e5dfa72200'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing System > Administration settings on Sophos XGS / SFOS 22.0 firewalls via API: mail server notification settings, SNMP agent configuration, system date/time, SNMP communities, SNMPv3 users, customizable end-user messages, appliance service access, admin settings (hostname, web admin, login security, password complexity, login disclaimer, factory reset), and Local Service ACL rules.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.1'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosAdminSettings',
        'Get-SfosApplianceAccess',
        'Get-SfosLocalServiceACL',
        'Get-SfosMessages',
        'Get-SfosNotification',
        'Get-SfosSNMPAgentConfiguration',
        'Get-SfosSNMPCommunity',
        'Get-SfosSNMPv3User',
        'Get-SfosTime',
        'New-SfosLocalServiceACL',
        'New-SfosSNMPCommunity',
        'New-SfosSNMPv3User',
        'Remove-SfosLocalServiceACL',
        'Remove-SfosSNMPCommunity',
        'Remove-SfosSNMPv3User',
        'Reset-SfosToFactoryDefaults',
        'Set-SfosAdminPasswordComplexity',
        'Set-SfosApplianceAccess',
        'Set-SfosHostname',
        'Set-SfosLocalServiceACL',
        'Set-SfosLoginDisclaimer',
        'Set-SfosLoginSecurity',
        'Set-SfosMessages',
        'Set-SfosNotification',
        'Set-SfosSNMPAgentConfiguration',
        'Set-SfosSNMPCommunity',
        'Set-SfosSNMPv3User',
        'Set-SfosTime',
        'Set-SfosWebAdminSettings'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Administration', 'Notification', 'SNMP', 'Time', 'ApplianceAccess', 'AdminSettings')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Administration/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Administration'
            ReleaseNotes = 'Documentation revised for production use: rewritten cmdlet help, module description and README.'
        }
    }
}
