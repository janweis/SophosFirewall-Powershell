@{
    RootModule           = 'SophosFirewall.Firewall.psm1'
    ModuleVersion        = '1.0.1'
    GUID                 = 'fe5a57d4-bdc0-4fce-958d-72bd4c9a77e9'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing firewall rules, rule groups, NAT rules and SSL/TLS inspection on Sophos XGS / SFOS 22.0 firewalls via API.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.1.0'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosFirewallRule',
        'New-SfosFirewallRule',
        'Set-SfosFirewallRule',
        'Remove-SfosFirewallRule',
        'New-SfosFirewallRuleNetworkPolicy',
        'Get-SfosFirewallRuleGroup',
        'New-SfosFirewallRuleGroup',
        'Set-SfosFirewallRuleGroup',
        'Remove-SfosFirewallRuleGroup',
        'Add-SfosFirewallRuleGroupMember',
        'Remove-SfosFirewallRuleGroupMember',
        'Get-SfosNATRule',
        'New-SfosNATRule',
        'Set-SfosNATRule',
        'Remove-SfosNATRule',
        'Get-SfosSSLTLSInspectionRule',
        'New-SfosSSLTLSInspectionRule',
        'Set-SfosSSLTLSInspectionRule',
        'Remove-SfosSSLTLSInspectionRule',
        'Get-SfosSSLTLSInspectionSettings',
        'Set-SfosSSLTLSInspectionSettings'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'NAT', 'TLS', 'Security')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Firewall/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Firewall'
            ReleaseNotes = 'Documentation only.'
        }
    }
}
