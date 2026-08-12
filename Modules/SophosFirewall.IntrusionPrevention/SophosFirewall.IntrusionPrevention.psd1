@{
    RootModule           = 'SophosFirewall.IntrusionPrevention.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '44f6945c-59a9-45a0-9a97-f6352eb5d054'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing intrusion prevention on Sophos XGS / SFOS 22.0 firewalls via API: IPS policies, custom signatures, IPS switch, DoS settings, DoS bypass rules, spoof prevention and trusted MACs.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.0.0'
        }
    )

    FunctionsToExport    = @(
        'Add-SfosIPSPolicyRule',
        'Export-SfosTrustedMACs',
        'Get-SfosDoSBypassRule',
        'Get-SfosDoSSettings',
        'Get-SfosIPSCustomSignature',
        'Get-SfosIPSFullSignaturePack',
        'Get-SfosIPSPolicy',
        'Get-SfosIPSSwitch',
        'Get-SfosSpoofPrevention',
        'Get-SfosTrustedMAC',
        'Import-SfosTrustedMACs',
        'New-SfosDoSBypassRule',
        'New-SfosIPSCustomSignature',
        'New-SfosIPSPolicy',
        'New-SfosIPSPolicyRule',
        'New-SfosTrustedMAC',
        'Remove-SfosDoSBypassRule',
        'Remove-SfosIPSCustomSignature',
        'Remove-SfosIPSPolicy',
        'Remove-SfosIPSPolicyRule',
        'Remove-SfosTrustedMAC',
        'Set-SfosDoSBypassRule',
        'Set-SfosDoSSettings',
        'Set-SfosIPSCustomSignature',
        'Set-SfosIPSFullSignaturePack',
        'Set-SfosIPSPolicy',
        'Set-SfosIPSSwitch',
        'Set-SfosSpoofPrevention',
        'Set-SfosTrustedMAC'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'IntrusionPrevention', 'IPS', 'DoS', 'SpoofPrevention', 'TrustedMAC')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.IntrusionPrevention/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.IntrusionPrevention'
            ReleaseNotes = 'Initial release of the IntrusionPrevention module for Sophos Firewall API management.'
        }
    }
}
