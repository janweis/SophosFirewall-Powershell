@{
    RootModule           = 'SophosFirewall.Email.psm1'
    ModuleVersion        = '1.3.5'
    GUID                 = '5503ab89-33ba-411d-b3e0-663b5cf824fd'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing email protection on Sophos XGS / SFOS 22.0 firewalls via API: SMTP and POP/IMAP scanning policies, MTA address groups, exception policies, data control lists, SPX, anti-spam rules and the mail configuration.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.5'
        }
    )

    FunctionsToExport    = @(
        'Get-SfosAdvancedSMTPSetting',
        'Get-SfosAntiSpamEmailArchiver',
        'Get-SfosAntiSpamQuarantineDigestSettings',
        'Get-SfosAntiSpamRule',
        'Get-SfosAntiSpamTrustedDomain',
        'Get-SfosAVASAddressGroup',
        'Get-SfosDataControlList',
        'Get-SfosDKIMSigning',
        'Get-SfosDKIMVerification',
        'Get-SfosEmailConfiguration',
        'Get-SfosMailExceptionPolicy',
        'Get-SfosMailMalwareProtection',
        'Get-SfosMailRelaySettings',
        'Get-SfosMTAAddressGroup',
        'Get-SfosMTABlockedSender',
        'Get-SfosMTADataControlList',
        'Get-SfosMTASPXConfiguration',
        'Get-SfosMTASPXTemplate',
        'Get-SfosPOPIMAPScanningPolicy',
        'Get-SfosSmarthostSettings',
        'Get-SfosSMTPDeploymentMode',
        'Get-SfosSMTPMalwareScanningPolicy',
        'Get-SfosSMTPPolicy',
        'Get-SfosSPXConfiguration',
        'Get-SfosSPXTemplate',
        'New-SfosAntiSpamEmailArchiver',
        'New-SfosAntiSpamRule',
        'New-SfosAntiSpamTrustedDomain',
        'New-SfosAVASAddressGroup',
        'New-SfosDataControlList',
        'New-SfosMailExceptionPolicy',
        'New-SfosMTAAddressGroup',
        'New-SfosMTADataControlList',
        'New-SfosMTASPXTemplate',
        'New-SfosPOPIMAPScanningPolicy',
        'New-SfosSMTPMalwareScanningPolicy',
        'New-SfosSMTPPolicy',
        'New-SfosSPXTemplate',
        'Remove-SfosAntiSpamEmailArchiver',
        'Remove-SfosAntiSpamRule',
        'Remove-SfosAntiSpamTrustedDomain',
        'Remove-SfosAVASAddressGroup',
        'Remove-SfosDataControlList',
        'Remove-SfosMailExceptionPolicy',
        'Remove-SfosMTAAddressGroup',
        'Remove-SfosMTADataControlList',
        'Remove-SfosMTASPXTemplate',
        'Remove-SfosPOPIMAPScanningPolicy',
        'Remove-SfosSMTPMalwareScanningPolicy',
        'Remove-SfosSMTPPolicy',
        'Remove-SfosSPXTemplate',
        'Set-SfosAdvancedSMTPSetting',
        'Set-SfosAntiSpamEmailArchiver',
        'Set-SfosAntiSpamQuarantineDigestSettings',
        'Set-SfosAntiSpamRule',
        'Set-SfosAVASAddressGroup',
        'Set-SfosDataControlList',
        'Set-SfosEmailConfiguration',
        'Set-SfosMailExceptionPolicy',
        'Set-SfosMailMalwareProtection',
        'Set-SfosMTAAddressGroup',
        'Set-SfosMTADataControlList',
        'Set-SfosMTASPXConfiguration',
        'Set-SfosMTASPXTemplate',
        'Set-SfosPOPIMAPScanningPolicy',
        'Set-SfosSMTPDeploymentMode',
        'Set-SfosSMTPMalwareScanningPolicy',
        'Set-SfosSMTPPolicy',
        'Set-SfosSPXConfiguration',
        'Set-SfosSPXTemplate'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Email', 'SMTP', 'MTA', 'AntiSpam')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Email/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Email'
            ReleaseNotes = 'First release. Covers the email area in both of its shapes: SMTP policies, MTA address groups, exception policies and data control lists for MTA mode, anti-spam rules and SMTP malware scanning policies for legacy mode, plus the objects both share - mail configuration, malware protection, POP/IMAP scanning policies, trusted domains and SPX. Relay, smarthost, blocked senders, DKIM and the quarantine digest are read-only.'
        }
    }
}
