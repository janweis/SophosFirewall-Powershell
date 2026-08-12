@{
    RootModule           = 'SophosFirewall.ActiveThreatResponse.psm1'
    ModuleVersion        = '1.1.0'
    GUID                 = '818bf495-5c4e-4bd4-a8e2-fef4b97d2372'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing Active Threat Response on Sophos XGS / SFOS 22.0 firewalls via API: ATP (Sophos X-Ops threat feeds) settings and third-party threat feeds.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.0'
        }
    )

    FunctionsToExport    = @(
        'Add-SfosATPHostException',
        'Add-SfosATPThreatException',
        'Get-SfosATPSettings',
        'Get-SfosThirdPartyFeed',
        'New-SfosThirdPartyFeed',
        'Remove-SfosATPHostException',
        'Remove-SfosATPThreatException',
        'Remove-SfosThirdPartyFeed',
        'Set-SfosATPSettings',
        'Set-SfosThirdPartyFeed'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'ActiveThreatResponse', 'ATP', 'ThreatFeed')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.ActiveThreatResponse/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.ActiveThreatResponse'
            ReleaseNotes = '1.0.1: comment-based help fix; if/else array-unwrap hardening. 1.1.0: Adds the -Session parameter to all 10 cmdlets for multi-session use (requires SophosFirewall.Core 1.3.0).'
        }
    }
}
