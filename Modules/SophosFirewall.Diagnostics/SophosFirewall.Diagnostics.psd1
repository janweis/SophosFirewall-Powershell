@{
    RootModule           = 'SophosFirewall.Diagnostics.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = '799d548b-6bac-4c7a-931d-bfd62e10bee3'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for the MONITOR & ANALYZE > Diagnostics area of Sophos XGS / SFOS 22.0 firewalls: remote support access, and read-only access to the web admin console log viewer.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.4.0'
        }
    )

    FormatsToProcess     = @('SophosFirewall.Diagnostics.Format.ps1xml')

    FunctionsToExport    = @(
        'Get-SfosSupportAccess',
        'Set-SfosSupportAccess',
        'Get-SfosLog',
        'Get-SfosLogCategory'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Diagnostics', 'SupportAccess', 'LogViewer')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Diagnostics/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Diagnostics'
            ReleaseNotes = 'Web admin console access (login, CSRF, the controller POST) moved to SophosFirewall.Core as Connect-SfosWebAdmin/Invoke-SfosWebAdminRequest, so a second module can reach the web admin console the same way. Behaviour of Get-SfosLog/Get-SfosLogCategory is unchanged. Requires SophosFirewall.Core 1.4.0.'
        }
    }
}
