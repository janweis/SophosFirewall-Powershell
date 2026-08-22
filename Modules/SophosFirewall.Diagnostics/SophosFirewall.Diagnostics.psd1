@{
    RootModule           = 'SophosFirewall.Diagnostics.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = '799d548b-6bac-4c7a-931d-bfd62e10bee3'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for the MONITOR & ANALYZE > Diagnostics area of Sophos XGS / SFOS 22.0 firewalls: remote support access, read-only access to the web admin console log viewer, and running commands on the appliance device console. Intended for administrators who need to open a temporary support channel, review recent log activity, or reach the device console without a physical or serial connection.'

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
        'Get-SfosLogCategory',
        'Export-SfosLog',
        'Import-SfosLog',
        'Invoke-SfosCliCommand',
        'Enter-SfosCliConsole'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Diagnostics', 'SupportAccess', 'LogViewer')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Diagnostics/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Diagnostics'
            ReleaseNotes = '1.4.0: Turns log retrieval into an analysis tool. Get-SfosLog and Get-SfosLogCategory read the web admin console''s log viewer, which the XML API does not expose. 28 field filters are available; each accepts multiple values combined with OR, different filters combine with AND, and each has a matching -Exclude... counterpart. -AnyIP and -AnyPort match either the source or the destination side, while -SourceIP/-DestinationIP and -SourcePort/-DestinationPort match one side only. New -Protocol and -Text filters; -Text searches every field value at once and never the field names. Export-SfosLog and Import-SfosLog capture a set of log entries to a file so it can be filtered repeatedly offline, without querying the appliance again; the captured file records when and from what it was taken, and whether a filter was already applied during capture. Invoke-SfosCliCommand and Enter-SfosCliConsole give access to the device console; Invoke-SfosCliCommand asks for confirmation before running a command, because the console executes commands without a confirmation step of its own. Fixed: filtered log queries could lose matching entries when a request came back short of the requested count and was retried with a broader query; this affected every filter and was most visible with the text search. Empty and unreadable entries returned by the appliance are now discarded instead of surfacing as binding errors.'
        }
    }
}
