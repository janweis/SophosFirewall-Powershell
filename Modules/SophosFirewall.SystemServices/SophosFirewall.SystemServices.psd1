@{
    RootModule           = 'SophosFirewall.SystemServices.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'ffcaa7e6-5e2d-4e98-978a-86b487ce8d35'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing System Services on Sophos XGS / SFOS 22.0 firewalls via API: QoS (traffic shaping) policies, syslog servers, the system service daemon manager, High Availability, and RED configuration.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.0'
        }
    )

    FunctionsToExport    = @(
        'Disable-SfosHAConfiguration',
        'Get-SfosHAConfiguration',
        'Get-SfosQoSPolicy',
        'Get-SfosREDConfiguration',
        'Get-SfosREDDeviceDeauthorizationSettings',
        'Get-SfosREDTLSVersionSettings',
        'Get-SfosSyslogServer',
        'Get-SfosSystemServiceStatus',
        'Initialize-SfosHAConfiguration',
        'New-SfosQoSPolicy',
        'New-SfosSyslogServer',
        'Remove-SfosQoSPolicy',
        'Remove-SfosSyslogServer',
        'Reset-SfosHAConfiguration',
        'Set-SfosQoSPolicy',
        'Set-SfosREDBetaFirmware',
        'Set-SfosREDConfiguration',
        'Set-SfosREDDeviceDeauthorizationSettings',
        'Set-SfosREDTLSVersionSettings',
        'Set-SfosSyslogServer',
        'Set-SfosSystemService'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'SystemServices', 'QoS', 'TrafficShaping', 'Syslog', 'HA', 'RED')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.SystemServices/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.SystemServices'
            ReleaseNotes = 'Initial release of the SystemServices module for Sophos Firewall API management. Includes the -Session parameter on every cmdlet (requires SophosFirewall.Core 1.3.0).'
        }
    }
}
