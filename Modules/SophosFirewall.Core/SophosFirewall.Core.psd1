@{
    RootModule           = 'SophosFirewall.Core.psm1'
    ModuleVersion        = '1.4.0'
    GUID                 = 'cf0350d0-30af-4cd9-ae9e-8eb43356718d'
    Author               = 'Jan Weis'
    Description          = 'Core helper functions for Sophos Firewall API modules. Provides session management, API communication, XML escaping, and response validation.'
    
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    
    FunctionsToExport    = @(
        'Connect-SfosFirewall',
        'Disconnect-SfosFirewall',
        'Get-SfosSession',
        'Invoke-SfosApi',
        'Get-SfosApiStatus',
        'Assert-SfosApiReturnSuccess',
        'Resolve-SfosParameters',
        'ConvertTo-SfosXmlEscaped',
        'ConvertFrom-SfosArchive',
        'Connect-SfosWebAdmin',
        'Invoke-SfosWebAdminRequest',
        'Connect-SfosCliConsole',
        'Send-SfosCliInput',
        'Receive-SfosCliOutput',
        'Disconnect-SfosCliConsole'
    )
    
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    
    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'XGS', 'SFOS', 'API', 'Core', 'Helper')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Core/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Core'
            ReleaseNotes = '1.4.0: Adds two further ways to reach the appliance alongside the documented XML API. Connect-SfosWebAdmin and Invoke-SfosWebAdminRequest reach the web admin console for screens the XML API does not cover; both are undocumented and firmware-dependent. Connect-SfosCliConsole, Send-SfosCliInput, Receive-SfosCliOutput and Disconnect-SfosCliConsole reach the appliance device console; only the admin and support accounts may open it, it asks for the account password again, and an open session has to be closed explicitly. New -AcceptLoginDisclaimer switch on the connect cmdlets: where the appliance has a login disclaimer configured, a connection attempt without this switch now reports the disclaimer text instead of failing with an unrelated error, and the switch is the only way to accept it - no cmdlet accepts a disclaimer on the caller''s behalf.'
        }
    }
}

