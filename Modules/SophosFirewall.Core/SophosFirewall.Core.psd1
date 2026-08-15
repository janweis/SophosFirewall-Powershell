@{
    RootModule           = 'SophosFirewall.Core.psm1'
    ModuleVersion        = '1.3.0'
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
        'ConvertTo-SfosXmlEscaped'
    )
    
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    
    PrivateData          = @{
        PSData = @{
            Tags       = @('Sophos', 'Firewall', 'XGS', 'SFOS', 'API', 'Core', 'Helper')
            LicenseUri = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Core/LICENSE.txt'
            ProjectUri = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Core'
        }
    }
}

