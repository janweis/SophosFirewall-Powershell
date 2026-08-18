@{
    RootModule           = 'SophosFirewall.Core.psm1'
    ModuleVersion        = '1.3.5'
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
        'ConvertFrom-SfosArchive'
    )
    
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    
    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'XGS', 'SFOS', 'API', 'Core', 'Helper')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Core/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Core'
            ReleaseNotes = 'Added ConvertFrom-SfosArchive, which reads the tar archive that Certificate, CertificateAuthority, CRL and FormTemplate return instead of XML. It tolerates the malformed tar header the firewall produces for object names containing non-ASCII characters: it returns every file entry read successfully, reports the break instead of throwing, and still recovers the full Entities.xml metadata regardless of where the tar structure breaks.'
        }
    }
}

