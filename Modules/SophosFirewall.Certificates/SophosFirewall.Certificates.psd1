@{
    RootModule           = 'SophosFirewall.Certificates.psm1'
    ModuleVersion        = '1.3.5'
    GUID                 = 'a62752b2-6ba5-4a37-aa13-ece098220332'
    Author               = 'Jan Weis'
    Description          = 'PowerShell module for managing certificates on Sophos XGS / SFOS 22.0 firewalls via API: certificates, certificate authorities and certificate revocation lists.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    RequiredModules      = @(
        @{
            ModuleName    = 'SophosFirewall.Core'
            ModuleVersion = '1.3.5'
        }
    )

    FunctionsToExport    = @(
        'Export-SfosCertificate',
        'Export-SfosCertificateAuthority',
        'Get-SfosCRL',
        'Get-SfosCertificate',
        'Get-SfosCertificateAuthority',
        'New-SfosCertificate',
        'New-SfosCertificateAuthority',
        'Remove-SfosCertificate',
        'Remove-SfosCertificateAuthority',
        'Set-SfosCertificate',
        'Set-SfosCertificateAuthority'
    )

    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('Sophos', 'Firewall', 'API', 'XGS', 'SFOS', 'Certificate', 'PKI', 'CRL')
            LicenseUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/blob/main/Modules/SophosFirewall.Certificates/LICENSE.txt'
            ProjectUri   = 'https://github.com/janweis/SophosFirewall-PowerShell/tree/main/Modules/SophosFirewall.Certificates'
            ReleaseNotes = 'First release. Adds certificates and certificate authorities, including upload of PKCS#12 and PEM material and export of stored files, plus read access to certificate revocation lists.'
        }
    }
}
