#requires -Version 5.1
#requires -Modules Pester

<#
.SYNOPSIS
    Unit tests for SophosFirewall.Certificates module.

.DESCRIPTION
    Tests for cmdlet structure and, above all, the XML actually sent to the firewall.
    Invoke-SfosApi is always mocked; no test touches a real firewall.

    This entity area answers a Get with a tar archive (application/octet-stream) rather than
    XML, so the mocked responses for a matching Get are hand-built byte[] tar archives holding
    an Entities.xml manifest plus, where relevant, certificate/key file entries - built by the
    New-TestSfosArchive helper defined below, not by any external tar tool.

    Coverage: module loading/manifest agreement and existence of all 11 exported functions with
    their identifying and connection parameters; parsing the archive into PSCustomObjects for
    Certificate, CertificateAuthority and CRL, including -NameLike client-side filtering,
    -AsXml, and the empty-result path for each entity's own dispatch (byte[] archive with no
    matching node for Certificate; plain "No. of records Zero." XML for CertificateAuthority and
    CRL); both upload shapes of New-/Set-SfosCertificate (PKCS#12 single field, PEM two-field)
    including the multipart file map and the SecureString password handling; the multipart
    upload of New-/Set-SfosCertificateAuthority, including preserving the existing Format on an
    unspecified Set; the read-first existence checks of Set-SfosCertificateAuthority and
    Remove-SfosCertificateAuthority versus the no-pre-check Remove-SfosCertificate; a missing
    local file failing before the write API call in every New-/Set- cmdlet, with the exact
    ordering measured per cmdlet (some check the file before any API call, some only after an
    existence-check Get); the Export- cmdlets writing only the certificate/key files - never
    Entities.xml or snapversion - to the target directory and returning exactly those paths;
    -WhatIf suppressing every write call; and 5xx/502/503 firewall error codes surfacing as
    exceptions naming the code.

    Measured module gap, not fixed here (module code is out of scope for this test file):
    both Export- cmdlets' help text promises -Path is "Created if it does not exist", but
    neither cmdlet actually creates it - Copy-Item fails if the directory is missing. The
    two Export- tests therefore pre-create -Path, matching what a caller has to do today.

.NOTES
    Minimum supported PowerShell version: 5.1

    Connection parameters ($conn) are built fresh inside a BeforeAll of each Describe/Context,
    never at the script's top level, following the pattern already used across this project's
    test suites.

    Running under Windows PowerShell 5.1: this machine's default $env:PSModulePath lists
    PowerShell 7's own module folders before the native Windows PowerShell ones. Pester 6, once
    loaded, ends up importing the PS7 copy of Microsoft.PowerShell.Security and its type data
    collides with the one PS 5.1 already loaded at startup. Work around it by restricting
    $env:PSModulePath in the child process before importing Pester, e.g.:

        $env:PSModulePath = 'C:\Users\<you>\Documents\PowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules'
        Import-Module Pester -MinimumVersion 5.0
        Invoke-Pester -Path '.\SophosFirewall.Certificates.Tests.ps1'

    Set that inside a script passed to `powershell.exe -NoProfile -File`, not inline in the
    calling shell - the variable must only apply to the child process.
#>

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Certificates\SophosFirewall.Certificates.psd1'
$CoreModulePath = Join-Path $ProjectRoot 'Modules\SophosFirewall.Core\SophosFirewall.Core.psd1'

if (-not (Test-Path $script:ModulePath)) {
    Write-Error "Module manifest not found: $script:ModulePath"
    exit 1
}

Import-Module $CoreModulePath -Force
Import-Module $script:ModulePath -Force

# --- Tar archive test helper --------------------------------------------------------------
# Hand-builds a minimal, valid ustar archive: an Entities.xml entry (the Response envelope
# Get-SfosApiStatus/Assert-SfosApiReturnSuccess and the entity node parsing both read) plus,
# optionally, one tar entry per certificate/key file. No tar.exe, no python. The header layout
# and checksum computation mirror what SophosFirewall.Core's ConvertFrom-SfosArchive parses.

function global:New-TestSfosTarHeader {
    param(
        [string]$Name,
        [int]$Size,
        [char]$TypeFlag = '0'
    )

    $header = New-Object byte[] 512
    $ascii = [System.Text.Encoding]::ASCII

    $nameBytes = $ascii.GetBytes($Name)
    [Array]::Copy($nameBytes, 0, $header, 0, [Math]::Min($nameBytes.Length, 100))

    $mode = $ascii.GetBytes('0000644')
    [Array]::Copy($mode, 0, $header, 100, $mode.Length)
    $uid = $ascii.GetBytes('0000000')
    [Array]::Copy($uid, 0, $header, 108, $uid.Length)
    $gid = $ascii.GetBytes('0000000')
    [Array]::Copy($gid, 0, $header, 116, $gid.Length)

    $sizeOctal = [Convert]::ToString($Size, 8).PadLeft(11, '0')
    $sizeBytes = $ascii.GetBytes($sizeOctal)
    [Array]::Copy($sizeBytes, 0, $header, 124, $sizeBytes.Length)

    $mtimeBytes = $ascii.GetBytes('00000000000')
    [Array]::Copy($mtimeBytes, 0, $header, 136, $mtimeBytes.Length)

    # checksum field: 8 spaces while summing
    for ($i = 148; $i -lt 156; $i++) { $header[$i] = 32 }

    $header[156] = [byte][char]$TypeFlag

    $magic = $ascii.GetBytes('ustar')
    [Array]::Copy($magic, 0, $header, 257, $magic.Length)
    $header[262] = 0
    $version = $ascii.GetBytes('00')
    [Array]::Copy($version, 0, $header, 263, $version.Length)

    $sum = 0
    for ($i = 0; $i -lt 512; $i++) { $sum += $header[$i] }
    $checksumOctal = [Convert]::ToString($sum, 8).PadLeft(6, '0')
    $checksumBytes = $ascii.GetBytes($checksumOctal + [char]0 + ' ')
    [Array]::Copy($checksumBytes, 0, $header, 148, $checksumBytes.Length)

    return $header
}

function global:Get-TestSfosPaddedBlocks {
    param([byte[]]$Data)
    if (-not $Data -or $Data.Length -eq 0) { return New-Object byte[] 0 }
    $blocks = [Math]::Ceiling($Data.Length / 512.0)
    $padded = New-Object byte[] ([int]$blocks * 512)
    [Array]::Copy($Data, $padded, $Data.Length)
    return $padded
}

function global:New-TestSfosArchive {
    <#
        Builds a byte[] ustar archive: EntitiesXml as './Entities.xml', plus one entry per
        hashtable in -File (@{ Name = './Files/...'; Content = [byte[]] }).
    #>
    param(
        [Parameter(Mandatory)]
        [string]$EntitiesXml,

        [hashtable[]]$File = @()
    )

    $utf8 = [System.Text.Encoding]::UTF8
    $stream = [System.IO.MemoryStream]::new()

    foreach ($f in $File) {
        $content = [byte[]]$f.Content
        $header = New-TestSfosTarHeader -Name $f.Name -Size $content.Length
        $stream.Write($header, 0, 512)
        $padded = Get-TestSfosPaddedBlocks -Data $content
        if ($padded.Length -gt 0) { $stream.Write($padded, 0, $padded.Length) }
    }

    $entitiesBytes = $utf8.GetBytes($EntitiesXml)
    $entitiesHeader = New-TestSfosTarHeader -Name './Entities.xml' -Size $entitiesBytes.Length
    $stream.Write($entitiesHeader, 0, 512)
    $entitiesPadded = Get-TestSfosPaddedBlocks -Data $entitiesBytes
    $stream.Write($entitiesPadded, 0, $entitiesPadded.Length)

    $endBlocks = New-Object byte[] 1024
    $stream.Write($endBlocks, 0, $endBlocks.Length)

    $bytes = $stream.ToArray()
    $stream.Dispose()

    # return $bytes would unroll the array onto the output pipeline and reassemble it as a
    # generic Object[] at the call site, losing the byte[] type Get-SfosCertificate's own
    # `-is [byte[]]` dispatch depends on. -NoEnumerate keeps it a single byte[] object.
    Write-Output -NoEnumerate $bytes
}

function global:New-TestSfosResponseEnvelope {
    param([string]$Body)
    return '<?xml version="1.0" encoding="UTF-8"?>' + "`n" +
        '<Response APIVersion="2200.1"><Login><status>Authentication Successful</status></Login>' +
        $Body + '</Response>'
}

# --------------------------------------------------------------------------------------------

Describe 'Module Loading' {
    It 'SophosFirewall.Certificates module should load' {
        Get-Module SophosFirewall.Certificates | Should -Not -BeNullOrEmpty
    }

    It 'SophosFirewall.Core dependency should load' {
        Get-Module SophosFirewall.Core | Should -Not -BeNullOrEmpty
    }

    It 'Should export exactly 11 functions' {
        (Get-Module SophosFirewall.Certificates).ExportedFunctions.Count | Should -Be 11
    }

    It 'Manifest FunctionsToExport should list exactly 11 functions, matching the loaded module' {
        $modulesDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Modules'
        $manifestPath = Join-Path $modulesDir 'SophosFirewall.Certificates\SophosFirewall.Certificates.psd1'

        $originalModulePath = $env:PSModulePath
        $env:PSModulePath = "$modulesDir;$originalModulePath"
        try {
            $manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
        }
        finally {
            $env:PSModulePath = $originalModulePath
        }

        $manifest.ExportedFunctions.Count | Should -Be 11
    }
}

$script:CmdletParameterCases = @(
    @{ Function = 'Get-SfosCertificate'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosCertificate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosCertificate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosCertificate'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Export-SfosCertificate'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosCertificateAuthority'; IdParam = 'NameLike'; Mandatory = $false }
    @{ Function = 'New-SfosCertificateAuthority'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Set-SfosCertificateAuthority'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Remove-SfosCertificateAuthority'; IdParam = 'Name'; Mandatory = $true }
    @{ Function = 'Export-SfosCertificateAuthority'; IdParam = 'Name'; Mandatory = $true }

    @{ Function = 'Get-SfosCRL'; IdParam = 'NameLike'; Mandatory = $false }
)

Describe 'Cmdlet existence and parameters' {

    It 'Exports <Function> with an identifying parameter <IdParam> and the six connection parameters' -TestCases $script:CmdletParameterCases {
        param($Function, $IdParam, $Mandatory)

        $cmd = Get-Command $Function -Module SophosFirewall.Certificates -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty -Because "$Function should be exported"

        $cmd.Parameters.Keys | Should -Contain $IdParam
        $isMandatory = ($cmd.Parameters[$IdParam].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory }) -contains $true
        $isMandatory | Should -Be $Mandatory

        foreach ($connParam in 'Firewall', 'Port', 'Username', 'Password', 'SkipCertificateCheck', 'Session') {
            $cmd.Parameters.Keys | Should -Contain $connParam
        }
    }

    It 'Export-SfosCertificate and Export-SfosCertificateAuthority require -Path' {
        foreach ($name in 'Export-SfosCertificate', 'Export-SfosCertificateAuthority') {
            $cmd = Get-Command $name -Module SophosFirewall.Certificates
            $isMandatory = ($cmd.Parameters['Path'].Attributes |
                    Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                    ForEach-Object { $_.Mandatory }) -contains $true
            $isMandatory | Should -Be $true
        }
    }
}

Describe 'Certificate - Get parses the archive' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $entities = New-TestSfosResponseEnvelope -Body (
            '<Certificate transactionid=""><Name>PortalCert</Name><CertificateFormat>pem</CertificateFormat><CertificateFile>PortalCert.pem</CertificateFile><PrivateKeyFile>PortalCert.key</PrivateKeyFile></Certificate>' +
            '<Certificate transactionid=""><Name>PortalCert2</Name><CertificateFormat>pem</CertificateFormat><CertificateFile>PortalCert2.pem</CertificateFile><PrivateKeyFile></PrivateKeyFile></Certificate>'
        )
        $script:TwoCertArchive = New-TestSfosArchive -EntitiesXml $entities
    }

    It 'returns PSCustomObjects with Name, CertificateFormat, CertificateFile, PrivateKeyFile and HasPrivateKey' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCertArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificate @conn)

        $result.Count | Should -Be 2
        ($result | Where-Object Name -eq 'PortalCert').CertificateFormat | Should -Be 'pem'
        ($result | Where-Object Name -eq 'PortalCert').CertificateFile | Should -Be 'PortalCert.pem'
        ($result | Where-Object Name -eq 'PortalCert').PrivateKeyFile | Should -Be 'PortalCert.key'
        ($result | Where-Object Name -eq 'PortalCert').HasPrivateKey | Should -Be $true
        ($result | Where-Object Name -eq 'PortalCert2').HasPrivateKey | Should -Be $false
    }

    It '-NameLike filters client-side to the exact match' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCertArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificate -NameLike 'PortalCert2' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'PortalCert2'
    }

    It '-AsXml returns the raw XmlElement nodes, filtered the same way' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCertArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificate -NameLike 'PortalCert2' -AsXml @conn)

        $result.Count | Should -Be 1
        $result[0] | Should -BeOfType [System.Xml.XmlElement]
        $result[0].Name | Should -Be 'PortalCert2'
    }

    It 'an archive with no matching Certificate node returns an empty array without throwing' {
        $emptyEntities = New-TestSfosResponseEnvelope -Body ''
        $emptyArchive = New-TestSfosArchive -EntitiesXml $emptyEntities

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $emptyArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificate -NameLike 'DoesNotExist' @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'New-SfosCertificate - upload shapes' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $pfxPath = Join-Path $TestDrive 'portal.pfx'
        Set-Content -LiteralPath $pfxPath -Value 'fake pfx bytes'
        $certPath = Join-Path $TestDrive 'portal.pem'
        $keyPath = Join-Path $TestDrive 'portal.key'
        Set-Content -LiteralPath $certPath -Value 'fake pem bytes'
        Set-Content -LiteralPath $keyPath -Value 'fake key bytes'
    }

    It 'PKCS#12 form sends operation=add, CertificateFormat pkcs12 (lower case) and the file via MultipartFile' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="200">Configuration applied successfully.</Status></Certificate></Response>' }
        }

        New-SfosCertificate -Name 'PortalCert' -PfxFilePath $pfxPath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<Certificate>' -and
            $InnerXml -match '<Name>PortalCert</Name>' -and
            $InnerXml -match '<CertificateFormat>pkcs12</CertificateFormat>' -and
            $InnerXml -match '<CertificateFile>portal\.pfx</CertificateFile>' -and
            $InnerXml -notmatch '<Password>' -and
            $MultipartFile.CertificateFile -eq $pfxPath
        }
    }

    It 'PKCS#12 form with -PfxPassword sends the decrypted value as the Password element, never in plain text elsewhere' {
        $securePwd = ConvertTo-SecureString 'S3cr3tPwd123' -AsPlainText -Force
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="200">Configuration applied successfully.</Status></Certificate></Response>' }
        }

        New-SfosCertificate -Name 'PortalCert' -PfxFilePath $pfxPath -PfxPassword $securePwd @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Password>S3cr3tPwd123</Password>'
        }
    }

    It 'a firewall error on a password-carrying call never leaks the password into the thrown message' {
        $securePwd = ConvertTo-SecureString 'S3cr3tPwd123' -AsPlainText -Force
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="510">Operation failed. Deleting entity referred by another entity.</Status></Certificate></Response>' }
        }

        $thrown = $null
        try {
            New-SfosCertificate -Name 'PortalCert' -PfxFilePath $pfxPath -PfxPassword $securePwd @conn -Confirm:$false
        }
        catch {
            $thrown = $_
        }

        $thrown | Should -Not -BeNullOrEmpty
        $thrown.Exception.Message | Should -Not -Match 'S3cr3tPwd123'
    }

    It 'PEM two-field form sends CertificateFormat pem and both files via MultipartFile' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="200">Configuration applied successfully.</Status></Certificate></Response>' }
        }

        New-SfosCertificate -Name 'PortalCert' -CertificateFilePath $certPath -PrivateKeyFilePath $keyPath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<CertificateFormat>pem</CertificateFormat>' -and
            $InnerXml -match '<CertificateFile>portal\.pem</CertificateFile>' -and
            $InnerXml -match '<PrivateKeyFile>portal\.key</PrivateKeyFile>' -and
            $MultipartFile.CertificateFile -eq $certPath -and
            $MultipartFile.PrivateKeyFile -eq $keyPath
        }
    }

    It 'throws naming the missing PFX file before any API call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        { New-SfosCertificate -Name 'PortalCert' -PfxFilePath (Join-Path $TestDrive 'missing.pfx') @conn -Confirm:$false } |
            Should -Throw '*does not exist*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }

    It 'throws naming the missing private key file before any API call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        { New-SfosCertificate -Name 'PortalCert' -CertificateFilePath $certPath -PrivateKeyFilePath (Join-Path $TestDrive 'missing.key') @conn -Confirm:$false } |
            Should -Throw '*does not exist*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }

    It 'throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="502">Operation failed. Entity having same name already exists.</Status></Certificate></Response>' }
        }

        { New-SfosCertificate -Name 'PortalCert' -PfxFilePath $pfxPath @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It '-WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        New-SfosCertificate -Name 'PortalCert' -PfxFilePath $pfxPath @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }
}

Describe 'Set-SfosCertificate - replaces existing material' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $certPath = Join-Path $TestDrive 'renewed.pem'
        $keyPath = Join-Path $TestDrive 'renewed.key'
        Set-Content -LiteralPath $certPath -Value 'fake renewed pem'
        Set-Content -LiteralPath $keyPath -Value 'fake renewed key'

        $existingEntities = New-TestSfosResponseEnvelope -Body (
            '<Certificate transactionid=""><Name>PortalCert</Name><CertificateFormat>pem</CertificateFormat><CertificateFile>PortalCert.pem</CertificateFile><PrivateKeyFile>PortalCert.key</PrivateKeyFile></Certificate>'
        )
        $script:ExistingArchive = New-TestSfosArchive -EntitiesXml $existingEntities

        $emptyEntities = New-TestSfosResponseEnvelope -Body ''
        $script:EmptyArchive = New-TestSfosArchive -EntitiesXml $emptyEntities
    }

    It 'sends operation=update with the new file when the object exists' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Certificate><Status code="200">Configuration applied successfully.</Status></Certificate></Response>' }
            }
        }

        Set-SfosCertificate -Name 'PortalCert' -CertificateFilePath $certPath -PrivateKeyFilePath $keyPath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Name>PortalCert</Name>' -and
            $InnerXml -match '<CertificateFile>renewed\.pem</CertificateFile>' -and
            $InnerXml -match '<PrivateKeyFile>renewed\.key</PrivateKeyFile>'
        }
    }

    It 'throws "was not found" for an unknown name, making only the existence-check call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:EmptyArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        { Set-SfosCertificate -Name 'DoesNotExist' -CertificateFilePath $certPath -PrivateKeyFilePath $keyPath @conn -Confirm:$false } |
            Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly
    }

    It 'throws naming a missing local file, after the existence-check Get but before any update call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><Certificate><Status code="200">Configuration applied successfully.</Status></Certificate></Response>' }
            }
        }

        { Set-SfosCertificate -Name 'PortalCert' -CertificateFilePath (Join-Path $TestDrive 'missing.pem') -PrivateKeyFilePath $keyPath @conn -Confirm:$false } |
            Should -Throw '*does not exist*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        Set-SfosCertificate -Name 'PortalCert' -CertificateFilePath $certPath -PrivateKeyFilePath $keyPath @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}

Describe 'Remove-SfosCertificate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
    }

    It 'sends a Remove request carrying the name, without a prior existence check' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="200">Configuration applied successfully.</Status></Certificate></Response>' }
        }

        Remove-SfosCertificate -Name 'PortalCert' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and
            $InnerXml -match '<Certificate>' -and
            $InnerXml -match '<Name>PortalCert</Name>'
        }
    }

    It 'throws naming the firewall error code on a 5xx failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Certificate><Status code="504">Operation failed. Certificate is referenced by another entity.</Status></Certificate></Response>' }
        }

        { Remove-SfosCertificate -Name 'PortalCert' @conn -Confirm:$false } | Should -Throw '*504*'
    }

    It '-WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        Remove-SfosCertificate -Name 'PortalCert' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }
}

Describe 'Export-SfosCertificate' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $utf8 = [System.Text.Encoding]::UTF8
        $script:CertBytes = $utf8.GetBytes("-----BEGIN CERTIFICATE-----`nFAKECERT`n-----END CERTIFICATE-----`n")
        $script:KeyBytes = $utf8.GetBytes("-----BEGIN PRIVATE KEY-----`nFAKEKEY`n-----END PRIVATE KEY-----`n")
        $snapVersionBytes = $utf8.GetBytes('19.5.5.123')

        $entities = New-TestSfosResponseEnvelope -Body (
            '<Certificate transactionid=""><Name>PortalCert</Name><CertificateFormat>pem</CertificateFormat><CertificateFile>PortalCert.pem</CertificateFile><PrivateKeyFile>PortalCert.key</PrivateKeyFile></Certificate>'
        )
        $script:ExportArchive = New-TestSfosArchive -EntitiesXml $entities -File @(
            @{ Name = './Files/CertificateFile/0/PortalCert.pem'; Content = $script:CertBytes }
            @{ Name = './Files/PrivateKeyFile/0/PortalCert.key'; Content = $script:KeyBytes }
            @{ Name = './snapversion'; Content = $snapVersionBytes }
        )
    }

    It 'writes only the certificate/key files to -Path and returns exactly those paths' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:ExportArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        # Measured: despite the help text ("Created if it does not exist"), the cmdlet's
        # Copy-Item call does not create -Path itself, so the target directory is created
        # here rather than exercising that gap - see the test file header for the finding.
        $target = Join-Path $TestDrive 'export1'
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        $result = @(Export-SfosCertificate -Name 'PortalCert' -Path $target @conn -Confirm:$false)

        $result.Count | Should -Be 2
        foreach ($path in $result) { Test-Path -LiteralPath $path | Should -Be $true }

        $writtenNames = @($result | ForEach-Object { Split-Path -Path $_ -Leaf } | Sort-Object)
        $writtenNames | Should -Be @('PortalCert.key', 'PortalCert.pem')

        $writtenFiles = @(Get-ChildItem -LiteralPath $target -File)
        $writtenFiles.Count | Should -Be 2
        $writtenFiles.Name | Should -Not -Contain 'Entities.xml'
        $writtenFiles.Name | Should -Not -Contain 'snapversion'

        $readCert = [System.IO.File]::ReadAllBytes((Join-Path $target 'PortalCert.pem'))
        $readKey = [System.IO.File]::ReadAllBytes((Join-Path $target 'PortalCert.key'))
        [Convert]::ToBase64String($readCert) | Should -Be ([Convert]::ToBase64String($script:CertBytes))
        [Convert]::ToBase64String($readKey) | Should -Be ([Convert]::ToBase64String($script:KeyBytes))
    }

    It 'throws "was not found" when the firewall answers plain XML (no match)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><Certificate transactionid=""><Status>No. of records Zero.</Status></Certificate></Response>' }
        }

        { Export-SfosCertificate -Name 'DoesNotExist' -Path (Join-Path $TestDrive 'export2') @conn -Confirm:$false } |
            Should -Throw '*was not found*'
    }

    It '-WhatIf does not call the API and writes nothing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        $target = Join-Path $TestDrive 'export3'
        Export-SfosCertificate -Name 'PortalCert' -Path $target @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
        Test-Path -LiteralPath $target | Should -Be $false
    }
}

Describe 'CertificateAuthority - Get parses the archive' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $entities = New-TestSfosResponseEnvelope -Body (
            '<CertificateAuthority transactionid=""><Name>CorporateRootCA</Name><Format>PEM</Format><CACertFile>CorporateRootCA.pem</CACertFile><CAPrivateKeyFile>CorporateRootCA.key</CAPrivateKeyFile><Type>Uploaded</Type></CertificateAuthority>' +
            '<CertificateAuthority transactionid=""><Name>PublicRootCA</Name><Format>PEM</Format><CACertFile>PublicRootCA.pem</CACertFile><CAPrivateKeyFile></CAPrivateKeyFile><Type>Built-in</Type></CertificateAuthority>'
        )
        $script:TwoCaArchive = New-TestSfosArchive -EntitiesXml $entities
    }

    It 'returns PSCustomObjects with Name, Format, CACertFile, CAPrivateKeyFile, Type and HasPrivateKey' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificateAuthority @conn)

        $result.Count | Should -Be 2
        $corp = $result | Where-Object Name -eq 'CorporateRootCA'
        $corp.Format | Should -Be 'PEM'
        $corp.CACertFile | Should -Be 'CorporateRootCA.pem'
        $corp.CAPrivateKeyFile | Should -Be 'CorporateRootCA.key'
        $corp.Type | Should -Be 'Uploaded'
        $corp.HasPrivateKey | Should -Be $true
        ($result | Where-Object Name -eq 'PublicRootCA').HasPrivateKey | Should -Be $false
    }

    It '-NameLike filters client-side to the exact match' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificateAuthority -NameLike 'PublicRootCA' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'PublicRootCA'
    }

    It '-AsXml returns the raw XmlElement nodes' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCertificateAuthority -NameLike 'CorporateRootCA' -AsXml @conn)

        $result.Count | Should -Be 1
        $result[0] | Should -BeOfType [System.Xml.XmlElement]
    }

    It 'a "No. of records Zero." response returns an empty array without throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CertificateAuthority transactionid=""><Status>No. of records Zero.</Status></CertificateAuthority></Response>' }
        }

        $result = @(Get-SfosCertificateAuthority -NameLike 'DoesNotExist' @conn)
        $result.Count | Should -Be 0
    }
}

Describe 'New-SfosCertificateAuthority' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $caCertPath = Join-Path $TestDrive 'ca-root.pem'
        Set-Content -LiteralPath $caCertPath -Value 'fake ca cert'
        $caKeyPath = Join-Path $TestDrive 'ca-root.key'
        Set-Content -LiteralPath $caKeyPath -Value 'fake ca key'
    }

    It 'trust-anchor-only upload sends the default Format PEM and the file via MultipartFile' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="200">Configuration applied successfully.</Status></CertificateAuthority></Response>' }
        }

        New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $caCertPath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="add">' -and
            $InnerXml -match '<CertificateAuthority>' -and
            $InnerXml -match '<Name>CorporateRootCA</Name>' -and
            $InnerXml -match '<Format>PEM</Format>' -and
            $InnerXml -match '<CACertFile>ca-root\.pem</CACertFile>' -and
            $InnerXml -notmatch '<CAPrivateKeyFile>' -and
            $MultipartFile.CACertFile -eq $caCertPath
        }
    }

    It 'with a private key and password sends both files and the decrypted Password element' {
        $securePwd = ConvertTo-SecureString 'CaKeyPwd456' -AsPlainText -Force
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="200">Configuration applied successfully.</Status></CertificateAuthority></Response>' }
        }

        New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $caCertPath -CAPrivateKeyFilePath $caKeyPath -CAPassword $securePwd @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<CAPrivateKeyFile>ca-root\.key</CAPrivateKeyFile>' -and
            $InnerXml -match '<Password>CaKeyPwd456</Password>' -and
            $MultipartFile.CAPrivateKeyFile -eq $caKeyPath
        }
    }

    It 'throws naming the missing certificate file before any API call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        { New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath (Join-Path $TestDrive 'missing.pem') @conn -Confirm:$false } |
            Should -Throw '*does not exist*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }

    It 'throws naming a missing private key file before any API call' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        { New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $caCertPath -CAPrivateKeyFilePath (Join-Path $TestDrive 'missing.key') @conn -Confirm:$false } |
            Should -Throw '*does not exist*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }

    It 'throws on a duplicate name (measured 502)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="502">Operation failed. Entity having same name already exists.</Status></CertificateAuthority></Response>' }
        }

        { New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $caCertPath @conn -Confirm:$false } | Should -Throw '*502*'
    }

    It 'throws on duplicate certificate content under a new name (measured 503)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="503">Operation failed. Entity having same parameter details already exists.</Status></CertificateAuthority></Response>' }
        }

        { New-SfosCertificateAuthority -Name 'AnotherName' -CACertFilePath $caCertPath @conn -Confirm:$false } | Should -Throw '*503*'
    }

    It '-WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $caCertPath @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }
}

Describe 'Set-SfosCertificateAuthority - read-modify-write on Format' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }
        $newCertPath = Join-Path $TestDrive 'ca-root-renewed.pem'
        Set-Content -LiteralPath $newCertPath -Value 'fake renewed ca cert'

        $existingEntities = New-TestSfosResponseEnvelope -Body (
            '<CertificateAuthority transactionid=""><Name>CorporateRootCA</Name><Format>DER</Format><CACertFile>CorporateRootCA.pem</CACertFile><CAPrivateKeyFile></CAPrivateKeyFile><Type>Uploaded</Type></CertificateAuthority>'
        )
        $script:ExistingCaArchive = New-TestSfosArchive -EntitiesXml $existingEntities
    }

    It 'preserves the existing Format when -Format is not passed' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="200">Configuration applied successfully.</Status></CertificateAuthority></Response>' }
            }
        }

        Set-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $newCertPath @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">' -and
            $InnerXml -match '<Format>DER</Format>'
        }
    }

    It 'overrides Format when -Format is passed explicitly' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="200">Configuration applied successfully.</Status></CertificateAuthority></Response>' }
            }
        }

        Set-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $newCertPath -Format 'PEM' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Format>PEM</Format>'
        }
    }

    It 'throws naming a missing local file before any API call (checked ahead of the existence-check Get)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        { Set-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath (Join-Path $TestDrive 'missing.pem') @conn -Confirm:$false } |
            Should -Throw '*does not exist*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }

    It 'throws "was not found" for an unknown name, making only the existence-check call' {
        $emptyEntities = New-TestSfosResponseEnvelope -Body ''
        $emptyArchive = New-TestSfosArchive -EntitiesXml $emptyEntities

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $emptyArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        { Set-SfosCertificateAuthority -Name 'DoesNotExist' -CACertFilePath $newCertPath @conn -Confirm:$false } |
            Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly
    }

    It '-WhatIf makes the existence-check call but never sends the update' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        Set-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath $newCertPath @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Set operation="update">'
        }
    }
}

Describe 'Remove-SfosCertificateAuthority' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $existingEntities = New-TestSfosResponseEnvelope -Body (
            '<CertificateAuthority transactionid=""><Name>CorporateRootCA</Name><Format>PEM</Format><CACertFile>CorporateRootCA.pem</CACertFile><CAPrivateKeyFile></CAPrivateKeyFile><Type>Uploaded</Type></CertificateAuthority>'
        )
        $script:ExistingCaArchive = New-TestSfosArchive -EntitiesXml $existingEntities
    }

    It 'reads the object first, then sends a Remove request carrying the name' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="200">Configuration applied successfully.</Status></CertificateAuthority></Response>' }
            }
        }

        Remove-SfosCertificateAuthority -Name 'CorporateRootCA' @conn -Confirm:$false

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 2 -Exactly
        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>' -and $InnerXml -match '<Name>CorporateRootCA</Name>'
        }
    }

    It 'throws "was not found" without attempting the Remove call' {
        $emptyEntities = New-TestSfosResponseEnvelope -Body ''
        $emptyArchive = New-TestSfosArchive -EntitiesXml $emptyEntities

        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $emptyArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        { Remove-SfosCertificateAuthority -Name 'DoesNotExist' @conn -Confirm:$false } | Should -Throw '*was not found*'

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 1 -Exactly
    }

    It 'throws naming the firewall error code on a 5xx failure' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            if ($InnerXml -match '<Get>') {
                [PSCustomObject]@{ Content = $script:ExistingCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
            }
            else {
                [PSCustomObject]@{ Content = '<Response><CertificateAuthority><Status code="504">Operation failed. CA is used.</Status></CertificateAuthority></Response>' }
            }
        }

        { Remove-SfosCertificateAuthority -Name 'CorporateRootCA' @conn -Confirm:$false } | Should -Throw '*504*'
    }

    It '-WhatIf makes the existence-check call but never sends the Remove' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:ExistingCaArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        Remove-SfosCertificateAuthority -Name 'CorporateRootCA' @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly -ParameterFilter {
            $InnerXml -match '<Remove>'
        }
    }
}

Describe 'Export-SfosCertificateAuthority' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $utf8 = [System.Text.Encoding]::UTF8
        $script:CaCertBytes = $utf8.GetBytes("-----BEGIN CERTIFICATE-----`nFAKECACERT`n-----END CERTIFICATE-----`n")

        $entities = New-TestSfosResponseEnvelope -Body (
            '<CertificateAuthority transactionid=""><Name>CorporateRootCA</Name><Format>PEM</Format><CACertFile>CorporateRootCA.pem</CACertFile><CAPrivateKeyFile></CAPrivateKeyFile><Type>Uploaded</Type></CertificateAuthority>'
        )
        $script:CaExportArchive = New-TestSfosArchive -EntitiesXml $entities -File @(
            @{ Name = './Files/CACertFile/0/CorporateRootCA.pem'; Content = $script:CaCertBytes }
        )
    }

    It 'writes only the certificate file to -Path and returns its path' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:CaExportArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        # Measured: same directory-creation gap as Export-SfosCertificate - see the test file
        # header and the "writes only the certificate/key files" test above.
        $target = Join-Path $TestDrive 'ca-export1'
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        $result = @(Export-SfosCertificateAuthority -Name 'CorporateRootCA' -Path $target @conn -Confirm:$false)

        $result.Count | Should -Be 1
        Split-Path -Path $result[0] -Leaf | Should -Be 'CorporateRootCA.pem'
        $readCaCert = [System.IO.File]::ReadAllBytes($result[0])
        [Convert]::ToBase64String($readCaCert) | Should -Be ([Convert]::ToBase64String($script:CaCertBytes))

        $writtenFiles = @(Get-ChildItem -LiteralPath $target -File)
        $writtenFiles.Count | Should -Be 1
        $writtenFiles.Name | Should -Not -Contain 'Entities.xml'
    }

    It 'throws "was not found" when the firewall answers plain XML (no match)' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CertificateAuthority transactionid=""><Status>No. of records Zero.</Status></CertificateAuthority></Response>' }
        }

        { Export-SfosCertificateAuthority -Name 'DoesNotExist' -Path (Join-Path $TestDrive 'ca-export2') @conn -Confirm:$false } |
            Should -Throw '*was not found*'
    }

    It '-WhatIf does not call the API' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates

        Export-SfosCertificateAuthority -Name 'CorporateRootCA' -Path (Join-Path $TestDrive 'ca-export3') @conn -WhatIf

        Should -Invoke -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -Times 0 -Exactly
    }
}

Describe 'Get-SfosCRL' {

    BeforeAll {
        $conn = @{
            Firewall = 'fw.example.test'
            Port     = 4444
            Username = 'apiuser'
            Password = (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        }

        $entities = New-TestSfosResponseEnvelope -Body (
            '<CRL transactionid=""><Name>Default</Name><CRLFile>Default.crl</CRLFile></CRL>' +
            '<CRL transactionid=""><Name>Secondary</Name><CRLFile>Secondary.crl</CRLFile></CRL>'
        )
        $script:TwoCrlArchive = New-TestSfosArchive -EntitiesXml $entities
    }

    It 'returns PSCustomObjects with Name and CRLFile' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCrlArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCRL @conn)

        $result.Count | Should -Be 2
        ($result | Where-Object Name -eq 'Default').CRLFile | Should -Be 'Default.crl'
    }

    It '-NameLike filters client-side to the exact match' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCrlArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCRL -NameLike 'Secondary' @conn)

        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'Secondary'
    }

    It '-AsXml returns the raw XmlElement nodes' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = $script:TwoCrlArchive; Headers = @{ 'Content-Type' = 'application/octet-stream' } }
        }

        $result = @(Get-SfosCRL -NameLike 'Default' -AsXml @conn)

        $result.Count | Should -Be 1
        $result[0] | Should -BeOfType [System.Xml.XmlElement]
    }

    It 'a "No. of records Zero." response returns an empty array without throwing' {
        Mock -CommandName Invoke-SfosApi -ModuleName SophosFirewall.Certificates -MockWith {
            [PSCustomObject]@{ Content = '<Response><Login><status>Authentication Successful</status></Login><CRL transactionid=""><Status>No. of records Zero.</Status></CRL></Response>' }
        }

        $result = @(Get-SfosCRL -NameLike 'DoesNotExist' @conn)
        $result.Count | Should -Be 0
    }
}

AfterAll {
    # The archive-building helpers were declared as function:global: so BeforeAll blocks in
    # every Describe above could see them; remove them so they do not leak into whatever test
    # file Pester loads next in the same session.
    foreach ($name in 'New-TestSfosTarHeader', 'Get-TestSfosPaddedBlocks', 'New-TestSfosArchive', 'New-TestSfosResponseEnvelope') {
        Remove-Item -Path "Function:\$name" -ErrorAction SilentlyContinue
    }
}
