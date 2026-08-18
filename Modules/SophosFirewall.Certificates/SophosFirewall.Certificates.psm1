#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.5' }

<#
.SYNOPSIS
    Manages the certificate store of a Sophos Firewall: certificates, certificate
    authorities and certificate revocation lists.

.DESCRIPTION
    Functions for the SYSTEM > Certificates area of the Sophos Firewall XML API (SFOS 22.0).
    A certificate identifies a service the firewall publishes or inspects; a certificate
    authority is the issuer the firewall trusts when it validates one; a revocation list
    names the certificates an authority has withdrawn.

    These endpoints do not answer with XML. A read returns an archive holding the stored
    files and a manifest describing them, so the Get cmdlets here return objects built from
    that manifest, and the Export cmdlets write the files themselves to disk.

    Total Functions: 13 (11 exported, 2 internal helpers) - see README.md for the full
    cmdlet table.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

    Three limitations come from the API, not from this module:

    - A revocation list can be read but not uploaded. Every documented request shape was
      refused, including the one from the vendor's own sample, so there is no New-SfosCRL.
    - Generating a certificate authority on the appliance is documented, but the operation
      reports success without storing anything, so it is deliberately not wrapped.
    - A certificate is stored as PEM whatever format it arrives in, and a private key is
      re-encoded, so an exported file is equivalent to the uploaded one rather than
      identical to it.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosCertificate

    Connects to the firewall and lists the stored certificates.

.EXAMPLE
    New-SfosCertificate -Name 'PortalCert' -PfxFilePath 'C:\pki\portal.pfx' -PfxPassword $pfxPassword
    Export-SfosCertificate -Name 'PortalCert' -Path 'C:\pki\export'

    Uploads a PKCS#12 bundle and writes the stored files back to disk.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>


#region Certificate

<#
.SYNOPSIS
    Builds the Set request body and multipart file map for a Certificate upload. Internal
    helper, not exported.

.DESCRIPTION
    Certificate has no partial update: every Set call - add or update alike - re-uploads the
    complete certificate material, so New-SfosCertificate and Set-SfosCertificate share this
    builder instead of doing read-modify-write on separate fields. It validates that the
    given file(s) exist, escapes every value that goes into the XML, and returns the inner
    XML together with the -MultipartFile map Invoke-SfosApi needs.

    Two upload shapes are supported, matching what was measured against a live firewall:
    a single PKCS#12/PFX file (CertificateFormat pkcs12, lower case - any other casing is
    refused with 501), or a separate PEM certificate and unencrypted private key
    (CertificateFormat pem). An encrypted PEM private key with a Password was never measured
    to work and is intentionally not offered here.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the Certificate object.

.PARAMETER PfxFilePath
    Path to a local .pfx/.p12 file. Selects the PKCS#12 upload shape.

.PARAMETER PfxPassword
    Optional. Export password of the PFX file, as a SecureString.

.PARAMETER CertificateFilePath
    Path to a local PEM certificate file. Selects the two-file PEM upload shape; requires
    -PrivateKeyFilePath as well.

.PARAMETER PrivateKeyFilePath
    Path to a local, unencrypted PEM private key file matching -CertificateFilePath.
#>
function New-SfosCertificateUploadPayload {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. This function
    # only assembles the request body in memory; the firewall is contacted by the caller,
    # which declares ShouldProcess itself.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Pkcs12')]
        [string]$PfxFilePath,

        [Parameter(ParameterSetName = 'Pkcs12')]
        [SecureString]$PfxPassword,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [string]$CertificateFilePath,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [string]$PrivateKeyFilePath
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($PSCmdlet.ParameterSetName -eq 'Pkcs12') {
        if (-not (Test-Path -LiteralPath $PfxFilePath -PathType Leaf)) {
            throw "The PFX file '$PfxFilePath' does not exist."
        }
        $pfxFile = Get-Item -LiteralPath $PfxFilePath
        $fileNameEsc = ConvertTo-SfosXmlEscaped -Text $pfxFile.Name

        $passwordXml = ''
        if ($PSBoundParameters.ContainsKey('PfxPassword') -and $PfxPassword) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
            try {
                $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                $passwordEsc = ConvertTo-SfosXmlEscaped -Text $plainPassword
                $passwordXml = "<Password>$passwordEsc</Password>"
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
                $plainPassword = $null
            }
        }

        $inner = @"
<Set operation="$Operation">
  <Certificate>
    <Name>$nameEsc</Name>
    <Action>UploadCertificate</Action>
    <CertificateFormat>pkcs12</CertificateFormat>
    $passwordXml
    <CertificateFile>$fileNameEsc</CertificateFile>
  </Certificate>
</Set>
"@

        return @{
            InnerXml      = $inner
            MultipartFile = @{ CertificateFile = $pfxFile.FullName }
        }
    }

    if (-not (Test-Path -LiteralPath $CertificateFilePath -PathType Leaf)) {
        throw "The certificate file '$CertificateFilePath' does not exist."
    }
    if (-not (Test-Path -LiteralPath $PrivateKeyFilePath -PathType Leaf)) {
        throw "The private key file '$PrivateKeyFilePath' does not exist."
    }
    $certFile = Get-Item -LiteralPath $CertificateFilePath
    $keyFile = Get-Item -LiteralPath $PrivateKeyFilePath
    $certNameEsc = ConvertTo-SfosXmlEscaped -Text $certFile.Name
    $keyNameEsc = ConvertTo-SfosXmlEscaped -Text $keyFile.Name

    $inner = @"
<Set operation="$Operation">
  <Certificate>
    <Name>$nameEsc</Name>
    <Action>UploadCertificate</Action>
    <CertificateFormat>pem</CertificateFormat>
    <CertificateFile>$certNameEsc</CertificateFile>
    <PrivateKeyFile>$keyNameEsc</PrivateKeyFile>
  </Certificate>
</Set>
"@

    return @{
        InnerXml      = $inner
        MultipartFile = @{ CertificateFile = $certFile.FullName; PrivateKeyFile = $keyFile.FullName }
    }
}

<#
.SYNOPSIS
    Retrieves Certificate objects from a Sophos Firewall.

.DESCRIPTION
    Returns Certificate objects (SYSTEM > Certificates > Certificate). A Certificate object
    holds a certificate and, usually, its private key, uploaded either as a single PKCS#12
    file or as a separate certificate/key pair - see New-SfosCertificate.

    A Get that matches at least one object answers as a downloaded file
    (application/octet-stream, a tar archive holding Entities.xml plus the certificate/key
    files); a Get that matches nothing answers as plain XML with "No. of records Zero.".
    This cmdlet handles both shapes and always returns PowerShell objects built from
    Entities.xml, never the archive itself - use Export-SfosCertificate to get the actual
    certificate/key files onto disk.

    If the archive's internal structure breaks before every object was read - the firewall
    is known to corrupt the tar header of an object whose name has non-ASCII characters -
    ConvertFrom-SfosArchive (SophosFirewall.Core) already emits a warning naming the last
    object read cleanly. That warning is not suppressed here; Entities.xml itself, and so
    every object this cmdlet lists, is unaffected by that corruption.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern, sent to the firewall as a server-side pre-filter
    and re-applied client-side. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements from Entities.xml instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per Certificate, with the
    properties Name, CertificateFormat (the format the firewall stored it as - an uploaded
    DER file is measured to come back as CertificateFormat "pem"; the firewall converts on
    upload), CertificateFile, PrivateKeyFile and HasPrivateKey. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosCertificate

    Lists every Certificate object on the firewall of the current connection, including the
    built-in ApplianceCertificate.

.EXAMPLE
    Get-SfosCertificate -NameLike 'Portal'

    Lists all Certificate objects whose name contains 'Portal'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/Certificate/Certificate.html

.LINK
    New-SfosCertificate
#>
function Get-SfosCertificate {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <Certificate>
    $filterXml
  </Certificate>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving Certificate objects: $($_.Exception.Message)"
    }

    # A Get with at least one match answers application/octet-stream (a tar archive); a Get
    # with none answers text/xml with "No. of records Zero." - the content type depends on
    # whether anything matched, not on the entity.
    if ($response.Content -is [byte[]]) {
        $archive = ConvertFrom-SfosArchive -Bytes $response.Content
        if (-not $archive.Entities) {
            throw 'Error retrieving Certificate objects: the firewall returned a file response with no readable Entities.xml.'
        }
        Assert-SfosApiReturnSuccess -Xml $archive.Entities -ObjectName 'Certificate' -Action 'get'
        $nodes = Select-Xml -Xml $archive.Entities -XPath '/Response/Certificate[Name]' | ForEach-Object -Process { $_.Node }
    }
    else {
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Certificate' -Action 'get'
        $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/Certificate[Name]' | ForEach-Object -Process { $_.Node }
    }

    $certObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name              = [string]$node.Name
            CertificateFormat = [string]$node.CertificateFormat
            CertificateFile   = [string]$node.CertificateFile
            PrivateKeyFile    = [string]$node.PrivateKeyFile
            HasPrivateKey     = [bool]([string]$node.PrivateKeyFile)
        }
    }

    $certObjects = @($certObjects)
    if ($NameLike) {
        $certObjects = @($certObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($certObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $certObjects
}

<#
.SYNOPSIS
    Creates a Certificate object on a Sophos Firewall by uploading certificate material.

.DESCRIPTION
    Uploads a certificate to SYSTEM > Certificates > Certificate, either as a single PKCS#12
    (.pfx/.p12) file or as a separate PEM certificate and unencrypted private key. Exactly one
    of the two shapes must be used per call; PowerShell enforces this through parameter sets.

    The documentation also lists Action values for generating a self-signed certificate, a
    CSR, or requesting a Let's Encrypt certificate. None of those were reproducible against a
    live firewall - every candidate Action value tried was rejected - so this cmdlet only
    implements the upload path, which is measured to work.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Certificates area.

.PARAMETER Name
    Required. Name of the Certificate object. The Add operation's own documentation limits
    this to 50 characters; the Delete operation's documentation for the same field says 60 -
    the two disagree, so this cmdlet uses the stricter Add limit of 50.

.PARAMETER PfxFilePath
    Required in the PKCS#12 form. Path to a local .pfx/.p12 file containing the certificate
    and, usually, its private key.

.PARAMETER PfxPassword
    Optional. Export password of the PFX file, as a SecureString. Never written to the
    console, help text or an error message in plain text.

.PARAMETER CertificateFilePath
    Required in the PEM form. Path to a local PEM certificate file. Requires
    -PrivateKeyFilePath as well.

.PARAMETER PrivateKeyFilePath
    Required in the PEM form. Path to a local, unencrypted PEM private key file matching
    -CertificateFilePath. An encrypted key was never measured to work against a live firewall
    and is not supported here.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create,
    or if the given file(s) do not exist.

.EXAMPLE
    New-SfosCertificate -Name 'PortalCertificate' -PfxFilePath 'C:\certs\portal.pfx' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    $pfxPassword = Read-Host -AsSecureString
    New-SfosCertificate -Name 'PortalCertificate' -PfxFilePath 'C:\certs\portal.pfx' -PfxPassword $pfxPassword

    Uploads a PFX file with its export password. The cmdlet asks for confirmation before it
    writes.

.EXAMPLE
    New-SfosCertificate -Name 'PortalCertificate' -CertificateFilePath 'C:\certs\portal.pem' -PrivateKeyFilePath 'C:\certs\portal.key'

    Uploads a certificate and its unencrypted private key as two separate PEM files.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/Certificate/operations/AddCertificate%26UpdateCertificate.html

.LINK
    Get-SfosCertificate
#>
function New-SfosCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z0-9_@.-]+$')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Pkcs12')]
        [ValidateNotNullOrEmpty()]
        [string]$PfxFilePath,

        [Parameter(ParameterSetName = 'Pkcs12')]
        [SecureString]$PfxPassword,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateFilePath,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [ValidateNotNullOrEmpty()]
        [string]$PrivateKeyFilePath,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("Certificate '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $payloadParams = @{
            Operation = 'add'
            Name      = $Name
        }
        if ($PSCmdlet.ParameterSetName -eq 'Pkcs12') {
            $payloadParams.PfxFilePath = $PfxFilePath
            if ($PSBoundParameters.ContainsKey('PfxPassword')) {
                $payloadParams.PfxPassword = $PfxPassword
            }
        }
        else {
            $payloadParams.CertificateFilePath = $CertificateFilePath
            $payloadParams.PrivateKeyFilePath = $PrivateKeyFilePath
        }

        try {
            $payload = New-SfosCertificateUploadPayload @payloadParams
        }
        catch {
            throw "Failed to create Certificate object '$Name': $($_.Exception.Message)"
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $payload.InnerXml -MultipartFile $payload.MultipartFile `
                -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create Certificate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Certificate' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Replaces the certificate material of an existing Certificate object on a Sophos Firewall.

.DESCRIPTION
    Certificate has no field-by-field update: the whole certificate (and, usually, its
    private key) is replaced by whatever is uploaded, so this cmdlet always sends complete
    new material - there is nothing to read back and merge. It first confirms the named
    object exists and throws a clear "was not found" error if it does not, then re-uploads
    with operation="update" using the same PKCS#12/PEM shapes as New-SfosCertificate.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Certificates area.

.PARAMETER Name
    Required. Name of the existing Certificate object to replace.

.PARAMETER PfxFilePath
    Required in the PKCS#12 form. Path to a local .pfx/.p12 file containing the new
    certificate and, usually, its private key.

.PARAMETER PfxPassword
    Optional. Export password of the PFX file, as a SecureString. Never written to the
    console, help text or an error message in plain text.

.PARAMETER CertificateFilePath
    Required in the PEM form. Path to a local PEM certificate file. Requires
    -PrivateKeyFilePath as well.

.PARAMETER PrivateKeyFilePath
    Required in the PEM form. Path to a local, unencrypted PEM private key file matching
    -CertificateFilePath.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name,
    for example from Get-SfosCertificate.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    if the named object does not exist, or if the given file(s) do not exist.

.EXAMPLE
    Set-SfosCertificate -Name 'PortalCertificate' -CertificateFilePath 'C:\certs\renewed.pem' -PrivateKeyFilePath 'C:\certs\renewed.key' -WhatIf

    Shows what the call would replace without sending it to the firewall.

.EXAMPLE
    Set-SfosCertificate -Name 'PortalCertificate' -CertificateFilePath 'C:\certs\renewed.pem' -PrivateKeyFilePath 'C:\certs\renewed.key'

    Replaces the certificate and key of the named object. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/Certificate/operations/AddCertificate%26UpdateCertificate.html

.LINK
    Get-SfosCertificate
#>
function Set-SfosCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z0-9_@.-]+$')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Pkcs12')]
        [ValidateNotNullOrEmpty()]
        [string]$PfxFilePath,

        [Parameter(ParameterSetName = 'Pkcs12')]
        [SecureString]$PfxPassword,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateFilePath,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [ValidateNotNullOrEmpty()]
        [string]$PrivateKeyFilePath,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $existing = @(Get-SfosCertificate -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The Certificate object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("Certificate '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $payloadParams = @{
            Operation = 'update'
            Name      = $Name
        }
        if ($PSCmdlet.ParameterSetName -eq 'Pkcs12') {
            $payloadParams.PfxFilePath = $PfxFilePath
            if ($PSBoundParameters.ContainsKey('PfxPassword')) {
                $payloadParams.PfxPassword = $PfxPassword
            }
        }
        else {
            $payloadParams.CertificateFilePath = $CertificateFilePath
            $payloadParams.PrivateKeyFilePath = $PrivateKeyFilePath
        }

        try {
            $payload = New-SfosCertificateUploadPayload @payloadParams
        }
        catch {
            throw "Failed to update Certificate object '$Name': $($_.Exception.Message)"
        }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $payload.InnerXml -MultipartFile $payload.MultipartFile `
                -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update Certificate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Certificate' -Action 'edit' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a Certificate object from a Sophos Firewall.

.DESCRIPTION
    Removes a Certificate object. Removal is measured to work for real against a live
    firewall - the object is gone from a following Get, not just reported as removed.

    Never remove the certificate the current connection authenticates with, and never remove
    a certificate that is still referenced elsewhere (a Web Server, an authentication policy,
    ...); the firewall documents dedicated failure codes for exactly that ("child exists").

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Certificates area.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name,
    for example from Get-SfosCertificate.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosCertificate -Name 'PortalCertificate' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosCertificate -Name 'PortalCertificate'

    Removes the named object. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/Certificate/operations/Delete%20Certificate.html

.LINK
    Get-SfosCertificate
#>
function Remove-SfosCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z0-9_@.-]+$')]
        [string]$Name,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("Certificate '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><Certificate><Name>$nameEsc</Name></Certificate></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove Certificate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Certificate' -Action 'remove' -Target $Name
    }
}

<#
.SYNOPSIS
    Writes the certificate and private key files of a Certificate object to disk.

.DESCRIPTION
    A Get on Certificate answers as a downloaded tar archive, not as fields - the actual
    certificate and (usually) private key bytes only exist in that archive, never in the
    PSCustomObject Get-SfosCertificate returns. This cmdlet is named Export- rather than
    following the Export-Sfos<Entity>s / bulk-CSV convention used elsewhere in this module
    family (see the project rules, naming section), because it exports one object's actual
    file content to disk, not a CSV summary of many objects.

    It requests the single named object with an exact-match server-side filter, extracts the
    archive to -Path via ConvertFrom-SfosArchive (SophosFirewall.Core), and returns the full
    paths of every file written.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

.PARAMETER Name
    Required. Name of the Certificate object to export.

.PARAMETER Path
    Required. Directory to write the certificate/key file(s) to. Created if it does not
    exist.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name,
    for example from Get-SfosCertificate.

.OUTPUTS
    System.String. The full path of every file written to -Path. Raises an error if the named
    object does not exist.

.EXAMPLE
    Export-SfosCertificate -Name 'PortalCertificate' -Path 'C:\Sfos\Export' -WhatIf

    Shows what the call would write without contacting the firewall.

.EXAMPLE
    Export-SfosCertificate -Name 'PortalCertificate' -Path 'C:\Sfos\Export'

    Writes the certificate (and private key, if the object has one) to the given directory
    and returns the file paths.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/Certificate/Certificate.html

.LINK
    Get-SfosCertificate
#>
function Export-SfosCertificate {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[A-Za-z0-9_@.-]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("Certificate '$Name' on $($params.Firewall)", "Export to '$Path'")) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Get><Certificate><Filter><key name=`"Name`" criteria=`"=`">$nameEsc</key></Filter></Certificate></Get>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to export Certificate object '$Name': $($_.Exception.Message)"
        }

        if ($response.Content -is [byte[]]) {
            # Unpack to a scratch folder first. The archive also carries its own manifest
            # and a version marker; only the certificate files belong in -Path.
            # The help promises the target directory is created when it is missing.
            if (-not (Test-Path -LiteralPath $Path)) {
                New-Item -ItemType Directory -Path $Path -Force | Out-Null
            }

            $staging = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $staging -Force | Out-Null
            try {
                $archive = ConvertFrom-SfosArchive -Bytes $response.Content -ExtractTo $staging
                if (-not $archive.Entities) {
                    throw "Failed to export Certificate object '$Name': the firewall returned a file response with no readable Entities.xml."
                }
                Assert-SfosApiReturnSuccess -Xml $archive.Entities -ObjectName 'Certificate' -Action 'export' -Target $Name

                $members = @($archive.Files | Where-Object -FilterScript { $_.Name -like './Files/*' -and $_.Path })
                if (-not $members.Count) {
                    throw "The Certificate object '$Name' was not found."
                }

                $written = foreach ($member in $members) {
                    $target = Join-Path $Path (Split-Path -Path $member.Path -Leaf)
                    Copy-Item -LiteralPath $member.Path -Destination $target -Force
                    $target
                }
                return @($written)
            }
            finally {
                Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Certificate' -Action 'export' -Target $Name
        throw "The Certificate object '$Name' was not found."
    }
}

#endregion

#region CertificateAuthority

<#
.SYNOPSIS
    Builds the Set request body for a CertificateAuthority entity.

.DESCRIPTION
    Builds the inner XML for a Set operation on CertificateAuthority, so New- and
    Set-SfosCertificateAuthority send the same entity shape. Type is a read-only field on
    this entity (Built-in/Uploaded/Internal, set by the firewall itself) and is never part
    of the request.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the certificate authority object.

.PARAMETER Format
    PEM or DER - the format of the uploaded certificate file.

.PARAMETER CACertFileName
    Base file name of the certificate, matching the multipart upload's filename.

.PARAMETER CAPrivateKeyFileName
    Optional. Base file name of the private key, matching the multipart upload's filename.

.PARAMETER Password
    Optional. Passphrase protecting the private key, as a SecureString. It is decrypted
    inside this function and never leaves it as plain text.
#>
function ConvertTo-SfosCertificateAuthorityEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Format,

        [Parameter(Mandatory)]
        [string]$CACertFileName,

        [string]$CAPrivateKeyFileName,

        [SecureString]$Password
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $formatEsc = ConvertTo-SfosXmlEscaped -Text $Format
    $certFileEsc = ConvertTo-SfosXmlEscaped -Text $CACertFileName

    $keyXml = ''
    if ($CAPrivateKeyFileName) {
        $keyXml = "<CAPrivateKeyFile>$(ConvertTo-SfosXmlEscaped -Text $CAPrivateKeyFileName)</CAPrivateKeyFile>"
    }

    $passwordXml = ''
    if ($Password) {
        # The plain value exists only inside this block, never as a parameter or a variable
        # the caller could inspect.
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            $passwordXml = "<Password>$(ConvertTo-SfosXmlEscaped -Text $plain)</Password>"
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return @"
<Set operation="$Operation">
  <CertificateAuthority>
    <Name>$nameEsc</Name>
    <Format>$formatEsc</Format>
    <CACertFile>$certFileEsc</CACertFile>
    $keyXml
    $passwordXml
  </CertificateAuthority>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves Certificate Authority objects from a Sophos Firewall.

.DESCRIPTION
    Returns Certificate Authority objects (SYSTEM > Certificates > Certificate Authorities).
    A matching Get answers with a tar archive (application/octet-stream), never with plain
    XML - only a Get with zero matches answers as XML. This cmdlet reads the archive's
    Entities.xml for the object list; it never reads the archive's per-object certificate
    files, because at least one factory-shipped CA (a name with non-ASCII characters)
    reproducibly desyncs the tar block chain for every file stored after it on this
    firmware, while Entities.xml itself stays intact and complete. When that happens, a
    warning names the last object whose file could still be read; the object list returned
    by this cmdlet is unaffected by it. Use Export-SfosCertificateAuthority to retrieve one
    object's actual certificate file.

    Because an unfiltered Get on this entity can be large (several hundred built-in trust
    anchors) and is where the archive defect above was found, prefer -NameLike when you
    only need specific objects.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. Sent to the
    firewall as a server-side pre-filter and re-applied client-side. If omitted, every
    Certificate Authority object is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements from the archive's Entities.xml instead of
    PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per Certificate Authority, with
    the properties Name, Format, CACertFile, CAPrivateKeyFile, Type and HasPrivateKey
    (derived from CAPrivateKeyFile). Returns System.Xml.XmlElement when -AsXml is used, and
    an empty array when no object matches.

.EXAMPLE
    Get-SfosCertificateAuthority -NameLike 'CorporateRootCA'

    Lists every Certificate Authority object whose name contains 'CorporateRootCA'.

.EXAMPLE
    Get-SfosCertificateAuthority | Where-Object HasPrivateKey

    Lists every Certificate Authority object that was uploaded with its own signing key.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/CertificateAuthority/CertificateAuthority.html

.LINK
    New-SfosCertificateAuthority
#>
function Get-SfosCertificateAuthority {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <CertificateAuthority>
    $filterXml
  </CertificateAuthority>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving CertificateAuthority objects: $($_.Exception.Message)"
    }

    if ($response.Content -is [string]) {
        # No binary body means nothing matched - a real match always answers as a tar
        # archive, never as XML, on this entity.
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CertificateAuthority' -Action 'get'
        return @()
    }

    $archive = ConvertFrom-SfosArchive -Bytes $response.Content
    if (-not $archive.Entities) {
        throw 'CertificateAuthority Get returned a binary response whose Entities.xml could not be located or parsed.'
    }

    $nodes = Select-Xml -Xml $archive.Entities -XPath '/Response/CertificateAuthority[Name]' | ForEach-Object -Process { $_.Node }

    $caObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name             = [string]$node.Name
            Format           = [string]$node.Format
            CACertFile       = [string]$node.CACertFile
            CAPrivateKeyFile = [string]$node.CAPrivateKeyFile
            Type             = [string]$node.Type
            HasPrivateKey    = [bool]([string]$node.CAPrivateKeyFile)
        }
    }

    $caObjects = @($caObjects)
    if ($NameLike) {
        $caObjects = @($caObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($caObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $caObjects
}

<#
.SYNOPSIS
    Creates a Certificate Authority object on a Sophos Firewall.

.DESCRIPTION
    Uploads a certificate authority (trust anchor, optionally with its signing private key)
    as a new Certificate Authority object (SYSTEM > Certificates > Certificate Authorities).
    This is a true multipart file upload: the request XML references the files by name, the
    files themselves travel as separate parts of the same request. Both files are checked
    for existence before anything is sent. Type is a read-only field on this entity and is
    never sent - the firewall always records an uploaded object as 'Uploaded' regardless of
    whether a private key was supplied.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Certificates area.

.PARAMETER Name
    Required. Name of the object.

.PARAMETER CACertFilePath
    Required. Local path to the certificate file to upload.

.PARAMETER Format
    Optional. PEM or DER. Defaults to PEM.

.PARAMETER CAPrivateKeyFilePath
    Optional. Local path to the private key file, if this CA is also used for signing.

.PARAMETER CAPassword
    Optional. Passphrase protecting the private key, as a SecureString.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath 'C:\PKI\root.pem' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath 'C:\PKI\root.pem'

    Uploads a trust-anchor-only Certificate Authority. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/CertificateAuthority/operations/AddCertificateAuthority%26EditCertificateAuthority.html

.LINK
    Get-SfosCertificateAuthority
#>
function New-SfosCertificateAuthority {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CACertFilePath,

        [ValidateSet('PEM', 'DER')]
        [string]$Format = 'PEM',

        [string]$CAPrivateKeyFilePath,

        [SecureString]$CAPassword,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not (Test-Path -LiteralPath $CACertFilePath -PathType Leaf)) {
            throw "CACertFilePath '$CACertFilePath' does not exist."
        }
        if ($CAPrivateKeyFilePath -and -not (Test-Path -LiteralPath $CAPrivateKeyFilePath -PathType Leaf)) {
            throw "CAPrivateKeyFilePath '$CAPrivateKeyFilePath' does not exist."
        }

        if (-not $PSCmdlet.ShouldProcess("CertificateAuthority '$Name' on $($params.Firewall)", 'Create')) {
            return
        }


        $certFileName = [System.IO.Path]::GetFileName($CACertFilePath)
        $keyFileName = $null
        if ($CAPrivateKeyFilePath) { $keyFileName = [System.IO.Path]::GetFileName($CAPrivateKeyFilePath) }

        $inner = ConvertTo-SfosCertificateAuthorityEntityXml -Operation 'add' -Name $Name -Format $Format `
            -CACertFileName $certFileName -CAPrivateKeyFileName $keyFileName -Password $CAPassword

        $multipartFiles = @{ CACertFile = $CACertFilePath }
        if ($CAPrivateKeyFilePath) { $multipartFiles['CAPrivateKeyFile'] = $CAPrivateKeyFilePath }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -MultipartFile $multipartFiles -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create CertificateAuthority object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CertificateAuthority' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a Certificate Authority object on a Sophos Firewall.

.DESCRIPTION
    Replaces a Certificate Authority object's certificate (and, optionally, its private key)
    with a freshly uploaded file. Unlike most Set-* cmdlets in this suite, this is not a
    read-modify-write of text fields: Get-SfosCertificateAuthority can report that an
    object's private key file exists, but it cannot read back the key's actual bytes, so
    there is nothing this cmdlet could resend on the caller's behalf. -CACertFilePath is
    therefore mandatory on every call, matching the only update shape measured against a
    live appliance (the same file, or a new one, re-uploaded in full). If the object
    currently has a private key and you do not pass -CAPrivateKeyFilePath again, the
    resulting private-key state of the object after the update is unverified - resupply the
    key file whenever the object has one. Format is the one field this cmdlet can preserve
    from the object it reads first, so it is optional here.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Certificates area.

.PARAMETER Name
    Required. Name of the target object.

.PARAMETER CACertFilePath
    Required. Local path to the certificate file to (re-)upload.

.PARAMETER Format
    Optional. PEM or DER. If omitted, the existing value is kept.

.PARAMETER CAPrivateKeyFilePath
    Optional. Local path to the private key file. See .DESCRIPTION for what happens when
    this is omitted on an object that already has a key.

.PARAMETER CAPassword
    Optional. Passphrase protecting the private key, as a SecureString.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name, for example
    from Get-SfosCertificateAuthority.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if the named object does not exist.

.EXAMPLE
    Set-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath 'C:\PKI\root-renewed.pem' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosCertificateAuthority -Name 'CorporateRootCA' -CACertFilePath 'C:\PKI\root-renewed.pem'

    Replaces the stored certificate with a renewed one. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/CertificateAuthority/operations/AddCertificateAuthority%26EditCertificateAuthority.html

.LINK
    Get-SfosCertificateAuthority
#>
function Set-SfosCertificateAuthority {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CACertFilePath,

        [ValidateSet('PEM', 'DER')]
        [string]$Format,

        [string]$CAPrivateKeyFilePath,

        [SecureString]$CAPassword,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not (Test-Path -LiteralPath $CACertFilePath -PathType Leaf)) {
            throw "CACertFilePath '$CACertFilePath' does not exist."
        }
        if ($CAPrivateKeyFilePath -and -not (Test-Path -LiteralPath $CAPrivateKeyFilePath -PathType Leaf)) {
            throw "CAPrivateKeyFilePath '$CAPrivateKeyFilePath' does not exist."
        }

        $existing = @(Get-SfosCertificateAuthority -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The CertificateAuthority object '$Name' was not found."
        }

        $targetFormat = if ($PSBoundParameters.ContainsKey('Format')) { $Format } else { [string]$existing[0].Format }

        if (-not $PSCmdlet.ShouldProcess("CertificateAuthority '$Name' on $($params.Firewall)", 'Update')) {
            return
        }


        $certFileName = [System.IO.Path]::GetFileName($CACertFilePath)
        $keyFileName = $null
        if ($CAPrivateKeyFilePath) { $keyFileName = [System.IO.Path]::GetFileName($CAPrivateKeyFilePath) }

        $inner = ConvertTo-SfosCertificateAuthorityEntityXml -Operation 'update' -Name $Name -Format $targetFormat `
            -CACertFileName $certFileName -CAPrivateKeyFileName $keyFileName -Password $CAPassword

        $multipartFiles = @{ CACertFile = $CACertFilePath }
        if ($CAPrivateKeyFilePath) { $multipartFiles['CAPrivateKeyFile'] = $CAPrivateKeyFilePath }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -MultipartFile $multipartFiles -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error updating CertificateAuthority object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CertificateAuthority' -Action 'edit' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a Certificate Authority object from a Sophos Firewall.

.DESCRIPTION
    Removes a Certificate Authority object. The cmdlet reads the object first and throws a
    clear "was not found" error for a nonexistent name, rather than passing through the
    firewall's own raw failure text for a not-found removal.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name,
    for example from Get-SfosCertificateAuthority.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal (for example, because the object is still referenced elsewhere), or if the named
    object does not exist.

.EXAMPLE
    Remove-SfosCertificateAuthority -Name 'CorporateRootCA' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosCertificateAuthority -Name 'CorporateRootCA'

    Removes the named object. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/CertificateAuthority/operations/Delete%20Certificate%20Authority.html

.LINK
    Get-SfosCertificateAuthority
#>
function Remove-SfosCertificateAuthority {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $existing = @(Get-SfosCertificateAuthority -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The CertificateAuthority object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("CertificateAuthority '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><CertificateAuthority><Name>$nameEsc</Name></CertificateAuthority></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove CertificateAuthority object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CertificateAuthority' -Action 'remove' -Target $Name
    }
}

<#
.SYNOPSIS
    Extracts one Certificate Authority object's files from a Sophos Firewall to disk.

.DESCRIPTION
    Downloads and extracts the certificate file (and private key file, if the object has
    one) of a single named Certificate Authority object. The cmdlet name is singular rather
    than the plural, CSV-bulk convention used elsewhere in this suite (Export-SfosIPHosts
    and similar): this exports one named object's binary files, not a table of many objects
    to a CSV/JSON file, so the bulk convention does not apply.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

.PARAMETER Name
    Required. Name of the object to export.

.PARAMETER Path
    Required. Directory to write the extracted file(s) to. Created if it does not exist.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    System.String. The full path of every file written to -Path.

.EXAMPLE
    Export-SfosCertificateAuthority -Name 'CorporateRootCA' -Path 'C:\Sfos\Export'

    Writes the certificate authority's certificate file (and its private key file, if
    present) to the given directory and returns their paths.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/CertificateAuthority/CertificateAuthority.html

.LINK
    Get-SfosCertificateAuthority
#>
function Export-SfosCertificateAuthority {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = @"
<Get>
  <CertificateAuthority>
    <Filter><key name="Name" criteria="=">$nameEsc</key></Filter>
  </CertificateAuthority>
</Get>
"@

         if (-not $PSCmdlet.ShouldProcess("CertificateAuthority '$Name' on $($params.Firewall)", "Export to '$Path'")) {
             return
         }

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error retrieving CertificateAuthority object '$Name': $($_.Exception.Message)"
        }

        if ($response.Content -is [string]) {
            $XmlResponse = [xml]$response.Content
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CertificateAuthority' -Action 'get' -Target $Name
            throw "The CertificateAuthority object '$Name' was not found."
        }

        # Unpack to a scratch folder first. The archive also carries its own manifest
        # and a version marker; only the certificate files belong in -Path.
        # The help promises the target directory is created when it is missing.
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }

        $staging = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $staging -Force | Out-Null
        try {
            $archive = ConvertFrom-SfosArchive -Bytes $response.Content -ExtractTo $staging
            $members = @($archive.Files | Where-Object -FilterScript { $_.Name -like './Files/*' -and $_.Path })

            if ($members.Count -eq 0) {
                throw "The CertificateAuthority object '$Name' was found, but no file could be extracted from the archive."
            }

            $written = foreach ($member in $members) {
                $target = Join-Path $Path (Split-Path -Path $member.Path -Leaf)
                Copy-Item -LiteralPath $member.Path -Destination $target -Force
                $target
            }
            return @($written)
        }
        finally {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion


#region CRL

<#
.SYNOPSIS
    Retrieves Certificate Revocation List (CRL) objects from a Sophos Firewall.

.DESCRIPTION
    Returns CRL objects (SYSTEM > Certificates > Certificate Revocation Lists). A matching
    Get answers with a tar archive (application/octet-stream), the same file-response shape
    as CertificateAuthority; this cmdlet reads the object list from the archive's
    Entities.xml, the same way Get-SfosCertificateAuthority does.

    Only Get-SfosCRL is provided for this entity. Uploading a CRL through the documented
    Add CRL operation was measured, repeatedly and with several structurally valid CRL
    files (including one deliberately expired one, to check whether the content is
    evaluated at all), to fail with a generic firewall error regardless of content - the
    dedicated "CRL expired" status the API documents for that case was never reached. There
    is no known way to create, update or remove a CRL object through this API on the
    firmware this was measured against, so New-/Set-/Remove-SfosCRL are not implemented.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. Sent to the
    firewall as a server-side pre-filter and re-applied client-side. If omitted, every CRL
    object is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Certificates area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate is
    validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements from the archive's Entities.xml instead of
    PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per CRL, with the properties
    Name and CRLFile. Returns System.Xml.XmlElement when -AsXml is used, and an empty array
    when no object matches.

.EXAMPLE
    Get-SfosCRL

    Lists every Certificate Revocation List object on the firewall of the current
    connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Certificates/CertificateCRL/CertificateCRL.html
#>
function Get-SfosCRL {
    [CmdletBinding()]
    param(
        [string]$NameLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <CRL>
    $filterXml
  </CRL>
</Get>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving CRL objects: $($_.Exception.Message)"
    }

    if ($response.Content -is [string]) {
        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'CRL' -Action 'get'
        return @()
    }

    $archive = ConvertFrom-SfosArchive -Bytes $response.Content
    if (-not $archive.Entities) {
        throw 'CRL Get returned a binary response whose Entities.xml could not be located or parsed.'
    }

    $nodes = Select-Xml -Xml $archive.Entities -XPath '/Response/CRL[Name]' | ForEach-Object -Process { $_.Node }

    $crlObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name    = [string]$node.Name
            CRLFile = [string]$node.CRLFile
        }
    }

    $crlObjects = @($crlObjects)
    if ($NameLike) {
        $crlObjects = @($crlObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($crlObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $crlObjects
}

#endregion
