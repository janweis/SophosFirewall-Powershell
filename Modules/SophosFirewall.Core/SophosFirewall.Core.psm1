#requires -Version 5.1
<#
    SophosFirewall.Core
    ====================
    PowerShell module that carries the transport layer for every Sophos Firewall (SFOS)
    domain module: connection and session state, HTTP(S) communication, the XML request
    envelope, XML escaping, and evaluation of the API response status. It has no knowledge
    of firewall entities such as hosts, services or rules; that lives in the domain modules
    that depend on this one.

    Also carries Connect-SfosWebAdmin and Invoke-SfosWebAdminRequest, an undocumented,
    firmware-bound path into the web admin interface (Web Admin Console - not the appliance's
    CLI console) for the handful of screens that have no equivalent in the XML API - see their
    own help before using them.

    Total Functions: 14 (11 exported, 3 internal helpers) - see README.md for the full
    cmdlet table.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>

#region Module Variables

# Default Sophos Firewall API port
[int]$script:DefaultSfosPort = 4444

# Session context for connection reuse across cmdlets
$script:SfosConnection = $null

# Named session registry for Connect-SfosFirewall -Name / -Session everywhere. A plain
# @{} hashtable literal's case sensitivity is not guaranteed across PowerShell versions,
# so the comparer is set explicitly - session names are looked up case-insensitively.
$script:SfosSessions = [System.Collections.Hashtable]::new([StringComparer]::OrdinalIgnoreCase)

# Guards the process-wide certificate callback under PS 5.1. ServicePointManager is static,
# so two calls in parallel runspaces could each save the other's temporary "accept all"
# callback as the original and leave validation permanently disabled.
$script:CertCallbackLock = [object]::new()

#endregion

#region XML Helper Functions

<#
.SYNOPSIS
    Escapes XML special characters in a text string.

.DESCRIPTION
    Replaces the five XML special characters (&, <, >, ", ') with their entity form, so the
    text can be interpolated into request XML without breaking the document or letting the
    value inject extra elements. Every domain module passes every value it interpolates into
    XML through this cmdlet first, without exception - names, descriptions, filter values,
    member names.

.PARAMETER Text
    Required. The text to escape. Accepts pipeline input. An empty string is allowed.

.INPUTS
    System.String. Text can be piped in.

.OUTPUTS
    System.String. The XML-escaped text.

.EXAMPLE
    ConvertTo-SfosXmlEscaped -Text 'Smith & Sons'

    Returns 'Smith &amp; Sons'.

.EXAMPLE
    'Smith & Sons', 'A "B" C' | ConvertTo-SfosXmlEscaped

    Escapes each piped-in string in turn.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function ConvertTo-SfosXmlEscaped {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Text
    )
    
    process {
        return ($Text `
                -replace '&', '&amp;' `
                -replace '<', '&lt;' `
                -replace '>', '&gt;' `
                -replace '"', '&quot;' `
                -replace "'", '&apos;')
    }
}

<#
.SYNOPSIS
    Builds a multipart/form-data request body. Internal helper, not exported.

.DESCRIPTION
    Builds the byte-exact body Invoke-SfosApi sends when a call carries a file upload: the
    request XML as its own raw (not URL-encoded) 'reqxml' part, followed by one part per
    file. Kept separate from Invoke-SfosApi so the body can be tested without a network
    call - measured for FormTemplate against a live firewall, and reused unmeasured for the
    other multipart operations that share the same field-name-equals-XML-element contract
    (Certificate, CertificateAuthority, CRL, TrustedMAC list, VPN client config).

    Built by hand rather than with Invoke-WebRequest -Form so the same code path runs under
    PowerShell 5.1, which has no -Form parameter. File content is read as bytes and written
    straight into the body stream, never through a string, so a binary upload such as a
    certificate is never subjected to character encoding.

.PARAMETER RequestXml
    Required. The complete request envelope, exactly as Invoke-SfosApi would otherwise
    URL-encode into the non-multipart body.

.PARAMETER MultipartFile
    Required. Hashtable of multipart field name to one file path or an array of file paths.
    The field name must match the XML element in RequestXml that references the upload; the
    element's text content must be the file's base name.
#>
function New-SfosMultipartRequestBody {
    # PSUseShouldProcessForStateChangingFunctions: the New- verb here builds an in-memory
    # byte array and reads local files; it changes nothing on the firewall or the caller's
    # system, so ShouldProcess would be a no-op prompt with nothing meaningful to confirm.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$RequestXml,

        [Parameter(Mandatory)]
        [hashtable]$MultipartFile
    )

    $boundary = 'SfosBoundary' + [guid]::NewGuid().ToString('N')
    $crlf = "`r`n"
    # No BOM: a BOM at the start of the 'reqxml' part would be sent to the firewall as part
    # of the XML text.
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)

    $extensionContentType = @{
        '.xml'  = 'text/xml'
        '.html' = 'text/html'
        '.htm'  = 'text/html'
        '.txt'  = 'text/plain'
        '.csv'  = 'text/csv'
    }

    $stream = [System.IO.MemoryStream]::new()
    try {
        # reqxml is a form field like any other here, but its value is the raw request XML -
        # it must not be URL-encoded the way the non-multipart body encodes it, or the
        # firewall receives literal percent-escapes instead of the request.
        $reqxmlHeader = "--$boundary$crlf" +
        "Content-Disposition: form-data; name=`"reqxml`"$crlf" +
        "Content-Type: text/xml$crlf$crlf"
        $bytes = $utf8NoBom.GetBytes($reqxmlHeader)
        $stream.Write($bytes, 0, $bytes.Length)
        $bytes = $utf8NoBom.GetBytes($RequestXml)
        $stream.Write($bytes, 0, $bytes.Length)
        $bytes = $utf8NoBom.GetBytes($crlf)
        $stream.Write($bytes, 0, $bytes.Length)

        foreach ($fieldName in $MultipartFile.Keys) {
            foreach ($path in @($MultipartFile[$fieldName])) {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                    throw "MultipartFile field '$fieldName' refers to a file that does not exist: $path"
                }

                $fileName = Split-Path -Path $path -Leaf
                $extension = [System.IO.Path]::GetExtension($fileName).ToLowerInvariant()
                $contentType = 'application/octet-stream'
                if ($extensionContentType.ContainsKey($extension)) {
                    $contentType = $extensionContentType[$extension]
                }

                $fileHeader = "--$boundary$crlf" +
                "Content-Disposition: form-data; name=`"$fieldName`"; filename=`"$fileName`"$crlf" +
                "Content-Type: $contentType$crlf$crlf"
                $bytes = $utf8NoBom.GetBytes($fileHeader)
                $stream.Write($bytes, 0, $bytes.Length)

                # Binary-safe: file bytes go from disk straight into the stream, never
                # through a string, so a certificate or other binary upload is never run
                # through character encoding.
                $fileBytes = [System.IO.File]::ReadAllBytes($path)
                $stream.Write($fileBytes, 0, $fileBytes.Length)

                $bytes = $utf8NoBom.GetBytes($crlf)
                $stream.Write($bytes, 0, $bytes.Length)
            }
        }

        $bytes = $utf8NoBom.GetBytes("--$boundary--$crlf")
        $stream.Write($bytes, 0, $bytes.Length)

        return [PSCustomObject]@{
            Body        = $stream.ToArray()
            ContentType = "multipart/form-data; boundary=$boundary"
        }
    }
    finally {
        $stream.Dispose()
    }
}

<#
.SYNOPSIS
    Throws when an API response reports a failed login. Internal helper, not exported.

.DESCRIPTION
    A failed login is reported outside the entity status: a lowercase status element
    directly under Login, with no code attribute, in an otherwise empty HTTP 200 body. Left
    unchecked, such a response looks like "no records" to a Get and like success to every
    write.

.PARAMETER Content
    Required. Raw response body to check. Anything that is not text is ignored: a few
    operations answer with a file instead of XML, and a rejected login is always XML.
#>
function Assert-SfosApiLoginSuccess {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [object]$Content
    )

    # Certificate, certificate authority, CRL and form template answer with a downloaded
    # file, so the body arrives as a byte array. Declaring this parameter as a string made
    # the call fail on the binding, long before anything was read, and the caller saw a
    # type conversion error instead of the response.
    if ($Content -isnot [string]) {
        return
    }

    if (-not $Content) {
        return
    }

    # A non-XML body is not this function's problem - the caller parses and reports it.
    $xml = $null
    try {
        $xml = [xml]$Content
    }
    catch {
        return
    }

    $loginNode = $xml.SelectSingleNode('/Response/Login/status')
    if (-not $loginNode) {
        return
    }

    $loginStatus = [string]$loginNode.InnerText
    if ($loginStatus -and $loginStatus -notmatch 'Success') {
        throw "Sophos API login failed: $loginStatus"
    }
}

<#
.SYNOPSIS
    Sends a request to the Sophos Firewall XML API and returns the raw response.

.DESCRIPTION
    Wraps the caller-supplied inner XML in the API request envelope, together with the
    login credentials, and posts it to the firewall's API endpoint. Domain modules use this
    cmdlet for every read and write; it is the only place in the module suite that opens an
    HTTP(S) connection. The response is returned unparsed; use Get-SfosApiStatus or
    Assert-SfosApiReturnSuccess to evaluate it.

    Call this cmdlet directly only for troubleshooting or for XML the shipped domain modules
    do not yet cover. Pass either the individual connection parameters, or -Session to reuse
    a connection from Connect-SfosFirewall.

.PARAMETER Firewall
    Required in the default parameter set. Host name or IP address of the firewall.

.PARAMETER Port
    Optional. TCP port of the management API. Default 4444.

.PARAMETER Username
    Required in the default parameter set. User name for the API login, as plain text.

.PARAMETER Password
    Required in the default parameter set. Password for the API login, as a SecureString.

.PARAMETER InnerXml
    Required. The request body without the surrounding Request/Login envelope, for example
    '<Get><IPHost></IPHost></Get>'.

.PARAMETER ApiVersion
    Optional. APIVersion attribute for the Request element, for example '2200.1'. If
    omitted, the firewall processes the request using its own current schema version, which
    keeps one module compatible with several firmware levels.

.PARAMETER TimeoutSec
    Optional. Maximum time in seconds to wait for the HTTP response. Default 30. Pass 0 to
    fall back to the default of the underlying web request instead of enforcing a limit.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. Belongs to the default
    parameter set; when calling with -Session, the session's own value is used instead.

.PARAMETER Session
    Required when used instead of the individual connection parameters. A session object
    from Connect-SfosFirewall, or the name of a session that was registered with
    Connect-SfosFirewall -Name. Firewall, Port, Username, Password and
    SkipCertificateCheck are all taken from it.

.PARAMETER MultipartFile
    Optional. Hashtable of multipart field name to one file path or an array of file paths,
    for the handful of operations that upload a file alongside the request XML (for example
    FormTemplate, Certificate, CertificateAuthority, CRL). The field name must match the XML
    element in -InnerXml that references the upload, and that element's text content must be
    the file's base name - the match between the two is how the firewall connects the
    uploaded file to the request. When omitted, the request is sent exactly as before this
    parameter existed: a single URL-encoded form field.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    Microsoft.PowerShell.Commands.WebResponseObject. The unparsed HTTP response from the
    firewall.

.EXAMPLE
    $securePw = Read-Host -AsSecureString
    $inner = '<Get><IPHost></IPHost></Get>'
    Invoke-SfosApi -Firewall 'firewall.example.com' -Port 4444 -Username 'admin' -Password $securePw -InnerXml $inner -SkipCertificateCheck

    Sends a raw Get request and returns the unparsed response.

.EXAMPLE
    Invoke-SfosApi -Firewall 'firewall.example.com' -Username 'admin' -Password $securePw -InnerXml $inner -TimeoutSec 5

    Fails fast against a host that might be unreachable, instead of waiting out the
    operating system's own default timeout.

.EXAMPLE
    Invoke-SfosApi -Session 'fw2' -InnerXml $inner

    Sends a raw request against a session that was registered earlier with
    Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2'.

.EXAMPLE
    $uploadInner = Get-Content .\add-formtemplate.xml -Raw
    Invoke-SfosApi -Session 'fw2' -InnerXml $uploadInner -MultipartFile @{ Template = 'C:\templates\portal.html' }

    Uploads a file alongside the request XML. The XML element referencing the upload
    ('Template') must equal the multipart field name, and its text must be the file's base
    name ('portal.html'), matching the file at the given path. The inner XML is read from a
    file here because the help renderer discards raw angle brackets together with the rest
    of the line.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosApiStatus

.LINK
    Assert-SfosApiReturnSuccess
#>
function Invoke-SfosApi {
    [CmdletBinding(DefaultParameterSetName = 'Explicit')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [string]$Firewall,

        [Parameter(ParameterSetName = 'Explicit')]
        [int]$Port = $script:DefaultSfosPort,

        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [string]$Username,

        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [SecureString]$Password,

        [Parameter(Mandatory)]
        [string]$InnerXml,

        [string]$ApiVersion,

        [int]$TimeoutSec = 30,

        [Parameter(ParameterSetName = 'Explicit')]
        [switch]$SkipCertificateCheck,

        [hashtable]$MultipartFile,

        [Parameter(Mandatory, ParameterSetName = 'Session')]
        [object]$Session
    )

    if ($PSCmdlet.ParameterSetName -eq 'Session') {
        $resolvedSession = Resolve-SfosSessionArgument -Session $Session
        if (-not $resolvedSession) {
            throw 'Invoke-SfosApi -Session did not resolve to a usable session. Pass a registered session name or the object returned by Connect-SfosFirewall.'
        }
        $Firewall = $resolvedSession.Firewall
        $Port = $resolvedSession.Port
        $Username = $resolvedSession.Username
        $Password = $resolvedSession.Password
        $SkipCertificateCheck = [bool]$resolvedSession.SkipCertificateCheck
    }

    # Variables for secure handling and cleanup
    $plainPassword = $null
    $passwordBstr = $null
    $savedCertCallback = $null
    $certCallbackChanged = $false
    $certLockTaken = $false

    try {
        # Security: XML-escape credentials to prevent injection attacks
        $usernameEscaped = ConvertTo-SfosXmlEscaped -Text $Username
        
        # Convert Password SecureString to plaintext with BSTR cleanup.
        # PtrToStringBSTR, not PtrToStringAuto: a BSTR is length-prefixed and may contain
        # embedded null characters, which PtrToStringAuto would silently truncate at.
        $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
        $passwordEscaped = ConvertTo-SfosXmlEscaped -Text $plainPassword
        
        $uri = ("https://{0}:{1}/webconsole/APIController" -f $Firewall, $Port)

        # APIVersion is optional. When omitted the firewall answers using its own current
        # schema version, which keeps a single module usable across firmware levels.
        $versionAttribute = ''
        if ($ApiVersion) {
            $versionAttribute = " APIVersion=`"$ApiVersion`""
        }
        $requestXml = "<Request$versionAttribute><Login><Username>$usernameEscaped</Username><Password>$passwordEscaped</Password></Login>$InnerXml</Request>"

        if ($MultipartFile -and $MultipartFile.Count -gt 0) {
            # Multipart transport: reqxml travels as its own raw part, and the file(s) as
            # further parts. Built by hand so the same code path runs under PS 5.1, which
            # has no -Form parameter on Invoke-WebRequest.
            $multipart = New-SfosMultipartRequestBody -RequestXml $requestXml -MultipartFile $MultipartFile

            $invokeParams = @{
                Uri         = $uri
                Method      = 'Post'
                Body        = $multipart.Body
                ContentType = $multipart.ContentType
                ErrorAction = 'Stop'
            }
        }
        else {
            # The body is form-encoded, so the XML has to be URL-encoded. Left unencoded, any
            # '&' - including every '&amp;' produced by XML escaping - terminates the reqxml
            # field and SFOS rejects the request with code 529 'Input request file is Invalid'.
            $body = 'reqxml=' + [uri]::EscapeDataString($requestXml)

            $invokeParams = @{
                Uri         = $uri
                Method      = 'Post'
                Body        = $body
                ErrorAction = 'Stop'
            }
        }

        # -TimeoutSec is identical on Invoke-WebRequest under PS 5.1 and PS 7+, so no version
        # branch is needed the way there is for -UseBasicParsing/-SkipCertificateCheck below.
        # 0 means "no enforced limit" - omit the parameter and let Invoke-WebRequest use its
        # own default rather than passing a literal 0, which Invoke-WebRequest would reject.
        if ($TimeoutSec -gt 0) {
            $invokeParams['TimeoutSec'] = $TimeoutSec
        }

        # -UseBasicParsing under PS 5.1: without it Invoke-WebRequest hands the response to
        # the Internet Explorer DOM parser, which throws NullReferenceException on any
        # machine that has no IE engine - Windows Server included. Every call would fail.
        # PS 7 dropped the parameter; passing it there is harmless but pointless.
        if ($PSVersionTable.PSVersion.Major -le 5) {
            $invokeParams['UseBasicParsing'] = $true
        }

        # Handle certificate validation for PS 5.1 vs PS 7+
        if ($SkipCertificateCheck) {
            if ($PSVersionTable.PSVersion.Major -le 5) {
                # Serialise the swap: the callback is process-wide, so a concurrent call
                # must not observe - and later restore - this call's temporary value.
                [System.Threading.Monitor]::Enter($script:CertCallbackLock)
                $certLockTaken = $true
                $savedCertCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
                $certCallbackChanged = $true
                [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            elseif ($PSVersionTable.PSVersion.Major -gt 5) {
                # PS 7+: Use parameter instead of global callback
                $invokeParams['SkipCertificateCheck'] = $true
            }
        }

        try {
            $response = Invoke-WebRequest @invokeParams
        }
        catch {
            # Flatten the exception chain. PowerShell reports "The SSL connection could not
            # be established, see inner exception", and the domain functions re-throw only
            # that top-level text - the inner exception naming the actual cause
            # (RemoteCertificateNameMismatch, connection refused, ...) never reaches the
            # caller. Doing it here fixes it for all 53 of them at once.
            $messages = @()
            $current = $_.Exception
            while ($current) {
                if ($current.Message -and $messages -notcontains $current.Message) {
                    $messages += $current.Message
                }
                $current = $current.InnerException
            }
            throw ($messages -join ' -> ')
        }

        # Every response passes through here, so this is the one place that can catch a
        # failed login. SFOS answers it with HTTP 200 and nothing but the lowercase
        # <status> under <Login> - no entity, no status code. Left unchecked, Get-* would
        # return an empty result and every write would report success.
        Assert-SfosApiLoginSuccess -Content $response.Content

        return $response
    }
    finally {
        # Restore previous certificate validation callback. The flag is required: the
        # saved callback is normally $null, so a null check would skip the restore and
        # leave certificate validation disabled for the rest of the process.
        if ($certCallbackChanged) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = $savedCertCallback
        }

        if ($certLockTaken) {
            [System.Threading.Monitor]::Exit($script:CertCallbackLock)
        }
        
        # Free BSTR memory to prevent leaks
        if ($passwordBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::FreeBSTR($passwordBstr)
        }
        
        # Clear plaintext variables from memory
        $plainPassword = $null
    }
}

#endregion

#region Response Parsing

<#
.SYNOPSIS
    Extracts the status information from a Sophos Firewall API response.

.DESCRIPTION
    Reads one or more status elements from a parsed API response and returns their code and
    message. Looks first under /Response/ObjectName/Status when -ObjectName is given, then
    falls back to /Response/Status. Assert-SfosApiReturnSuccess uses this cmdlet internally;
    call it directly when troubleshooting a response, to see every status the firewall
    actually returned.

.PARAMETER Xml
    Required. The parsed XML response from the firewall.

.PARAMETER ObjectName
    Optional. Name of the entity element to look under for the status, for example 'Zone'.
    If omitted, only the top-level /Response/Status is checked.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per status found, with the
    properties Code, Message and XPathHint. Returns nothing when the response carries no
    status at all.

.EXAMPLE
    Get-SfosApiStatus -Xml $response -ObjectName 'Zone'

    Reads the status of a Zone response.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Assert-SfosApiReturnSuccess
#>
function Get-SfosApiStatus {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [xml]$Xml,
        
        [string]$ObjectName
    )
    
    # SelectNodes, not property access: $Xml.Response.$ObjectName silently returns the CLR
    # member of XmlElement when the entity is called Name, Item or Count, and it collapses
    # several <Status> siblings - a bulk delete returns one per object - into a single
    # value whose .code reads "200 529".
    $statusNodes = @()
    $hint = $null

    if ($ObjectName) {
        # '<Status>' is not always an API status. Some entities carry a field of that name:
        # a FirewallRule and a NATRule both hold <Status>Enable</Status> as their enabled
        # flag, so a plain /Response/FirewallRule/Status matches six data fields on a
        # six-rule response and none of them says anything about the request.
        #
        # A node counts as an API status when it carries a 'code' attribute, or when its
        # parent is not a data object - data objects have a <Name>, status containers do
        # not. Both halves matter: dropping the @code test would hide a real error that
        # arrives alongside a named object, and dropping the Name test brings the
        # Enable/Disable fields back.
        $statusNodes = @($Xml.SelectNodes("/Response/$ObjectName/Status[@code or not(../Name)]"))
        $hint = "/Response/$ObjectName/Status"
    }

    if (-not $statusNodes.Count) {
        $statusNodes = @($Xml.SelectNodes('/Response/Status'))
        $hint = '/Response/Status'
    }

    if (-not $statusNodes.Count) {
        # A bare 'return', not 'return $null': the caller almost always wraps this in @(),
        # and @($null) is a one-element array holding $null rather than an empty one, which
        # reads as "one unreadable status" instead of "no status at all".
        return
    }

    # One object per status node, so a caller can tell which entity failed
    foreach ($statusNode in $statusNodes) {
        [PSCustomObject]@{
            Code      = [string]$statusNode.GetAttribute('code')
            Message   = [string]$statusNode.InnerText
            XPathHint = $hint
        }
    }
}

<#
.SYNOPSIS
    Throws when a Sophos Firewall API response does not report success.

.DESCRIPTION
    Checks the login status and the entity status codes of a parsed API response and throws
    a clear error naming the action and target if the request did not succeed. Codes 200
    and 216 are treated as success, 201/203/211-215 as success with a warning, and every
    other code in the documented range as a failure. Codes 217 and 222 are also treated as a
    warning; every other undocumented code throws, so an unrecognised status is never
    mistaken for success.

    When no status is found at the path derived from -ObjectName, and none at the general
    fallback path either, the cmdlet searches the rest of the response once for any node
    that still looks like a status. A status found this way still throws on a failure code
    and still succeeds on a success code, with a warning that names the path so -ObjectName
    can be corrected for that operation. A response with genuinely no status anywhere is
    unaffected.

    Domain modules call this cmdlet after every read and write to turn a failed request into
    a thrown error instead of a silently wrong result.

.PARAMETER Xml
    Required. The parsed XML response from the firewall.

.PARAMETER ObjectName
    Optional. Name of the entity element the status is expected under, for example 'Zone'.
    If omitted, only the top-level /Response/Status is checked before the fallback search.

.PARAMETER Action
    Optional. Short description of the action being performed, used in the error message,
    for example 'create'. Default 'execute request'.

.PARAMETER Target
    Optional. Name of the target object, used in the error message.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and throws an exception if the response reports a
    failure or an unrecognised status.

.EXAMPLE
    Assert-SfosApiReturnSuccess -Xml $response -ObjectName 'Zone' -Action 'create' -Target 'DMZ'

    Throws a descriptive error if creating the Zone 'DMZ' failed; otherwise returns nothing.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosApiStatus
#>
function Assert-SfosApiReturnSuccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$Xml,
        
        [string]$ObjectName,
        
        [string]$Action,
        
        [string]$Target
    )
    
    $actionPart = if ($Action) { $Action } else { 'execute request' }
    $targetPart = if ($Target) { " for '$Target'" } else { '' }

    # Authentication is reported outside the entity status and would otherwise slip past
    # every code check below. Invoke-SfosApi already catches this for live calls; the check
    # is repeated here for callers that hand in a parsed response directly.
    $loginNode = $Xml.SelectSingleNode('/Response/Login/status')
    if ($loginNode) {
        $loginStatus = [string]$loginNode.InnerText
        if ($loginStatus -and $loginStatus -notmatch 'Success') {
            throw "Sophos API login failed while trying to $actionPart$targetPart. $loginStatus"
        }
    }

    # Where-Object, not just @(): Get-SfosApiStatus returns $null when the response carries
    # no <Status> at all, and @($null) is a one-element array holding $null - not an empty
    # one. Without the filter the loop below inspects that $null and reports a status-less
    # response as a broken status.
    $statusList = @(Get-SfosApiStatus -Xml $Xml -ObjectName $ObjectName | Where-Object { $_ })

    # Fail-open guard: some operations land their status FLAT at a different path than the
    # nested Get/Remove shape -ObjectName points at, so the lookup above finds nothing there
    # and nothing at the /Response/Status fallback either. Returning at that point would
    # report success for a write that may have failed. Before treating "nothing at the
    # expected path" as "no status anywhere" (which is legitimately what an empty Get result
    # looks like), search the rest of the response once for any node the existing heuristic still
    # recognises as an API status: a Status carrying a code attribute, or a code-less Status
    # whose parent has no <Name> child. That second half is the same data-field exclusion
    # used above - a FirewallRule/NATRule's <Status>Enable</Status> sits next to <Name> and
    # stays excluded here too.
    $fallbackUsed = $false
    if (-not $statusList.Count) {
        $fallbackNodes = @($Xml.SelectNodes('//Status[@code or not(../Name)]') | Where-Object { $_ })
        if ($fallbackNodes.Count) {
            $fallbackUsed = $true
            $statusList = @($fallbackNodes | ForEach-Object {
                    $pathParts = @()
                    $ancestor = $_
                    while ($ancestor -and $ancestor.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                        $pathParts = , $ancestor.Name + $pathParts
                        $ancestor = $ancestor.ParentNode
                    }
                    $actualPath = '/' + ($pathParts -join '/')
                    [PSCustomObject]@{
                        Code      = [string]$_.GetAttribute('code')
                        Message   = [string]$_.InnerText
                        XPathHint = "$actualPath (found outside the expected path for -ObjectName '$ObjectName' - measure and correct -ObjectName for this operation)"
                    }
                })
        }
    }

    if (-not $statusList.Count) {
        return
    }

    foreach ($status in $statusList) {
        # An empty result is reported as <Status>No. of records Zero.</Status> without a
        # code attribute. That is not a failure, so Get-* must not throw on it.
        #
        # Only that one wording is waved through. Treating *every* code-less status as an
        # empty result fails open: a filtered Get on ContentConditionList answers
        # <Status>Transaction fail</Status>, also without a code, and the caller would have
        # seen an empty list while matching objects existed. Same class of defect as the
        # login failure that used to read as success - so anything unrecognised throws.
        if (-not $status.Code) {
            if ($status.Message -match 'records\s+Zero') {
                continue
            }

            throw "Sophos API returned a status without a code while trying to $actionPart$targetPart. '$($status.Message)' (StatusPath=$($status.XPathHint))"
        }

        $code = 0
        if (-not [int]::TryParse($status.Code, [ref]$code)) {
            throw "Sophos API returned an unreadable status code while trying to $actionPart$targetPart. Code '$($status.Code)' - $($status.Message) (StatusPath=$($status.XPathHint))"
        }

        # Status codes per the table published by Sophos
        if ($code -eq 200 -or $code -eq 216) {
            if ($fallbackUsed) {
                Write-Warning "Sophos API reported success (code $code) while trying to $actionPart$targetPart, but the status was found outside the expected path for -ObjectName '$ObjectName'. The operation likely succeeded; measure and correct -ObjectName for this operation. (StatusPath=$($status.XPathHint))"
            }
            continue
        }

        if ($code -eq 201 -or $code -eq 203 -or ($code -ge 211 -and $code -le 215)) {
            Write-Warning "Sophos API reported code $code while trying to $actionPart$targetPart. $($status.Message)"
            continue
        }

        # The published table runs 200-216 and then resumes at 500, so 217-499 is undefined.
        # Only 217 and 222 are let through as a warning, because they occur on writes that
        # otherwise complete correctly, for example a WebFilterCategory created with an
        # external URL list, which answers 217 or 222 'Unable to get status message'.
        #
        # The rest of that range still throws. Waving through every undocumented code would
        # fail open - an unrecognised code would be reported as success while the firewall
        # did nothing, which is exactly the defect class this module has been bitten by
        # before. A wrongly reported failure is visible and harmless; a wrongly reported
        # success is neither.
        if ($code -eq 217 -or $code -eq 222) {
            Write-Warning "Sophos API returned code $code while trying to $actionPart$targetPart, which the published status table does not describe. The operation is expected to have succeeded, but verify the result on the firewall. $($status.Message)"
            continue
        }

        throw "Sophos API error while trying to $actionPart$targetPart. Code $code - $($status.Message) (StatusPath=$($status.XPathHint))"
    }
}

#endregion

#region Session Management

<#
.SYNOPSIS
    Resolves a -Session argument to a session object. Internal helper, not exported.

.DESCRIPTION
    Accepts the same shapes a domain cmdlet's -Session parameter can receive: $null (passed
    straight through, meaning "no session"), a registered session name (looked up in the
    named-session registry, case-insensitively), an object already tagged as a session
    returned by Connect-SfosFirewall, or - as a fallback - any other object that at least has
    a Firewall property, so a caller who built a compatible object by hand is not blocked.
    Anything else throws.

.PARAMETER Session
    Required. The raw value bound to a cmdlet's -Session parameter.
#>
function Resolve-SfosSessionArgument {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [AllowNull()]
        [object]$Session
    )

    if ($null -eq $Session) {
        return $null
    }

    if ($Session -is [string]) {
        if ($script:SfosSessions.ContainsKey($Session)) {
            return $script:SfosSessions[$Session]
        }
        throw "No session named '$Session' is registered. Use Get-SfosSession to list registered sessions, or Connect-SfosFirewall -Name '$Session' to register one."
    }

    if ($Session.PSObject.TypeNames -contains 'SophosFirewall.Session') {
        return $Session
    }

    # Duck-typing fallback: accept anything that looks like a session object rather than
    # requiring the exact type, so a hand-built compatible object still works.
    if ($Session.PSObject.Properties.Match('Firewall').Count -gt 0) {
        return $Session
    }

    throw 'The value passed to -Session is neither a registered session name nor a session object. Use Get-SfosSession to list registered sessions, or pass the object returned by Connect-SfosFirewall.'
}

<#
.SYNOPSIS
    Resolves the connection parameters a cmdlet should use for an API call.

.DESCRIPTION
    Fills in Firewall, Port, Username, Password and SkipCertificateCheck from the active
    connection wherever the caller did not supply them explicitly, and throws a clear error
    if no connection information is available at all. Every domain cmdlet calls this once,
    at the start of its body, instead of reading the connection state itself.

    When the caller passed -Session, that session is used as the base instead of the default
    connection set by Connect-SfosFirewall; passing -Session $null explicitly switches the
    default connection off rather than keeping it. A value the caller supplied directly for
    Firewall, Port, Username, Password or SkipCertificateCheck always takes precedence over
    both the session and the default connection.

.PARAMETER BoundParameters
    Required. The calling cmdlet's own $PSBoundParameters.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Collections.Hashtable. Contains the resolved Firewall, Port, Username, Password
    and SkipCertificateCheck, ready to splat into Invoke-SfosApi.

.EXAMPLE
    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    Resolves the connection to use, typically called once in a cmdlet's begin block.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>
function Resolve-SfosParameters {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters
    )

    $base = $script:SfosConnection
    if ($BoundParameters.ContainsKey('Session')) {
        # ContainsKey, not a truthiness test on the value: an explicit -Session $null must
        # switch off the default-session fallback, not be treated as "not supplied".
        $base = Resolve-SfosSessionArgument -Session $BoundParameters['Session']
    }

    $resolved = @{
        Firewall             = $BoundParameters.Firewall
        Port                 = $BoundParameters.Port
        Username             = $BoundParameters.Username
        Password             = $BoundParameters.Password
        SkipCertificateCheck = $BoundParameters.SkipCertificateCheck
    }

    if ($base) {
        if (-not $resolved.Firewall) {
            $resolved.Firewall = $base.Firewall
        }
        # ContainsKey again: 0 is falsy, so -not would treat an explicit -Port 0 as
        # "not supplied" and quietly substitute another port instead of rejecting it.
        if (-not $BoundParameters.ContainsKey('Port')) {
            $resolved.Port = $base.Port
        }
        if (-not $resolved.Username) {
            $resolved.Username = $base.Username
        }
        if (-not $resolved.Password) {
            $resolved.Password = $base.Password
        }
        # ContainsKey, not -not: an explicit -SkipCertificateCheck:$false must win over
        # a session that was opened with the switch enabled.
        if (-not $BoundParameters.ContainsKey('SkipCertificateCheck')) {
            $resolved.SkipCertificateCheck = $base.SkipCertificateCheck
        }
    }

    if (-not $resolved.Firewall -or -not $resolved.Username -or -not $resolved.Password) {
        throw 'No active Sophos Firewall connection found. Use Connect-SfosFirewall to establish a connection, pass -Session, or provide Firewall, Username, and Password explicitly.'
    }

    if (-not $BoundParameters.ContainsKey('Port') -and -not $resolved.Port) {
        $resolved.Port = $script:DefaultSfosPort
    }

    # Connect-SfosFirewall validates the range, this path did not: a negative port used to
    # travel all the way into the URI and surface as an opaque UriFormatException.
    if ($resolved.Port -lt 1 -or $resolved.Port -gt 65535) {
        throw "Port $($resolved.Port) is outside the valid range 1-65535."
    }

    return $resolved
}

<#
.SYNOPSIS
    Opens a connection to a Sophos Firewall for use by every other cmdlet.

.DESCRIPTION
    Stores the firewall address, credentials and connection options as the default
    connection, so subsequent cmdlets from any module in this suite can be called without
    connection parameters. The password is kept as a SecureString, never as plain text. This
    cmdlet does not itself send a request; the credentials are only validated on first use.

    Call it once at the start of a session. Use -Name to hold more than one connection at
    the same time and address a specific one later with a cmdlet's own -Session parameter.

.PARAMETER Firewall
    Required. Host name or IP address of the firewall.

.PARAMETER Port
    Optional. TCP port of the management API. Default 4444.

.PARAMETER Credential
    Required. A PSCredential holding the API user name and password.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate.

.PARAMETER Name
    Optional. Registers this connection under a name in the session registry, so it can be
    referenced later as -Session '<Name>' from any cmdlet, or listed with Get-SfosSession,
    without holding a reference to the returned object. Lookup is case-insensitive. A
    connection made without -Name still becomes the default session, just without a registry
    entry.

.PARAMETER NoDefault
    Optional. Keeps the current default session unchanged instead of replacing it with this
    connection. Only meaningful together with -Name; without -Name this switch has no effect
    and the connection still becomes the default, because there would otherwise be no way to
    reach it again.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. The session object, with the properties
    Firewall, Port, Username, Password and SkipCertificateCheck. Pass it to another cmdlet's
    -Session parameter, or splat it directly.

.EXAMPLE
    $cred = Get-Credential -Message 'Sophos Firewall Admin'
    Connect-SfosFirewall -Firewall '192.168.1.1' -Port 4444 -Credential $cred -SkipCertificateCheck

    Opens a connection and makes it the default for every subsequent cmdlet call.

.EXAMPLE
    $cred = Get-Credential -Message 'Sophos Firewall Admin'
    Connect-SfosFirewall -Firewall 'fw1.example.test' -Credential $cred -Name 'fw1'
    Connect-SfosFirewall -Firewall 'fw2.example.test' -Credential $cred -Name 'fw2' -NoDefault
    Get-SfosSession

    Holds two connections at once: fw1 becomes the default session, fw2 is registered but
    does not replace it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Disconnect-SfosFirewall

.LINK
    Get-SfosSession
#>
function Connect-SfosFirewall {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. Connecting only
    # stores session data in this process and reads from the firewall to verify it; nothing
    # on the appliance changes, so there is nothing for ShouldProcess to confirm.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Firewall,

        [ValidateRange(1, 65535)]
        [int]$Port = $script:DefaultSfosPort,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscredential]$Credential,

        [switch]$SkipCertificateCheck,

        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [switch]$NoDefault
    )

    $session = [PSCustomObject]@{
        Firewall             = $Firewall
        Port                 = $Port
        Username             = $Credential.UserName
        Password             = $Credential.Password
        SkipCertificateCheck = [bool]$SkipCertificateCheck
    }
    $session.PSObject.TypeNames.Insert(0, 'SophosFirewall.Session')

    if ($Name) {
        $script:SfosSessions[$Name] = $session
    }

    # -NoDefault only has an effect together with -Name: without a registered name there is
    # no other way to reach this connection again, so treating a bare -NoDefault as "make no
    # default at all" would just lose the session. See .PARAMETER NoDefault.
    if (-not ($NoDefault -and $Name)) {
        $script:SfosConnection = $session
    }

    Write-Verbose "Connected to Sophos Firewall at $Firewall`:$Port as $($Credential.UserName)"
    return $session
}

<#
.SYNOPSIS
    Closes one, several, or all Sophos Firewall sessions.

.DESCRIPTION
    Removes stored connection state so it can no longer be used by other cmdlets. Nothing is
    sent to the firewall; this only clears local session data. Four ways to select what to
    close, mutually exclusive: no parameter clears the default session; -Name removes the one
    named session from the registry, and also clears the default session if that named
    session is currently the default; -Session does the same, but takes the session object
    itself, so Get-SfosSession | Disconnect-SfosFirewall works; -All clears the default
    session and empties the entire registry.

.PARAMETER Name
    Required in this parameter set. The registered name of the session to remove.

.PARAMETER Session
    Required in this parameter set. A session object from Connect-SfosFirewall, or the name
    of a session that was registered with Connect-SfosFirewall -Name. Accepts pipeline input.

.PARAMETER All
    Required in this parameter set. Closes the default session and every registered named
    session.

.INPUTS
    System.Object. Session can be piped in, for example from Get-SfosSession.

.OUTPUTS
    None.

.EXAMPLE
    Disconnect-SfosFirewall

    Closes the default session.

.EXAMPLE
    Disconnect-SfosFirewall -Name 'fw2'

    Closes the session registered under the name 'fw2'.

.EXAMPLE
    Get-SfosSession -Name 'fw2' | Disconnect-SfosFirewall

    Closes the session found by Get-SfosSession.

.EXAMPLE
    Disconnect-SfosFirewall -All

    Closes every open and registered session.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall

.LINK
    Get-SfosSession
#>
function Disconnect-SfosFirewall {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. Disconnecting drops
    # session data held in this process; the firewall is never contacted, so there is nothing
    # for ShouldProcess to confirm.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    # PSReviewUnusedParameter: -All only selects the 'All' parameter set; $PSCmdlet.ParameterSetName
    # drives the body, so the switch's value itself is never read once it has done that job.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'All')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Name')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Session', ValueFromPipeline)]
        [object]$Session,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All
    )

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Default' {
                if ($script:SfosConnection) {
                    Write-Verbose "Disconnected from Sophos Firewall at $($script:SfosConnection.Firewall)"
                    $script:SfosConnection = $null
                }
            }
            'Name' {
                if (-not $script:SfosSessions.ContainsKey($Name)) {
                    throw "No session named '$Name' is registered. Use Get-SfosSession to list registered sessions."
                }
                $removed = $script:SfosSessions[$Name]
                $script:SfosSessions.Remove($Name)
                if ($script:SfosConnection -and $script:SfosConnection -eq $removed) {
                    $script:SfosConnection = $null
                }
                Write-Verbose "Disconnected session '$Name' from Sophos Firewall at $($removed.Firewall)"
            }
            'Session' {
                # Get-SfosSession's own view object (Name/Firewall/Port/Username/
                # SkipCertificateCheck/IsDefault, deliberately without Password) is not the
                # same object reference as the registry entry and carries no
                # 'SophosFirewall.Session' PSTypeName, so Resolve-SfosSessionArgument's
                # duck-typing fallback would pass it through unchanged - and the reference
                # match below would then find nothing and silently disconnect nothing, the
                # exact "answers success, changes nothing" failure this project's rules
                # single out as the worst outcome available. Route it through its own Name
                # instead so 'Get-SfosSession -Name x | Disconnect-SfosFirewall' resolves to
                # the actual registered object.
                $target = $Session
                if ($target -isnot [string] -and
                    $target.PSObject.TypeNames -notcontains 'SophosFirewall.Session' -and
                    $target.PSObject.Properties.Match('Name').Count -gt 0) {
                    $target = [string]$target.Name
                }

                $resolved = Resolve-SfosSessionArgument -Session $target
                if ($resolved) {
                    foreach ($key in @($script:SfosSessions.Keys)) {
                        if ($script:SfosSessions[$key] -eq $resolved) {
                            $script:SfosSessions.Remove($key)
                        }
                    }
                    if ($script:SfosConnection -and $script:SfosConnection -eq $resolved) {
                        $script:SfosConnection = $null
                    }
                    Write-Verbose "Disconnected session from Sophos Firewall at $($resolved.Firewall)"
                }
            }
            'All' {
                $script:SfosConnection = $null
                $script:SfosSessions.Clear()
                Write-Verbose 'Disconnected all Sophos Firewall sessions.'
            }
        }
    }
}

<#
.SYNOPSIS
    Lists registered Sophos Firewall sessions, or one specific session by name.

.DESCRIPTION
    Returns a view of the sessions that were registered with Connect-SfosFirewall -Name,
    showing which one is currently the default. The stored password is never part of the
    output.

.PARAMETER Name
    Optional. Returns only the session registered under this name. Throws if no session with
    that name is registered. If omitted, every registered session is returned.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per session, with the properties
    Name, Firewall, Port, Username, SkipCertificateCheck and IsDefault.

.EXAMPLE
    Get-SfosSession

    Lists every registered session.

.EXAMPLE
    Get-SfosSession -Name 'fw2'

    Returns the session registered under the name 'fw2'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>
function Get-SfosSession {
    # PSUseSingularNouns: 'Session' is already singular - this cmdlet returns either every
    # registered session (no -Name) or exactly one (-Name), same as every other Get-Sfos*.
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$Name
    )

    if ($Name) {
        if (-not $script:SfosSessions.ContainsKey($Name)) {
            throw "No session named '$Name' is registered. Use Connect-SfosFirewall -Name '$Name' to register one."
        }
        $entry = $script:SfosSessions[$Name]
        return [PSCustomObject]@{
            Name                 = $Name
            Firewall             = $entry.Firewall
            Port                 = $entry.Port
            Username             = $entry.Username
            SkipCertificateCheck = $entry.SkipCertificateCheck
            IsDefault            = [bool]($script:SfosConnection -and $script:SfosConnection -eq $entry)
        }
    }

    foreach ($key in @($script:SfosSessions.Keys | Sort-Object)) {
        $entry = $script:SfosSessions[$key]
        [PSCustomObject]@{
            Name                 = $key
            Firewall             = $entry.Firewall
            Port                 = $entry.Port
            Username             = $entry.Username
            SkipCertificateCheck = $entry.SkipCertificateCheck
            IsDefault            = [bool]($script:SfosConnection -and $script:SfosConnection -eq $entry)
        }
    }
}

#endregion

#region Web Admin Console

<#
.SYNOPSIS
    Logs into the Sophos Firewall's web admin interface and returns a session context.

.DESCRIPTION
    This is the web admin interface (Web Admin Console, Controller?mode=...) - the browser
    UI an administrator signs into, and the interface the appliance itself names in its own
    login log ("User <account> logged in successfully to Web Admin Console"). It is NOT the
    appliance's CLI console reached through the web UI's own "Console" button - that is a
    separate SSH/terminal feature this cmdlet does not touch. It is also not the documented
    XML management API - there is no way to reach the web admin interface through
    Invoke-SfosApi.

    It is UNDOCUMENTED: no Sophos reference describes this mechanism, it is tied to the exact
    firmware build the login/CSRF/web admin pages were measured against (SFOS 22.0.1.490), and
    it can change or break on any firmware update without notice. Use it only where a domain
    module needs a web admin screen that has no equivalent in the XML API - see that module's
    own documentation for what it is used for and why.

    Performs the four-step web admin login measured against a live appliance: GET the root
    page to obtain the session cookie, POST the credentials (mode=151), GET the web admin
    start page to read the CSRF token out of its HTML, and return everything a subsequent
    request (Invoke-SfosWebAdminRequest) needs. No token or cookie is cached across calls to
    this cmdlet - each call opens its own fresh web admin session.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the web admin login. If omitted, the value from the current
    connection is used.

.PARAMETER Password
    Optional. Password for the web admin login, as a SecureString. If omitted, the value from
    the current connection is used. Unpacked to plain text only for the instant the login
    request is built, and cleared again in a finally block.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. The web admin session, with the properties
    BaseUri, WebSession, Csrf and SkipCertificateCheck. Pass it to
    Invoke-SfosWebAdminRequest.

.EXAMPLE
    $webAdmin = Connect-SfosWebAdmin -Firewall '192.0.2.10' -Port 4444 -Username 'admin' -Password $securePw -SkipCertificateCheck
    Invoke-SfosWebAdminRequest -WebAdminSession $webAdmin -Mode 5002

    Logs into the web admin interface directly and reads its filter catalog.

.EXAMPLE
    $webAdmin = Connect-SfosWebAdmin -Session 'fw1'

    Logs into the web admin interface using a connection registered earlier with
    Connect-SfosFirewall -Name 'fw1'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Invoke-SfosWebAdminRequest
#>
function Connect-SfosWebAdmin {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose, matching
    # Connect-SfosFirewall's own reasoning: this only performs a login and returns a session
    # context in this process; no configuration on the appliance changes, so there is nothing
    # for ShouldProcess to confirm. Unlike Connect-SfosFirewall, this does contact the
    # appliance on every call - but that contact is a login, not a write.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $baseUri = "https://{0}:{1}" -f $params.Firewall, $params.Port
    $invokeCommon = @{
        UseBasicParsing = $true
        TimeoutSec      = 30
    }

    $savedCertCallback = $null
    $certCallbackChanged = $false
    $certLockTaken = $false

    if ($params.SkipCertificateCheck) {
        if ($PSVersionTable.PSVersion.Major -le 5) {
            # Shares Invoke-SfosApi's own process-wide lock: both guard the same static
            # ServicePointManager callback, and two independent locks would give each other
            # no protection at all against a concurrent call.
            [System.Threading.Monitor]::Enter($script:CertCallbackLock)
            $certLockTaken = $true
            $savedCertCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
            $certCallbackChanged = $true
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        else {
            $invokeCommon['SkipCertificateCheck'] = $true
        }
    }

    $plainPassword = $null
    $passwordBstr = [IntPtr]::Zero

    try {
        try {
            $rootResponse = Invoke-WebRequest -Uri "$baseUri/" -SessionVariable webSession -ErrorAction Stop @invokeCommon
        }
        catch {
            throw "Could not reach the Sophos Firewall web console at $baseUri : $($_.Exception.Message)"
        }
        if ($rootResponse.StatusCode -ne 200) {
            throw "Sophos Firewall web console at $baseUri returned HTTP $($rootResponse.StatusCode) while opening a session."
        }

        $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($params.Password)
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)

        $loginJson = @{ username = $params.Username; password = $plainPassword; languageid = '1' } | ConvertTo-Json -Compress
        $loginBody = 'mode=151&json=' + [uri]::EscapeDataString($loginJson)

        try {
            $loginResponse = Invoke-WebRequest -Uri "$baseUri/webconsole/Controller" -Method Post `
                -Body $loginBody -ContentType 'application/x-www-form-urlencoded' `
                -WebSession $webSession -ErrorAction Stop @invokeCommon
        }
        catch {
            throw "Sophos Firewall web console login failed for '$($params.Username)' on $baseUri : $($_.Exception.Message)"
        }

        $loginResult = $null
        try {
            $loginResult = $loginResponse.Content | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            throw "Sophos Firewall web console login for '$($params.Username)' on $baseUri did not answer with the expected JSON. The console interface may have changed."
        }

        if (-not $loginResult.PSObject.Properties.Match('status').Count -or [int]$loginResult.status -ne 200) {
            throw "Sophos Firewall web console login failed for '$($params.Username)' on $baseUri (status '$($loginResult.status)')."
        }

        try {
            $pageResponse = Invoke-WebRequest -Uri "$baseUri/webconsole/webpages/index.jsp" `
                -WebSession $webSession -ErrorAction Stop @invokeCommon
        }
        catch {
            throw "Could not load the Sophos Firewall web console start page on $baseUri after login: $($_.Exception.Message)"
        }

        $csrfMatch = [regex]::Match($pageResponse.Content, 'Cyberoam\.c\$rFt0k3n\s*=\s*''([^'']+)''')
        if (-not $csrfMatch.Success) {
            throw "Could not read the CSRF token from the Sophos Firewall web console start page on $baseUri. The console interface may have changed."
        }

        return [PSCustomObject]@{
            BaseUri              = $baseUri
            WebSession           = $webSession
            Csrf                 = $csrfMatch.Groups[1].Value
            SkipCertificateCheck = [bool]$params.SkipCertificateCheck
        }
    }
    finally {
        if ($certCallbackChanged) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = $savedCertCallback
        }
        if ($certLockTaken) {
            [System.Threading.Monitor]::Exit($script:CertCallbackLock)
        }
        if ($passwordBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
        }
        $plainPassword = $null
    }
}

<#
.SYNOPSIS
    Sends one request to the Sophos Firewall web admin interface's controller.

.DESCRIPTION
    This is the web admin interface (Web Admin Console, Controller?mode=...), not the
    appliance's CLI console reached through the web UI's own "Console" button, and not the
    documented XML management API - there is no way to reach the web admin interface through
    Invoke-SfosApi.

    It is UNDOCUMENTED, tied to the exact firmware build it was measured against, and can
    change or break on any firmware update without notice. Use it only where a domain module
    needs a web admin screen that has no equivalent in the XML API. Only call a mode you have
    measured yourself: an unfamiliar mode number is a write against the web admin interface,
    not necessarily a read, and can change settings or reboot/shut down the appliance instead
    of just reading data.

    POSTs to Controller?csrf=<token> with the given mode and JSON body, using the session
    cookie and CSRF token from Connect-SfosWebAdmin, and returns the parsed JSON response. The
    headers X-Requested-With and Referer are always sent - measured against a live appliance,
    a request missing them can be answered with the web admin login page (HTML containing
    'loginstylesheet') instead of the requested data. That case is detected here and turned
    into a clear error, rather than an opaque parsing failure.

.PARAMETER WebAdminSession
    Required. The session context returned by Connect-SfosWebAdmin.

.PARAMETER Mode
    Required. The web admin controller mode, for example 5001 or 5002.

.PARAMETER Json
    Optional. The JSON body for this mode, as a compact string. Default '{}'.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. The parsed JSON response.

.EXAMPLE
    $webAdmin = Connect-SfosWebAdmin -Session 'fw1'
    Invoke-SfosWebAdminRequest -WebAdminSession $webAdmin -Mode 5002 -Json '{}'

    Reads the web admin interface's filter catalog against a registered session.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosWebAdmin
#>
function Invoke-SfosWebAdminRequest {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$WebAdminSession,

        [Parameter(Mandatory)]
        [int]$Mode,

        [string]$Json = '{}'
    )

    $headers = @{
        'X-Requested-With' = 'XMLHttpRequest'
        'Referer'           = "$($WebAdminSession.BaseUri)/webconsole/webpages/index.jsp"
    }
    $body = "mode=$Mode&json=" + [uri]::EscapeDataString($Json)

    $invokeParams = @{
        Uri             = "$($WebAdminSession.BaseUri)/webconsole/Controller?csrf=$($WebAdminSession.Csrf)"
        Method          = 'Post'
        Body            = $body
        ContentType     = 'application/x-www-form-urlencoded'
        WebSession      = $WebAdminSession.WebSession
        Headers         = $headers
        UseBasicParsing = $true
        TimeoutSec      = 30
        ErrorAction     = 'Stop'
    }

    # The certificate callback Connect-SfosWebAdmin installs for PS 5.1 is restored before
    # that cmdlet returns, so every later request in the same web admin session - this one
    # included - has to re-apply -SkipCertificateCheck itself rather than relying on a
    # callback left over from login.
    $savedCertCallback = $null
    $certCallbackChanged = $false
    $certLockTaken = $false
    if ($WebAdminSession.SkipCertificateCheck) {
        if ($PSVersionTable.PSVersion.Major -le 5) {
            [System.Threading.Monitor]::Enter($script:CertCallbackLock)
            $certLockTaken = $true
            $savedCertCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
            $certCallbackChanged = $true
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        else {
            $invokeParams['SkipCertificateCheck'] = $true
        }
    }

    try {
        try {
            $response = Invoke-WebRequest @invokeParams
        }
        finally {
            if ($certCallbackChanged) {
                [Net.ServicePointManager]::ServerCertificateValidationCallback = $savedCertCallback
            }
            if ($certLockTaken) {
                [System.Threading.Monitor]::Exit($script:CertCallbackLock)
            }
        }
    }
    catch {
        throw "Sophos Firewall web console request (mode $Mode) failed: $($_.Exception.Message)"
    }

    if ($response.Content -match 'loginstylesheet') {
        throw "Sophos Firewall web console request (mode $Mode) received the login page instead of data. This happens when the session is no longer valid, or when the required headers 'X-Requested-With: XMLHttpRequest' and 'Referer' are missing from the request."
    }

    try {
        return $response.Content | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Sophos Firewall web console request (mode $Mode) did not answer with the expected JSON. The console interface may have changed."
    }
}

#endregion

#region Archive Response Parsing

<#
.SYNOPSIS
    Reads a tar archive returned by the Sophos Firewall API as a file response.

.DESCRIPTION
    Certificate, CertificateAuthority, CRL and FormTemplate answer a Get with
    application/octet-stream instead of XML: a tar archive holding an Entities.xml (the same
    Response envelope a normal Get returns, describing every matching object) plus one file
    per object. Domain modules pass the raw response bytes to this cmdlet instead of parsing
    the archive themselves.

    The firewall double-UTF8-encodes any non-ASCII byte inside a tar header's name field
    (observed on object names containing non-ASCII characters). That shifts every field
    after the name by the extra byte count, so the header's own checksum no longer matches
    and the block chain cannot be walked past that entry - every file after it is
    unreachable through the tar structure, even though its bytes are still present in the
    response. This cmdlet does not throw when that happens: it returns every file entry read
    successfully before the break, sets -Truncated, names the last entry that read cleanly,
    and warns with that name so the caller knows which object's own file could not be read.

    Entities.xml is read independently of the block chain, by scanning the raw response for
    its Response...Response envelope rather than walking the tar structure to find it. That
    keeps the metadata for every matching object available even when one object's file
    entry desynchronises everything stored after it in the archive - the corruption is
    confined to individual file headers and does not touch the XML text itself.

.PARAMETER Bytes
    Required. The raw response body, exactly as received - never routed through a string or
    a character encoding, so binary file content stays byte-exact.

.PARAMETER ExtractTo
    Optional. Directory to write the contained files to, preserving their relative path from
    the archive root. Created if it does not exist. Without this parameter, files are only
    returned in memory via the Bytes property of each entry in .Files.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties:
    Entities (the parsed Entities.xml as an [xml] document, or $null if none was found),
    Files (an array of objects with Name and Bytes, plus Path when -ExtractTo was used;
    empty array if the archive holds no readable file), Truncated (whether the tar block
    chain broke before the end of the archive), and TruncatedAfter (the name of the last
    file entry read cleanly before the break, or $null if nothing broke or the very first
    entry was already unreadable).

.EXAMPLE
    $inner = Get-Content .\get-certificateauthority.xml -Raw
    $response = Invoke-SfosApi -Session 'fw1' -InnerXml $inner
    $archive = ConvertFrom-SfosArchive -Bytes $response.Content

    Reads every CertificateAuthority object's metadata from $archive.Entities, even if one
    object's certificate file could not be extracted.

.EXAMPLE
    $archive = ConvertFrom-SfosArchive -Bytes $response.Content -ExtractTo 'C:\Sfos\Export'

    Also writes every file the archive contains to disk and records the written path on
    each entry in .Files.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function ConvertFrom-SfosArchive {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [string]$ExtractTo
    )

    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $ascii = [System.Text.Encoding]::ASCII

    # Entities.xml is located by scanning the raw bytes for its own envelope rather than by
    # walking the tar block chain, because that chain can desynchronise before reaching it -
    # Entities.xml is always the last entry - while the bytes themselves are still present
    # right where the archive placed them. Latin-1 maps every byte to exactly one character
    # and back, so this search never alters or loses a byte; it only locates the range to
    # decode as UTF-8 afterwards.
    $entities = $null
    if ($Bytes.Length -gt 0) {
        $fullText = $latin1.GetString($Bytes)
        $startIndex = $fullText.IndexOf('<?xml')
        if ($startIndex -lt 0) {
            $startIndex = $fullText.IndexOf('<Response')
        }
        if ($startIndex -ge 0) {
            $endMarker = '</Response>'
            $endIndex = $fullText.LastIndexOf($endMarker)
            if ($endIndex -ge $startIndex) {
                $endIndex = $endIndex + $endMarker.Length
                $entitiesBytes = $Bytes[$startIndex..($endIndex - 1)]
                $entitiesText = [System.Text.Encoding]::UTF8.GetString($entitiesBytes)
                try {
                    $entities = [xml]$entitiesText
                }
                catch {
                    Write-Warning "ConvertFrom-SfosArchive found an Entities.xml block but could not parse it as XML: $($_.Exception.Message)"
                }
            }
        }
    }

    # The tar block chain is walked separately, purely to recover the individual files. A
    # 512-byte block that is entirely zero marks a clean end of archive, not a break.
    $files = [System.Collections.Generic.List[object]]::new()
    $truncated = $false
    $truncatedAfter = $null
    $lastGoodName = $null
    $position = 0

    while (($position + 512) -le $Bytes.Length) {
        $header = $Bytes[$position..($position + 511)]

        $isZeroBlock = $true
        for ($i = 0; $i -lt 512; $i++) {
            if ($header[$i] -ne 0) {
                $isZeroBlock = $false
                break
            }
        }
        if ($isZeroBlock) {
            break
        }

        $name = $ascii.GetString($header[0..99]).TrimEnd([char]0)
        $typeFlag = [char]$header[156]

        $sizeText = $ascii.GetString($header[124..135]).Trim([char]0, ' ')
        $size = -1
        if ($sizeText) {
            try { $size = [Convert]::ToInt64($sizeText, 8) } catch { $size = -1 }
        }
        else {
            $size = 0
        }

        $checksumText = $ascii.GetString($header[148..155]).Trim([char]0, ' ')
        $expectedChecksum = -1
        if ($checksumText) {
            try { $expectedChecksum = [Convert]::ToInt64($checksumText, 8) } catch { $expectedChecksum = -1 }
        }

        # The recorded checksum treats its own 8-byte field as ASCII spaces while summing
        # every other byte of the header - this is what a double-encoded name field throws
        # out of alignment, which is exactly the corruption this cmdlet is built to detect.
        $actualChecksum = 0
        for ($i = 0; $i -lt 512; $i++) {
            if ($i -ge 148 -and $i -lt 156) {
                $actualChecksum += 32
            }
            else {
                $actualChecksum += $header[$i]
            }
        }

        $headerValid = ($size -ge 0) -and ($expectedChecksum -ge 0) -and ($actualChecksum -eq $expectedChecksum)

        if ($headerValid) {
            $dataStart = $position + 512
            if (($dataStart + $size) -gt $Bytes.Length) {
                $headerValid = $false
            }
        }

        if (-not $headerValid) {
            $truncated = $true
            $truncatedAfter = $lastGoodName
            if ($truncatedAfter) {
                Write-Warning "ConvertFrom-SfosArchive: the archive's internal structure could not be read past the entry after '$truncatedAfter' - the firewall produced a malformed tar header there (commonly caused by non-ASCII characters in an object's stored name). Returning every file read successfully before that point; Entities.xml metadata is unaffected."
            }
            else {
                Write-Warning 'ConvertFrom-SfosArchive: the archive starts with a malformed tar header and no file could be read from it. Entities.xml metadata is unaffected.'
            }
            break
        }

        $dataStart = $position + 512
        if ($typeFlag -eq '0' -or $typeFlag -eq [char]0) {
            if ($size -eq 0) {
                $content = [byte[]]@()
            }
            else {
                $content = $Bytes[$dataStart..($dataStart + $size - 1)]
            }
            $files.Add([PSCustomObject]@{ Name = $name; Bytes = $content })
        }

        $lastGoodName = $name
        $dataBlocks = [Math]::Ceiling($size / 512.0)
        $position = $dataStart + ([int64]$dataBlocks * 512)
    }

    if ($ExtractTo) {
        if (-not (Test-Path -LiteralPath $ExtractTo)) {
            New-Item -ItemType Directory -Path $ExtractTo -Force | Out-Null
        }
        $extractRoot = (Resolve-Path -LiteralPath $ExtractTo).ProviderPath

        foreach ($file in $files) {
            $relative = $file.Name -replace '^\./', ''
            $targetPath = [System.IO.Path]::GetFullPath((Join-Path -Path $extractRoot -ChildPath $relative))

            # Refuse to write outside -ExtractTo: a stored name containing '..' would
            # otherwise be able to place a file anywhere the process can write.
            if (-not $targetPath.StartsWith($extractRoot, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Warning "ConvertFrom-SfosArchive: skipped extracting '$($file.Name)' because it resolves outside -ExtractTo."
                continue
            }

            $targetDir = Split-Path -Path $targetPath -Parent
            if ($targetDir -and -not (Test-Path -LiteralPath $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }
            [System.IO.File]::WriteAllBytes($targetPath, $file.Bytes)
            $file | Add-Member -MemberType NoteProperty -Name 'Path' -Value $targetPath -Force
        }
    }

    return [PSCustomObject]@{
        Entities       = $entities
        Files          = $files.ToArray()
        Truncated      = $truncated
        TruncatedAfter = $truncatedAfter
    }
}

#endregion

#region Module Exports

Export-ModuleMember -Function @(
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
    'Invoke-SfosWebAdminRequest'
)

#endregion
