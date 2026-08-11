#requires -Version 5.1
<#
.SYNOPSIS
    Core helper functions for Sophos Firewall API modules.

.DESCRIPTION
    Provides shared functionality for all Sophos Firewall PowerShell modules including:
    - Session management (Connect/Disconnect)
    - API communication (Invoke-SfosApi)
    - Response parsing and validation
    - XML escaping for security
    - Parameter resolution from session context

.NOTES
    Module Name: SophosFirewall.Core
    Author: Jan Weis
    Homepage: https://www.it-explorations.de
    Version: 1.0.0
    PowerShell Version: 5.1+
    
.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>

#region Module Variables

# Default Sophos Firewall API port
[int]$script:DefaultSfosPort = 4444

# Session context for connection reuse across cmdlets
$script:SfosConnection = $null

# Guards the process-wide certificate callback under PS 5.1. ServicePointManager is static,
# so two calls in parallel runspaces could each save the other's temporary "accept all"
# callback as the original and leave validation permanently disabled.
$script:CertCallbackLock = [object]::new()

#endregion

#region XML Helper Functions

<#
.SYNOPSIS
    Escapes XML special characters in text strings.

.DESCRIPTION
    Converts special characters to XML-safe entities to prevent injection attacks
    and ensure proper XML formatting.

.PARAMETER Text
    The text string to escape.

.OUTPUTS
    System.String. The XML-escaped string.

.EXAMPLE
    # Escape a value before interpolating it into request XML.
    # Returns: Smith &amp; Sons
    ConvertTo-SfosXmlEscaped -Text "Smith & Sons"

    # Angle brackets are deliberately absent from this example: PowerShell's help renderer
    # treats raw < > in an .EXAMPLE as markup and silently drops them together with the rest
    # of the line, so an example containing them reaches the reader mutilated. The cmdlet
    # escapes them all the same - see .DESCRIPTION.
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
    Throws when an API response reports a failed login. Internal helper, not exported.

.DESCRIPTION
    SFOS reports authentication outside the entity status: a lowercase <status> element
    directly under <Login>, with no code attribute, in an otherwise empty HTTP 200 body.
    Because it matches neither status path, an unchecked response looks like "no records"
    to Get-* and like success to every write operation.

.PARAMETER Content
    Raw response body.
#>
function Assert-SfosApiLoginSuccess {
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Content
    )

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
    Invokes a Sophos Firewall API request.
.DESCRIPTION
    Sends an XML request to the Sophos Firewall API endpoint and returns the response.
.PARAMETER Firewall
    The Sophos Firewall hostname or IP address.
.PARAMETER Port
    The management/API port number (default: 4444).
.PARAMETER Username
    The username for authentication (protected via XML-escaping).
.PARAMETER Password
    The password for authentication (as SecureString for security).
.PARAMETER InnerXml
    The inner XML content of the API request.
.PARAMETER ApiVersion
    Optional APIVersion attribute for the <Request> element (for example '2200.1').
    When omitted, the firewall processes the request using its own current schema
    version, which is what keeps one module compatible with several firmware levels.
.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for self-signed certificates.
.OUTPUTS
    The response from the API as a WebResponseObject.
.EXAMPLE
    # -Username is a plain string; only -Password is a SecureString. Passing a SecureString
    # for the user name converts it to the text "System.Security.SecureString" and the login
    # fails. The inner XML is shown entity-encoded because PowerShell's help renderer drops
    # raw angle brackets from examples - pass it with real < and >.
    $securePw = Read-Host -AsSecureString
    $inner = "&lt;Get&gt;&lt;IPHost&gt;&lt;/IPHost&gt;&lt;/Get&gt;"
    Invoke-SfosApi -Firewall "firewall.example.com" -Port 4444 -Username "admin" -Password $securePw -InnerXml $inner -SkipCertificateCheck
#>
function Invoke-SfosApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Firewall,
        
        [int]$Port = $script:DefaultSfosPort,
        
        [Parameter(Mandatory)]
        [string]$Username,
        
        [Parameter(Mandatory)]
        [SecureString]$Password,
        
        [Parameter(Mandatory)]
        [string]$InnerXml,

        [string]$ApiVersion,

        [switch]$SkipCertificateCheck
    )

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
    Extracts status information from API XML response.

.DESCRIPTION
    Parses the XML response to find status codes and messages.
    Looks in /Response/ObjectName/Status or /Response/Status.

.PARAMETER Xml
    The XML response from the API.

.PARAMETER ObjectName
    Optional object name to search for specific status node.

.OUTPUTS
    PSCustomObject with Code, Message, and XPathHint properties.

.EXAMPLE
    Get-SfosApiStatus -Xml $response -ObjectName "Zone"
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
    Validates that an API response indicates success.

.DESCRIPTION
    Checks the login status and the entity status codes of an API response and throws if
    the request did not succeed. Codes follow the table published by Sophos: 200 and 216
    are success, 201/203/211-215 succeed with a warning, everything else is a failure.
    There is no code 202 in that table.

    The published table covers 200-216 and 500-599. Codes 217 and 222 were measured against
    a live firewall on operations that demonstrably succeeded and only produce a warning;
    every other undocumented code throws, so an unrecognised status is never mistaken for
    success. See the comments at the corresponding checks.

.PARAMETER Xml
    The XML response from the API.

.PARAMETER ObjectName
    Optional object name for status lookup.

.PARAMETER Action
    Description of the action being performed (for error messages).

.PARAMETER Target
    Target object name (for error messages).

.EXAMPLE
    Assert-SfosApiReturnSuccess -Xml $response -ObjectName "Zone" -Action "Create" -Target "DMZ"
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
            continue
        }

        if ($code -eq 201 -or $code -eq 203 -or ($code -ge 211 -and $code -le 215)) {
            Write-Warning "Sophos API reported code $code while trying to $actionPart$targetPart. $($status.Message)"
            continue
        }

        # The published table runs 200-216 and then resumes at 500, so 217-499 is undefined.
        # Only the two codes actually measured against a firewall are let through, and only
        # because the write demonstrably succeeded in both cases: creating a WebFilterCategory
        # with an external URL list answers 217 or 222 'Unable to get status message' and the
        # object is created correctly.
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
    Resolves connection parameters from session context or explicit values.

.DESCRIPTION
    Looks up connection parameters from the module session variable if not explicitly provided.
    Ensures all required parameters are available for API calls.

.PARAMETER BoundParameters
    Hashtable of bound parameters from calling cmdlet.

.OUTPUTS
    Hashtable with resolved Firewall, Port, Username, Password, and SkipCertificateCheck.

.EXAMPLE
    $resolved = Resolve-SfosParameters -BoundParameters $PSBoundParameters
#>
function Resolve-SfosParameters {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BoundParameters
    )
    
    $resolved = @{
        Firewall             = $BoundParameters.Firewall
        Port                 = $BoundParameters.Port
        Username             = $BoundParameters.Username
        Password             = $BoundParameters.Password
        SkipCertificateCheck = $BoundParameters.SkipCertificateCheck
    }
    
    if ($script:SfosConnection) {
        if (-not $resolved.Firewall) {
            $resolved.Firewall = $script:SfosConnection.Firewall
        }
        # ContainsKey again: 0 is falsy, so -not would treat an explicit -Port 0 as
        # "not supplied" and quietly substitute another port instead of rejecting it.
        if (-not $BoundParameters.ContainsKey('Port')) {
            $resolved.Port = $script:SfosConnection.Port
        }
        if (-not $resolved.Username) {
            $resolved.Username = $script:SfosConnection.Username
        }
        if (-not $resolved.Password) {
            $resolved.Password = $script:SfosConnection.Password
        }
        # ContainsKey, not -not: an explicit -SkipCertificateCheck:$false must win over
        # a session that was opened with the switch enabled.
        if (-not $BoundParameters.ContainsKey('SkipCertificateCheck')) {
            $resolved.SkipCertificateCheck = $script:SfosConnection.SkipCertificateCheck
        }
    }
    
    if (-not $resolved.Firewall -or -not $resolved.Username -or -not $resolved.Password) {
        throw 'No active Sophos Firewall connection found. Use Connect-SfosFirewall to establish a connection or provide Firewall, Username, and Password explicitly.'
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
    Establishes a connection to a Sophos Firewall.

.DESCRIPTION
    Stores connection details in the module session variable for reuse by other cmdlets.
    Credentials are stored as SecureString for security.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address.

.PARAMETER Port
    Management/API port number (default: 4444).

.PARAMETER Credential
    PSCredential object containing username and password.

.PARAMETER SkipCertificateCheck
    Skips SSL certificate validation for self-signed certificates.

.OUTPUTS
    PSCustomObject with connection details.

.EXAMPLE
    $cred = Get-Credential -Message "Sophos Firewall Admin"
    Connect-SfosFirewall -Firewall "192.168.1.1" -Port 4444 -Credential $cred -SkipCertificateCheck
#>
function Connect-SfosFirewall {
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
        
        [switch]$SkipCertificateCheck
    )
    
    $script:SfosConnection = [PSCustomObject]@{
        Firewall             = $Firewall
        Port                 = $Port
        Username             = $Credential.UserName
        Password             = $Credential.Password
        SkipCertificateCheck = [bool]$SkipCertificateCheck
    }
    
    Write-Verbose "Connected to Sophos Firewall at $Firewall`:$Port as $($Credential.UserName)"
    return $script:SfosConnection
}

<#
.SYNOPSIS
    Disconnects from the Sophos Firewall.

.DESCRIPTION
    Clears the module session variable, removing stored credentials.

.EXAMPLE
    Disconnect-SfosFirewall
#>
function Disconnect-SfosFirewall {
    [CmdletBinding()]
    param()
    
    if ($script:SfosConnection) {
        Write-Verbose "Disconnected from Sophos Firewall at $($script:SfosConnection.Firewall)"
        $script:SfosConnection = $null
    }
}

#endregion

#region Module Exports

Export-ModuleMember -Function @(
    'Connect-SfosFirewall',
    'Disconnect-SfosFirewall',
    'Invoke-SfosApi',
    'Get-SfosApiStatus',
    'Assert-SfosApiReturnSuccess',
    'Resolve-SfosParameters',
    'ConvertTo-SfosXmlEscaped'
)

#endregion
