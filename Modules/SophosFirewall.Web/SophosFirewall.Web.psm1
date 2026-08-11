#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.1.0' }
<#
        .SYNOPSIS
        Manages web protection objects on Sophos Firewall: URL groups, web categories, file types,
        user activities, web filter policies and exceptions, surfing quotas, content conditions
        and the web protection settings.

        .DESCRIPTION
        PowerShell module for the PROTECT > Web area of the Sophos XGS / SFOS 22.0 XML API.

        This module provides functions to create, read, update, and delete:
        - URL Groups (with member management)
        - Web Categories (local domain/keyword lists and external URL lists)
        - File Types (file extension and MIME header groupings)
        - User Activities (with member management)
        - Web Filter Policies (including rule and category builders)
        - Web Filter Exceptions
        - Surfing Quota Policies
        - Content Condition Lists (with member management)

        It also exposes the web protection settings, which the API models as singletons
        without a name and with no create or delete operation:
        - Malware Protection
        - Web Filter Settings
        - Web Filter Protection Settings
        - Web Filter Advanced Settings
        - Default Web Filter Notification Settings

        All functions support pipeline input, filtering, and connection context management.
        Use Connect-SfosFirewall once, then call functions without connection parameters.

        .EXAMPLE
        # Connect to the firewall and list the web categories
        Connect-SfosFirewall -Firewall "192.168.1.1" -Credential (Get-Credential) -SkipCertificateCheck
        Get-SfosWebFilterCategory -NameLike "Social"

        .EXAMPLE
        # Create a URL group and add a member
        New-SfosWebFilterURLGroup -Name "Blocked-Sites" -Members "example.invalid" -Description "Manually blocked"
        Add-SfosWebFilterURLGroupMember -Name "Blocked-Sites" -Members "another.invalid"

        .EXAMPLE
        # Build a web filter policy from rules
        $rule = New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -Id "Gambling" -Type WebCategory) -HttpAction Deny
        New-SfosWebFilterPolicy -Name "Restricted" -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

        .EXAMPLE
        # Append a rule without losing the existing ones
        Add-SfosWebFilterPolicyRule -Name "Restricted" -Rule (New-SfosWebFilterPolicyRule -Category (New-SfosWebFilterPolicyCategory -Id "Weapons" -Type WebCategory) -HttpAction Warn)

        .EXAMPLE
        # Read the web protection settings
        Get-SfosWebFilterProtectionSettings

        .NOTES
        Module Name: SophosFirewall.Web
        Author: Jan Weis
        Homepage: https://www.it-explorations.de
        Version: 1.0.0
        PowerShell Version: 5.1+

        Dependencies:
        - SophosFirewall.Core module (provides Connect-SfosFirewall, Invoke-SfosApi, etc.)

        API Compatibility:
        - Sophos SFOS 22.0
        - Sophos XGS Firewall Series

        Total Functions: 52
        - 6 URL Group functions (including Add/Remove members)
        - 4 File Type functions
        - 4 Web Category functions
        - 6 User Activity functions (including Add/Remove members)
        - 4 Web Filter Exception functions
        - 8 Web Filter Policy functions (including rule/category builders and rule management)
        - 4 Surfing Quota Policy functions
        - 6 Content Condition List functions (including Add/Remove members)
        - 10 settings functions (5 Get/Set pairs)

        Behaviour that differs from the vendor documentation was measured against a live
        appliance and is recorded in the .NOTES of the affected function. The most important
        ones:
        - Remove-SfosFileType always fails on this firmware, including for freshly created
          objects.
        - Set-SfosUserActivity must always send <NewName>; omitting it renames the object to
          an empty name while reporting success.
        - Set-SfosWebFilterCategory can only grow an external URL list, never shrink it.
        - A partial update of the settings singletons can silently reset a field that was
          never sent, which is why every Set-* here reads the current state first.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Connect-SfosFirewall

        .LINK
        Get-SfosWebFilterPolicy

        .LINK
        Get-SfosWebFilterCategory
#>

# Helper functions are provided by SophosFirewall.Core module
# Module dependency is handled via RequiredModules in .psd1

#region WebFilterURLGroup

<#
        .SYNOPSIS
        Retrieves WebFilterURLGroup objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for WebFilterURLGroup objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosWebFilterURLGroup

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosWebFilterURLGroup -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosWebFilterURLGroup -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        The member list wrapper element is <URLlist> with a lowercase 'l' - not <URLList> as the naming convention of every other list wrapper in this API would suggest.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterURLGroup {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter: SFOS evaluates only the first <key> of the first <Filter>,
    # so only the name is sent. Everything else is filtered client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <WebFilterURLGroup>
    $filterXml
  </WebFilterURLGroup>
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
        throw "Error retrieving WebFilterURLGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # und Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterURLGroup' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/WebFilterURLGroup[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $webFilterURLGroupObjects = @()
    foreach ($node in $nodes) {
        $webFilterURLGroupObjects += [PSCustomObject]@{
            Name        = $node.Name
            Description = $node.Description
            URLlist     = [string[]]@($node.URLlist | Select-Object -ExpandProperty URL)
        }
    }

    return $webFilterURLGroupObjects
}

<#
        .SYNOPSIS
        Creates a new WebFilterURLGroup on the Sophos Firewall.

        .DESCRIPTION
        Creates a WebFilterURLGroup object that bundles one or more URLs for use in web filter policy rules and exceptions.
        After creation, use Add-SfosWebFilterURLGroupMember to add additional URLs.

        .PARAMETER Name
        Name of the URL group (1-50 characters, no commas).

        .PARAMETER Members
        Array of URLs to include in the group. At least one URL is required.

        .PARAMETER Description
        Optional description.

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a URL group with two entries
        New-SfosWebFilterURLGroup -Name "AllowedNews" -Members @("news.example.com", "example.org/news") -Description "Approved news sites"

        .EXAMPLE
        # Create with a single entry
        New-SfosWebFilterURLGroup -Name "VendorPortal" -Members "portal.vendor.example"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterURLGroup

        .LINK
        Add-SfosWebFilterURLGroupMember
#>
function New-SfosWebFilterURLGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    }

    $xmlMember = ''
    foreach ($member in $members) {
        if (-not $member) {
            continue
        }
        $mEsc = ConvertTo-SfosXmlEscaped -Text $member
        $xmlMember += "<URL>$mEsc</URL>"
    }

    $inner = @"
<Set operation="add">
  <WebFilterURLGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <URLlist>
        $xmlMember
    </URLlist>
  </WebFilterURLGroup>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("WebFilterURLGroup '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating WebFilterURLGroup object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterURLGroup' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing WebFilterURLGroup object on the Sophos Firewall.

        .DESCRIPTION
        Updates a WebFilterURLGroup object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current group first and keeps whatever
        the caller does not explicitly pass (Description, Members). To clear a field, pass it
        explicitly with an empty value.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more URLs to include. If omitted, the existing entries are kept.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update the description only, the URL list is preserved
        Set-SfosWebFilterURLGroup -Name "AllowedNews" -Description "Approved news and media sites"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosWebFilterURLGroup -NameLike "AllowedNews" | Set-SfosWebFilterURLGroup -Description "Updated"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterURLGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('URLlist')]
        [string[]]$members,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall. So read the current group first and override only what the caller
        # actually passed.
        $existing = @(Get-SfosWebFilterURLGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WebFilterURLGroup object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetMembers = if ($PSBoundParameters.ContainsKey('members')) {
            @($members)
        }
        else {
            @($existing[0].URLlist)
        }

        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $xmlMember = ''
        foreach ($member in $targetMembers) {
            if (-not $member) {
                continue
            }
            $mEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<URL>$mEsc</URL>"
        }

        $inner = @"
<Set operation="update">
  <WebFilterURLGroup>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <URLlist>
        $xmlMember
    </URLlist>
  </WebFilterURLGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("WebFilterURLGroup '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating WebFilterURLGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterURLGroup' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a WebFilterURLGroup object from the Sophos Firewall.

        .DESCRIPTION
        Removes a WebFilterURLGroup object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosWebFilterURLGroup -Name "Example" -WhatIf

        .EXAMPLE
        # Remove an object
        Remove-SfosWebFilterURLGroup -Name "Example"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosWebFilterURLGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("WebFilterURLGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <WebFilterURLGroup>
    <Name>$nameEsc</Name>
  </WebFilterURLGroup>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing WebFilterURLGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterURLGroup' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds members to an existing WebFilterURLGroup object on the Sophos Firewall.

        .DESCRIPTION
        Adds URLs to a WebFilterURLGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more URLs to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Add URLs to an existing group
        Add-SfosWebFilterURLGroupMember -Name "AllowedNews" -Members "news2.example.com","news3.example.com"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Add-SfosWebFilterURLGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {

        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $webFilterURLGroup = Get-SfosWebFilterURLGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact group
        $webFilterURLGroup = @($webFilterURLGroup | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($webFilterURLGroup.Count -eq 0) {
            throw "The WebFilterURLGroup object '$Name' was not found."
        }

        $webFilterURLGroup = $webFilterURLGroup[0]

        # Prefill existing members. SFOS applies the URL list as a whole - a
        # <Set operation="update"> replaces it instead of appending - so the current
        # entries must be written back together with the new ones.
        $urlGroupMembers = @()
        $urlGroupMembers += $webFilterURLGroup.URLlist
        $urlGroupMembers += $members
        $urlGroupMembers = $urlGroupMembers | Where-Object -FilterScript { $_ } | Select-Object -Unique

        # Build XML member list
        $xmlMember = ''
        foreach ($member in $urlGroupMembers) {
            if (-not $member) {
                continue
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<URL>$memberEsc</URL>"
        }

        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        $descriptionXml = ''
        if ($webFilterURLGroup.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $webFilterURLGroup.Description)</Description>"
        }

        $inner = @"
<Set operation="update">
    <WebFilterURLGroup>
        <Name>$nameEsc</Name>
        $descriptionXml
        <URLlist>
            $xmlMember
        </URLlist>
    </WebFilterURLGroup>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("WebFilterURLGroup '$($Name)' on $($params.Firewall)", 'Add members')) {
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
            throw "Error adding members to WebFilterURLGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterURLGroup' -Action 'add members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes members from an existing WebFilterURLGroup object on the Sophos Firewall.

        .DESCRIPTION
        Removes URLs from a WebFilterURLGroup object using the Sophos Firewall XML API. The cmdlet validates input where possible and escapes user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        One or more URLs to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Remove URLs from an existing group
        Remove-SfosWebFilterURLGroupMember -Name "AllowedNews" -Members "news2.example.com","news3.example.com"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosWebFilterURLGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }
    process {

        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $webFilterURLGroup = Get-SfosWebFilterURLGroup -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact group
        $webFilterURLGroup = @($webFilterURLGroup | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($webFilterURLGroup.Count -eq 0) {
            throw "The WebFilterURLGroup object '$Name' was not found."
        }

        $webFilterURLGroup = $webFilterURLGroup[0]

        if (@($webFilterURLGroup.URLlist).Count -eq 0) {
            # Nothing to remove
            return
        }

        # Prefill existing members
        $urlGroupMembers = [Collections.ArrayList]@()
        $urlGroupMembers.AddRange([string[]]@($webFilterURLGroup.URLlist))

        foreach ($member in $members) {
            [int]$indexMember = $urlGroupMembers.IndexOf($member)

            if ($indexMember -ne -1) {
                $urlGroupMembers.RemoveAt($indexMember)
            }
        }

        $xmlMember = ''
        foreach ($member in $urlGroupMembers) {
            if (-not $member) {
                continue
            }
            $memberEsc = ConvertTo-SfosXmlEscaped -Text $member
            $xmlMember += "<URL>$memberEsc</URL>"
        }

        # 'update' with the complete remaining list, not 'remove': SFOS replaces the
        # member list with whatever is sent, so a <Set operation="remove"> carrying the
        # members to drop would keep exactly those and discard the rest.
        # SFOS replaces the whole entity on update - an element that is not sent is
        # cleared on the firewall. Without carrying the description over, changing the
        # member list silently wiped it.
        $descriptionXml = ''
        if ($webFilterURLGroup.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $webFilterURLGroup.Description)</Description>"
        }

        $inner = @"
<Set operation="update">
    <WebFilterURLGroup>
        <Name>$nameEsc</Name>
        $descriptionXml
        <URLlist>
            $xmlMember
        </URLlist>
    </WebFilterURLGroup>
</Set>
"@
        # Send Request to the API
        if (-not $PSCmdlet.ShouldProcess("WebFilterURLGroup '$($Name)' on $($params.Firewall)", 'Remove members')) {
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
            throw "Error removing members from WebFilterURLGroup '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterURLGroup' -Action 'remove members' -Target $Name
    }
}

#endregion

#region FileType

<#
        .SYNOPSIS
        Retrieves FileType objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for FileType objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosFileType

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosFileType -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosFileType -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosFileType {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter: SFOS evaluates only the first <key> of the first <Filter>,
    # so only the name is sent. Everything else is filtered client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <FileType>
    $filterXml
  </FileType>
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
        throw "Error retrieving FileType objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # Funktion, die intern hierher zurueckgreift, um den Ist-Zustand zu ermitteln: sie
    # wuerde 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FileType' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/FileType[Name]' -ErrorAction SilentlyContinue |
    ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $fileTypeObjects = @()
    foreach ($node in $nodes) {
        # No Template property: the firewall never returns <Template>, so the value would
        # always be empty and would suggest a field that can be read back. See
        # Set-SfosFileType .NOTES.
        $fileTypeObjects += [PSCustomObject]@{
            Name              = $node.Name
            Description       = $node.Description
            FileExtensionList = [string[]]@($node.FileExtensionList | Select-Object -ExpandProperty FileExtension)
            MIMEHeaderList    = [string[]]@($node.MIMEHeaderList | Select-Object -ExpandProperty MIMEHeader)
        }
    }

    return $fileTypeObjects
}

<#
        .SYNOPSIS
        Creates a new FileType object on the Sophos Firewall.

        .DESCRIPTION
        Creates a FileType object that groups file extensions and MIME headers for use in web filter policy rules (e.g. as a rule category of type FileType).

        .PARAMETER Name
        Name of the file type object (1-50 characters, no commas).

        .PARAMETER FileExtension
        Optional array of file extensions (e.g. 'txt', 'jpg', 'gif').

        .PARAMETER MIMEHeader
        Optional array of MIME headers.

        .PARAMETER Description
        Optional description (max 1000 characters).

        .PARAMETER Template
        Optional template name, e.g. 'Blank'.

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a file type object for archive files
        New-SfosFileType -Name "ArchiveFiles" -FileExtension @("zip", "rar", "7z") -Description "Common archive formats"

        .NOTES
        Minimum supported PowerShell version: 5.1

        Live finding (SFOS 22.0, APIVersion 2200.1): -Template is accepted by the create
        request but Get-SfosFileType never returns a <Template> element on this firmware,
        regardless of whether one was sent. There is no way to confirm from the API whether
        the value was actually stored.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFileType

        .LINK
        Set-SfosFileType
#>
function New-SfosFileType {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$FileExtension,

        [string[]]$MIMEHeader,

        [ValidateLength(0, 1000)]
        [string]$Description,

        [string]$Template,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $xmlTemplate = ''
    if ($Template) {
        $templateEsc = ConvertTo-SfosXmlEscaped -Text $Template
        $xmlTemplate = "<Template>$templateEsc</Template>"
    }

    $xmlFileExtension = ''
    foreach ($extension in $FileExtension) {
        if (-not $extension) {
            continue
        }
        $extEsc = ConvertTo-SfosXmlEscaped -Text $extension
        $xmlFileExtension += "<FileExtension>$extEsc</FileExtension>"
    }
    $xmlFileExtensionList = ''
    if ($xmlFileExtension) {
        $xmlFileExtensionList = "<FileExtensionList>$xmlFileExtension</FileExtensionList>"
    }

    $xmlMimeHeader = ''
    foreach ($header in $MIMEHeader) {
        if (-not $header) {
            continue
        }
        $hdrEsc = ConvertTo-SfosXmlEscaped -Text $header
        $xmlMimeHeader += "<MIMEHeader>$hdrEsc</MIMEHeader>"
    }
    $xmlMimeHeaderList = ''
    if ($xmlMimeHeader) {
        $xmlMimeHeaderList = "<MIMEHeaderList>$xmlMimeHeader</MIMEHeaderList>"
    }

    $inner = @"
<Set operation="add">
  <FileType>
    <Name>$nameEsc</Name>
    $xmlTemplate
    $xmlFileExtensionList
    $xmlMimeHeaderList
    $xmlDescription
  </FileType>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("FileType '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating FileType object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FileType' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing FileType object on the Sophos Firewall.

        .DESCRIPTION
        Updates a FileType object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current object first and keeps whatever
        the caller does not explicitly pass (Description, Template, FileExtension, MIMEHeader).
        To clear a field, pass it explicitly with an empty value.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER FileExtension
        Optional array of file extensions. If omitted, the existing entries are kept.

        .PARAMETER MIMEHeader
        Optional array of MIME headers. If omitted, the existing entries are kept.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update the description only, extensions and MIME headers are preserved
        Set-SfosFileType -Name "ArchiveFiles" -Description "Common archive and compressed formats"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosFileType -NameLike "ArchiveFiles" | Set-SfosFileType -Description "Updated"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        This cmdlet deliberately has no -Template parameter, unlike New-SfosFileType.
        Template appears only in the vendor's sample XML, not in the documented attribute
        table, and Get-SfosFileType never returns a <Template> element - measured on SFOS
        22.0 / APIVersion 2200.1, whether or not one was sent. A field the Get cannot read
        back is a field the read-modify-write cannot preserve (see the project build rules, section 5), so
        offering it here would promise something the API does not deliver. Template is
        therefore a create-time parameter only.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosFileType {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('FileExtensionList')]
        [string[]]$FileExtension,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('MIMEHeaderList')]
        [string[]]$MIMEHeader,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 1000)]
        [string]$Description,

        # No -Template here on purpose: Get-SfosFileType never returns <Template>, so the
        # read-modify-write below could not preserve it. See .NOTES.

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall. So read the current object first and override only what the caller
        # actually passed.
        $existing = @(Get-SfosFileType -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The FileType object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetFileExtension = if ($PSBoundParameters.ContainsKey('FileExtension')) {
            @($FileExtension)
        }
        else {
            @($existing[0].FileExtensionList)
        }

        $targetMimeHeader = if ($PSBoundParameters.ContainsKey('MIMEHeader')) {
            @($MIMEHeader)
        }
        else {
            @($existing[0].MIMEHeaderList)
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        $xmlFileExtension = ''
        foreach ($extension in $targetFileExtension) {
            if (-not $extension) {
                continue
            }
            $extEsc = ConvertTo-SfosXmlEscaped -Text $extension
            $xmlFileExtension += "<FileExtension>$extEsc</FileExtension>"
        }
        $xmlFileExtensionList = ''
        if ($xmlFileExtension) {
            $xmlFileExtensionList = "<FileExtensionList>$xmlFileExtension</FileExtensionList>"
        }

        $xmlMimeHeader = ''
        foreach ($header in $targetMimeHeader) {
            if (-not $header) {
                continue
            }
            $hdrEsc = ConvertTo-SfosXmlEscaped -Text $header
            $xmlMimeHeader += "<MIMEHeader>$hdrEsc</MIMEHeader>"
        }
        $xmlMimeHeaderList = ''
        if ($xmlMimeHeader) {
            $xmlMimeHeaderList = "<MIMEHeaderList>$xmlMimeHeader</MIMEHeaderList>"
        }

        $inner = @"
<Set operation="update">
  <FileType>
    <Name>$nameEsc</Name>
    $xmlFileExtensionList
    $xmlMimeHeaderList
    $xmlDescription
  </FileType>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("FileType '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating FileType object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FileType' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a FileType object from the Sophos Firewall.

        .DESCRIPTION
        Removes a FileType object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosFileType -Name "Example" -WhatIf

        .EXAMPLE
        # Remove an object
        Remove-SfosFileType -Name "Example"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        Known firmware defect (reproduced against SFOS 22.0, APIVersion 2200.1): the documented
        Delete operation for FileType takes exactly one parameter (Name) and lists 200/500/504
        as possible responses. On the tested firmware it answers Status code="500" - "Operation
        could not be performed on Entity." for every call, including a freshly created object
        that is referenced nowhere else. A control call removing a WebFilterURLGroup in the same
        test run returned 200, so this is specific to FileType, not to the Remove path in
        general. This cmdlet is implemented documentation-faithfully regardless; callers should
        expect Remove-SfosFileType to fail on this firmware and plan accordingly (e.g. do not
        rely on being able to delete FileType objects created for testing).

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosFileType {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("FileType '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <FileType>
    <Name>$nameEsc</Name>
  </FileType>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing FileType object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'FileType' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion


#region WebFilterCategory

<#
        .SYNOPSIS
        Retrieves WebFilterCategory objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for WebFilterCategory objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER ClassificationLike
        Optional classification filter, matched as a substring anywhere in the value (e.g. "Productive"). The firewall does not support filtering on Classification, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosWebFilterCategory

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosWebFilterCategory -NameLike "Gambling"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosWebFilterCategory -NameLike "Gambling" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterCategory {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$ClassificationLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
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
  <WebFilterCategory>
    $filterXml
  </WebFilterCategory>
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
        throw "Error retrieving WebFilterCategory objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-Funktion,
    # die intern hierher zurueckgreift, um den Ist-Zustand zu ermitteln: sie wuerde 'Objekt
    # nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterCategory' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/WebFilterCategory[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($ClassificationLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Classification -like "*$ClassificationLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $webFilterCategoryObjects = @()
    foreach ($node in $nodes) {
        $webFilterCategoryObjects += [PSCustomObject]@{
            Name                         = $node.Name
            Classification               = $node.Classification
            ConfigureCategory            = $node.ConfigureCategory
            QoSPolicy                    = $node.QoSPolicy
            Description                  = $node.Description
            DomainList                   = [string[]]($node.DomainList | Select-Object -ExpandProperty Domain)
            KeywordList                  = [string[]]($node.KeywordList | Select-Object -ExpandProperty Keyword)
            URLList                      = [string[]]($node.URLList | Select-Object -ExpandProperty URL)
            OverrideDefaultDeniedMessage = $node.OverrideDefaultDeniedMessage
            DefaultDeniedMessage         = $node.DefaultDeniedMessage
            Notification                 = $node.Notification
        }
    }

    return $webFilterCategoryObjects
}

<#
        .SYNOPSIS
        Creates a new WebFilterCategory on the Sophos Firewall.

        .DESCRIPTION
        Creates a WebFilterCategory, either matched locally by domain/keyword or as an
        external (URL-based) category. ConfigureCategory is not exposed as its own
        parameter - it is derived from which parameter set is selected: passing -Domain
        and/or -Keyword builds a 'Local' category, passing -Url builds an 'External' one
        (the project build rules, section 4). The firewall documents Classification, QoSPolicy and
        ConfigureCategory as optional, but rejects a create that omits any of them with a
        500/501, so all three are always sent.

        .PARAMETER Name
        Name of the web filter category (1-50 characters; '^', ';', apostrophe, quote and backtick are not allowed).

        .PARAMETER Classification
        Traffic classification: 'Productive', 'Unproductive', 'Acceptable' or 'Objectionable'.

        .PARAMETER QoSPolicy
        Name of a QoS policy to apply, or 'None'.

        .PARAMETER Domain
        Array of domains for a local ('Local') category. Selects the 'Local' parameter set. Each entry is at most 250 characters.

        .PARAMETER Keyword
        Array of keywords for a local ('Local') category. Selects the 'Local' parameter set. Each entry is at most 250 characters.

        .PARAMETER Url
        Array of URLs for an external ('External') category. Selects the 'External' parameter set. Entries must not include a scheme (http://, https://) - the firewall rejects those with an opaque 501; use a bare host[/path] value, e.g. "www.example.com/list".

        .PARAMETER Description
        Optional description (max 512 characters).

        .PARAMETER OverrideDefaultDeniedMessage
        Optional override of the default denied message: 'Enable' or 'Disable'.

        .PARAMETER DefaultDeniedMessage
        Optional custom denied message text/HTML.

        .PARAMETER Notification
        Optional notification setting: 'Enable' or 'Disable'.

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a local category matched by domain
        New-SfosWebFilterCategory -Name "Custom-Local" -Classification Productive -QoSPolicy None -Domain "example.com"

        .EXAMPLE
        # Create an external category matched by URL
        New-SfosWebFilterCategory -Name "External-Feed" -Classification Acceptable -QoSPolicy None -Url "www.example.com/list.txt"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterCategory
#>
function New-SfosWebFilterCategory {
    [CmdletBinding(DefaultParameterSetName = 'Local', SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Productive', 'Unproductive', 'Acceptable', 'Objectionable')]
        [string]$Classification,

        [Parameter(Mandatory)]
        [string]$QoSPolicy,

        [Parameter(ParameterSetName = 'Local')]
        [string[]]$Domain,

        [Parameter(ParameterSetName = 'Local')]
        [string[]]$Keyword,

        [Parameter(ParameterSetName = 'External')]
        [string[]]$Url,

        [ValidateLength(0, 512)]
        [string]$Description,

        [ValidateSet('Enable', 'Disable')]
        [string]$OverrideDefaultDeniedMessage,

        [string]$DefaultDeniedMessage,

        [ValidateSet('Enable', 'Disable')]
        [string]$Notification,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $qosEsc = ConvertTo-SfosXmlEscaped -Text $QoSPolicy

    # ConfigureCategory is not its own parameter - it is derived from the selected
    # parameter set (Local via -Domain/-Keyword, External via -Url). The set names match
    # the API values exactly, so the set name is sent as-is.
    $configureCategory = $PSCmdlet.ParameterSetName

    $xmlDescription = ''
    if ($Description) {
        $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $xmlDomainList = ''
    if ($Domain) {
        $domainXml = ''
        foreach ($domainItem in $Domain) {
            if (-not $domainItem) {
                continue
            }
            if ($domainItem.Length -gt 250) {
                throw "Domain entry '$domainItem' must be 250 characters or fewer."
            }
            $domainXml += "<Domain>$(ConvertTo-SfosXmlEscaped -Text $domainItem)</Domain>"
        }
        $xmlDomainList = "<DomainList>$domainXml</DomainList>"
    }

    $xmlKeywordList = ''
    if ($Keyword) {
        $keywordXml = ''
        foreach ($keywordItem in $Keyword) {
            if (-not $keywordItem) {
                continue
            }
            if ($keywordItem.Length -gt 250) {
                throw "Keyword entry '$keywordItem' must be 250 characters or fewer."
            }
            $keywordXml += "<Keyword>$(ConvertTo-SfosXmlEscaped -Text $keywordItem)</Keyword>"
        }
        $xmlKeywordList = "<KeywordList>$keywordXml</KeywordList>"
    }

    $xmlUrlList = ''
    if ($Url) {
        $urlXml = ''
        foreach ($urlItem in $Url) {
            if (-not $urlItem) {
                continue
            }
            # Live-verified: a URL carrying a scheme (http://, https://) is rejected with an
            # opaque "501 Configuration parameters validation failed" naming only the XPath,
            # not the value. The firewall expects a bare host[/path] entry.
            if ($urlItem -match '^[a-zA-Z][a-zA-Z0-9+.\-]*://') {
                throw "URL entry '$urlItem' must not include a scheme (http://, https://); use a bare host[/path] value instead."
            }
            $urlXml += "<URL>$(ConvertTo-SfosXmlEscaped -Text $urlItem)</URL>"
        }
        $xmlUrlList = "<URLList>$urlXml</URLList>"
    }

    $xmlOverride = ''
    if ($PSBoundParameters.ContainsKey('OverrideDefaultDeniedMessage')) {
        $xmlOverride = "<OverrideDefaultDeniedMessage>$OverrideDefaultDeniedMessage</OverrideDefaultDeniedMessage>"
    }

    $xmlDefaultDeniedMessage = ''
    if ($DefaultDeniedMessage) {
        $xmlDefaultDeniedMessage = "<DefaultDeniedMessage>$(ConvertTo-SfosXmlEscaped -Text $DefaultDeniedMessage)</DefaultDeniedMessage>"
    }

    $xmlNotification = ''
    if ($PSBoundParameters.ContainsKey('Notification')) {
        $xmlNotification = "<Notification>$Notification</Notification>"
    }

    $inner = @"
<Set operation="add">
  <WebFilterCategory>
    <Name>$nameEsc</Name>
    <Classification>$Classification</Classification>
    <QoSPolicy>$qosEsc</QoSPolicy>
    <ConfigureCategory>$configureCategory</ConfigureCategory>
    $xmlDescription
    $xmlDomainList
    $xmlKeywordList
    $xmlUrlList
    $xmlOverride
    $xmlDefaultDeniedMessage
    $xmlNotification
  </WebFilterCategory>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("WebFilterCategory '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating WebFilterCategory object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Live-verified: a create/update for ConfigureCategory=External can answer with a status
    # code outside the documented 200-216/500-599 ranges (217 and 222 both observed) even
    # though the object was created correctly. Assert-SfosApiReturnSuccess treats those as a
    # warning rather than a failure, so this call does not throw for them - but a caller
    # relying on "no output" should still expect a Write-Warning on the External path.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterCategory' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing WebFilterCategory object on the Sophos Firewall.

        .DESCRIPTION
        Updates a WebFilterCategory object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current category first and keeps
        whatever the caller does not explicitly pass. QoSPolicy and ConfigureCategory are
        singled out by the firewall as effectively mandatory (500/501 if missing), so both
        are always sent. ConfigureCategory cannot be split into parameter sets here: with
        pipeline input PowerShell fixes the parameter set before it binds properties
        (the project build rules, section 4), so a Get-SfosWebFilterCategory | Set-SfosWebFilterCategory call
        would silently land in whichever set is the default. It is therefore a single
        mandatory parameter instead, matching the pattern used for HostType in
        Set-SfosIPHost.

        KNOWN FIRMWARE DEFECT (live-verified): unlike every other list in this module,
        URLList on an update is APPEND-ONLY - it does not follow the whole-entity-replace
        rule. Sending fewer URLs than currently stored, or an empty <URLList>, still leaves
        every previously stored URL in place (observed status code 201 "Operation partially
        successful"). -Url can therefore grow the list but cannot shrink or clear it; there
        is no client-side workaround short of removing and recreating the object.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Classification
        Traffic classification: 'Productive', 'Unproductive', 'Acceptable' or 'Objectionable'. If omitted, the existing value on the firewall is kept.

        .PARAMETER QoSPolicy
        Name of a QoS policy to apply, or 'None'. If omitted, the existing value on the firewall is kept.

        .PARAMETER ConfigureCategory
        Category type: 'Local' or 'External'. Mandatory - determines whether Domain/Keyword or Url apply.

        .PARAMETER Domain
        Array of domains (ConfigureCategory 'Local'). If omitted, the existing domains are kept.

        .PARAMETER Keyword
        Array of keywords (ConfigureCategory 'Local'). If omitted, the existing keywords are kept.

        .PARAMETER Url
        Array of URLs (ConfigureCategory 'External'). If omitted, the existing URLs are kept. Entries must not include a scheme (http://, https://) - the firewall rejects those with an opaque 501; use a bare host[/path] value, e.g. "www.example.com/list". Known firmware defect: updates append to the stored URL list rather than replacing it (see DESCRIPTION), so this parameter cannot be used to remove or clear URLs.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER OverrideDefaultDeniedMessage
        Override of the default denied message: 'Enable' or 'Disable'. If omitted, the existing value is kept.

        .PARAMETER DefaultDeniedMessage
        Custom denied message text/HTML. If omitted, the existing value is kept.

        .PARAMETER Notification
        Notification setting: 'Enable' or 'Disable'. If omitted, the existing value is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update just the description, keeping everything else
        Set-SfosWebFilterCategory -Name "Custom-Local" -ConfigureCategory Local -Description "Updated"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosWebFilterCategory -NameLike "Custom-Local" | Set-SfosWebFilterCategory -Domain "example.org"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterCategory {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Productive', 'Unproductive', 'Acceptable', 'Objectionable')]
        [string]$Classification,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$QoSPolicy,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Local', 'External')]
        [string]$ConfigureCategory,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('DomainList')]
        [string[]]$Domain,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('KeywordList')]
        [string[]]$Keyword,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('URLList')]
        [string[]]$Url,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 512)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$OverrideDefaultDeniedMessage,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DefaultDeniedMessage,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Notification,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall. Read the current category first and override only what the caller
        # actually passed.
        $existing = @(Get-SfosWebFilterCategory -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WebFilterCategory object '$Name' was not found."
        }

        $targetClassification = if ($PSBoundParameters.ContainsKey('Classification')) {
            $Classification
        }
        else {
            [string]$existing[0].Classification
        }

        $targetQoSPolicy = if ($PSBoundParameters.ContainsKey('QoSPolicy')) {
            $QoSPolicy
        }
        else {
            [string]$existing[0].QoSPolicy
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetOverride = if ($PSBoundParameters.ContainsKey('OverrideDefaultDeniedMessage')) {
            $OverrideDefaultDeniedMessage
        }
        else {
            [string]$existing[0].OverrideDefaultDeniedMessage
        }

        $targetDefaultDeniedMessage = if ($PSBoundParameters.ContainsKey('DefaultDeniedMessage')) {
            $DefaultDeniedMessage
        }
        else {
            [string]$existing[0].DefaultDeniedMessage
        }

        $targetNotification = if ($PSBoundParameters.ContainsKey('Notification')) {
            $Notification
        }
        else {
            [string]$existing[0].Notification
        }

        $qosEsc = ConvertTo-SfosXmlEscaped -Text $targetQoSPolicy

        $xmlDescription = ''
        if ($targetDescription) {
            $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>"
        }

        $xmlOverride = ''
        if ($targetOverride) {
            $xmlOverride = "<OverrideDefaultDeniedMessage>$targetOverride</OverrideDefaultDeniedMessage>"
        }

        $xmlDefaultDeniedMessage = ''
        if ($targetDefaultDeniedMessage) {
            $xmlDefaultDeniedMessage = "<DefaultDeniedMessage>$(ConvertTo-SfosXmlEscaped -Text $targetDefaultDeniedMessage)</DefaultDeniedMessage>"
        }

        $xmlNotification = ''
        if ($targetNotification) {
            $xmlNotification = "<Notification>$targetNotification</Notification>"
        }

        # Only the list matching the (possibly changed) ConfigureCategory is sent, mirroring
        # New-SfosWebFilterCategory. Switching type re-derives Domain/Keyword/Url the same way.
        $xmlDomainList = ''
        $xmlKeywordList = ''
        $xmlUrlList = ''
        if ($ConfigureCategory -eq 'Local') {
            $targetDomain = if ($PSBoundParameters.ContainsKey('Domain')) { @($Domain) } else { @($existing[0].DomainList) }
            $targetKeyword = if ($PSBoundParameters.ContainsKey('Keyword')) { @($Keyword) } else { @($existing[0].KeywordList) }

            $domainXml = ''
            foreach ($domainItem in $targetDomain) {
                if (-not $domainItem) {
                    continue
                }
                if ($domainItem.Length -gt 250) {
                    throw "Domain entry '$domainItem' must be 250 characters or fewer."
                }
                $domainXml += "<Domain>$(ConvertTo-SfosXmlEscaped -Text $domainItem)</Domain>"
            }
            $xmlDomainList = "<DomainList>$domainXml</DomainList>"

            $keywordXml = ''
            foreach ($keywordItem in $targetKeyword) {
                if (-not $keywordItem) {
                    continue
                }
                if ($keywordItem.Length -gt 250) {
                    throw "Keyword entry '$keywordItem' must be 250 characters or fewer."
                }
                $keywordXml += "<Keyword>$(ConvertTo-SfosXmlEscaped -Text $keywordItem)</Keyword>"
            }
            $xmlKeywordList = "<KeywordList>$keywordXml</KeywordList>"
        }
        else {
            $targetUrl = if ($PSBoundParameters.ContainsKey('Url')) { @($Url) } else { @($existing[0].URLList) }

            # Known firmware defect (see comment-based help): URLList updates are
            # append-only on this firmware, so sending fewer entries than currently stored
            # does not remove any of them.
            $urlXml = ''
            foreach ($urlItem in $targetUrl) {
                if (-not $urlItem) {
                    continue
                }
                # See New-SfosWebFilterCategory: a URL with a scheme is rejected with an
                # opaque 501 that names only the XPath, not the value.
                if ($urlItem -match '^[a-zA-Z][a-zA-Z0-9+.\-]*://') {
                    throw "URL entry '$urlItem' must not include a scheme (http://, https://); use a bare host[/path] value instead."
                }
                $urlXml += "<URL>$(ConvertTo-SfosXmlEscaped -Text $urlItem)</URL>"
            }
            $xmlUrlList = "<URLList>$urlXml</URLList>"
        }

        $inner = @"
<Set operation="update">
  <WebFilterCategory>
    <Name>$nameEsc</Name>
    <Classification>$targetClassification</Classification>
    <QoSPolicy>$qosEsc</QoSPolicy>
    <ConfigureCategory>$ConfigureCategory</ConfigureCategory>
    $xmlDescription
    $xmlDomainList
    $xmlKeywordList
    $xmlUrlList
    $xmlOverride
    $xmlDefaultDeniedMessage
    $xmlNotification
  </WebFilterCategory>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("WebFilterCategory '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating WebFilterCategory object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # See New-SfosWebFilterCategory: ConfigureCategory=External can answer with an
        # undocumented status code (217/222 observed); Assert-SfosApiReturnSuccess warns
        # instead of throwing for those.
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterCategory' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a WebFilterCategory object from the Sophos Firewall.

        .DESCRIPTION
        Removes a WebFilterCategory object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosWebFilterCategory -Name "Custom-Local" -WhatIf

        .EXAMPLE
        # Remove an object
        Remove-SfosWebFilterCategory -Name "Custom-Local"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosWebFilterCategory {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("WebFilterCategory '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <WebFilterCategory>
    <Name>$nameEsc</Name>
  </WebFilterCategory>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing WebFilterCategory object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterCategory' -Action 'remove' -Target $Name
    }
}

#endregion

#region UserActivity

<#
        .SYNOPSIS
        Retrieves UserActivity objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for UserActivity objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosUserActivity

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosUserActivity -NameLike "Search"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosUserActivity -NameLike "Search" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        The CategoryList entries are returned as PSCustomObjects with 'ID' (the referenced
        object's plain-text name) and 'Type' properties. The underlying XML child element is
        spelled '<type>' in lowercase on this firmware, unlike the documentation sample.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosUserActivity {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
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
  <UserActivity>
    $filterXml
  </UserActivity>
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
        throw "Error retrieving UserActivity objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set- und
    # Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserActivity' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/UserActivity[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering. Only the first <key> of the first <Filter> is evaluated by
    # SFOS, so the filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $userActivityObjects = @()
    foreach ($node in $nodes) {
        $categoryList = @()
        foreach ($categoryNode in $node.CategoryList.Category) {
            $categoryList += [PSCustomObject]@{
                ID   = $categoryNode.ID
                Type = $categoryNode.type
            }
        }

        $userActivityObjects += [PSCustomObject]@{
            Name         = $node.Name
            Desc         = $node.Desc
            NewName      = $node.NewName
            CategoryList = $categoryList
        }
    }

    return $userActivityObjects
}

<#
        .SYNOPSIS
        Creates a new UserActivity on the Sophos Firewall.

        .DESCRIPTION
        Creates a UserActivity object grouping one or more categories (web categories,
        file types or URL groups). The firewall documents CategoryList as optional but
        rejects a create that omits it with a 501 InvalidParams, so it is mandatory here.

        .PARAMETER Name
        Name of the user activity (1-50 characters; '^', ';', apostrophe, quote and backtick are not allowed).

        .PARAMETER Desc
        Optional description (max 255 characters).

        .PARAMETER CategoryList
        Array of category entries. Each entry needs an 'ID' (the plain-text name of the referenced object) and a 'Type' property, e.g. [PSCustomObject]@{ID='Search Engines';Type='web category'}. Type is 'web category', 'file type' or 'url group'.

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a user activity grouping two web categories
        New-SfosUserActivity -Name "Search-Activity" -Desc "Test" -CategoryList @([PSCustomObject]@{ID='Search Engines';Type='web category'}, [PSCustomObject]@{ID='Image Search';Type='web category'})

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserActivity

        .LINK
        Add-SfosUserActivityMember
#>
function New-SfosUserActivity {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Desc,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object[]]$CategoryList,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $descEsc = ''
    if ($Desc) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Desc
    }

    $xmlCategory = ''
    foreach ($category in $CategoryList) {
        if (-not $category.ID -or -not $category.Type) {
            throw "Each CategoryList entry for UserActivity '$Name' needs an 'ID' and a 'Type' property, e.g. [PSCustomObject]@{ID='Search Engines';Type='web category'}."
        }
        $idEsc = ConvertTo-SfosXmlEscaped -Text $category.ID
        $typeEsc = ConvertTo-SfosXmlEscaped -Text $category.Type
        $xmlCategory += "<Category><ID>$idEsc</ID><type>$typeEsc</type></Category>"
    }

    $inner = @"
<Set operation="add">
  <UserActivity>
    <Name>$nameEsc</Name>
    <Desc>$descEsc</Desc>
    <CategoryList>
        $xmlCategory
    </CategoryList>
  </UserActivity>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("UserActivity '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating UserActivity object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserActivity' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing UserActivity object on the Sophos Firewall.

        .DESCRIPTION
        Updates a UserActivity object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current object first and keeps
        whatever the caller does not explicitly pass (Desc, CategoryList).

        THE MOST DANGEROUS FINDING IN THIS AREA (live-verified): an update sent without
        <NewName> answers HTTP 200 / status code 200, but renames the object to an EMPTY
        name. The object then becomes unreachable under its old name and stays behind as
        an invisible orphan. This cmdlet therefore always sends <NewName> - the new name
        when -NewName is supplied, otherwise the object's current name - never omit it,
        even though the API documentation marks NewName as optional. Do not remove this as
        seemingly redundant.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER NewName
        New name to rename the object to. If omitted, the object keeps its current name - but <NewName> is still sent on every update (see DESCRIPTION).

        .PARAMETER Desc
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER CategoryList
        Array of category entries (see New-SfosUserActivity). If omitted, the existing categories are kept. The firewall rejects an update with an empty category list.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update just the description, keeping the category list
        Set-SfosUserActivity -Name "Search-Activity" -Desc "Updated"

        .EXAMPLE
        # Rename the object
        Set-SfosUserActivity -Name "Search-Activity" -NewName "Search-Activity-Renamed"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosUserActivity -NameLike "Search-Activity" | Set-SfosUserActivity -Desc "Updated via pipeline"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosUserActivity {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$NewName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Desc,

        [Parameter(ValueFromPipelineByPropertyName)]
        [object[]]$CategoryList,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared. Read the
        # current object first and keep whatever the caller did not pass.
        $existing = @(Get-SfosUserActivity -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The UserActivity object '$Name' was not found."
        }

        # Live-verified: an update without <NewName> is answered with HTTP 200 / status 200
        # but renames the object to an empty name, leaving an unreachable orphan behind.
        # <NewName> is therefore always sent - the current name when the caller is not
        # renaming. Do not "simplify" this away.
        $targetNewName = if ($PSBoundParameters.ContainsKey('NewName')) {
            $NewName
        }
        else {
            $Name
        }

        $targetDesc = if ($PSBoundParameters.ContainsKey('Desc')) {
            $Desc
        }
        else {
            [string]$existing[0].Desc
        }

        $targetCategoryList = if ($PSBoundParameters.ContainsKey('CategoryList')) {
            @($CategoryList)
        }
        else {
            @($existing[0].CategoryList)
        }

        if ($targetCategoryList.Count -eq 0) {
            throw "UserActivity '$Name' needs at least one CategoryList entry; the firewall rejects an update with an empty category list."
        }

        $newNameEsc = ConvertTo-SfosXmlEscaped -Text $targetNewName
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDesc

        $xmlCategory = ''
        foreach ($category in $targetCategoryList) {
            if (-not $category.ID -or -not $category.Type) {
                throw "Each CategoryList entry for UserActivity '$Name' needs an 'ID' and a 'Type' property, e.g. [PSCustomObject]@{ID='Search Engines';Type='web category'}."
            }
            $idEsc = ConvertTo-SfosXmlEscaped -Text $category.ID
            $typeEsc = ConvertTo-SfosXmlEscaped -Text $category.Type
            $xmlCategory += "<Category><ID>$idEsc</ID><type>$typeEsc</type></Category>"
        }

        $inner = @"
<Set operation="update">
  <UserActivity>
    <Name>$nameEsc</Name>
    <NewName>$newNameEsc</NewName>
    <Desc>$descEsc</Desc>
    <CategoryList>
        $xmlCategory
    </CategoryList>
  </UserActivity>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("UserActivity '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating UserActivity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserActivity' -Action 'edit' -Target $targetNewName
    }
}

<#
        .SYNOPSIS
        Removes a UserActivity object from the Sophos Firewall.

        .DESCRIPTION
        Removes a UserActivity object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosUserActivity -Name "Search-Activity" -WhatIf

        .EXAMPLE
        # Remove an object
        Remove-SfosUserActivity -Name "Search-Activity"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosUserActivity {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("UserActivity '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <UserActivity>
    <Name>$nameEsc</Name>
  </UserActivity>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing UserActivity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserActivity' -Action 'remove' -Target $Name
    }
}

<#
        .SYNOPSIS
        Adds category members to an existing UserActivity object on the Sophos Firewall.

        .DESCRIPTION
        Adds categories to a UserActivity object using the Sophos Firewall XML API. Internally this reads the object, merges the new entries into the existing CategoryList and sends a full <Set operation="update">, because SFOS applies the member list as a whole - a plain update would otherwise replace it instead of appending.

        This cmdlet updates the object internally, so - just like Set-SfosUserActivity - it
        always sends <NewName> set to the object's current name. Without it, the update
        would answer success while silently renaming the object to an empty name
        (live-verified defect). Do not remove this as seemingly redundant.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        Array of category entries to add. Each entry needs an 'ID' (the plain-text name of the referenced object) and a 'Type' property, e.g. [PSCustomObject]@{ID='Search Engines';Type='web category'}. Entries already present (matched on ID and Type) are left unchanged.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Add a web category to an existing user activity
        Add-SfosUserActivityMember -Name "Search-Activity" -Members @([PSCustomObject]@{ID='Search Engines';Type='web category'})

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Add-SfosUserActivityMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {

        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $userActivity = Get-SfosUserActivity -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact object
        $userActivity = @($userActivity | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($userActivity.Count -eq 0) {
            throw "The UserActivity object '$Name' was not found."
        }

        $userActivity = $userActivity[0]

        # Prefill existing categories. SFOS applies the category list as a whole - a
        # <Set operation="update"> replaces it instead of appending - so the current
        # entries must be written back together with the new ones.
        $categoryEntries = [Collections.ArrayList]@()
        foreach ($existingCategory in @($userActivity.CategoryList)) {
            [void]$categoryEntries.Add($existingCategory)
        }

        foreach ($member in $Members) {
            if (-not $member.ID -or -not $member.Type) {
                throw "Each member entry for UserActivity '$Name' needs an 'ID' and a 'Type' property, e.g. [PSCustomObject]@{ID='Search Engines';Type='web category'}."
            }
            $alreadyPresent = $categoryEntries | Where-Object -FilterScript { $_.ID -eq $member.ID -and $_.Type -eq $member.Type }
            if (-not $alreadyPresent) {
                [void]$categoryEntries.Add([PSCustomObject]@{ ID = $member.ID; Type = $member.Type })
            }
        }

        $xmlCategory = ''
        foreach ($category in $categoryEntries) {
            $idEsc = ConvertTo-SfosXmlEscaped -Text $category.ID
            $typeEsc = ConvertTo-SfosXmlEscaped -Text $category.Type
            $xmlCategory += "<Category><ID>$idEsc</ID><type>$typeEsc</type></Category>"
        }

        # SFOS replaces the whole entity on update - an element that is not sent is cleared
        # on the firewall. Without carrying Desc over, adding a member would silently wipe it.
        $descXml = ''
        if ($userActivity.Desc) {
            $descXml = "<Desc>$(ConvertTo-SfosXmlEscaped -Text $userActivity.Desc)</Desc>"
        }

        # See Set-SfosUserActivity: this update must always carry <NewName>, set here to the
        # object's current (unchanged) name, or the firewall renames it to an empty name.
        $newNameEsc = ConvertTo-SfosXmlEscaped -Text $userActivity.Name

        $inner = @"
<Set operation="update">
    <UserActivity>
        <Name>$nameEsc</Name>
        <NewName>$newNameEsc</NewName>
        $descXml
        <CategoryList>
            $xmlCategory
        </CategoryList>
    </UserActivity>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("UserActivity '$($Name)' on $($params.Firewall)", 'Add members')) {
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
            throw "Error adding members to UserActivity '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserActivity' -Action 'add members' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes category members from an existing UserActivity object on the Sophos Firewall.

        .DESCRIPTION
        Removes categories from a UserActivity object using the Sophos Firewall XML API. Internally this reads the object, drops the matching entries from the existing CategoryList and sends a full <Set operation="update"> with the remaining entries - 'update' with the complete remaining list, not a partial remove, because SFOS replaces the member list with whatever is sent.

        This cmdlet updates the object internally, so - just like Set-SfosUserActivity - it
        always sends <NewName> set to the object's current name. Without it, the update
        would answer success while silently renaming the object to an empty name
        (live-verified defect). Do not remove this as seemingly redundant.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Members
        Array of category entries to remove. Each entry needs an 'ID' and a 'Type' property matching an existing entry, e.g. [PSCustomObject]@{ID='Search Engines';Type='web category'}. Entries that are not present are ignored.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Remove a web category from an existing user activity
        Remove-SfosUserActivityMember -Name "Search-Activity" -Members @([PSCustomObject]@{ID='Search Engines';Type='web category'})

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosUserActivityMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^\^;''"`]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Members,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }
    process {

        # Check Name
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # Retrieve existing object
        $userActivity = Get-SfosUserActivity -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -NameLike $Name `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -NameLike is a substring match, so narrow the result down to the exact object
        $userActivity = @($userActivity | Where-Object -FilterScript { $_.Name -eq $Name })

        if ($userActivity.Count -eq 0) {
            throw "The UserActivity object '$Name' was not found."
        }

        $userActivity = $userActivity[0]

        if (@($userActivity.CategoryList).Count -eq 0) {
            # Nothing to remove
            return
        }

        # Prefill existing categories, then drop the ones the caller asked to remove
        $categoryEntries = [Collections.ArrayList]@()
        foreach ($existingCategory in @($userActivity.CategoryList)) {
            [void]$categoryEntries.Add($existingCategory)
        }

        foreach ($member in $Members) {
            $indexMember = -1
            for ($i = 0; $i -lt $categoryEntries.Count; $i++) {
                if ($categoryEntries[$i].ID -eq $member.ID -and $categoryEntries[$i].Type -eq $member.Type) {
                    $indexMember = $i
                    break
                }
            }
            if ($indexMember -ne -1) {
                $categoryEntries.RemoveAt($indexMember)
            }
        }

        # The firewall rejects an update with an empty category list (see
        # Set-SfosUserActivity), so this is caught here with a message naming the object
        # instead of letting the API return an opaque 501.
        if ($categoryEntries.Count -eq 0) {
            throw "Cannot remove the last CategoryList entry from UserActivity '$Name'; the firewall requires at least one category. Use Remove-SfosUserActivity to delete the whole object instead."
        }

        $xmlCategory = ''
        foreach ($category in $categoryEntries) {
            $idEsc = ConvertTo-SfosXmlEscaped -Text $category.ID
            $typeEsc = ConvertTo-SfosXmlEscaped -Text $category.Type
            $xmlCategory += "<Category><ID>$idEsc</ID><type>$typeEsc</type></Category>"
        }

        # SFOS replaces the whole entity on update - an element that is not sent is cleared
        # on the firewall. Without carrying Desc over, removing a member would silently wipe it.
        $descXml = ''
        if ($userActivity.Desc) {
            $descXml = "<Desc>$(ConvertTo-SfosXmlEscaped -Text $userActivity.Desc)</Desc>"
        }

        # See Set-SfosUserActivity: this update must always carry <NewName>, set here to the
        # object's current (unchanged) name, or the firewall renames it to an empty name.
        $newNameEsc = ConvertTo-SfosXmlEscaped -Text $userActivity.Name

        $inner = @"
<Set operation="update">
    <UserActivity>
        <Name>$nameEsc</Name>
        <NewName>$newNameEsc</NewName>
        $descXml
        <CategoryList>
            $xmlCategory
        </CategoryList>
    </UserActivity>
</Set>
"@
        # Send Request to the API
        if (-not $PSCmdlet.ShouldProcess("UserActivity '$($Name)' on $($params.Firewall)", 'Remove members')) {
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
            throw "Error removing members from UserActivity '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'UserActivity' -Action 'remove members' -Target $Name
    }
}

#endregion


#region WebFilterException

<#
        .SYNOPSIS
        Retrieves WebFilterException objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for WebFilterException objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        All four match lists (SourceIPAddress, DestinationIPAddress, URLRegex, WebCategory)
        live together inside a single <DomainList> wrapper on the firewall - the vendor's
        attribute table shows them as top-level fields, but that is not how the API returns
        them [live]. This cmdlet flattens them back into individually named properties.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Desc, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosWebFilterException

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosWebFilterException -NameLike "Example"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosWebFilterException -NameLike "Example" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        Predefined Sophos exceptions (IsDefault=yes, e.g. 'Sophos Services') are returned like any
        other object - check the IsDefault property before scripting bulk changes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterException {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
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
  <WebFilterException>
    $filterXml
  </WebFilterException>
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
        throw "Error retrieving WebFilterException objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch Set-
    # SfosWebFilterException, das intern hierher zurueckgreift, um den Ist-Zustand zu
    # ermitteln: es wuerde 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterException' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/WebFilterException[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Desc -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects. SrcIp/DstIp/URLRegex/WebCategory alle stammen aus dem
    # gemeinsamen <DomainList>-Wrapper, siehe .DESCRIPTION.
    $webFilterExceptionObjects = @()
    foreach ($node in $nodes) {
        $webFilterExceptionObjects += [PSCustomObject]@{
            Name                  = $node.Name
            Desc                  = $node.Desc
            Enabled               = $node.Enabled
            HttpsDecrypt          = $node.HttpsDecrypt
            VirusScan             = $node.VirusScan
            PolicyCheck           = $node.PolicyCheck
            ZeroDayProtection     = $node.ZeroDayProtection
            CertValidation        = $node.CertValidation
            EnableSrcIP           = $node.EnableSrcIP
            SourceIPAddress       = [string[]]@($node.DomainList | Select-Object -ExpandProperty SrcIp -ErrorAction SilentlyContinue)
            EnableDstIP           = $node.EnableDstIP
            DestinationIPAddress  = [string[]]@($node.DomainList | Select-Object -ExpandProperty DstIp -ErrorAction SilentlyContinue)
            EnableURLRegex        = $node.EnableURLRegex
            URLRegex              = [string[]]@($node.DomainList | Select-Object -ExpandProperty URLRegex -ErrorAction SilentlyContinue)
            EnableWebCat          = $node.EnableWebCat
            WebCategory           = [string[]]@($node.DomainList | Select-Object -ExpandProperty WebCategory -ErrorAction SilentlyContinue)
            IsDefault             = $node.IsDefault
        }
    }

    return $webFilterExceptionObjects
}

<#
        .SYNOPSIS
        Creates a new WebFilterException object on the Sophos Firewall.

        .DESCRIPTION
        Creates a WebFilterException that lets matching traffic bypass web filtering
        checks. At least one match criterion (-SourceIPAddress, -DestinationIPAddress,
        -URLRegex or -WebCategory) is required - the Sophos API rejects an object with
        none of these with an undiagnostic 501 (empty <InvalidParams/>), so this cmdlet
        checks that client-side first.

        CertValidation is not documented anywhere (neither the attribute table nor the
        sample XML mention it). Testing against the lab firewall additionally found that
        Enabled - documented as optional - is required on create as well: omitting either
        Enabled or CertValidation makes the create request fail (500 or 501, both without
        a usable diagnostic) [live]. This cmdlet always sends both, defaulting to 'on'.
        HttpsDecrypt, VirusScan, PolicyCheck and ZeroDayProtection are confirmed optional
        on create and are only sent when explicitly supplied.

        .PARAMETER Name
        Name of the exception (1-60 characters; the characters ^ ; ' " \ are not allowed).

        .PARAMETER Desc
        Optional description (max 250 characters).

        .PARAMETER Enabled
        Enables or disables the exception: 'on' or 'off'. Like CertValidation this is not marked
        mandatory in the vendor documentation, but a create request without it fails with a
        diagnostic-free 500 ('Operation could not be performed on Entity') [live]. Always sent;
        default 'on'.

        .PARAMETER HttpsDecrypt
        Whether HTTPS traffic matching this exception is decrypted: 'on' or 'off'. If omitted, the firewall applies its own default.

        .PARAMETER VirusScan
        Whether matching traffic is still virus-scanned: 'on' or 'off'. If omitted, the firewall applies its own default.

        .PARAMETER PolicyCheck
        Whether matching traffic still runs through policy checks: 'on' or 'off'. If omitted, the firewall applies its own default.

        .PARAMETER ZeroDayProtection
        Whether Zero-day Protection still applies to matching traffic: 'on' or 'off'. If omitted, the firewall applies its own default.

        .PARAMETER CertValidation
        Whether certificate validation still applies to matching traffic: 'on' or 'off'. Undocumented but required by the API on every write [live]. Default: 'on'.

        .PARAMETER SourceIPAddress
        One or more source IP addresses/networks this exception matches. Presence of this parameter (with at least one entry) sets EnableSrcIP=yes on the firewall.

        .PARAMETER DestinationIPAddress
        One or more destination IP addresses/networks this exception matches. Presence of this parameter (with at least one entry) sets EnableDstIP=yes on the firewall.

        .PARAMETER URLRegex
        One or more URL regular expressions this exception matches. Presence of this parameter (with at least one entry) sets EnableURLRegex=yes on the firewall.

        .PARAMETER WebCategory
        One or more web category names this exception matches. Presence of this parameter (with at least one entry) sets EnableWebCat=yes on the firewall.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create an exception that bypasses filtering for a source network
        New-SfosWebFilterException -Name "Example" -SourceIPAddress "10.0.1.0/24" -Desc "Internal test range"

        .EXAMPLE
        # Create an exception matching a web category, with virus scanning kept on
        New-SfosWebFilterException -Name "Example-Category" -WebCategory "Business" -VirusScan on

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterException
#>
function New-SfosWebFilterException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^^;''"\\]+$')]
        [string]$Name,

        [ValidateLength(0, 250)]
        [string]$Desc,

        [ValidateSet('on', 'off')]
        [string]$Enabled = 'on',

        [ValidateSet('on', 'off')]
        [string]$HttpsDecrypt,

        [ValidateSet('on', 'off')]
        [string]$VirusScan,

        [ValidateSet('on', 'off')]
        [string]$PolicyCheck,

        [ValidateSet('on', 'off')]
        [string]$ZeroDayProtection,

        [ValidateSet('on', 'off')]
        [string]$CertValidation = 'on',

        [string[]]$SourceIPAddress,

        [string[]]$DestinationIPAddress,

        [string[]]$URLRegex,

        [string[]]$WebCategory,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Desc

    # Ein Objekt ohne jedes Match-Kriterium wird von der API mit einem diagnosefreien
    # 501 (leeres <InvalidParams/>) abgelehnt [live]. Clientseitig vorab pruefen, statt
    # einen nutzlosen Roundtrip zu machen.
    if (-not ($SourceIPAddress -or $DestinationIPAddress -or $URLRegex -or $WebCategory)) {
        throw "WebFilterException '$Name' needs at least one match criterion: -SourceIPAddress, -DestinationIPAddress, -URLRegex or -WebCategory. The Sophos API rejects an object with none of these with an undiagnostic 501 (empty <InvalidParams/>)."
    }

    # Die Enable*-Felder sind keine eigenen Parameter, sondern werden aus dem
    # Vorhandensein des jeweiligen Array-Parameters abgeleitet (the project build rules SS4). So kann
    # der Aufrufer den live bestaetigten Invalid-State "Enable*=yes ohne Daten" gar
    # nicht erst erzeugen.
    $enableSrcIP = if ($SourceIPAddress -and @($SourceIPAddress).Count -gt 0) { 'yes' } else { 'no' }
    $enableDstIP = if ($DestinationIPAddress -and @($DestinationIPAddress).Count -gt 0) { 'yes' } else { 'no' }
    $enableURLRegex = if ($URLRegex -and @($URLRegex).Count -gt 0) { 'yes' } else { 'no' }
    $enableWebCat = if ($WebCategory -and @($WebCategory).Count -gt 0) { 'yes' } else { 'no' }

    $srcIpXml = ''
    foreach ($ip in $SourceIPAddress) {
        if (-not $ip) { continue }
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $ip
        $srcIpXml += "<SrcIp>$ipEsc</SrcIp>"
    }

    $dstIpXml = ''
    foreach ($ip in $DestinationIPAddress) {
        if (-not $ip) { continue }
        $ipEsc = ConvertTo-SfosXmlEscaped -Text $ip
        $dstIpXml += "<DstIp>$ipEsc</DstIp>"
    }

    $urlRegexXml = ''
    foreach ($regex in $URLRegex) {
        if (-not $regex) { continue }
        $regexEsc = ConvertTo-SfosXmlEscaped -Text $regex
        $urlRegexXml += "<URLRegex>$regexEsc</URLRegex>"
    }

    $webCategoryXml = ''
    foreach ($category in $WebCategory) {
        if (-not $category) { continue }
        $categoryEsc = ConvertTo-SfosXmlEscaped -Text $category
        $webCategoryXml += "<WebCategory>$categoryEsc</WebCategory>"
    }

    # HttpsDecrypt/VirusScan/PolicyCheck/ZeroDayProtection sind on/off-Enums - anders
    # als Desc darf hier kein leeres Element gesendet werden, wenn der Aufrufer nichts
    # angegeben hat. Ungebunden bleibt das Feld deshalb ganz weg, statt es leer zu
    # senden, und der Firewall-Default greift. Enabled und CertValidation dagegen
    # muessen immer mitgesendet werden - siehe .DESCRIPTION - und tragen deshalb feste
    # Parameter-Defaults statt einer bedingten Huelle.
    $httpsDecryptXml = if ($PSBoundParameters.ContainsKey('HttpsDecrypt')) { "<HttpsDecrypt>$HttpsDecrypt</HttpsDecrypt>" } else { '' }
    $virusScanXml = if ($PSBoundParameters.ContainsKey('VirusScan')) { "<VirusScan>$VirusScan</VirusScan>" } else { '' }
    $policyCheckXml = if ($PSBoundParameters.ContainsKey('PolicyCheck')) { "<PolicyCheck>$PolicyCheck</PolicyCheck>" } else { '' }
    $zeroDayXml = if ($PSBoundParameters.ContainsKey('ZeroDayProtection')) { "<ZeroDayProtection>$ZeroDayProtection</ZeroDayProtection>" } else { '' }

    $inner = @"
<Set operation="add">
  <WebFilterException>
    <Name>$nameEsc</Name>
    <Desc>$descEsc</Desc>
    <Enabled>$Enabled</Enabled>
    $httpsDecryptXml
    $virusScanXml
    $policyCheckXml
    $zeroDayXml
    <CertValidation>$CertValidation</CertValidation>
    <EnableSrcIP>$enableSrcIP</EnableSrcIP>
    <EnableDstIP>$enableDstIP</EnableDstIP>
    <EnableURLRegex>$enableURLRegex</EnableURLRegex>
    <EnableWebCat>$enableWebCat</EnableWebCat>
    <DomainList>
        $srcIpXml
        $dstIpXml
        $urlRegexXml
        $webCategoryXml
    </DomainList>
  </WebFilterException>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("WebFilterException '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating WebFilterException object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Check login status
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterException' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing WebFilterException object on the Sophos Firewall.

        .DESCRIPTION
        Updates a WebFilterException object using the Sophos Firewall XML API. You can supply
        the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall, confirmed live for Desc and the DomainList entries. This
        cmdlet reads the current object first and keeps whatever the caller does not
        explicitly pass. To clear a field, pass it explicitly with an empty value.

        CertValidation is undocumented but required by the API on every write [live]; it is
        always sent, carried over from the existing object unless overridden.

        Predefined exceptions are flagged IsDefault=yes by Get-SfosWebFilterException. The API
        applies no write protection to them - a Set on 'Sophos Services' is accepted like any
        other object. Check IsDefault before scripting bulk changes.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER NewName
        New name to rename the object to (1-60 characters; the characters ^ ; ' " \ are not allowed). If omitted, the object keeps its current name.

        .PARAMETER Desc
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER Enabled
        Enables or disables the exception: 'on' or 'off'. If omitted, the existing value on the firewall is kept.

        .PARAMETER HttpsDecrypt
        Whether HTTPS traffic matching this exception is decrypted: 'on' or 'off'. If omitted, the existing value on the firewall is kept.

        .PARAMETER VirusScan
        Whether matching traffic is still virus-scanned: 'on' or 'off'. If omitted, the existing value on the firewall is kept.

        .PARAMETER PolicyCheck
        Whether matching traffic still runs through policy checks: 'on' or 'off'. If omitted, the existing value on the firewall is kept.

        .PARAMETER ZeroDayProtection
        Whether Zero-day Protection still applies to matching traffic: 'on' or 'off'. If omitted, the existing value on the firewall is kept.

        .PARAMETER CertValidation
        Whether certificate validation still applies to matching traffic: 'on' or 'off'. Undocumented but required by the API on every write [live]. If omitted, the existing value on the firewall is kept.

        .PARAMETER SourceIPAddress
        One or more source IP addresses/networks this exception matches. If omitted, the existing list is kept. Presence of this parameter (with at least one entry) sets EnableSrcIP=yes; an explicit empty array sets EnableSrcIP=no.

        .PARAMETER DestinationIPAddress
        One or more destination IP addresses/networks this exception matches. If omitted, the existing list is kept. Presence of this parameter (with at least one entry) sets EnableDstIP=yes; an explicit empty array sets EnableDstIP=no.

        .PARAMETER URLRegex
        One or more URL regular expressions this exception matches. If omitted, the existing list is kept. Presence of this parameter (with at least one entry) sets EnableURLRegex=yes; an explicit empty array sets EnableURLRegex=no.

        .PARAMETER WebCategory
        One or more web category names this exception matches. If omitted, the existing list is kept. Presence of this parameter (with at least one entry) sets EnableWebCat=yes; an explicit empty array sets EnableWebCat=no.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update the description without touching anything else
        Set-SfosWebFilterException -Name "Example" -Desc "Updated description"

        .EXAMPLE
        # Rename an object
        Set-SfosWebFilterException -Name "Example" -NewName "Example-Renamed"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosWebFilterException -NameLike "Example" | Set-SfosWebFilterException -VirusScan on

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^^;''"\\]+$')]
        [string]$Name,

        [ValidateLength(1, 60)]
        [ValidatePattern('^[^^;''"\\]+$')]
        [string]$NewName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 250)]
        [string]$Desc,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('on', 'off')]
        [string]$Enabled,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('on', 'off')]
        [string]$HttpsDecrypt,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('on', 'off')]
        [string]$VirusScan,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('on', 'off')]
        [string]$PolicyCheck,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('on', 'off')]
        [string]$ZeroDayProtection,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('on', 'off')]
        [string]$CertValidation,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$SourceIPAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$DestinationIPAddress,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$URLRegex,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$WebCategory,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall, confirmed live for Desc and the DomainList entries. So read the
        # current object first and override only what the caller actually passed.
        $existing = @(Get-SfosWebFilterException -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WebFilterException object '$Name' was not found."
        }

        $targetDesc = if ($PSBoundParameters.ContainsKey('Desc')) {
            $Desc
        }
        else {
            [string]$existing[0].Desc
        }

        # Enabled ist in der Doku als optional markiert, wird aber bei jedem
        # Schreibzugriff verlangt - ein Update ohne Enabled schlaegt live mit einem
        # diagnosefreien 500 fehl. Wie CertValidation deshalb immer mitsenden.
        $targetEnabled = if ($PSBoundParameters.ContainsKey('Enabled')) {
            $Enabled
        }
        else {
            [string]$existing[0].Enabled
        }
        if (-not $targetEnabled) {
            $targetEnabled = 'on'
        }

        $targetHttpsDecrypt = if ($PSBoundParameters.ContainsKey('HttpsDecrypt')) {
            $HttpsDecrypt
        }
        else {
            [string]$existing[0].HttpsDecrypt
        }

        $targetVirusScan = if ($PSBoundParameters.ContainsKey('VirusScan')) {
            $VirusScan
        }
        else {
            [string]$existing[0].VirusScan
        }

        $targetPolicyCheck = if ($PSBoundParameters.ContainsKey('PolicyCheck')) {
            $PolicyCheck
        }
        else {
            [string]$existing[0].PolicyCheck
        }

        $targetZeroDayProtection = if ($PSBoundParameters.ContainsKey('ZeroDayProtection')) {
            $ZeroDayProtection
        }
        else {
            [string]$existing[0].ZeroDayProtection
        }

        # CertValidation ist in der Doku (Attributtabelle und Sample) gar nicht
        # vorhanden, muss aber bei jedem Schreibzugriff mitgesendet werden - ohne
        # antwortet die API mit 501 und leerem <InvalidParams/> [live].
        $targetCertValidation = if ($PSBoundParameters.ContainsKey('CertValidation')) {
            $CertValidation
        }
        else {
            [string]$existing[0].CertValidation
        }
        if (-not $targetCertValidation) {
            $targetCertValidation = 'on'
        }

        $targetSourceIPAddress = if ($PSBoundParameters.ContainsKey('SourceIPAddress')) {
            @($SourceIPAddress)
        }
        else {
            @($existing[0].SourceIPAddress)
        }

        $targetDestinationIPAddress = if ($PSBoundParameters.ContainsKey('DestinationIPAddress')) {
            @($DestinationIPAddress)
        }
        else {
            @($existing[0].DestinationIPAddress)
        }

        $targetURLRegex = if ($PSBoundParameters.ContainsKey('URLRegex')) {
            @($URLRegex)
        }
        else {
            @($existing[0].URLRegex)
        }

        $targetWebCategory = if ($PSBoundParameters.ContainsKey('WebCategory')) {
            @($WebCategory)
        }
        else {
            @($existing[0].WebCategory)
        }

        # Ein Objekt ohne jedes Match-Kriterium wird von der API mit einem diagnosefreien
        # 501 (leeres <InvalidParams/>) abgelehnt [live]. Clientseitig vorab pruefen, statt
        # einen nutzlosen Roundtrip zu machen - das gilt auch fuer ein Update, das die
        # letzte verbliebene Liste leert.
        if (-not ($targetSourceIPAddress -or $targetDestinationIPAddress -or $targetURLRegex -or $targetWebCategory)) {
            throw "WebFilterException '$Name' needs at least one match criterion: -SourceIPAddress, -DestinationIPAddress, -URLRegex or -WebCategory. The Sophos API rejects an object with none of these with an undiagnostic 501 (empty <InvalidParams/>)."
        }

        # Die Enable*-Felder sind keine eigenen Parameter, sondern werden aus dem
        # Vorhandensein der jeweiligen Zielliste abgeleitet (the project build rules SS4). So kann der
        # Aufrufer den live bestaetigten Invalid-State "Enable*=yes ohne Daten" gar nicht
        # erst erzeugen.
        $enableSrcIP = if (@($targetSourceIPAddress).Count -gt 0) { 'yes' } else { 'no' }
        $enableDstIP = if (@($targetDestinationIPAddress).Count -gt 0) { 'yes' } else { 'no' }
        $enableURLRegex = if (@($targetURLRegex).Count -gt 0) { 'yes' } else { 'no' }
        $enableWebCat = if (@($targetWebCategory).Count -gt 0) { 'yes' } else { 'no' }

        $srcIpXml = ''
        foreach ($ip in $targetSourceIPAddress) {
            if (-not $ip) { continue }
            $ipEsc = ConvertTo-SfosXmlEscaped -Text $ip
            $srcIpXml += "<SrcIp>$ipEsc</SrcIp>"
        }

        $dstIpXml = ''
        foreach ($ip in $targetDestinationIPAddress) {
            if (-not $ip) { continue }
            $ipEsc = ConvertTo-SfosXmlEscaped -Text $ip
            $dstIpXml += "<DstIp>$ipEsc</DstIp>"
        }

        $urlRegexXml = ''
        foreach ($regex in $targetURLRegex) {
            if (-not $regex) { continue }
            $regexEsc = ConvertTo-SfosXmlEscaped -Text $regex
            $urlRegexXml += "<URLRegex>$regexEsc</URLRegex>"
        }

        $webCategoryXml = ''
        foreach ($category in $targetWebCategory) {
            if (-not $category) { continue }
            $categoryEsc = ConvertTo-SfosXmlEscaped -Text $category
            $webCategoryXml += "<WebCategory>$categoryEsc</WebCategory>"
        }

        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDesc

        # NewName nur mitsenden, wenn tatsaechlich umbenannt werden soll. Anders als bei
        # UserActivity ist das hier nicht als Pflichtfeld dokumentiert oder live
        # erzwungen - ein leer mitgesendetes <NewName> koennte das gleiche Risiko wie dort
        # bergen (Umbenennung auf einen leeren Namen), deshalb vorsichtshalber weglassen
        # statt mit dem aktuellen Namen zu fuellen.
        $newNameXml = ''
        if ($PSBoundParameters.ContainsKey('NewName')) {
            $newNameEsc = ConvertTo-SfosXmlEscaped -Text $NewName
            $newNameXml = "<NewName>$newNameEsc</NewName>"
        }

        $inner = @"
<Set operation="update">
  <WebFilterException>
    <Name>$nameEsc</Name>
    $newNameXml
    <Desc>$descEsc</Desc>
    <Enabled>$targetEnabled</Enabled>
    <HttpsDecrypt>$targetHttpsDecrypt</HttpsDecrypt>
    <VirusScan>$targetVirusScan</VirusScan>
    <PolicyCheck>$targetPolicyCheck</PolicyCheck>
    <ZeroDayProtection>$targetZeroDayProtection</ZeroDayProtection>
    <CertValidation>$targetCertValidation</CertValidation>
    <EnableSrcIP>$enableSrcIP</EnableSrcIP>
    <EnableDstIP>$enableDstIP</EnableDstIP>
    <EnableURLRegex>$enableURLRegex</EnableURLRegex>
    <EnableWebCat>$enableWebCat</EnableWebCat>
    <DomainList>
        $srcIpXml
        $dstIpXml
        $urlRegexXml
        $webCategoryXml
    </DomainList>
  </WebFilterException>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("WebFilterException '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating WebFilterException object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterException' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a WebFilterException object from the Sophos Firewall.

        .DESCRIPTION
        Removes a WebFilterException object using the Sophos Firewall XML API. This cmdlet
        supports ShouldProcess; use -WhatIf to preview the change.

        Predefined exceptions are flagged IsDefault=yes by Get-SfosWebFilterException. The API
        applies no write protection to them - a Remove on a Sophos-shipped default such as
        'Sophos Services' is accepted like any other object. Check IsDefault before removing.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosWebFilterException -Name "Example" -WhatIf

        .EXAMPLE
        # Remove an object
        Remove-SfosWebFilterException -Name "Example"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosWebFilterException {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^^;''"\\]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("WebFilterException '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <WebFilterException>
    <Name>$nameEsc</Name>
  </WebFilterException>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing WebFilterException object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        # Check login status
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterException' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion


#region WebFilterPolicy

# --- WebFilterPolicy ---
#
# RuleList/Rule is not documented in the attribute table at all - only reconstructed from
# the sample XML and the live GET (web-spec.md section 6). SFOS replaces RuleList and every
# other field of the entity wholesale on <Set operation="update"> - an element that is not
# sent is cleared, not left alone (web-spec.md section 0). Every write cmdlet below therefore
# funnels through ConvertTo-SfosWebFilterPolicyEntityXml with a fully resolved policy object,
# built either directly from bound parameters (New-*) or by reading the current object first
# and overriding only what the caller actually passed (Set-*, Add-/Remove-*Rule).
#
# WebFilterPolicy carries no IsDefault flag, unlike WebFilterException. A predefined policy
# such as 'Default Policy' can be overwritten by Set-/Remove-SfosWebFilterPolicy and by both
# rule cmdlets without any warning from the API - see the .NOTES on each write cmdlet.

<#
.SYNOPSIS
    Builds the <Category> XML for a single WebFilterPolicy rule category. Internal helper,
    not exported.

.DESCRIPTION
    Converts one category object (as produced by New-SfosWebFilterPolicyCategory or returned
    by Get-SfosWebFilterPolicy) into the <Category><ID>...</ID><type>...</type></Category>
    fragment SFOS expects inside a rule's <CategoryList>.

    The wire element is lowercase <type> - confirmed live, and the same oddity the project build rules
    documents for UserActivity's <type> child element. The object property stays PascalCase
    ("Type") for PowerShell ergonomics; only the emitted XML tag is lowercase.

.PARAMETER Category
    Category object with ID and Type properties.
#>
function ConvertTo-SfosWebFilterPolicyCategoryXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Category
    )

    $idEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Category.ID)
    $typeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Category.Type)

    return "<Category><ID>$idEsc</ID><type>$typeEsc</type></Category>"
}

<#
.SYNOPSIS
    Builds the <Rule> XML for a single WebFilterPolicy rule. Internal helper, not exported.

.DESCRIPTION
    Converts one rule object (as produced by New-SfosWebFilterPolicyRule or returned by
    Get-SfosWebFilterPolicy) into a complete <Rule> element, including its CategoryList,
    ExceptionList, UserList and CCLList children. Every value is escaped here.

.PARAMETER Rule
    Rule object with CategoryList, HTTPAction, HTTPSAction, FollowHTTPAction, Schedule,
    PolicyRuleEnabled, CCLRuleEnabled, ExceptionList, UserList and CCLList properties.
#>
function ConvertTo-SfosWebFilterPolicyRuleXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Rule
    )

    $categoryXml = ''
    foreach ($category in @($Rule.CategoryList)) {
        if (-not $category) {
            continue
        }
        $categoryXml += ConvertTo-SfosWebFilterPolicyCategoryXml -Category $category
    }

    $exceptionXml = ''
    foreach ($item in @($Rule.ExceptionList)) {
        if (-not $item) {
            continue
        }
        $exceptionXml += "<FileTypeCategory>$(ConvertTo-SfosXmlEscaped -Text $item)</FileTypeCategory>"
    }

    $userXml = ''
    foreach ($item in @($Rule.UserList)) {
        if (-not $item) {
            continue
        }
        $userXml += "<User>$(ConvertTo-SfosXmlEscaped -Text $item)</User>"
    }

    $cclXml = ''
    foreach ($item in @($Rule.CCLList)) {
        if (-not $item) {
            continue
        }
        $cclXml += "<CCL>$(ConvertTo-SfosXmlEscaped -Text $item)</CCL>"
    }

    $httpActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.HTTPAction)
    $httpsActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.HTTPSAction)
    $followEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.FollowHTTPAction)
    $scheduleEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Schedule)
    $policyEnabledEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.PolicyRuleEnabled)
    $cclEnabledEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.CCLRuleEnabled)

    return "<Rule><CategoryList>$categoryXml</CategoryList><HTTPAction>$httpActionEsc</HTTPAction><HTTPSAction>$httpsActionEsc</HTTPSAction><FollowHTTPAction>$followEsc</FollowHTTPAction><Schedule>$scheduleEsc</Schedule><PolicyRuleEnabled>$policyEnabledEsc</PolicyRuleEnabled><CCLRuleEnabled>$cclEnabledEsc</CCLRuleEnabled><ExceptionList>$exceptionXml</ExceptionList><UserList>$userXml</UserList><CCLList>$cclXml</CCLList></Rule>"
}

<#
.SYNOPSIS
    Builds the <Set> inner XML for a WebFilterPolicy entity. Internal helper, not exported.

.DESCRIPTION
    Centralizes the WebFilterPolicy XML shape so New-, Set-SfosWebFilterPolicy,
    Add-SfosWebFilterPolicyRule and Remove-SfosWebFilterPolicyRule all send an identical,
    complete entity body. Takes a fully resolved policy object - same property shape
    Get-SfosWebFilterPolicy returns - and escapes every value.

    SFOS replaces the whole entity on <Set operation="update">: any element this function
    does not emit is cleared on the firewall. The caller is responsible for merging in
    every field it wants preserved before calling this function; nothing is read back here.

.PARAMETER Operation
    'add' or 'update', passed straight to <Set operation="...">.

.PARAMETER Policy
    Fully resolved policy object with Name, Description, DefaultAction, EnableReporting,
    DownloadFileSizeRestrictionEnabled, DownloadFileSizeRestriction, GoogAppDomainListEnabled,
    GoogAppDomainList, RuleList, EnforceSafeSearch, EnforceImageLicensing,
    YoutubeFilterEnabled, YoutubeFilterIsStrict, XFFEnabled, Office365Enabled, QuotaLimit,
    Office365TenantsList and Office365DirectoryId properties.
#>
function ConvertTo-SfosWebFilterPolicyEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Policy
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Name)
    $descEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Description)
    # DefaultAction: the doc's attribute table claims "max 1 character", which is wrong -
    # the values are the literal words Allow/Deny (web-spec.md section 6). Not implemented.
    $defaultActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DefaultAction)
    $sizeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DownloadFileSizeRestriction)

    $reportingXml = ''
    if ($Policy.EnableReporting) {
        $reportingXml = "<EnableReporting>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.EnableReporting))</EnableReporting>"
    }

    $sizeEnabledXml = ''
    if ($Policy.DownloadFileSizeRestrictionEnabled) {
        $sizeEnabledXml = "<DownloadFileSizeRestrictionEnabled>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DownloadFileSizeRestrictionEnabled))</DownloadFileSizeRestrictionEnabled>"
    }

    $googEnabledXml = ''
    if ($Policy.GoogAppDomainListEnabled) {
        $googEnabledXml = "<GoogAppDomainListEnabled>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.GoogAppDomainListEnabled))</GoogAppDomainListEnabled>"
    }

    $googListXml = ''
    if ($Policy.GoogAppDomainList) {
        $googListXml = "<GoogAppDomainList>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.GoogAppDomainList))</GoogAppDomainList>"
    }

    $ruleListXml = ''
    foreach ($rule in @($Policy.RuleList)) {
        if (-not $rule) {
            continue
        }
        $ruleListXml += ConvertTo-SfosWebFilterPolicyRuleXml -Rule $rule
    }

    $safeSearchXml = ''
    if ($Policy.EnforceSafeSearch) {
        $safeSearchXml = "<EnforceSafeSearch>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.EnforceSafeSearch))</EnforceSafeSearch>"
    }

    $imageLicensingXml = ''
    if ($Policy.EnforceImageLicensing) {
        $imageLicensingXml = "<EnforceImageLicensing>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.EnforceImageLicensing))</EnforceImageLicensing>"
    }

    $youtubeEnabledXml = ''
    if ($Policy.YoutubeFilterEnabled) {
        $youtubeEnabledXml = "<YoutubeFilterEnabled>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.YoutubeFilterEnabled))</YoutubeFilterEnabled>"
    }

    $youtubeStrictXml = ''
    if ($Policy.YoutubeFilterIsStrict) {
        $youtubeStrictXml = "<YoutubeFilterIsStrict>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.YoutubeFilterIsStrict))</YoutubeFilterIsStrict>"
    }

    $xffXml = ''
    if ($Policy.XFFEnabled) {
        $xffXml = "<XFFEnabled>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.XFFEnabled))</XFFEnabled>"
    }

    $office365EnabledXml = ''
    if ($Policy.Office365Enabled) {
        $office365EnabledXml = "<Office365Enabled>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Office365Enabled))</Office365Enabled>"
    }

    $quotaXml = ''
    if ($Policy.QuotaLimit) {
        $quotaXml = "<QuotaLimit>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.QuotaLimit))</QuotaLimit>"
    }

    $tenantsXml = ''
    if ($Policy.Office365TenantsList) {
        $tenantsXml = "<Office365TenantsList>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Office365TenantsList))</Office365TenantsList>"
    }

    $directoryIdXml = ''
    if ($Policy.Office365DirectoryId) {
        $directoryIdXml = "<Office365DirectoryId>$(ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Office365DirectoryId))</Office365DirectoryId>"
    }

    return @"
<Set operation="$Operation">
  <WebFilterPolicy>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <DefaultAction>$defaultActionEsc</DefaultAction>
    $reportingXml
    $sizeEnabledXml
    <DownloadFileSizeRestriction>$sizeEsc</DownloadFileSizeRestriction>
    $googEnabledXml
    $googListXml
    <RuleList>$ruleListXml</RuleList>
    $safeSearchXml
    $imageLicensingXml
    $youtubeEnabledXml
    $youtubeStrictXml
    $xffXml
    $office365EnabledXml
    $quotaXml
    $tenantsXml
    $directoryIdXml
  </WebFilterPolicy>
</Set>
"@
}

<#
        .SYNOPSIS
        Retrieves WebFilterPolicy objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for WebFilterPolicy objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Each returned RuleList entry mirrors the shape produced by New-SfosWebFilterPolicyRule, so a rule read back from Get-SfosWebFilterPolicy can be reused directly with
        Add-SfosWebFilterPolicyRule or passed to Set-SfosWebFilterPolicy -Rule.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject with properties: Name, Description, DefaultAction, EnableReporting, DownloadFileSizeRestrictionEnabled, DownloadFileSizeRestriction, GoogAppDomainListEnabled,
        GoogAppDomainList, RuleList (array of rule objects with CategoryList, HTTPAction, HTTPSAction, FollowHTTPAction, Schedule, PolicyRuleEnabled, CCLRuleEnabled, ExceptionList,
        UserList, CCLList), EnforceSafeSearch, EnforceImageLicensing, YoutubeFilterEnabled, YoutubeFilterIsStrict, XFFEnabled, Office365Enabled, QuotaLimit, Office365TenantsList,
        Office365DirectoryId. System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all policies
        Get-SfosWebFilterPolicy

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosWebFilterPolicy -NameLike "Basic"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosWebFilterPolicy -NameLike "Basic" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterPolicy {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter. SFOS evaluates only the first <key> of the first <Filter>;
    # additional keys and blocks are silently dropped, so every requested filter is applied
    # again client-side below.
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<Filter><key name="Name" criteria="like">{0}</key></Filter>' -f $nameLikeEsc)
    }

    $inner = @"
<Get>
  <WebFilterPolicy>
    $filterXml
  </WebFilterPolicy>
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
        throw "Error retrieving WebFilterPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Without this check a firewall-side error - missing permission, invalid filter, server
    # error - would be read as an empty result instead of being reported. This also affects
    # Set-SfosWebFilterPolicy and the rule cmdlets, which call back into this function to
    # read the current object.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/WebFilterPolicy[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Build PSCustomObjects
    $policyObjects = foreach ($node in @($nodes)) {
        # A policy with no rules has no <RuleList> element at all (SFOS drops it rather than
        # sending an empty wrapper), so $node.RuleList is $null. Without the -FilterScript
        # below, @($null.Rule) is a one-element array containing $null, not an empty array -
        # every rule-less policy would otherwise report a single, entirely blank rule.
        $rules = foreach ($ruleNode in @($node.RuleList.Rule | Where-Object -FilterScript { $_ })) {
            $categories = foreach ($catNode in @($ruleNode.CategoryList.Category | Where-Object -FilterScript { $_ })) {
                [PSCustomObject]@{
                    ID   = [string]$catNode.ID
                    Type = [string]$catNode.type
                }
            }

            [PSCustomObject]@{
                # Same $null-when-empty foreach quirk as above, guarded the same way.
                CategoryList      = @($categories | Where-Object -FilterScript { $_ })
                HTTPAction        = [string]$ruleNode.HTTPAction
                HTTPSAction       = [string]$ruleNode.HTTPSAction
                FollowHTTPAction  = [string]$ruleNode.FollowHTTPAction
                Schedule          = [string]$ruleNode.Schedule
                PolicyRuleEnabled = [string]$ruleNode.PolicyRuleEnabled
                CCLRuleEnabled    = [string]$ruleNode.CCLRuleEnabled
                # SFOS sends an empty <FileTypeCategory/> inside an otherwise unused
                # <ExceptionList>, which -ExpandProperty turns into a single empty string
                # instead of an absent element - filtered out here so an unused list reads
                # as @(), not @(''). Applied to all three optional list children for symmetry.
                ExceptionList     = [string[]]@($ruleNode.ExceptionList | Select-Object -ExpandProperty FileTypeCategory | Where-Object -FilterScript { $_ })
                UserList          = [string[]]@($ruleNode.UserList | Select-Object -ExpandProperty User | Where-Object -FilterScript { $_ })
                CCLList           = [string[]]@($ruleNode.CCLList | Select-Object -ExpandProperty CCL | Where-Object -FilterScript { $_ })
            }
        }

        [PSCustomObject]@{
            Name                                = [string]$node.Name
            Description                         = [string]$node.Description
            DefaultAction                       = [string]$node.DefaultAction
            EnableReporting                     = [string]$node.EnableReporting
            DownloadFileSizeRestrictionEnabled  = [string]$node.DownloadFileSizeRestrictionEnabled
            DownloadFileSizeRestriction         = [string]$node.DownloadFileSizeRestriction
            GoogAppDomainListEnabled            = [string]$node.GoogAppDomainListEnabled
            GoogAppDomainList                   = [string]$node.GoogAppDomainList
            # A policy with no rules leaves the foreach above unexecuted, which assigns
            # $rules = $null - @($null) would be a one-element array, not @(). Filtered the
            # same way as CategoryList above.
            RuleList                            = @($rules | Where-Object -FilterScript { $_ })
            EnforceSafeSearch                   = [string]$node.EnforceSafeSearch
            EnforceImageLicensing               = [string]$node.EnforceImageLicensing
            YoutubeFilterEnabled                = [string]$node.YoutubeFilterEnabled
            YoutubeFilterIsStrict               = [string]$node.YoutubeFilterIsStrict
            XFFEnabled                          = [string]$node.XFFEnabled
            Office365Enabled                    = [string]$node.Office365Enabled
            QuotaLimit                          = [string]$node.QuotaLimit
            Office365TenantsList                = [string]$node.Office365TenantsList
            Office365DirectoryId                = [string]$node.Office365DirectoryId
        }
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first <Filter> is
    # evaluated by SFOS, and unsupported keys are ignored altogether, so every filter is
    # re-applied here on the returned objects.
    $policyObjects = @($policyObjects)
    if ($NameLike) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        $keptNames = @($policyObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $policyObjects
}

<#
        .SYNOPSIS
        Creates a new web filter policy on the Sophos Firewall.

        .DESCRIPTION
        Creates a WebFilterPolicy object that controls how HTTP/HTTPS traffic is categorized and
        actioned by category, URL group, user activity, dynamic category or file type. Rules can
        be supplied at creation time via -Rule, built with New-SfosWebFilterPolicyRule, or added
        afterwards with Add-SfosWebFilterPolicyRule.

        DownloadFileSizeRestriction must always be sent to the API, on every add and every
        update - a request without it is rejected with a 501. This cmdlet makes the parameter
        mandatory for exactly that reason.

        .PARAMETER Name
        Name of the web filter policy (1-50 characters, no commas).

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER DefaultAction
        Action applied when no rule matches: 'Allow' or 'Deny'. The vendor doc's attribute table
        claims "max 1 character" for this field; that is a documentation error and is not
        implemented here - the values are the literal words Allow/Deny.

        .PARAMETER EnableReporting
        Whether to include this policy's traffic in reporting: 'Enable' or 'Disable'. The
        vendor doc lists only 'Enable' as a valid value; the firewall accepts 'Disable' as well.

        .PARAMETER DownloadFileSizeRestrictionEnabled
        Whether the download file size restriction is active: '0' or '1'.

        .PARAMETER DownloadFileSizeRestriction
        Maximum download size in MB, 0-1536. Mandatory on every create and update - omitting it
        is rejected by the firewall with a 501. 0 is accepted live even though the vendor doc's
        wording suggests otherwise.

        .PARAMETER GoogAppDomainListEnabled
        Whether the Google Apps domain restriction is active: '0' or '1'.

        .PARAMETER GoogAppDomainList
        Comma-separated list of allowed Google Apps domains (max 256 characters).

        .PARAMETER Rule
        Zero or more rule objects, in the exact order they should be evaluated by the firewall.
        Build each entry with New-SfosWebFilterPolicyRule. SFOS persists rule order unchanged.

        .PARAMETER EnforceSafeSearch
        Enforce SafeSearch on supported search engines: '0' or '1'.

        .PARAMETER EnforceImageLicensing
        Enforce Google image licensing filter: '0' or '1'.

        .PARAMETER YoutubeFilterEnabled
        Enable the YouTube filter: '0' or '1'.

        .PARAMETER YoutubeFilterIsStrict
        Use YouTube's strict filtering mode: '0' or '1'.

        .PARAMETER XFFEnabled
        Honor the X-Forwarded-For header when applying this policy: '0' or '1'.

        .PARAMETER Office365Enabled
        Enable Office 365 tenant restriction for this policy: '0' or '1'.

        .PARAMETER QuotaLimit
        Quota time limit in minutes for Quota-actioned rules, 1-1440. Firewall default is 60
        when omitted.

        .PARAMETER Office365TenantsList
        Allowed Office 365 tenant identifiers for this policy.

        .PARAMETER Office365DirectoryId
        Office 365 directory ID used for tenant restriction.

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a policy with no rules yet, add rules afterwards
        New-SfosWebFilterPolicy -Name "Basic-Policy" -DefaultAction Allow -DownloadFileSizeRestriction 0

        .EXAMPLE
        # Create a policy with one rule built from the two builder cmdlets
        $category = New-SfosWebFilterPolicyCategory -ID "Extreme" -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        New-SfosWebFilterPolicy -Name "Block-Extreme" -DefaultAction Allow -DownloadFileSizeRestriction 100 -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterPolicy

        .LINK
        New-SfosWebFilterPolicyRule

        .LINK
        New-SfosWebFilterPolicyCategory
#>
function New-SfosWebFilterPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(Mandatory)]
        [ValidateSet('Allow', 'Deny')]
        [string]$DefaultAction,

        [ValidateSet('Enable', 'Disable')]
        [string]$EnableReporting,

        [ValidateSet('0', '1')]
        [string]$DownloadFileSizeRestrictionEnabled,

        [Parameter(Mandatory)]
        [ValidateRange(0, 1536)]
        [int]$DownloadFileSizeRestriction,

        [ValidateSet('0', '1')]
        [string]$GoogAppDomainListEnabled,

        [ValidateLength(0, 256)]
        [string]$GoogAppDomainList,

        [PSCustomObject[]]$Rule,

        [ValidateSet('0', '1')]
        [string]$EnforceSafeSearch,

        [ValidateSet('0', '1')]
        [string]$EnforceImageLicensing,

        [ValidateSet('0', '1')]
        [string]$YoutubeFilterEnabled,

        [ValidateSet('0', '1')]
        [string]$YoutubeFilterIsStrict,

        [ValidateSet('0', '1')]
        [string]$XFFEnabled,

        [ValidateSet('0', '1')]
        [string]$Office365Enabled,

        [ValidateRange(1, 1440)]
        [int]$QuotaLimit,

        [string]$Office365TenantsList,

        [string]$Office365DirectoryId,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $quotaValue = ''
    if ($PSBoundParameters.ContainsKey('QuotaLimit')) {
        $quotaValue = [string]$QuotaLimit
    }

    $policy = [PSCustomObject]@{
        Name                                = $Name
        Description                         = $Description
        DefaultAction                       = $DefaultAction
        EnableReporting                     = $EnableReporting
        DownloadFileSizeRestrictionEnabled  = $DownloadFileSizeRestrictionEnabled
        DownloadFileSizeRestriction         = [string]$DownloadFileSizeRestriction
        GoogAppDomainListEnabled            = $GoogAppDomainListEnabled
        GoogAppDomainList                   = $GoogAppDomainList
        RuleList                            = @($Rule)
        EnforceSafeSearch                   = $EnforceSafeSearch
        EnforceImageLicensing               = $EnforceImageLicensing
        YoutubeFilterEnabled                = $YoutubeFilterEnabled
        YoutubeFilterIsStrict               = $YoutubeFilterIsStrict
        XFFEnabled                          = $XFFEnabled
        Office365Enabled                    = $Office365Enabled
        QuotaLimit                          = $quotaValue
        Office365TenantsList                = $Office365TenantsList
        Office365DirectoryId                = $Office365DirectoryId
    }

    $inner = ConvertTo-SfosWebFilterPolicyEntityXml -Operation 'add' -Policy $policy

    if (-not $PSCmdlet.ShouldProcess("WebFilterPolicy '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating WebFilterPolicy object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterPolicy' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing WebFilterPolicy object on the Sophos Firewall.

        .DESCRIPTION
        Updates a WebFilterPolicy object using the Sophos Firewall XML API. You can supply the
        target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current policy first and keeps whatever
        the caller does not explicitly pass. To clear a field, pass it explicitly with an
        empty value.

        WebFilterPolicy carries no IsDefault flag, unlike WebFilterException. There is no
        protection against overwriting a predefined policy such as 'Default Policy' - see
        .NOTES.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER DefaultAction
        Action applied when no rule matches: 'Allow' or 'Deny'. If omitted, the existing value
        is kept.

        .PARAMETER EnableReporting
        Whether to include this policy's traffic in reporting: 'Enable' or 'Disable'. If
        omitted, the existing value is kept.

        .PARAMETER DownloadFileSizeRestrictionEnabled
        Whether the download file size restriction is active: '0' or '1'. If omitted, the
        existing value is kept.

        .PARAMETER DownloadFileSizeRestriction
        Maximum download size in MB, 0-1536. If omitted, the existing value is kept and
        resent - the API rejects an update that omits this field entirely with a 501.

        .PARAMETER GoogAppDomainListEnabled
        Whether the Google Apps domain restriction is active: '0' or '1'. If omitted, the
        existing value is kept.

        .PARAMETER GoogAppDomainList
        Comma-separated list of allowed Google Apps domains (max 256 characters). If omitted,
        the existing value is kept.

        .PARAMETER Rule
        Complete replacement rule list, in the order the firewall should evaluate them. This
        REPLACES the existing RuleList wholesale, exactly as the API does - it does not merge
        with the rules already on the firewall. Omit this parameter to keep the existing rules
        unchanged. To add or remove a single rule without touching the rest of the list, use
        Add-SfosWebFilterPolicyRule / Remove-SfosWebFilterPolicyRule instead.

        .PARAMETER EnforceSafeSearch
        Enforce SafeSearch on supported search engines: '0' or '1'. If omitted, the existing
        value is kept.

        .PARAMETER EnforceImageLicensing
        Enforce Google image licensing filter: '0' or '1'. If omitted, the existing value is
        kept.

        .PARAMETER YoutubeFilterEnabled
        Enable the YouTube filter: '0' or '1'. If omitted, the existing value is kept.

        .PARAMETER YoutubeFilterIsStrict
        Use YouTube's strict filtering mode: '0' or '1'. If omitted, the existing value is
        kept.

        .PARAMETER XFFEnabled
        Honor the X-Forwarded-For header when applying this policy: '0' or '1'. If omitted,
        the existing value is kept.

        .PARAMETER Office365Enabled
        Enable Office 365 tenant restriction for this policy: '0' or '1'. If omitted, the
        existing value is kept.

        .PARAMETER QuotaLimit
        Quota time limit in minutes for Quota-actioned rules, 1-1440. If omitted, the existing
        value is kept.

        .PARAMETER Office365TenantsList
        Allowed Office 365 tenant identifiers for this policy. If omitted, the existing value
        is kept.

        .PARAMETER Office365DirectoryId
        Office 365 directory ID used for tenant restriction. If omitted, the existing value is
        kept.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the
        stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use
        the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Change only the default action, every other field (including RuleList) is preserved
        Set-SfosWebFilterPolicy -Name "Basic-Policy" -DefaultAction Deny

        .EXAMPLE
        # Update using pipeline input
        Get-SfosWebFilterPolicy -NameLike "Basic-Policy" | Set-SfosWebFilterPolicy -Description "Updated"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        No write protection for predefined policies: WebFilterPolicy has no IsDefault flag, so
        this cmdlet will overwrite a policy such as 'Default Policy' - including its RuleList -
        without any warning from the API. Verify -Name before running this against a
        shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [ValidateSet('Allow', 'Deny')]
        [string]$DefaultAction,

        [ValidateSet('Enable', 'Disable')]
        [string]$EnableReporting,

        [ValidateSet('0', '1')]
        [string]$DownloadFileSizeRestrictionEnabled,

        [ValidateRange(0, 1536)]
        [int]$DownloadFileSizeRestriction,

        [ValidateSet('0', '1')]
        [string]$GoogAppDomainListEnabled,

        [ValidateLength(0, 256)]
        [string]$GoogAppDomainList,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('RuleList')]
        [PSCustomObject[]]$Rule,

        [ValidateSet('0', '1')]
        [string]$EnforceSafeSearch,

        [ValidateSet('0', '1')]
        [string]$EnforceImageLicensing,

        [ValidateSet('0', '1')]
        [string]$YoutubeFilterEnabled,

        [ValidateSet('0', '1')]
        [string]$YoutubeFilterIsStrict,

        [ValidateSet('0', '1')]
        [string]$XFFEnabled,

        [ValidateSet('0', '1')]
        [string]$Office365Enabled,

        [ValidateRange(1, 1440)]
        [int]$QuotaLimit,

        [string]$Office365TenantsList,

        [string]$Office365DirectoryId,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall. So read the current policy first and override only what the caller
        # actually passed.
        $existing = @(Get-SfosWebFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WebFilterPolicy object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) {
            $targetPolicy.Description = $Description
        }
        if ($PSBoundParameters.ContainsKey('DefaultAction')) {
            $targetPolicy.DefaultAction = $DefaultAction
        }
        if ($PSBoundParameters.ContainsKey('EnableReporting')) {
            $targetPolicy.EnableReporting = $EnableReporting
        }
        if ($PSBoundParameters.ContainsKey('DownloadFileSizeRestrictionEnabled')) {
            $targetPolicy.DownloadFileSizeRestrictionEnabled = $DownloadFileSizeRestrictionEnabled
        }
        if ($PSBoundParameters.ContainsKey('DownloadFileSizeRestriction')) {
            $targetPolicy.DownloadFileSizeRestriction = [string]$DownloadFileSizeRestriction
        }
        if ($PSBoundParameters.ContainsKey('GoogAppDomainListEnabled')) {
            $targetPolicy.GoogAppDomainListEnabled = $GoogAppDomainListEnabled
        }
        if ($PSBoundParameters.ContainsKey('GoogAppDomainList')) {
            $targetPolicy.GoogAppDomainList = $GoogAppDomainList
        }
        if ($PSBoundParameters.ContainsKey('Rule')) {
            # Wholesale replacement, matching the API - not a merge. See .PARAMETER Rule.
            $targetPolicy.RuleList = @($Rule)
        }
        if ($PSBoundParameters.ContainsKey('EnforceSafeSearch')) {
            $targetPolicy.EnforceSafeSearch = $EnforceSafeSearch
        }
        if ($PSBoundParameters.ContainsKey('EnforceImageLicensing')) {
            $targetPolicy.EnforceImageLicensing = $EnforceImageLicensing
        }
        if ($PSBoundParameters.ContainsKey('YoutubeFilterEnabled')) {
            $targetPolicy.YoutubeFilterEnabled = $YoutubeFilterEnabled
        }
        if ($PSBoundParameters.ContainsKey('YoutubeFilterIsStrict')) {
            $targetPolicy.YoutubeFilterIsStrict = $YoutubeFilterIsStrict
        }
        if ($PSBoundParameters.ContainsKey('XFFEnabled')) {
            $targetPolicy.XFFEnabled = $XFFEnabled
        }
        if ($PSBoundParameters.ContainsKey('Office365Enabled')) {
            $targetPolicy.Office365Enabled = $Office365Enabled
        }
        if ($PSBoundParameters.ContainsKey('QuotaLimit')) {
            $targetPolicy.QuotaLimit = [string]$QuotaLimit
        }
        if ($PSBoundParameters.ContainsKey('Office365TenantsList')) {
            $targetPolicy.Office365TenantsList = $Office365TenantsList
        }
        if ($PSBoundParameters.ContainsKey('Office365DirectoryId')) {
            $targetPolicy.Office365DirectoryId = $Office365DirectoryId
        }

        $inner = ConvertTo-SfosWebFilterPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("WebFilterPolicy '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating WebFilterPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterPolicy' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a WebFilterPolicy object from the Sophos Firewall.

        .DESCRIPTION
        Removes a WebFilterPolicy object using the Sophos Firewall XML API. This cmdlet
        supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the
        stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use
        the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosWebFilterPolicy -Name "Basic-Policy" -WhatIf

        .EXAMPLE
        # Pipeline removal
        Get-SfosWebFilterPolicy -NameLike "Basic" | Remove-SfosWebFilterPolicy

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        No write protection for predefined policies: WebFilterPolicy has no IsDefault flag, so
        this cmdlet will remove a policy such as 'Default Policy' just as readily as one of
        your own. Verify -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosWebFilterPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("WebFilterPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <WebFilterPolicy>
    <Name>$nameEsc</Name>
  </WebFilterPolicy>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing WebFilterPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterPolicy' -Action 'remove' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Builds a category reference for use inside a WebFilterPolicy rule.

        .DESCRIPTION
        Creates the small object New-SfosWebFilterPolicyRule expects for its -Category
        parameter. Performs no API call. Category/ID is a plain-text name, not a numeric ID -
        for example 'Extreme', 'Weapons' or 'Blocked URLs for Default Policy', not a number.

        .PARAMETER ID
        Plain-text name of the referenced object - a web category name, URL group name, user
        activity name, dynamic category name or file type name, matching -Type. Look the exact
        spelling up on the firewall (Get-SfosWebFilterCategory, Get-SfosWebFilterURLGroup,
        Get-SfosUserActivity, Get-SfosFileType); this is not a numeric identifier.

        .PARAMETER Type
        Kind of object -ID refers to: 'WebCategory', 'URLGroup', 'UserActivity',
        'DynamicCategory' or 'FileType'.

        .OUTPUTS
        PSCustomObject with ID and Type properties.

        .EXAMPLE
        # Reference the predefined 'Extreme' web category
        New-SfosWebFilterPolicyCategory -ID "Extreme" -Type WebCategory

        .EXAMPLE
        # Build a category and feed it straight into a rule and a new policy
        $category = New-SfosWebFilterPolicyCategory -ID "Weapons" -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        New-SfosWebFilterPolicy -Name "Block-Weapons" -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1
        This cmdlet performs no API call; it only builds an in-memory object.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterPolicyRule
#>
function New-SfosWebFilterPolicyCategory {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. This function
    # builds an in-memory object and never calls the API, so there is no state change for
    # ShouldProcess to confirm. The verb New is still correct - it creates an object that is
    # then handed to New-/Set-/Add-SfosWebFilterPolicyRule, which do declare ShouldProcess.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateLength(1, 50)]
        [string]$ID,

        [Parameter(Mandatory, Position = 1)]
        [ValidateSet('WebCategory', 'URLGroup', 'UserActivity', 'DynamicCategory', 'FileType')]
        [string]$Type
    )

    return [PSCustomObject]@{
        ID   = $ID
        Type = $Type
    }
}

<#
        .SYNOPSIS
        Builds a rule for use inside a WebFilterPolicy's RuleList.

        .DESCRIPTION
        Creates the object New-SfosWebFilterPolicy -Rule, Set-SfosWebFilterPolicy -Rule and
        Add-SfosWebFilterPolicyRule expect. Performs no API call - the rule only becomes part
        of a policy once handed to one of those cmdlets. SFOS persists rule order unchanged,
        so build rules in the order they must be evaluated.

        .PARAMETER Category
        One or more category objects built with New-SfosWebFilterPolicyCategory.

        .PARAMETER HTTPAction
        Action for HTTP traffic matching this rule's categories: 'Deny', 'Allow', 'Warn' or
        'Quota'. Default: 'Deny'. The vendor doc's attribute table also lists 'Log' as a
        valid value; live-verified against the lab firewall, every combination tried with
        'Log' (either action, with or without FollowHTTPAction) was rejected with a bare
        501 'Configuration parameters validation failed.' / empty <InvalidParams/>, so 'Log'
        is deliberately not offered here.

        .PARAMETER HTTPSAction
        Action for HTTPS traffic matching this rule's categories: 'Deny', 'Allow', 'Warn' or
        'Quota'. Default: 'Deny'. See -HTTPAction for why 'Log' is not offered even though
        the vendor doc lists it.

        .PARAMETER FollowHTTPAction
        Whether HTTPSAction follows HTTPAction: '0' or '1'. Default: '0'.

        .PARAMETER Schedule
        Name of the Schedule object this rule is active during, for example 'All The Time'.
        Default: 'All The Time' (a Sophos factory-default schedule).

        .PARAMETER PolicyRuleEnabled
        Whether this rule is active: '0' or '1'. Default: '1'.

        .PARAMETER CCLRuleEnabled
        Whether the Cloud Application Control List is active for this rule: '0' or '1'.
        Default: '0'.

        .PARAMETER ExceptionFileType
        File type category names excluded from this rule. Rarely used; not observed populated
        on the lab firewall.

        .PARAMETER User
        User names this rule additionally applies to. Rarely used; not observed populated on
        the lab firewall.

        .PARAMETER CCL
        Cloud Application Control List entries for this rule. Rarely used; not observed
        populated on the lab firewall.

        .PARAMETER InputObject
        An existing rule to use as the base, as returned in the RuleList of
        Get-SfosWebFilterPolicy. Accepts pipeline input. Only the parameters you actually
        supply override it, so a single field can be changed without disturbing the rest.
        Without it, every omitted parameter falls back to its default.

        .OUTPUTS
        PSCustomObject with CategoryList, HTTPAction, HTTPSAction, FollowHTTPAction, Schedule,
        PolicyRuleEnabled, CCLRuleEnabled, ExceptionList, UserList and CCLList properties -
        the same shape Get-SfosWebFilterPolicy returns for each RuleList entry.

        .EXAMPLE
        # Deny HTTP and HTTPS traffic in the 'Extreme' category, all the time
        $category = New-SfosWebFilterPolicyCategory -ID "Extreme" -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        New-SfosWebFilterPolicy -Name "Block-Extreme" -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

        .EXAMPLE
        # Warn on a URL group during business hours only
        $category = New-SfosWebFilterPolicyCategory -ID "Blocked-Sites" -Type URLGroup
        New-SfosWebFilterPolicyRule -Category $category -HTTPAction Warn -HTTPSAction Warn -Schedule "Work hours"

        .EXAMPLE
        # Change one field of an existing rule. Piping the rule in keeps everything else -
        # without -InputObject the defaults would reset Schedule and the enabled flags.
        $policy = Get-SfosWebFilterPolicy -NameLike "Block-Extreme"
        $edited = $policy.RuleList[0] | New-SfosWebFilterPolicyRule -HTTPAction Allow
        Set-SfosWebFilterPolicy -Name "Block-Extreme" -Rule @($edited) + @($policy.RuleList[1..($policy.RuleList.Count - 1)])

        .NOTES
        Minimum supported PowerShell version: 5.1
        This cmdlet performs no API call; it only builds an in-memory object.

        Without -InputObject every parameter you leave out takes its default, which makes the
        cmdlet unsuitable for editing an existing rule: building a rule just to change the
        action would also reset Schedule, PolicyRuleEnabled and CCLRuleEnabled. Pipe the
        existing rule in, or edit the property on the object returned by
        Get-SfosWebFilterPolicy and hand the whole RuleList back to Set-SfosWebFilterPolicy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterPolicyCategory

        .LINK
        New-SfosWebFilterPolicy

        .LINK
        Add-SfosWebFilterPolicyRule
#>
function New-SfosWebFilterPolicyRule {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. This function
    # builds an in-memory object and never calls the API, so there is no state change for
    # ShouldProcess to confirm. The verb New is still correct - it creates an object that is
    # then handed to New-/Set-/Add-SfosWebFilterPolicyRule, which do declare ShouldProcess.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$Category,

        # 'Log' is in the vendor doc's value list but rejected live with a 501 in every
        # combination tried - see .PARAMETER HTTPAction. Not offered here.
        [ValidateSet('Deny', 'Allow', 'Warn', 'Quota')]
        [string]$HTTPAction = 'Deny',

        [ValidateSet('Deny', 'Allow', 'Warn', 'Quota')]
        [string]$HTTPSAction = 'Deny',

        [ValidateSet('0', '1')]
        [string]$FollowHTTPAction = '0',

        [string]$Schedule = 'All The Time',

        [ValidateSet('0', '1')]
        [string]$PolicyRuleEnabled = '1',

        [ValidateSet('0', '1')]
        [string]$CCLRuleEnabled = '0',

        [string[]]$ExceptionFileType,

        [string[]]$User,

        [string[]]$CCL
    )

    process {
        # Precedence per field: an explicitly bound parameter wins, otherwise the value from
        # -InputObject, otherwise the parameter default. The ContainsKey test is what makes
        # editing safe - without it every default would overwrite the base, so changing one
        # field of an existing rule would silently reset Schedule and the enabled flags.
        # Same reasoning as New-SfosFirewallRuleNetworkPolicy; see the project build rules, section 5.
        #
        # -Category cannot be Mandatory any more, because a rule arriving through
        # -InputObject already carries its categories. Without either, there is nothing to
        # build from, so that combination is rejected here instead.
        if (-not $InputObject -and -not $PSBoundParameters.ContainsKey('Category')) {
            throw 'New-SfosWebFilterPolicyRule needs -Category, unless an existing rule is supplied through -InputObject.'
        }

        $categoryValue = if ($PSBoundParameters.ContainsKey('Category')) { @($Category) }
        elseif ($InputObject) { @($InputObject.CategoryList) }
        else { @() }

        $httpAction = if ($PSBoundParameters.ContainsKey('HTTPAction')) { $HTTPAction }
        elseif ($InputObject -and $InputObject.HTTPAction) { [string]$InputObject.HTTPAction }
        else { $HTTPAction }

        $httpsAction = if ($PSBoundParameters.ContainsKey('HTTPSAction')) { $HTTPSAction }
        elseif ($InputObject -and $InputObject.HTTPSAction) { [string]$InputObject.HTTPSAction }
        else { $HTTPSAction }

        $followHttpAction = if ($PSBoundParameters.ContainsKey('FollowHTTPAction')) { $FollowHTTPAction }
        elseif ($InputObject -and $null -ne $InputObject.FollowHTTPAction) { [string]$InputObject.FollowHTTPAction }
        else { $FollowHTTPAction }

        $scheduleValue = if ($PSBoundParameters.ContainsKey('Schedule')) { $Schedule }
        elseif ($InputObject -and $InputObject.Schedule) { [string]$InputObject.Schedule }
        else { $Schedule }

        $ruleEnabled = if ($PSBoundParameters.ContainsKey('PolicyRuleEnabled')) { $PolicyRuleEnabled }
        elseif ($InputObject -and $null -ne $InputObject.PolicyRuleEnabled) { [string]$InputObject.PolicyRuleEnabled }
        else { $PolicyRuleEnabled }

        $cclEnabled = if ($PSBoundParameters.ContainsKey('CCLRuleEnabled')) { $CCLRuleEnabled }
        elseif ($InputObject -and $null -ne $InputObject.CCLRuleEnabled) { [string]$InputObject.CCLRuleEnabled }
        else { $CCLRuleEnabled }

        $exceptionValue = if ($PSBoundParameters.ContainsKey('ExceptionFileType')) { @($ExceptionFileType) }
        elseif ($InputObject) { @($InputObject.ExceptionList) }
        else { @() }

        $userValue = if ($PSBoundParameters.ContainsKey('User')) { @($User) }
        elseif ($InputObject) { @($InputObject.UserList) }
        else { @() }

        $cclValue = if ($PSBoundParameters.ContainsKey('CCL')) { @($CCL) }
        elseif ($InputObject) { @($InputObject.CCLList) }
        else { @() }

        return [PSCustomObject]@{
            CategoryList      = @($categoryValue | Where-Object -FilterScript { $_ })
            HTTPAction        = $httpAction
            HTTPSAction       = $httpsAction
            FollowHTTPAction  = $followHttpAction
            Schedule          = $scheduleValue
            PolicyRuleEnabled = $ruleEnabled
            CCLRuleEnabled    = $cclEnabled
            ExceptionList     = @($exceptionValue | Where-Object -FilterScript { $_ })
            UserList          = @($userValue | Where-Object -FilterScript { $_ })
            CCLList           = @($cclValue | Where-Object -FilterScript { $_ })
        }
    }
}

<#
        .SYNOPSIS
        Appends a rule to the end of an existing WebFilterPolicy's RuleList.

        .DESCRIPTION
        Reads the current WebFilterPolicy, appends the supplied rule after the existing ones,
        and writes the whole entity back - SFOS replaces RuleList wholesale on update, so the
        existing rules and their order are read back first and resent unchanged alongside the
        new one.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Rule
        Rule object to append, built with New-SfosWebFilterPolicyRule.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the
        stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use
        the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Add a rule blocking the 'Weapons' category to an existing policy
        $category = New-SfosWebFilterPolicyCategory -ID "Weapons" -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        Add-SfosWebFilterPolicyRule -Name "Basic-Policy" -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        No write protection for predefined policies: WebFilterPolicy has no IsDefault flag, so
        this cmdlet will happily append a rule to a policy such as 'Default Policy'. Verify
        -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterPolicyRule

        .LINK
        Remove-SfosWebFilterPolicyRule
#>
function Add-SfosWebFilterPolicyRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject]$Rule,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $existing = @(Get-SfosWebFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WebFilterPolicy object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $targetPolicy.RuleList = @($existing[0].RuleList) + $Rule

        $inner = ConvertTo-SfosWebFilterPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("WebFilterPolicy '$($Name)' on $($params.Firewall)", 'Add rule')) {
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
            throw "Error adding a rule to WebFilterPolicy '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterPolicy' -Action 'add rule' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a single rule from an existing WebFilterPolicy's RuleList by index.

        .DESCRIPTION
        Reads the current WebFilterPolicy, drops the rule at the given zero-based index from
        its RuleList, and writes the whole entity back - SFOS replaces RuleList wholesale on
        update, so the remaining rules and their order are resent unchanged.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Index
        Zero-based position of the rule to remove within the policy's RuleList, in the order
        returned by Get-SfosWebFilterPolicy. Throws if out of range.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the
        stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use
        the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored
        connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Remove the first rule of the policy
        Remove-SfosWebFilterPolicyRule -Name "Basic-Policy" -Index 0

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.
        No write protection for predefined policies: WebFilterPolicy has no IsDefault flag, so
        this cmdlet will happily remove a rule from a policy such as 'Default Policy'. Verify
        -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Add-SfosWebFilterPolicyRule
#>
function Remove-SfosWebFilterPolicyRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$Index,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $existing = @(Get-SfosWebFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The WebFilterPolicy object '$Name' was not found."
        }

        $currentRules = @($existing[0].RuleList)
        if ($Index -lt 0 -or $Index -ge $currentRules.Count) {
            throw "WebFilterPolicy '$Name' has $($currentRules.Count) rule(s); index $Index is out of range."
        }

        $targetRules = @()
        for ($i = 0; $i -lt $currentRules.Count; $i++) {
            if ($i -ne $Index) {
                $targetRules += $currentRules[$i]
            }
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $targetPolicy.RuleList = $targetRules

        $inner = ConvertTo-SfosWebFilterPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("WebFilterPolicy '$($Name)' on $($params.Firewall)", "Remove rule at index $Index")) {
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
            throw "Error removing rule at index $Index from WebFilterPolicy '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterPolicy' -Action 'remove rule' -Target $Name
    }
    end {
    }
}

#endregion


#region SurfingQuotaPolicy

<#
        .SYNOPSIS
        Retrieves SurfingQuotaPolicy objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for SurfingQuotaPolicy objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        A SurfingQuotaPolicy is either Cyclic (a recurring daily/weekly/monthly/yearly hour
        budget) or NonCyclic (a one-off validity window with a total hour budget). The
        CycleType-specific fields (CycleHours/CycleMinutes/PerDay for Cyclic, Validity/
        MaximumHours/Minutes for NonCyclic) are populated only for the matching type; the
        firewall omits the other set of elements entirely rather than sending them empty.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the supplied value may match anywhere in the object name). Sent to the firewall as the server-side filter.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. The firewall does not support filtering on Description, so this filter is always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosSurfingQuotaPolicy

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosSurfingQuotaPolicy -NameLike "Daily"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosSurfingQuotaPolicy -NameLike "Daily" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosSurfingQuotaPolicy {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$NameLike,
        [string]$DescriptionLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
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
  <SurfingQuotaPolicy>
    $filterXml
  </SurfingQuotaPolicy>
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
        throw "Error retrieving SurfingQuotaPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set-
    # Funktion, die intern hierher zurueckgreift, um den Ist-Zustand zu ermitteln: sie
    # wuerde 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SurfingQuotaPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SurfingQuotaPolicy[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $surfingQuotaPolicyObjects = @()
    foreach ($node in $nodes) {
        $surfingQuotaPolicyObjects += [PSCustomObject]@{
            Name          = $node.Name
            CycleType     = $node.CycleType
            CycleHours    = $node.CycleHours
            CycleMinutes  = $node.CycleMinutes
            PerDay        = $node.PerDay
            Validity      = $node.Validity
            MaximumHours  = $node.MaximumHours
            Minutes       = $node.Minutes
            Description   = $node.Description
        }
    }

    return $surfingQuotaPolicyObjects
}

<#
        .SYNOPSIS
        Creates a new SurfingQuotaPolicy on the Sophos Firewall.

        .DESCRIPTION
        Creates a Surfing Quota Policy, which defines the allowed surfing time for a user to
        access the internet. A policy is either Cyclic (a recurring hour budget per day/week/
        month/year, via -CycleHours/-CycleMinutes/-PerDay) or NonCyclic (a one-off validity
        window with a total hour budget, via -Validity/-MaximumHours/-Minutes). -CycleType
        selects which of the two field groups is required; the other group is not sent.

        .PARAMETER Name
        Name of the policy (1-60 characters, no commas).

        .PARAMETER CycleType
        'Cyclic' or 'NonCyclic'. Selects which of the type-specific parameters below are
        required. The Sophos documentation marks CycleType itself as optional, but the
        firewall answers with a 501 InvalidParams error if it is omitted.

        .PARAMETER CycleHours
        Cycle hours, the upper limit of surfing hours per cycle. Required when -CycleType is
        'Cyclic'.

        .PARAMETER CycleMinutes
        Cycle minutes, the upper limit of surfing minutes per cycle (0-9999). Required when
        -CycleType is 'Cyclic'.

        .PARAMETER PerDay
        Cycle recurrence: 'Days', 'Weekly', 'Monthly' or 'Yearly'. Required when -CycleType is
        'Cyclic'.

        .PARAMETER Validity
        Total number of surfing days allowed, or 'Unlimited' for no restriction. Required when
        -CycleType is 'NonCyclic'.

        .PARAMETER MaximumHours
        Total surfing hours allowed, or 'Unlimited' for no restriction. Required when
        -CycleType is 'NonCyclic'.

        .PARAMETER Minutes
        Additional surfing minutes allowed on top of -MaximumHours (0-59). Optional, only
        meaningful when -CycleType is 'NonCyclic'.

        .PARAMETER Description
        Optional description (max 255 characters).

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a Cyclic policy: 2 hours 30 minutes per day
        New-SfosSurfingQuotaPolicy -Name "Daily-Quota" -CycleType Cyclic -CycleHours 2 -CycleMinutes 30 -PerDay Days

        .EXAMPLE
        # Create a NonCyclic policy: 100 hours over 30 days
        New-SfosSurfingQuotaPolicy -Name "Monthly-Quota" -CycleType NonCyclic -Validity 30 -MaximumHours 100 -Description "One-off quota"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSurfingQuotaPolicy
#>
function New-SfosSurfingQuotaPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Cyclic', 'NonCyclic')]
        [string]$CycleType,

        # --- Cyclic ---
        [string]$CycleHours,

        [ValidateRange(0, 9999)]
        [int]$CycleMinutes,

        [ValidateSet('Days', 'Weekly', 'Monthly', 'Yearly')]
        [string]$PerDay,

        # --- NonCyclic ---
        [string]$Validity,

        [string]$MaximumHours,

        [ValidateRange(0, 59)]
        [int]$Minutes,

        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
    }
    $xmlDescription = ''
    if ($Description) {
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    # CycleType picks one of two mutually exclusive field groups. The firewall does not
    # accept both at once and silently defaults the group that is not sent (Validity and
    # MaximumHours both come back as 'Unlimited' for a Cyclic policy, for example) - so no
    # attempt is made here to send the other group's fields.
    $xmlTypeFields = ''
    switch ($CycleType) {
        'Cyclic' {
            if (-not $PSBoundParameters.ContainsKey('CycleHours') -or -not $PSBoundParameters.ContainsKey('CycleMinutes') -or -not $PSBoundParameters.ContainsKey('PerDay')) {
                throw "SurfingQuotaPolicy '$Name' with CycleType 'Cyclic' requires -CycleHours, -CycleMinutes and -PerDay."
            }
            if ($CycleHours -notmatch '^[0-9]+$') {
                throw "CycleHours '$CycleHours' must be a non-negative integer for SurfingQuotaPolicy '$Name'."
            }
            $cycleHoursEsc = ConvertTo-SfosXmlEscaped -Text $CycleHours
            $xmlTypeFields = "<CycleHours>$cycleHoursEsc</CycleHours><CycleMinutes>$CycleMinutes</CycleMinutes><PerDay>$PerDay</PerDay>"
        }
        'NonCyclic' {
            if (-not $PSBoundParameters.ContainsKey('Validity') -or -not $PSBoundParameters.ContainsKey('MaximumHours')) {
                throw "SurfingQuotaPolicy '$Name' with CycleType 'NonCyclic' requires -Validity and -MaximumHours."
            }
            if ($Validity -ne 'Unlimited' -and $Validity -notmatch '^[0-9]{1,4}$') {
                throw "Validity '$Validity' must be 'Unlimited' or a number from 0 to 3660 for SurfingQuotaPolicy '$Name'."
            }
            if ($MaximumHours -ne 'Unlimited' -and $MaximumHours -notmatch '^[0-9]{1,7}$') {
                throw "MaximumHours '$MaximumHours' must be 'Unlimited' or a non-negative number for SurfingQuotaPolicy '$Name'."
            }
            $validityEsc = ConvertTo-SfosXmlEscaped -Text $Validity
            $maxHoursEsc = ConvertTo-SfosXmlEscaped -Text $MaximumHours
            $xmlTypeFields = "<Validity>$validityEsc</Validity><MaximumHours>$maxHoursEsc</MaximumHours>"
            if ($PSBoundParameters.ContainsKey('Minutes')) {
                $xmlTypeFields += "<Minutes>$Minutes</Minutes>"
            }
        }
    }

    $inner = @"
<Set operation="add">
  <SurfingQuotaPolicy>
    <Name>$nameEsc</Name>
    <CycleType>$CycleType</CycleType>
    $xmlTypeFields
    $xmlDescription
  </SurfingQuotaPolicy>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("SurfingQuotaPolicy '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating SurfingQuotaPolicy object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SurfingQuotaPolicy' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing SurfingQuotaPolicy object on the Sophos Firewall.

        .DESCRIPTION
        Updates a SurfingQuotaPolicy object using the Sophos Firewall XML API. You can supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall (confirmed live: updating only -Description without also
        resending -MaximumHours reset MaximumHours to 'Unlimited' and dropped Minutes
        entirely). This cmdlet reads the current policy first and keeps whatever the caller
        does not explicitly pass. -CycleType is mandatory on every call because it decides
        which of the two type-specific field groups is required.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER CycleType
        'Cyclic' or 'NonCyclic'. Determines which of the type-specific parameters below are
        required. If the type is changed, the fields belonging to the new type must be
        supplied - the firewall does not carry over values from the previous type.

        .PARAMETER CycleHours
        Cycle hours. If omitted and -CycleType is 'Cyclic', the existing value is kept.

        .PARAMETER CycleMinutes
        Cycle minutes (0-9999). If omitted and -CycleType is 'Cyclic', the existing value is kept.

        .PARAMETER PerDay
        Cycle recurrence: 'Days', 'Weekly', 'Monthly' or 'Yearly'. If omitted and -CycleType is 'Cyclic', the existing value is kept.

        .PARAMETER Validity
        Total surfing days allowed, or 'Unlimited'. If omitted and -CycleType is 'NonCyclic', the existing value is kept.

        .PARAMETER MaximumHours
        Total surfing hours allowed, or 'Unlimited'. If omitted and -CycleType is 'NonCyclic', the existing value is kept.

        .PARAMETER Minutes
        Additional surfing minutes allowed (0-59). If omitted and -CycleType is 'NonCyclic', the existing value is kept.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update an object by name
        Set-SfosSurfingQuotaPolicy -Name "Daily-Quota" -CycleType Cyclic -CycleHours 3 -CycleMinutes 0 -PerDay Days

        .EXAMPLE
        # Update using pipeline input, only the description changes
        Get-SfosSurfingQuotaPolicy -NameLike "Quota" | Set-SfosSurfingQuotaPolicy -CycleType Cyclic -Description "Revised policy"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosSurfingQuotaPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Cyclic', 'NonCyclic')]
        [string]$CycleType,

        # --- Cyclic ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$CycleHours,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0, 9999)]
        [int]$CycleMinutes,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Days', 'Weekly', 'Monthly', 'Yearly')]
        [string]$PerDay,

        # --- NonCyclic ---
        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Validity,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$MaximumHours,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(0, 59)]
        [int]$Minutes,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared or reset
        # to a default (Unlimited/Unlimited for the type that is not addressed). Read the
        # current policy first and keep whatever the caller did not pass.
        $existing = @(Get-SfosSurfingQuotaPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SurfingQuotaPolicy object '$Name' was not found."
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        # Parameter sets cannot carry this: with pipeline input PowerShell fixes the set
        # before it binds properties, so a Cyclic/NonCyclic-specific parameter would never
        # bind for the type that is not the default set. The combination is validated here
        # instead, against a single parameter set (the project build rules SS4).
        $xmlTypeFields = ''
        switch ($CycleType) {
            'Cyclic' {
                $targetCycleHours = if ($PSBoundParameters.ContainsKey('CycleHours')) { $CycleHours } else { [string]$existing[0].CycleHours }
                $targetCycleMinutes = if ($PSBoundParameters.ContainsKey('CycleMinutes')) { $CycleMinutes } else { [string]$existing[0].CycleMinutes }
                $targetPerDay = if ($PSBoundParameters.ContainsKey('PerDay')) { $PerDay } else { [string]$existing[0].PerDay }

                if (-not $targetCycleHours -or -not $targetCycleMinutes -or -not $targetPerDay) {
                    throw "SurfingQuotaPolicy '$Name' with CycleType 'Cyclic' needs -CycleHours, -CycleMinutes and -PerDay (none were found on the existing object either)."
                }
                if ($targetCycleHours -notmatch '^[0-9]+$') {
                    throw "CycleHours '$targetCycleHours' must be a non-negative integer for SurfingQuotaPolicy '$Name'."
                }
                $cycleHoursEsc = ConvertTo-SfosXmlEscaped -Text $targetCycleHours
                $xmlTypeFields = "<CycleHours>$cycleHoursEsc</CycleHours><CycleMinutes>$targetCycleMinutes</CycleMinutes><PerDay>$targetPerDay</PerDay>"
            }
            'NonCyclic' {
                $targetValidity = if ($PSBoundParameters.ContainsKey('Validity')) { $Validity } else { [string]$existing[0].Validity }
                $targetMaximumHours = if ($PSBoundParameters.ContainsKey('MaximumHours')) { $MaximumHours } else { [string]$existing[0].MaximumHours }
                $targetMinutes = if ($PSBoundParameters.ContainsKey('Minutes')) { [string]$Minutes } else { [string]$existing[0].Minutes }

                if (-not $targetValidity -or -not $targetMaximumHours) {
                    throw "SurfingQuotaPolicy '$Name' with CycleType 'NonCyclic' needs -Validity and -MaximumHours (neither was found on the existing object either)."
                }
                if ($targetValidity -ne 'Unlimited' -and $targetValidity -notmatch '^[0-9]{1,4}$') {
                    throw "Validity '$targetValidity' must be 'Unlimited' or a number from 0 to 3660 for SurfingQuotaPolicy '$Name'."
                }
                if ($targetMaximumHours -ne 'Unlimited' -and $targetMaximumHours -notmatch '^[0-9]{1,7}$') {
                    throw "MaximumHours '$targetMaximumHours' must be 'Unlimited' or a non-negative number for SurfingQuotaPolicy '$Name'."
                }
                $validityEsc = ConvertTo-SfosXmlEscaped -Text $targetValidity
                $maxHoursEsc = ConvertTo-SfosXmlEscaped -Text $targetMaximumHours
                $xmlTypeFields = "<Validity>$validityEsc</Validity><MaximumHours>$maxHoursEsc</MaximumHours>"
                if ($targetMinutes) {
                    $xmlTypeFields += "<Minutes>$targetMinutes</Minutes>"
                }
            }
        }

        $inner = @"
<Set operation="update">
  <SurfingQuotaPolicy>
    <Name>$nameEsc</Name>
    <CycleType>$CycleType</CycleType>
    $xmlTypeFields
    $xmlDescription
  </SurfingQuotaPolicy>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("SurfingQuotaPolicy '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating SurfingQuotaPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SurfingQuotaPolicy' -Action 'edit' -Target $Name
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a SurfingQuotaPolicy object from the Sophos Firewall.

        .DESCRIPTION
        Removes a SurfingQuotaPolicy object using the Sophos Firewall XML API. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosSurfingQuotaPolicy -Name "Daily-Quota" -WhatIf

        .EXAMPLE
        # Pipeline removal
        Get-SfosSurfingQuotaPolicy -NameLike "Quota" | Remove-SfosSurfingQuotaPolicy

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosSurfingQuotaPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("SurfingQuotaPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <SurfingQuotaPolicy>
    <Name>$nameEsc</Name>
  </SurfingQuotaPolicy>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing SurfingQuotaPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SurfingQuotaPolicy' -Action 'remove' -Target $Name
    }
    end {
    }
}

#endregion

#region ContentConditionList

<#
        .SYNOPSIS
        Retrieves ContentConditionList objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ContentConditionList objects. By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        ContentConditionList objects are identified by Key, not by Name (the same Key is what
        Remove-SfosContentConditionList requires, per the Sophos documentation). This cmdlet
        therefore filters server-side on Key only. A <Filter> on Name reproducibly answers
        <Status>Transaction fail</Status> without a code attribute for this entity - and a
        Status without a code attribute is treated as "no records" everywhere else in this
        module - so sending a Name filter would silently return an empty result even when
        matching objects exist. -NameLike is therefore always applied client-side only.

        Note: Sophos GET responses can be inconsistent regarding status elements. This cmdlet is designed to return an empty result when no records are found.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER KeyLike
        Optional key filter. In Sophos SFOS, 'like' behaves as a substring match. Sent to the firewall as the server-side filter - the only filter key confirmed to work for this entity.

        .PARAMETER NameLike
        Optional name filter, matched as a substring anywhere in the value. Always applied client-side; see .DESCRIPTION for why a server-side Name filter is not used.

        .PARAMETER DescriptionLike
        Optional description filter, matched as a substring anywhere in the value. Always applied client-side.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all objects
        Get-SfosContentConditionList

        .EXAMPLE
        # Filter by key (substring match)
        Get-SfosContentConditionList -KeyLike "Quota"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosContentConditionList -KeyLike "Quota" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosContentConditionList {
    [CmdletBinding()]
    param(
        # Functional parameters
        [string]$KeyLike,
        [string]$NameLike,
        [string]$DescriptionLike,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Only Key is sent server-side. A Filter on Name fails outright for this entity - see
    # the function help for the measured reason - so NameLike is never sent to the firewall.
    $filterXml = ''
    if ($KeyLike) {
        $keyLikeEsc = ConvertTo-SfosXmlEscaped -Text $KeyLike
        $filterXml = ('<Filter><key name="Key" criteria="like">{0}</key></Filter>' -f $keyLikeEsc)
    }

    $inner = @"
<Get>
  <ContentConditionList>
    $filterXml
  </ContentConditionList>
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
        throw "Error retrieving ContentConditionList objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Ohne diese Pruefung wird ein Firewall-Fehler - fehlende Berechtigung, ungueltiger
    # Filter, Serverfehler - als leeres Ergebnis gelesen. Das trifft auch die Set- und
    # Member-Funktionen, die intern hierher zurueckgreifen, um den Ist-Zustand zu
    # ermitteln: sie wuerden 'Objekt nicht gefunden' melden statt des echten Fehlers.
    # Ein leeres Ergebnis kommt ohne code-Attribut und loest hier nichts aus.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ContentConditionList' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ContentConditionList[Name]' | ForEach-Object -Process {
        $_.Node
    }

    # Client-side filtering, combined with AND. Only the first <key> of the first
    # <Filter> is evaluated by SFOS, and unsupported keys are ignored altogether,
    # so every filter is re-applied here on the returned nodes.
    if ($KeyLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Key -like "*$KeyLike*" })
    }
    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    # Erstelle PSCustomObjects
    $contentConditionListObjects = @()
    foreach ($node in $nodes) {
        $contentConditionListObjects += [PSCustomObject]@{
            Name        = $node.Name
            Key         = $node.Key
            Description = $node.Description
            ContentList = [string[]]($node.ContentList | Select-Object -ExpandProperty ContentString)
        }
    }

    return $contentConditionListObjects
}

<#
        .SYNOPSIS
        Creates a new ContentConditionList on the Sophos Firewall.

        .DESCRIPTION
        Creates a Content Condition List: a named set of raw regular expressions that other
        Web Filter rules can reference by content match.

        No -Key parameter is exposed: the Sophos documentation marks Key as mandatory, but
        live testing shows the firewall ignores any client-supplied Key on create and instead
        derives its own from -Name (non-alphanumeric characters such as spaces and hyphens
        stripped) plus a fixed '_Custom' suffix - e.g. Name 'Sensitive-Terms' becomes Key
        'SensitiveTerms_Custom' regardless of what is sent. Read the actual Key back with
        Get-SfosContentConditionList after creating the object; Set-SfosContentConditionList
        and Remove-SfosContentConditionList require that Key, not the Name.

        .PARAMETER Name
        Name of the content condition list (1-255 characters, no commas).

        .PARAMETER Description
        Optional description (max 255 characters).

        .PARAMETER ContentStrings
        Array of raw regular expressions. The firewall keeps duplicate values rather than
        ignoring them, so this cmdlet does not deduplicate the array either.

        # Connection parameters (optional - use stored context if not provided)

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, uses stored connection context.

        .PARAMETER Port
        Management/API port number. If omitted, uses stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, uses stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, uses stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation.

        .OUTPUTS
        None. Throws an exception if creation fails.

        .EXAMPLE
        # Create a list with two regexes
        New-SfosContentConditionList -Name "Sensitive-Terms" -ContentStrings @("foo", "bar") -Description "Test list"

        .EXAMPLE
        # Create an empty list and add members later
        New-SfosContentConditionList -Name "Blocked-Terms"
        Add-SfosContentConditionListMember -Key (Get-SfosContentConditionList -NameLike "Blocked-Terms").Key -ContentStrings "baz"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosContentConditionList

        .LINK
        Add-SfosContentConditionListMember
#>
function New-SfosContentConditionList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateLength(0, 255)]
        [string]$Description,

        [string[]]$ContentStrings,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $xmlDescription = ''
    if ($Description) {
        $descEsc = ConvertTo-SfosXmlEscaped -Text $Description
        $xmlDescription = "<Description>$descEsc</Description>"
    }

    $xmlContentString = ''
    foreach ($contentString in $ContentStrings) {
        if (-not $contentString) {
            continue
        }
        $csEsc = ConvertTo-SfosXmlEscaped -Text $contentString
        $xmlContentString += "<ContentString>$csEsc</ContentString>"
    }
    $xmlContentList = ''
    if ($xmlContentString) {
        $xmlContentList = "<ContentList>$xmlContentString</ContentList>"
    }

    $inner = @"
<Set operation="add">
  <ContentConditionList>
    <Name>$nameEsc</Name>
    $xmlDescription
    $xmlContentList
  </ContentConditionList>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("ContentConditionList '$($Name)' on $($params.Firewall)", 'Create')) {
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
        throw "Error creating ContentConditionList object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ContentConditionList' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates an existing ContentConditionList object on the Sophos Firewall.

        .DESCRIPTION
        Updates a ContentConditionList object using the Sophos Firewall XML API. The object is
        identified by -Key, not by Name - Key is what the firewall assigned on creation (see
        New-SfosContentConditionList) and is what Remove-SfosContentConditionList requires as
        well. -Name may be changed; Key itself stays stable across the rename (confirmed live).

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall (confirmed live: updating with only one ContentString cleared
        both the Description and the second, previously present ContentString). This cmdlet
        reads the current object first and keeps whatever the caller does not explicitly pass.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Key
        Key of the target object, as returned by Get-SfosContentConditionList.

        .PARAMETER Name
        New display name for the object. If omitted, the existing name is kept.

        .PARAMETER ContentStrings
        One or more raw regular expressions to store. If omitted, the existing list is kept.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Update an object by key
        Set-SfosContentConditionList -Key "SensitiveTerms_Custom" -Description "Updated list"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosContentConditionList -KeyLike "Quota" | Set-SfosContentConditionList -ContentStrings "foo", "bar", "baz"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosContentConditionList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 127)]
        [ValidatePattern('^[^,]+$')]
        [string]$Key,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$ContentStrings,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $keyEsc = ConvertTo-SfosXmlEscaped -Text $Key

        # SFOS replaces the whole entity on update - anything not sent is cleared. Read the
        # current object first and keep whatever the caller did not pass.
        $existing = @(Get-SfosContentConditionList -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -KeyLike $Key `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Key -eq $Key })

        if ($existing.Count -eq 0) {
            throw "The ContentConditionList object with key '$Key' was not found."
        }

        $targetName = if ($PSBoundParameters.ContainsKey('Name')) {
            $Name
        }
        else {
            [string]$existing[0].Name
        }

        $targetDescription = if ($PSBoundParameters.ContainsKey('Description')) {
            $Description
        }
        else {
            [string]$existing[0].Description
        }

        $targetContentStrings = if ($PSBoundParameters.ContainsKey('ContentStrings')) {
            @($ContentStrings)
        }
        else {
            @($existing[0].ContentList)
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $targetName

        $xmlDescription = ''
        if ($targetDescription) {
            $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription
            $xmlDescription = "<Description>$descEsc</Description>"
        }

        $xmlContentString = ''
        foreach ($contentString in $targetContentStrings) {
            if (-not $contentString) {
                continue
            }
            $csEsc = ConvertTo-SfosXmlEscaped -Text $contentString
            $xmlContentString += "<ContentString>$csEsc</ContentString>"
        }
        $xmlContentList = ''
        if ($xmlContentString) {
            $xmlContentList = "<ContentList>$xmlContentString</ContentList>"
        }

        $inner = @"
<Set operation="update">
  <ContentConditionList>
    <Name>$nameEsc</Name>
    <Key>$keyEsc</Key>
    $xmlDescription
    $xmlContentList
  </ContentConditionList>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ContentConditionList '$Key' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating ContentConditionList object '$Key': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ContentConditionList' -Action 'edit' -Target $Key
    }
    end {
    }
}

<#
        .SYNOPSIS
        Removes a ContentConditionList object from the Sophos Firewall.

        .DESCRIPTION
        Removes a ContentConditionList object using the Sophos Firewall XML API. Per the
        Sophos documentation, deletion is identified by Key, not by Name. This cmdlet
        supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Key
        Key of the target object, as returned by Get-SfosContentConditionList.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if removal fails.

        .EXAMPLE
        # Preview removal
        Remove-SfosContentConditionList -Key "SensitiveTerms_Custom" -WhatIf

        .EXAMPLE
        # Pipeline removal
        Get-SfosContentConditionList -KeyLike "Quota" | Remove-SfosContentConditionList

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosContentConditionList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 127)]
        [ValidatePattern('^[^,]+$')]
        [string]$Key,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        if (-not $PSCmdlet.ShouldProcess("ContentConditionList '$Key' on $($params.Firewall)", 'Remove')) {
            return
        }

        $keyEsc = ConvertTo-SfosXmlEscaped -Text $Key

        $inner = @"
<Remove>
  <ContentConditionList>
    <Key>$keyEsc</Key>
  </ContentConditionList>
</Remove>
"@

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Error removing ContentConditionList object '$Key': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ContentConditionList' -Action 'remove' -Target $Key
    }
    end {
    }
}

<#
        .SYNOPSIS
        Adds content strings to an existing ContentConditionList object on the Sophos Firewall.

        .DESCRIPTION
        Adds one or more raw regular expressions to a ContentConditionList object using the
        Sophos Firewall XML API. The cmdlet validates input where possible and escapes user
        input for XML safety. Per the Sophos documentation, duplicate values are not ignored,
        so this cmdlet does not deduplicate against the existing list either.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Key
        Key of the target object, as returned by Get-SfosContentConditionList.

        .PARAMETER ContentStrings
        One or more raw regular expressions to add.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Add content strings to an existing object
        Add-SfosContentConditionListMember -Key "SensitiveTerms_Custom" -ContentStrings "foo", "bar"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Add-SfosContentConditionListMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 127)]
        [ValidatePattern('^[^,]+$')]
        [string]$Key,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ContentStrings,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {

        # Check Key
        $keyEsc = ConvertTo-SfosXmlEscaped -Text $Key

        # Retrieve existing object
        $contentConditionList = Get-SfosContentConditionList -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -KeyLike $Key `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -KeyLike is a substring match, so narrow the result down to the exact object
        $contentConditionList = @($contentConditionList | Where-Object -FilterScript { $_.Key -eq $Key })

        if ($contentConditionList.Count -eq 0) {
            throw "The ContentConditionList object with key '$Key' was not found."
        }

        $contentConditionList = $contentConditionList[0]

        # Prefill existing content strings. SFOS applies the list as a whole - a
        # <Set operation="update"> replaces it instead of appending - so the current values
        # must be written back together with the new ones. Duplicates are kept rather than
        # deduplicated: the Sophos documentation states duplicate ContentString values are
        # not ignored.
        $contentConditionListMembers = @()
        $contentConditionListMembers += $contentConditionList.ContentList
        $contentConditionListMembers += $ContentStrings
        $contentConditionListMembers = $contentConditionListMembers | Where-Object -FilterScript { $_ }

        # Build XML content string list
        $xmlContentString = ''
        foreach ($contentString in $contentConditionListMembers) {
            if (-not $contentString) {
                continue
            }
            $csEsc = ConvertTo-SfosXmlEscaped -Text $contentString
            $xmlContentString += "<ContentString>$csEsc</ContentString>"
        }

        # SFOS replaces the whole entity on update - an element that is not sent is cleared
        # on the firewall. Without carrying Name and Description over, adding a member would
        # silently wipe both.
        $nameXml = "<Name>$(ConvertTo-SfosXmlEscaped -Text $contentConditionList.Name)</Name>"

        $descriptionXml = ''
        if ($contentConditionList.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $contentConditionList.Description)</Description>"
        }

        $inner = @"
<Set operation="update">
    <ContentConditionList>
        $nameXml
        <Key>$keyEsc</Key>
        $descriptionXml
        <ContentList>
            $xmlContentString
        </ContentList>
    </ContentConditionList>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("ContentConditionList '$Key' on $($params.Firewall)", 'Add members')) {
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
            throw "Error adding members to ContentConditionList '$Key': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ContentConditionList' -Action 'add members' -Target $Key
    }
}

<#
        .SYNOPSIS
        Removes content strings from an existing ContentConditionList object on the Sophos Firewall.

        .DESCRIPTION
        Removes one or more raw regular expressions from a ContentConditionList object using
        the Sophos Firewall XML API. The cmdlet validates input where possible and escapes
        user input for XML safety.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Key
        Key of the target object, as returned by Get-SfosContentConditionList.

        .PARAMETER ContentStrings
        One or more raw regular expressions to remove.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Remove content strings from an existing object
        Remove-SfosContentConditionListMember -Key "SensitiveTerms_Custom" -ContentStrings "foo", "bar"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Remove-SfosContentConditionListMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 127)]
        [ValidatePattern('^[^,]+$')]
        [string]$Key,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ContentStrings,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }
    process {

        # Check Key
        $keyEsc = ConvertTo-SfosXmlEscaped -Text $Key

        # Retrieve existing object
        $contentConditionList = Get-SfosContentConditionList -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -KeyLike $Key `
            -SkipCertificateCheck:$params.SkipCertificateCheck

        # -KeyLike is a substring match, so narrow the result down to the exact object
        $contentConditionList = @($contentConditionList | Where-Object -FilterScript { $_.Key -eq $Key })

        if ($contentConditionList.Count -eq 0) {
            throw "The ContentConditionList object with key '$Key' was not found."
        }

        $contentConditionList = $contentConditionList[0]

        if (@($contentConditionList.ContentList).Count -eq 0) {
            # Nothing to remove
            return
        }

        # Prefill existing content strings
        $contentConditionListMembers = [Collections.ArrayList]@()
        $contentConditionListMembers.AddRange([string[]]@($contentConditionList.ContentList))

        foreach ($contentString in $ContentStrings) {
            [int]$indexMember = $contentConditionListMembers.IndexOf($contentString)

            if ($indexMember -ne -1) {
                $contentConditionListMembers.RemoveAt($indexMember)
            }
        }

        $xmlContentString = ''
        foreach ($contentString in $contentConditionListMembers) {
            if (-not $contentString) {
                continue
            }
            $csEsc = ConvertTo-SfosXmlEscaped -Text $contentString
            $xmlContentString += "<ContentString>$csEsc</ContentString>"
        }

        # 'update' with the complete remaining list, not 'remove': SFOS replaces the list
        # with whatever is sent, so a <Set operation="remove"> carrying the strings to drop
        # would keep exactly those and discard the rest.
        # SFOS replaces the whole entity on update - an element that is not sent is cleared
        # on the firewall. Without carrying Name and Description over, removing a member
        # would silently wipe both.
        $nameXml = "<Name>$(ConvertTo-SfosXmlEscaped -Text $contentConditionList.Name)</Name>"

        $descriptionXml = ''
        if ($contentConditionList.Description) {
            $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $contentConditionList.Description)</Description>"
        }

        $inner = @"
<Set operation="update">
    <ContentConditionList>
        $nameXml
        <Key>$keyEsc</Key>
        $descriptionXml
        <ContentList>
            $xmlContentString
        </ContentList>
    </ContentConditionList>
</Set>
"@
        if (-not $PSCmdlet.ShouldProcess("ContentConditionList '$Key' on $($params.Firewall)", 'Remove members')) {
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
            throw "Error removing members from ContentConditionList '$Key': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content

        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ContentConditionList' -Action 'remove members' -Target $Key
    }
}

#endregion


# SophosFirewall.Web fragment - Settings singletons (MalwareProtection, WebFilterSettings,
# WebFilterProtectionSettings, WebFilterAdvancedSettings, DefaultWebFilterNotificationSettings)
#
# These five elements are singletons on the Sophos Firewall: there is exactly one instance
# per firewall, it has no <Name>, and the API exposes no create/delete for it - only <Get>
# and <Set operation="update">. That is why this fragment has no New-*/Remove-* cmdlets for
# them, unlike every other entity in this module family (the project build rules SS4 permits deviation from
# the CRUD skeleton when documented with a reason; this is the reason).
#
# IMPORTANT correction versus the original spec (web-spec.md SS0/SS7): live testing against
# WebFilterProtectionSettings showed that a partial <Set operation="update"> which omitted
# PharmingProtection nonetheless reset it from Enable to Disable, with HTTP 200 / status
# code="200" - i.e. NOT a true independent single-field update for that field, contradicting
# the "true single-field update" assumption in the spec. Because it is unknown which other
# fields on which of these five entities carry the same defect, every Set-* cmdlet in this
# fragment now follows the same read-modify-write pattern as the object entities elsewhere in
# this module family (the project build rules SS5): call the matching Get-* first, resolve each field to the
# caller's explicit value (via $PSBoundParameters.ContainsKey()) or otherwise the value just
# read back, and always send the complete entity. This costs one extra GET per Set, but closes
# the defect regardless of which field actually triggers it - the root cause was deliberately
# not isolated further (would have required additional writes to the field's do-not-touch
# list) and is left as an open question below.
#
# Security-relevant fields (PharmingProtection, AllowInvalidCertificate, DenyUnknownProtocol,
# Scanning, BlockUnscannableContent) additionally have no cmdlet default: with the
# read-modify-write pattern above this is what keeps a call that only wants to set one
# unrelated field from ever inventing a value for these - the value sent is always either the
# caller's explicit input or the value already on the firewall, never a cmdlet default.

#region MalwareProtection

<#
        .SYNOPSIS
        Retrieves the MalwareProtection settings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the MalwareProtection settings singleton. There is exactly one instance of this element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns the raw XML node instead of a PowerShell-friendly object.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve the current malware protection settings
        Get-SfosMalwareProtection

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>) and XML escaping for user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosMalwareProtection {
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><MalwareProtection></MalwareProtection></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MalwareProtection settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MalwareProtection' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/MalwareProtection')
    if (-not $node) {
        throw 'MalwareProtection settings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        PrimaryAntiVirusEngine = [string]$node.PrimaryAntiVirusEngine
    }
}

<#
        .SYNOPSIS
        Updates the MalwareProtection settings on the Sophos Firewall.

        .DESCRIPTION
        Updates the MalwareProtection settings singleton using the Sophos Firewall XML API. This cmdlet reads the current settings first and resends every field, overriding only what the caller explicitly passes (read-modify-write - see the fragment header comment for why this is required even though the entity is a singleton). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER PrimaryAntiVirusEngine
        The primary anti-virus engine to use. No -ValidateSet is applied deliberately: on the lab firewall, the documented value 'Sophos/Avira' was rejected with a raw HTTP 500, most likely because the second engine is not licensed on that appliance. Restricting this parameter to a fixed list would hide that the failure is a licensing/availability problem, not a request format problem - so the raw API error is passed through unmodified. If omitted, the value currently on the firewall is kept.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Switch the primary anti-virus engine
        Set-SfosMalwareProtection -PrimaryAntiVirusEngine 'Sophos'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write: 'Sophos' is the only value that could be tested without touching the do-not-touch list, and it was already the value on the firewall, so this cmdlet was verified structurally (same pattern as the live-tested Set-SfosWebFilterSettings/Set-SfosWebFilterAdvancedSettings) and via its Get path, not via a live value change.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosMalwareProtection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$PrimaryAntiVirusEngine,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosMalwareProtection -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetEngine = if ($PSBoundParameters.ContainsKey('PrimaryAntiVirusEngine')) {
        $PrimaryAntiVirusEngine
    }
    else {
        $existing.PrimaryAntiVirusEngine
    }

    if (-not $PSCmdlet.ShouldProcess("MalwareProtection on $($params.Firewall)", 'Update')) {
        return
    }

    $engineEsc = ConvertTo-SfosXmlEscaped -Text ([string]$targetEngine)

    $inner = @"
<Set operation="update">
  <MalwareProtection>
    <PrimaryAntiVirusEngine>$engineEsc</PrimaryAntiVirusEngine>
  </MalwareProtection>
</Set>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating MalwareProtection settings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MalwareProtection' -Action 'update'
}

#endregion

#region WebFilterSettings

<#
        .SYNOPSIS
        Retrieves the WebFilterSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the WebFilterSettings singleton. There is exactly one instance of this element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns the raw XML node instead of a PowerShell-friendly object.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve the current web filter settings
        Get-SfosWebFilterSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        TopImageFile and BottomImageFile are not exposed anywhere in this module: the API documents them as Datatype 'FILE', passed in a multipart request, which the shared Invoke-SfosApi (urlencoded reqxml body) cannot send. They are also absent from every Get response on the lab firewall, so there is nothing to read back either.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterSettings>, a singleton
    # holding one configuration, and it has no <WebFilterSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><WebFilterSettings></WebFilterSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WebFilterSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WebFilterSettings')
    if (-not $node) {
        throw 'WebFilterSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    # The firewall omits elements that are at their disabled/empty state (observed for
    # DefaultWarnedMessage, DefaultDeniedMessage, the filetype/override/quota message pair
    # and PUAWhitelist on the lab firewall) instead of returning them empty. Casting a
    # missing property to [string] yields '' and an absent PUAWhitelist yields @(), so every
    # field below still has a value to read back for the read-modify-write in Set-*.
    $puaList = @()
    if ($node.PUAWhitelist) {
        $puaList = @($node.PUAWhitelist | Select-Object -ExpandProperty PUA)
    }

    return [PSCustomObject]@{
        WebCaching                     = [string]$node.WebCaching
        Scanning                       = [string]$node.Scanning
        BlockUnscannableContent        = [string]$node.BlockUnscannableContent
        PharmingProtection              = [string]$node.PharmingProtection
        OverrideDefaultWarnedMessage   = [string]$node.OverrideDefaultWarnedMessage
        DefaultWarnedMessage           = [string]$node.DefaultWarnedMessage
        OverrideDefaultDeniedMessage   = [string]$node.OverrideDefaultDeniedMessage
        DefaultDeniedMessage           = [string]$node.DefaultDeniedMessage
        DeniedMessageImage             = [string]$node.DeniedMessageImage
        DefaultFiletypeDeniedMessage   = [string]$node.DefaultFiletypeDeniedMessage
        DefaultFiletypeWarnedMessage   = [string]$node.DefaultFiletypeWarnedMessage
        OverrideDefaultOverrideMessage = [string]$node.OverrideDefaultOverrideMessage
        DefaultOverrideMessage         = [string]$node.DefaultOverrideMessage
        OverrideDefaultQuotaMessage    = [string]$node.OverrideDefaultQuotaMessage
        DefaultQuotaMessage            = [string]$node.DefaultQuotaMessage
        PUAWhitelist                   = [string[]]$puaList
    }
}

<#
        .SYNOPSIS
        Updates the WebFilterSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the WebFilterSettings singleton using the Sophos Firewall XML API. This cmdlet reads the current settings first and resends every field, overriding only what the caller explicitly passes (read-modify-write - see the fragment header comment for why this is required even though the entity is a singleton). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER WebCaching
        'Enable' or 'Disable' web caching (observed values). If omitted, the current value is kept.

        .PARAMETER Scanning
        The anti-virus scanning mode (observed value: 'Single Anti-Virus (Maximum Performance)'). Security-relevant: never defaulted by this cmdlet - only sent when explicitly bound, otherwise the value read from the firewall is resent unchanged. If omitted, the current value is kept.

        .PARAMETER BlockUnscannableContent
        How to handle content that cannot be scanned (observed value: 'Block (Best Protection)'). Security-relevant: never defaulted by this cmdlet. If omitted, the current value is kept.

        .PARAMETER PharmingProtection
        'Enable' or 'Disable' pharming protection (observed values). Security-relevant: never defaulted by this cmdlet - live testing showed a related singleton (WebFilterProtectionSettings) silently resetting this exact field to 'Disable' on an update that never mentioned it, so it is treated as never-touch unless the caller explicitly asks for a change. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultWarnedMessage
        'Enable' or 'Disable' the custom warned-message override (observed values). If omitted, the current value is kept.

        .PARAMETER DefaultWarnedMessage
        Custom warned-page message text/HTML. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultDeniedMessage
        'Enable' or 'Disable' the custom denied-message override (observed values). If omitted, the current value is kept.

        .PARAMETER DefaultDeniedMessage
        Custom denied-page message text/HTML. If omitted, the current value is kept.

        .PARAMETER DeniedMessageImage
        Image shown on the denied page (observed value: 'Default'). If omitted, the current value is kept.

        .PARAMETER DefaultFiletypeDeniedMessage
        Custom message shown when a file type is denied. If omitted, the current value is kept.

        .PARAMETER DefaultFiletypeWarnedMessage
        Custom message shown when a file type is warned. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultOverrideMessage
        Enables the custom override-page message. No -ValidateSet is applied: the Sophos documentation contradicts itself for this field - the attribute table states only '0'/'1' are valid, but the sample XML on the same page uses 'Enable'/'Disable'. This was not resolved by live testing, so the parameter accepts any string rather than risk rejecting a value the firewall actually wants. If omitted, the current value is kept.

        .PARAMETER DefaultOverrideMessage
        Custom override-page message text/HTML. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultQuotaMessage
        Enables the custom quota-page message. No -ValidateSet is applied for the same documented table/sample contradiction as OverrideDefaultOverrideMessage. If omitted, the current value is kept.

        .PARAMETER DefaultQuotaMessage
        Custom quota-page message text/HTML. If omitted, the current value is kept.

        .PARAMETER PUAWhitelist
        Array of PUA (potentially unwanted application) names to whitelist. If omitted, the current list is kept. Pass an empty array to clear it.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Toggle web caching
        Set-SfosWebFilterSettings -WebCaching 'Enable'

        .EXAMPLE
        # Re-send the denied message image field unchanged (proves the field round-trips)
        Set-SfosWebFilterSettings -DeniedMessageImage 'Default'

        .NOTES
        Minimum supported PowerShell version: 5.1
        TopImageFile/BottomImageFile are not supported - see Get-SfosWebFilterSettings notes.
        Live-verified fields (round-tripped via this cmdlet, full state diff against a saved baseline): WebCaching, DeniedMessageImage. PharmingProtection, Scanning and BlockUnscannableContent were never written during verification; only their Get path and the read-modify-write code path (identical in structure to the tested fields) were checked.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterSettings>, a singleton
    # holding one configuration, and it has no <WebFilterSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$WebCaching,
        [string]$Scanning,
        [string]$BlockUnscannableContent,
        [string]$PharmingProtection,
        [string]$OverrideDefaultWarnedMessage,
        [string]$DefaultWarnedMessage,
        [string]$OverrideDefaultDeniedMessage,
        [string]$DefaultDeniedMessage,
        [string]$DeniedMessageImage,
        [string]$DefaultFiletypeDeniedMessage,
        [string]$DefaultFiletypeWarnedMessage,
        [string]$OverrideDefaultOverrideMessage,
        [string]$DefaultOverrideMessage,
        [string]$OverrideDefaultQuotaMessage,
        [string]$DefaultQuotaMessage,
        [string[]]$PUAWhitelist,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosWebFilterSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetWebCaching = if ($bp.ContainsKey('WebCaching')) { $WebCaching } else { $existing.WebCaching }
    $targetScanning = if ($bp.ContainsKey('Scanning')) { $Scanning } else { $existing.Scanning }
    $targetBlockUnscannable = if ($bp.ContainsKey('BlockUnscannableContent')) { $BlockUnscannableContent } else { $existing.BlockUnscannableContent }
    $targetPharming = if ($bp.ContainsKey('PharmingProtection')) { $PharmingProtection } else { $existing.PharmingProtection }
    $targetOverrideWarned = if ($bp.ContainsKey('OverrideDefaultWarnedMessage')) { $OverrideDefaultWarnedMessage } else { $existing.OverrideDefaultWarnedMessage }
    $targetWarnedMsg = if ($bp.ContainsKey('DefaultWarnedMessage')) { $DefaultWarnedMessage } else { $existing.DefaultWarnedMessage }
    $targetOverrideDenied = if ($bp.ContainsKey('OverrideDefaultDeniedMessage')) { $OverrideDefaultDeniedMessage } else { $existing.OverrideDefaultDeniedMessage }
    $targetDeniedMsg = if ($bp.ContainsKey('DefaultDeniedMessage')) { $DefaultDeniedMessage } else { $existing.DefaultDeniedMessage }
    $targetDeniedImg = if ($bp.ContainsKey('DeniedMessageImage')) { $DeniedMessageImage } else { $existing.DeniedMessageImage }
    $targetFtDenied = if ($bp.ContainsKey('DefaultFiletypeDeniedMessage')) { $DefaultFiletypeDeniedMessage } else { $existing.DefaultFiletypeDeniedMessage }
    $targetFtWarned = if ($bp.ContainsKey('DefaultFiletypeWarnedMessage')) { $DefaultFiletypeWarnedMessage } else { $existing.DefaultFiletypeWarnedMessage }
    $targetOverrideOverride = if ($bp.ContainsKey('OverrideDefaultOverrideMessage')) { $OverrideDefaultOverrideMessage } else { $existing.OverrideDefaultOverrideMessage }
    $targetOverrideMsg = if ($bp.ContainsKey('DefaultOverrideMessage')) { $DefaultOverrideMessage } else { $existing.DefaultOverrideMessage }
    $targetOverrideQuota = if ($bp.ContainsKey('OverrideDefaultQuotaMessage')) { $OverrideDefaultQuotaMessage } else { $existing.OverrideDefaultQuotaMessage }
    $targetQuotaMsg = if ($bp.ContainsKey('DefaultQuotaMessage')) { $DefaultQuotaMessage } else { $existing.DefaultQuotaMessage }
    $targetPua = if ($bp.ContainsKey('PUAWhitelist')) { @($PUAWhitelist) } else { @($existing.PUAWhitelist) }

    if (-not $PSCmdlet.ShouldProcess("WebFilterSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $puaXml = ''
    foreach ($pua in $targetPua) {
        if (-not $pua) {
            continue
        }
        $puaEsc = ConvertTo-SfosXmlEscaped -Text $pua
        $puaXml += "<PUA>$puaEsc</PUA>"
    }

    $inner = @"
<Set operation="update">
  <WebFilterSettings>
    <WebCaching>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetWebCaching))</WebCaching>
    <Scanning>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetScanning))</Scanning>
    <BlockUnscannableContent>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetBlockUnscannable))</BlockUnscannableContent>
    <PharmingProtection>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetPharming))</PharmingProtection>
    <OverrideDefaultWarnedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideWarned))</OverrideDefaultWarnedMessage>
    <DefaultWarnedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetWarnedMsg))</DefaultWarnedMessage>
    <OverrideDefaultDeniedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideDenied))</OverrideDefaultDeniedMessage>
    <DefaultDeniedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDeniedMsg))</DefaultDeniedMessage>
    <DeniedMessageImage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDeniedImg))</DeniedMessageImage>
    <DefaultFiletypeDeniedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetFtDenied))</DefaultFiletypeDeniedMessage>
    <DefaultFiletypeWarnedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetFtWarned))</DefaultFiletypeWarnedMessage>
    <OverrideDefaultOverrideMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideOverride))</OverrideDefaultOverrideMessage>
    <DefaultOverrideMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideMsg))</DefaultOverrideMessage>
    <OverrideDefaultQuotaMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideQuota))</OverrideDefaultQuotaMessage>
    <DefaultQuotaMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetQuotaMsg))</DefaultQuotaMessage>
    <PUAWhitelist>$puaXml</PUAWhitelist>
  </WebFilterSettings>
</Set>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating WebFilterSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterSettings' -Action 'update'
}

#endregion

#region WebFilterProtectionSettings

<#
        .SYNOPSIS
        Retrieves the WebFilterProtectionSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the WebFilterProtectionSettings singleton. There is exactly one instance of this element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns the raw XML node instead of a PowerShell-friendly object.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve the current web filter protection settings
        Get-SfosWebFilterProtectionSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        This element is documented in Sophos's admin help under several folder names that all resolve to this same XML root (AntiVirusFTP, AntiVirusHTTPsConfiguration) - see the module README for the mapping. Do not implement cmdlets for those folder names separately; they would be a second, competing write target for the same fields.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterProtectionSettings>, a singleton
    # holding one configuration, and it has no <WebFilterProtectionSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><WebFilterProtectionSettings></WebFilterProtectionSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WebFilterProtectionSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterProtectionSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WebFilterProtectionSettings')
    if (-not $node) {
        throw 'WebFilterProtectionSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $puaList = @()
    if ($node.PUAWhitelist) {
        $puaList = @($node.PUAWhitelist | Select-Object -ExpandProperty PUA)
    }

    return [PSCustomObject]@{
        ScanMode                 = [string]$node.ScanMode
        FileSizeThreshold        = [int]$node.FileSizeThreshold
        FTPFileSizeThreshold     = [int]$node.FTPFileSizeThreshold
        AudioVideoFileScanning   = [string]$node.AudioVideoFileScanning
        HTTPSScanningCA          = [string]$node.HTTPSScanningCA
        DenyUnknownProtocol      = [string]$node.DenyUnknownProtocol
        AllowInvalidCertificate  = [string]$node.AllowInvalidCertificate
        NoHttpsNotification      = [string]$node.NoHttpsNotification
        Scanning                 = [string]$node.Scanning
        BlockUnscannableContent  = [string]$node.BlockUnscannableContent
        PharmingProtection       = [string]$node.PharmingProtection
        PUADetection              = [string]$node.PUADetection
        PUAWhitelist             = [string[]]$puaList
    }
}

<#
        .SYNOPSIS
        Updates the WebFilterProtectionSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the WebFilterProtectionSettings singleton using the Sophos Firewall XML API. This cmdlet reads the current settings first and resends every field, overriding only what the caller explicitly passes (read-modify-write - see the fragment header comment for why this is required even though the entity is a singleton, and in particular why this specific entity is the one where the defect was found: a partial update that never mentioned PharmingProtection silently reset it to 'Disable' with a code="200" success response). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER ScanMode
        The scanning mode (observed value: 'BatchMode'). If omitted, the current value is kept.

        .PARAMETER FileSizeThreshold
        HTTP/HTTPS file size scanning threshold in KB. If omitted, the current value is kept.

        .PARAMETER FTPFileSizeThreshold
        FTP file size scanning threshold in KB. If omitted, the current value is kept.

        .PARAMETER AudioVideoFileScanning
        'Enable' or 'Disable' audio/video file scanning (observed values). If omitted, the current value is kept.

        .PARAMETER HTTPSScanningCA
        Name of the CA certificate used for HTTPS scanning. If omitted, the current value is kept.

        .PARAMETER DenyUnknownProtocol
        'Enable' or 'Disable' denying unknown protocols on HTTPS ports (observed values). Security-relevant: never defaulted by this cmdlet - only sent when explicitly bound, otherwise the value read from the firewall is resent unchanged. If omitted, the current value is kept.

        .PARAMETER AllowInvalidCertificate
        'Enable' or 'Disable' allowing invalid HTTPS certificates (observed values). Security-relevant: never defaulted by this cmdlet. If omitted, the current value is kept.

        .PARAMETER NoHttpsNotification
        'Enable' or 'Disable' suppressing the HTTPS scanning notification page (observed values). If omitted, the current value is kept.

        .PARAMETER Scanning
        The anti-virus scanning mode (observed value: 'Single Anti-Virus (Maximum Performance)'). Security-relevant: never defaulted by this cmdlet. If omitted, the current value is kept.

        .PARAMETER BlockUnscannableContent
        How to handle content that cannot be scanned (observed value: 'Block (Best Protection)'). Security-relevant: never defaulted by this cmdlet. If omitted, the current value is kept.

        .PARAMETER PharmingProtection
        'Enable' or 'Disable' pharming protection (observed values). Security-relevant: never defaulted by this cmdlet. This is the field on which the silent-reset defect described in .DESCRIPTION was found; it is on the do-not-touch list for this module's own verification and was never written during testing.

        .PARAMETER PUADetection
        'Enable' or 'Disable' PUA (potentially unwanted application) detection (observed value: 'Disable'). If omitted, the current value is kept.

        .PARAMETER PUAWhitelist
        Array of PUA names to whitelist. If omitted, the current list is kept. Pass an empty array to clear it.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Change only the scan mode, leaving every other field - including PharmingProtection - untouched
        Set-SfosWebFilterProtectionSettings -ScanMode 'BatchMode'

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write: every field of this entity is either on the do-not-touch list (PharmingProtection, Scanning, BlockUnscannableContent, AllowInvalidCertificate, DenyUnknownProtocol) or was excluded from the write-test scope agreed for this task. Verified via its Get path and structurally, by the same read-modify-write pattern already live-tested on Set-SfosWebFilterSettings/Set-SfosWebFilterAdvancedSettings.
        Open question, not resolved by this task: which field(s) of WebFilterProtectionSettings actually trigger the PharmingProtection reset described in .DESCRIPTION. Deliberately not isolated further, since read-modify-write closes the defect regardless of the trigger and isolating it would have required more writes to a do-not-touch field.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterProtectionSettings>, a singleton
    # holding one configuration, and it has no <WebFilterProtectionSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ScanMode,
        [int]$FileSizeThreshold,
        [int]$FTPFileSizeThreshold,
        [string]$AudioVideoFileScanning,
        [string]$HTTPSScanningCA,
        [string]$DenyUnknownProtocol,
        [string]$AllowInvalidCertificate,
        [string]$NoHttpsNotification,
        [string]$Scanning,
        [string]$BlockUnscannableContent,
        [string]$PharmingProtection,
        [string]$PUADetection,
        [string[]]$PUAWhitelist,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosWebFilterProtectionSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetScanMode = if ($bp.ContainsKey('ScanMode')) { $ScanMode } else { $existing.ScanMode }
    $targetFileSize = if ($bp.ContainsKey('FileSizeThreshold')) { $FileSizeThreshold } else { $existing.FileSizeThreshold }
    $targetFtpFileSize = if ($bp.ContainsKey('FTPFileSizeThreshold')) { $FTPFileSizeThreshold } else { $existing.FTPFileSizeThreshold }
    $targetAudioVideo = if ($bp.ContainsKey('AudioVideoFileScanning')) { $AudioVideoFileScanning } else { $existing.AudioVideoFileScanning }
    $targetHttpsCa = if ($bp.ContainsKey('HTTPSScanningCA')) { $HTTPSScanningCA } else { $existing.HTTPSScanningCA }
    $targetDenyUnknown = if ($bp.ContainsKey('DenyUnknownProtocol')) { $DenyUnknownProtocol } else { $existing.DenyUnknownProtocol }
    $targetAllowInvalid = if ($bp.ContainsKey('AllowInvalidCertificate')) { $AllowInvalidCertificate } else { $existing.AllowInvalidCertificate }
    $targetNoHttpsNotif = if ($bp.ContainsKey('NoHttpsNotification')) { $NoHttpsNotification } else { $existing.NoHttpsNotification }
    $targetScanning = if ($bp.ContainsKey('Scanning')) { $Scanning } else { $existing.Scanning }
    $targetBlockUnscannable = if ($bp.ContainsKey('BlockUnscannableContent')) { $BlockUnscannableContent } else { $existing.BlockUnscannableContent }
    $targetPharming = if ($bp.ContainsKey('PharmingProtection')) { $PharmingProtection } else { $existing.PharmingProtection }
    $targetPuaDetection = if ($bp.ContainsKey('PUADetection')) { $PUADetection } else { $existing.PUADetection }
    $targetPua = if ($bp.ContainsKey('PUAWhitelist')) { @($PUAWhitelist) } else { @($existing.PUAWhitelist) }

    if (-not $PSCmdlet.ShouldProcess("WebFilterProtectionSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $puaXml = ''
    foreach ($pua in $targetPua) {
        if (-not $pua) {
            continue
        }
        $puaEsc = ConvertTo-SfosXmlEscaped -Text $pua
        $puaXml += "<PUA>$puaEsc</PUA>"
    }

    $inner = @"
<Set operation="update">
  <WebFilterProtectionSettings>
    <ScanMode>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetScanMode))</ScanMode>
    <FileSizeThreshold>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetFileSize))</FileSizeThreshold>
    <FTPFileSizeThreshold>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetFtpFileSize))</FTPFileSizeThreshold>
    <AudioVideoFileScanning>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetAudioVideo))</AudioVideoFileScanning>
    <HTTPSScanningCA>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetHttpsCa))</HTTPSScanningCA>
    <DenyUnknownProtocol>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDenyUnknown))</DenyUnknownProtocol>
    <AllowInvalidCertificate>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetAllowInvalid))</AllowInvalidCertificate>
    <NoHttpsNotification>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetNoHttpsNotif))</NoHttpsNotification>
    <Scanning>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetScanning))</Scanning>
    <BlockUnscannableContent>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetBlockUnscannable))</BlockUnscannableContent>
    <PharmingProtection>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetPharming))</PharmingProtection>
    <PUADetection>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetPuaDetection))</PUADetection>
    <PUAWhitelist>$puaXml</PUAWhitelist>
  </WebFilterProtectionSettings>
</Set>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating WebFilterProtectionSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterProtectionSettings' -Action 'update'
}

#endregion

#region WebFilterAdvancedSettings

<#
        .SYNOPSIS
        Retrieves the WebFilterAdvancedSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the WebFilterAdvancedSettings singleton. There is exactly one instance of this element per firewall. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns the raw XML node instead of a PowerShell-friendly object.

        .OUTPUTS
        PSCustomObject (default). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve the current advanced web filter settings
        Get-SfosWebFilterAdvancedSettings

        .NOTES
        Minimum supported PowerShell version: 5.1
        This element is documented under the folder name WebProxy as well, which resolves to the same XML root. Do not implement a separate WebProxy cmdlet; it would be a second, competing write target for the same fields (confirmed live: WebProxyPort set via this element's XML root appeared immediately under the WebProxy folder's Get).

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosWebFilterAdvancedSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterAdvancedSettings>, a singleton
    # holding one configuration, and it has no <WebFilterAdvancedSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><WebFilterAdvancedSettings></WebFilterAdvancedSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WebFilterAdvancedSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterAdvancedSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WebFilterAdvancedSettings')
    if (-not $node) {
        throw 'WebFilterAdvancedSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    # TrustedPorts/Port can contain a range ("1025-65535"), not only single port numbers, so
    # this stays [string[]] rather than [int[]].
    $trustedPorts = @()
    if ($node.TrustedPorts) {
        $trustedPorts = @($node.TrustedPorts | Select-Object -ExpandProperty Port)
    }

    return [PSCustomObject]@{
        WebCaching                = [string]$node.WebCaching
        WebProxyPort              = [int]$node.WebProxyPort
        WebProxyMinimumTLSVersion = [string]$node.WebProxyMinimumTLSVersion
        TrustedPorts              = [string[]]$trustedPorts
    }
}

<#
        .SYNOPSIS
        Updates the WebFilterAdvancedSettings on the Sophos Firewall.

        .DESCRIPTION
        Updates the WebFilterAdvancedSettings singleton using the Sophos Firewall XML API. This cmdlet reads the current settings first and resends every field, overriding only what the caller explicitly passes (read-modify-write - see the fragment header comment for why this is required even though the entity is a singleton). This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER WebCaching
        'Enable' or 'Disable' web caching (observed values; live-verified as a working toggle on this element). If omitted, the current value is kept.

        .PARAMETER WebProxyPort
        TCP port the web proxy listens on (observed value: 3128; live-verified as a working change). If omitted, the current value is kept.

        .PARAMETER WebProxyMinimumTLSVersion
        Minimum TLS version accepted by the web proxy (observed value: 'TLS 1.1'). If omitted, the current value is kept.

        .PARAMETER TrustedPort
        Array of trusted ports/port ranges (observed: single ports and one range, e.g. '1025-65535'). If omitted, the current list is kept. Pass an empty array to clear it.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails.

        .EXAMPLE
        # Change only the proxy port, leaving TrustedPorts and the TLS minimum untouched
        Set-SfosWebFilterAdvancedSettings -WebProxyPort 3128

        .NOTES
        Minimum supported PowerShell version: 5.1
        Live-verified fields (round-tripped via this cmdlet, full state diff against a saved baseline): WebCaching, WebProxyPort.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosWebFilterAdvancedSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterAdvancedSettings>, a singleton
    # holding one configuration, and it has no <WebFilterAdvancedSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$WebCaching,
        [int]$WebProxyPort,
        [string]$WebProxyMinimumTLSVersion,
        [string[]]$TrustedPort,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosWebFilterAdvancedSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetWebCaching = if ($bp.ContainsKey('WebCaching')) { $WebCaching } else { $existing.WebCaching }
    $targetProxyPort = if ($bp.ContainsKey('WebProxyPort')) { $WebProxyPort } else { $existing.WebProxyPort }
    $targetTlsVersion = if ($bp.ContainsKey('WebProxyMinimumTLSVersion')) { $WebProxyMinimumTLSVersion } else { $existing.WebProxyMinimumTLSVersion }
    $targetTrustedPorts = if ($bp.ContainsKey('TrustedPort')) { @($TrustedPort) } else { @($existing.TrustedPorts) }

    if (-not $PSCmdlet.ShouldProcess("WebFilterAdvancedSettings on $($params.Firewall)", 'Update')) {
        return
    }

    # Loop variable deliberately not named $trustedPort: PowerShell variable names are
    # case-insensitive, and that would collide with the [string[]]$TrustedPort parameter -
    # assigning a scalar into it would then coerce through the parameter's array type
    # instead of creating a plain string, and ConvertTo-SfosXmlEscaped would fail to bind.
    $portsXml = ''
    foreach ($portValue in $targetTrustedPorts) {
        if (-not $portValue) {
            continue
        }
        $portEsc = ConvertTo-SfosXmlEscaped -Text $portValue
        $portsXml += "<Port>$portEsc</Port>"
    }

    $inner = @"
<Set operation="update">
  <WebFilterAdvancedSettings>
    <WebCaching>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetWebCaching))</WebCaching>
    <WebProxyPort>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetProxyPort))</WebProxyPort>
    <WebProxyMinimumTLSVersion>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetTlsVersion))</WebProxyMinimumTLSVersion>
    <TrustedPorts>$portsXml</TrustedPorts>
  </WebFilterAdvancedSettings>
</Set>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating WebFilterAdvancedSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterAdvancedSettings' -Action 'update'
}

#endregion

#region DefaultWebFilterNotificationSettings

<#
        .SYNOPSIS
        Retrieves the DefaultWebFilterNotificationSettings from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for the DefaultWebFilterNotificationSettings singleton - around 70 free-text/HTML notification message fields shown to end users (blocked page text, zero-day analysis progress text, and similar). There is exactly one instance of this element per firewall. The API defines no fixed schema for this element, so the returned object is built dynamically from whatever child elements the firewall actually returns, rather than from a hard-coded property list - this keeps the cmdlet correct if a firmware update adds, removes or renames a field. By default the cmdlet returns a PowerShell-friendly object. Use -AsXml to return the raw XML node.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .PARAMETER AsXml
        Returns the raw XML node instead of a PowerShell-friendly object.

        .OUTPUTS
        PSCustomObject (default) with one property per message field found on the firewall. System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all current notification message texts
        Get-SfosDefaultWebFilterNotificationSettings

        .EXAMPLE
        # Inspect one message field
        (Get-SfosDefaultWebFilterNotificationSettings).Warning

        .NOTES
        Minimum supported PowerShell version: 5.1
        Values are returned XML-decoded (plain text, with any embedded HTML such as '<br>' intact) via .InnerText - the same text can be passed back into Set-SfosDefaultWebFilterNotificationSettings unmodified, which XML-escapes it exactly once before sending, so the round trip does not double-escape.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosDefaultWebFilterNotificationSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DefaultWebFilterNotificationSettings>, a singleton
    # holding one configuration, and it has no <DefaultWebFilterNotificationSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><DefaultWebFilterNotificationSettings></DefaultWebFilterNotificationSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DefaultWebFilterNotificationSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultWebFilterNotificationSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/DefaultWebFilterNotificationSettings')
    if (-not $node) {
        throw 'DefaultWebFilterNotificationSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $result = [ordered]@{}
    foreach ($child in $node.ChildNodes) {
        if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) {
            continue
        }
        $result[$child.Name] = [string]$child.InnerText
    }

    return [PSCustomObject]$result
}

<#
        .SYNOPSIS
        Updates one or more DefaultWebFilterNotificationSettings message fields on the Sophos Firewall.

        .DESCRIPTION
        Updates the DefaultWebFilterNotificationSettings singleton using the Sophos Firewall XML API. Because this element carries around 70 free-text/HTML message fields with no fixed API schema, individual named parameters were rejected as unwieldy and as a source of drift if a firmware update adds a field. Instead this cmdlet takes a single -Message hashtable whose keys are validated against the field names actually read back from the firewall by Get-SfosDefaultWebFilterNotificationSettings (called at the start of every invocation) - an unknown key throws immediately, before any request is sent, naming the field and listing the fields that do exist on this firmware. This cmdlet then resends every field of the entity (read-modify-write - see the fragment header comment), applying only the keys present in -Message on top of the values just read. This cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        .PARAMETER Message
        Hashtable of field name/value pairs to update, e.g. @{ Warning = 'Warning!'; DownloadBlocked = 'This download is blocked' }. Keys must match a field name returned by Get-SfosDefaultWebFilterNotificationSettings; unknown keys throw. Values may contain embedded HTML - they are XML-escaped exactly once, matching how Get-SfosDefaultWebFilterNotificationSettings decodes them, so round-tripping a value read from Get back into Message does not double-escape it. Fields not present as a key are left at their current value.

        .PARAMETER Firewall
        Sophos Firewall hostname or IP address. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Port
        Management/API port number (typically 4444). If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Username
        Username for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER Password
        Password for API authentication. If omitted, the cmdlet attempts to use the stored connection context.

        .PARAMETER SkipCertificateCheck
        Skips SSL certificate validation for the API call.

        .OUTPUTS
        None. Throws an exception if the update fails or if -Message contains an unknown field name.

        .EXAMPLE
        # Change a single message field
        Set-SfosDefaultWebFilterNotificationSettings -Message @{ Warning = 'Achtung!' }

        .NOTES
        Minimum supported PowerShell version: 5.1
        Not verified against the live firewall as a write: every field of this entity is on the do-not-touch list for this task. Verified live: the Get path (full field set read back), and the unknown-key validation path, which calls Get and then throws before any Set request is built or sent - so it exercises real firewall data without writing anything. The write path itself (XML building and the actual Set-* call) is unverified beyond code review and structural identity with the live-tested WebFilterSettings/WebFilterAdvancedSettings cmdlets.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Set-SfosDefaultWebFilterNotificationSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DefaultWebFilterNotificationSettings>, a singleton
    # holding one configuration, and it has no <DefaultWebFilterNotificationSetting> child. the project build rules, section 3
    # puts the Sophos spelling above PowerShell habit and reserves the singular concession
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [hashtable]$Message,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDefaultWebFilterNotificationSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $validNames = @($existing.PSObject.Properties.Name)

    if ($Message) {
        foreach ($key in $Message.Keys) {
            if ($validNames -notcontains $key) {
                throw "Set-SfosDefaultWebFilterNotificationSettings: '$key' is not a known DefaultWebFilterNotificationSettings field on this firewall. Known fields: $($validNames -join ', ')"
            }
        }
    }

    if (-not $PSCmdlet.ShouldProcess("DefaultWebFilterNotificationSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $fieldsXml = ''
    foreach ($name in $validNames) {
        $value = $existing.$name
        if ($Message -and $Message.ContainsKey($name)) {
            $value = $Message[$name]
        }
        $valueEsc = ConvertTo-SfosXmlEscaped -Text ([string]$value)
        $fieldsXml += "<$name>$valueEsc</$name>"
    }

    $inner = "<Set operation=`"update`"><DefaultWebFilterNotificationSettings>$fieldsXml</DefaultWebFilterNotificationSettings></Set>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating DefaultWebFilterNotificationSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultWebFilterNotificationSettings' -Action 'update'
}

#endregion

