#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.4.0' }
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

        Total Functions: 57 (54 exported, 3 internal helpers) - see README.md for the full
        cmdlet table.

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
        Retrieves web filter URL group objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the URL group objects that are defined on the firewall. A URL group bundles
        one or more URLs under a single name for use in web filter policy rules and
        exceptions. Use this cmdlet to review the existing groups or to feed them into
        another cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall
        is changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the web
        filter URL groups. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per URL group, with the
        properties Name, Description and URLlist. Returns System.Xml.XmlElement when -AsXml
        is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosWebFilterURLGroup

        Lists every URL group on the firewall of the current connection.

        .EXAMPLE
        Get-SfosWebFilterURLGroup -NameLike 'Example'

        Lists all URL groups whose name contains 'Example'.

        .EXAMPLE
        Get-SfosWebFilterURLGroup -NameLike 'Example' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterURLGroup

        .LINK
        Set-SfosWebFilterURLGroup
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
        [object]$Session,

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
        Creates a web filter URL group on a Sophos Firewall.

        .DESCRIPTION
        Creates a URL group object that bundles one or more URLs under a single name, for
        use in web filter policy rules and exceptions. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with write permission. Use Add-SfosWebFilterURLGroupMember afterwards to add further
        URLs.

        .PARAMETER Name
        Required. Name of the new URL group. 1 to 50 characters, no comma.

        .PARAMETER Members
        Required. One or more URLs to include in the group.

        .PARAMETER Description
        Optional. Free-text description of the URL group.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter URL groups. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosWebFilterURLGroup -Name 'AllowedNews' -Members 'news.example.com' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosWebFilterURLGroup -Name 'AllowedNews' -Members 'news.example.com','example.org/news' -Description 'Approved news sites'

        Creates a URL group with two entries and a description.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a web filter URL group on a Sophos Firewall.

        .DESCRIPTION
        Changes the description or member list of an existing URL group. The cmdlet reads
        the current object first and sends it back complete, so a field you do not pass
        keeps its current value; pass a field explicitly, with an empty value if needed, to
        clear it. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the URL group to update.

        .PARAMETER Members
        Optional. URLs to store in the group, replacing the current list. If omitted, the
        current list is kept.

        .PARAMETER Description
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter URL groups. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The URL group name can be piped in by property name, for example the
        output of Get-SfosWebFilterURLGroup.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterURLGroup -Name 'AllowedNews' -Description 'Approved news sites' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterURLGroup -Name 'AllowedNews' -Description 'Approved news and media sites'

        Updates the description. The URL list is kept unchanged.

        .EXAMPLE
        Get-SfosWebFilterURLGroup -NameLike 'AllowedNews' | Set-SfosWebFilterURLGroup -Description 'Updated'

        Updates every matching group with a new description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterURLGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a web filter URL group from a Sophos Firewall.

        .DESCRIPTION
        Deletes a URL group object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission. Remove any web filter policy rule or exception that
        still references the group first, or the firewall keeps the reference in place.

        .PARAMETER Name
        Required. Name of the URL group to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter URL groups. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The URL group name can be piped in by property name, for example the
        output of Get-SfosWebFilterURLGroup.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosWebFilterURLGroup -Name 'Example' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosWebFilterURLGroup -Name 'Example'

        Removes the URL group. The cmdlet asks for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterURLGroup
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Adds URLs to an existing web filter URL group on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more URLs to a URL group without removing the ones already stored. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the URL group to change.

        .PARAMETER Members
        Required. One or more URLs to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter URL groups. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosWebFilterURLGroupMember -Name 'AllowedNews' -Members 'news2.example.com' -WhatIf

        Shows what the call would add without sending it to the firewall.

        .EXAMPLE
        Add-SfosWebFilterURLGroupMember -Name 'AllowedNews' -Members 'news2.example.com','news3.example.com'

        Adds two URLs to the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterURLGroup

        .LINK
        Remove-SfosWebFilterURLGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes URLs from an existing web filter URL group on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more URLs from a URL group, keeping the remaining entries. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the URL group to change.

        .PARAMETER Members
        Required. One or more URLs to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter URL groups. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosWebFilterURLGroupMember -Name 'AllowedNews' -Members 'news2.example.com' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosWebFilterURLGroupMember -Name 'AllowedNews' -Members 'news2.example.com','news3.example.com'

        Removes two URLs from the group.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterURLGroup

        .LINK
        Add-SfosWebFilterURLGroupMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves file type objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the file type objects that are defined on the firewall. A file type object
        groups file extensions and MIME headers under a single name, for use as a category
        in web filter policy rules. Use this cmdlet to review the existing objects or to
        feed them into another cmdlet through the pipeline. The cmdlet only reads; nothing
        on the firewall is changed. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        file type objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per file type, with the
        properties Name, Description, FileExtensionList and MIMEHeaderList. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosFileType

        Lists every file type object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosFileType -NameLike 'Example'

        Lists all file type objects whose name contains 'Example'.

        .EXAMPLE
        Get-SfosFileType -NameLike 'Example' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosFileType

        .LINK
        Set-SfosFileType
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
        [object]$Session,

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
        # always be empty and would suggest a field that can be read back.
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
        Creates a file type object on a Sophos Firewall.

        .DESCRIPTION
        Creates a file type object that groups file extensions and MIME headers under a
        single name, for use as a category in web filter policy rules. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the new file type object. 1 to 50 characters, no comma.

        .PARAMETER FileExtension
        Optional. File extensions to include, for example 'txt', 'jpg', 'gif'.

        .PARAMETER MIMEHeader
        Optional. MIME headers to include.

        .PARAMETER Description
        Optional. Free-text description of the file type object. Up to 1000 characters.

        .PARAMETER Template
        Optional. Template name applied when the object is created. Get-SfosFileType does
        not return this value afterwards.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        file type objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosFileType -Name 'ArchiveFiles' -FileExtension 'zip','rar','7z' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosFileType -Name 'ArchiveFiles' -FileExtension 'zip','rar','7z' -Description 'Common archive formats'

        Creates a file type object for archive file extensions.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a file type object on a Sophos Firewall.

        .DESCRIPTION
        Changes the description, file extensions or MIME headers of an existing file type
        object. The cmdlet reads the current object first and sends it back complete, so a
        field you do not pass keeps its current value; pass a field explicitly, with an
        empty value if needed, to clear it. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with write permission.

        This cmdlet has no -Template parameter. The firewall never returns the template
        value of an existing object, so it can only be set when the object is created, with
        New-SfosFileType.

        .PARAMETER Name
        Required. Name of the file type object to update.

        .PARAMETER FileExtension
        Optional. File extensions to store, replacing the current list. If omitted, the
        current list is kept.

        .PARAMETER MIMEHeader
        Optional. MIME headers to store, replacing the current list. If omitted, the current
        list is kept.

        .PARAMETER Description
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        file type objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The file type name can be piped in by property name, for example the
        output of Get-SfosFileType.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosFileType -Name 'ArchiveFiles' -Description 'Common archive formats' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosFileType -Name 'ArchiveFiles' -Description 'Common archive and compressed formats'

        Updates the description. The file extensions and MIME headers are kept unchanged.

        .EXAMPLE
        Get-SfosFileType -NameLike 'ArchiveFiles' | Set-SfosFileType -Description 'Updated'

        Updates every matching file type object with a new description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFileType
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
        # read-modify-write below could not preserve it.

        # Connection parameters (optional - use stored context if not provided)
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
        Removes a file type object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a file type object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER Name
        Required. Name of the file type object to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        file type objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The file type name can be piped in by property name, for example the
        output of Get-SfosFileType.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosFileType -Name 'Example' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosFileType -Name 'Example'

        Removes the file type object. The cmdlet asks for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosFileType
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves web filter category objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the web filter category objects that are defined on the firewall. A web
        filter category matches traffic either locally, by domain or keyword, or
        externally, by a URL list, and is used as a category in web filter policy rules.
        Use this cmdlet to review the existing objects or to feed them into another cmdlet
        through the pipeline. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER ClassificationLike
        Optional. Returns only objects whose classification contains the given text
        anywhere, for example 'Productive'. Applied on the client. If omitted, the
        classification is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the web
        filter category objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per web filter category, with
        the properties Name, Classification, ConfigureCategory, QoSPolicy, Description,
        DomainList, KeywordList, URLList, OverrideDefaultDeniedMessage,
        DefaultDeniedMessage and Notification. Returns System.Xml.XmlElement when -AsXml is
        used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosWebFilterCategory

        Lists every web filter category on the firewall of the current connection.

        .EXAMPLE
        Get-SfosWebFilterCategory -NameLike 'Gambling'

        Lists all web filter categories whose name contains 'Gambling'.

        .EXAMPLE
        Get-SfosWebFilterCategory -NameLike 'Gambling' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterCategory

        .LINK
        Set-SfosWebFilterCategory
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
        [object]$Session,

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
            # @(...) plus the empty-filter is required: without it a missing wrapper yields
            # $null / @('') instead of an empty array.
            KeywordList                  = [string[]]@($node.KeywordList | Select-Object -ExpandProperty Keyword | Where-Object { $_ })
            URLList                      = [string[]]@($node.URLList | Select-Object -ExpandProperty URL | Where-Object { $_ })
            OverrideDefaultDeniedMessage = $node.OverrideDefaultDeniedMessage
            DefaultDeniedMessage         = $node.DefaultDeniedMessage
            Notification                 = $node.Notification
        }
    }

    return $webFilterCategoryObjects
}

<#
        .SYNOPSIS
        Creates a web filter category on a Sophos Firewall.

        .DESCRIPTION
        Creates a web filter category that matches traffic either locally, by domain or
        keyword, or externally, by a URL list, for use as a category in web filter policy
        rules. Passing -Domain and/or -Keyword builds a local category; passing -Url builds
        an external one. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the new web filter category. 1 to 50 characters. The characters
        ^, ;, apostrophe, quote and backtick are not allowed.

        .PARAMETER Classification
        Required. Traffic classification. Valid values: Productive, Unproductive,
        Acceptable, Objectionable.

        .PARAMETER QoSPolicy
        Required. Name of a QoS policy to apply, or 'None'.

        .PARAMETER Domain
        Optional. Domains that make up a local category. Each entry is at most 250
        characters. Selects the local form of the category together with -Keyword.

        .PARAMETER Keyword
        Optional. Keywords that make up a local category. Each entry is at most 250
        characters. Selects the local form of the category together with -Domain.

        .PARAMETER Url
        Optional. URLs that make up an external category. Give a bare host and path, for
        example 'www.example.com/list.txt', without a scheme such as http:// or https://.

        .PARAMETER Description
        Optional. Free-text description of the category. Up to 512 characters.

        .PARAMETER OverrideDefaultDeniedMessage
        Optional. Whether the category shows a custom denied message instead of the
        default one. Valid values: Enable, Disable.

        .PARAMETER DefaultDeniedMessage
        Optional. Custom denied message text or HTML, used when
        -OverrideDefaultDeniedMessage is Enable.

        .PARAMETER Notification
        Optional. Whether a notification is shown when the category blocks traffic. Valid
        values: Enable, Disable.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter category objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosWebFilterCategory -Name 'Custom-Local' -Classification Productive -QoSPolicy None -Domain 'example.com' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosWebFilterCategory -Name 'Custom-Local' -Classification Productive -QoSPolicy None -Domain 'example.com'

        Creates a local category matched by domain.

        .EXAMPLE
        New-SfosWebFilterCategory -Name 'External-Feed' -Classification Acceptable -QoSPolicy None -Url 'www.example.com/list.txt'

        Creates an external category matched by a URL list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterCategory

        .LINK
        Set-SfosWebFilterCategory
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
            # A URL carrying a scheme (http://, https://) is rejected with an
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

    # A create/update for ConfigureCategory=External can answer with a status
    # code outside the documented 200-216/500-599 ranges (217 and 222 both observed) even
    # though the object was created correctly. Assert-SfosApiReturnSuccess treats those as a
    # warning rather than a failure, so this call does not throw for them - but a caller
    # relying on "no output" should still expect a Write-Warning on the External path.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterCategory' -Action 'create' -Target $Name
}

<#
        .SYNOPSIS
        Updates a web filter category on a Sophos Firewall.

        .DESCRIPTION
        Changes the classification, member list or other settings of an existing web
        filter category. The cmdlet reads the current object first and sends it back
        complete, so a field you do not pass keeps its current value. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission.

        -Url only adds URLs to the external list; it does not remove entries already
        stored. Removing a URL requires deleting and recreating the category.

        .PARAMETER Name
        Required. Name of the web filter category to update.

        .PARAMETER Classification
        Optional. Traffic classification, replacing the current value. Valid values:
        Productive, Unproductive, Acceptable, Objectionable. If omitted, the current value
        is kept.

        .PARAMETER QoSPolicy
        Optional. Name of a QoS policy to apply, or 'None', replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER ConfigureCategory
        Required. Category form: Local or External. Determines whether Domain/Keyword or
        Url apply.

        .PARAMETER Domain
        Optional. Domains to store, replacing the current list. Applies to a Local
        category. If omitted, the current list is kept.

        .PARAMETER Keyword
        Optional. Keywords to store, replacing the current list. Applies to a Local
        category. If omitted, the current list is kept.

        .PARAMETER Url
        Optional. URLs to add to an External category. Give a bare host and path, for
        example 'www.example.com/list.txt', without a scheme such as http:// or https://.
        If omitted, the current list is kept.

        .PARAMETER Description
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER OverrideDefaultDeniedMessage
        Optional. Whether the category shows a custom denied message, replacing the
        current value. Valid values: Enable, Disable. If omitted, the current value is
        kept.

        .PARAMETER DefaultDeniedMessage
        Optional. Custom denied message text or HTML, replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER Notification
        Optional. Whether a notification is shown when the category blocks traffic,
        replacing the current value. Valid values: Enable, Disable. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter category objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter category name and other fields can be piped in by
        property name, for example the output of Get-SfosWebFilterCategory.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterCategory -Name 'Custom-Local' -ConfigureCategory Local -Description 'Updated' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterCategory -Name 'Custom-Local' -ConfigureCategory Local -Description 'Updated'

        Updates the description. All other fields are kept unchanged.

        .EXAMPLE
        Get-SfosWebFilterCategory -NameLike 'Custom-Local' | Set-SfosWebFilterCategory -ConfigureCategory Local -Domain 'example.org'

        Adds a domain to every matching local category.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterCategory
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
            # @() must wrap the whole if/else: a one-element array from a branch
            # unrolls to a scalar on assignment.
            $targetDomain = @(if ($PSBoundParameters.ContainsKey('Domain')) { $Domain } else { $existing[0].DomainList })
            $targetKeyword = @(if ($PSBoundParameters.ContainsKey('Keyword')) { $Keyword } else { $existing[0].KeywordList })

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
            $targetUrl = @(if ($PSBoundParameters.ContainsKey('Url')) { $Url } else { $existing[0].URLList })

            # URLList updates are append-only: sending fewer entries than currently
            # stored does not remove any of them.
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
        Removes a web filter category from a Sophos Firewall.

        .DESCRIPTION
        Deletes a web filter category by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission. Remove any web filter policy rule that still
        references the category first, or the firewall keeps the reference in place.

        .PARAMETER Name
        Required. Name of the web filter category to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter category objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter category name can be piped in by property name, for
        example the output of Get-SfosWebFilterCategory.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosWebFilterCategory -Name 'Custom-Local' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosWebFilterCategory -Name 'Custom-Local'

        Removes the web filter category. The cmdlet asks for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterCategory
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves user activity objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the user activity objects that are defined on the firewall. A user activity
        groups one or more categories - web categories, file types or URL groups - under a
        single name, for use in web filter policy rules. Use this cmdlet to review the
        existing objects or to feed them into another cmdlet through the pipeline. The
        cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        user activity objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per user activity, with the
        properties Name, Desc, NewName and CategoryList. Each CategoryList entry is a
        PSCustomObject with ID (the plain-text name of the referenced object) and Type.
        Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosUserActivity

        Lists every user activity on the firewall of the current connection.

        .EXAMPLE
        Get-SfosUserActivity -NameLike 'Search'

        Lists all user activities whose name contains 'Search'.

        .EXAMPLE
        Get-SfosUserActivity -NameLike 'Search' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosUserActivity

        .LINK
        Set-SfosUserActivity
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
        [object]$Session,

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
        Creates a user activity object on a Sophos Firewall.

        .DESCRIPTION
        Creates a user activity object that groups one or more categories - web
        categories, file types or URL groups - under a single name, for use in web filter
        policy rules. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the new user activity. 1 to 50 characters. The characters ^, ;,
        apostrophe, quote and backtick are not allowed.

        .PARAMETER Desc
        Optional. Free-text description of the user activity. Up to 255 characters.

        .PARAMETER CategoryList
        Required. One or more category entries. Each entry is a PSCustomObject with an ID
        property (the plain-text name of the referenced object) and a Type property, for
        example @{ID='Search Engines';Type='web category'}. Type is 'web category', 'file
        type' or 'url group'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        user activity objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosUserActivity -Name 'Search-Activity' -CategoryList @([PSCustomObject]@{ID='Search Engines';Type='web category'}) -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosUserActivity -Name 'Search-Activity' -Desc 'Search engine traffic' -CategoryList @([PSCustomObject]@{ID='Search Engines';Type='web category'}, [PSCustomObject]@{ID='Image Search';Type='web category'})

        Creates a user activity grouping two web categories.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a user activity object on a Sophos Firewall.

        .DESCRIPTION
        Changes the name, description or category list of an existing user activity. The
        cmdlet reads the current object first and sends it back complete, so a field you do
        not pass keeps its current value. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER Name
        Required. Name of the user activity to update.

        .PARAMETER NewName
        Optional. New name for the object. If omitted, the current name is kept.

        .PARAMETER Desc
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER CategoryList
        Optional. Category entries to store, replacing the current list (see
        New-SfosUserActivity for the entry format). If omitted, the current list is kept.
        The firewall does not accept an empty category list.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        user activity objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The user activity name and other fields can be piped in by property
        name, for example the output of Get-SfosUserActivity.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosUserActivity -Name 'Search-Activity' -Desc 'Updated' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosUserActivity -Name 'Search-Activity' -Desc 'Updated'

        Updates the description. The category list is kept unchanged.

        .EXAMPLE
        Set-SfosUserActivity -Name 'Search-Activity' -NewName 'Search-Activity-Renamed'

        Renames the object.

        .EXAMPLE
        Get-SfosUserActivity -NameLike 'Search-Activity' | Set-SfosUserActivity -Desc 'Updated via pipeline'

        Updates every matching user activity with a new description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserActivity
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

        # An update without <NewName> is answered with HTTP 200 / status 200
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
        Removes a user activity object from a Sophos Firewall.

        .DESCRIPTION
        Deletes a user activity object by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission. Remove any web filter policy rule that still
        references the object first, or the firewall keeps the reference in place.

        .PARAMETER Name
        Required. Name of the user activity to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        user activity objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The user activity name can be piped in by property name, for example
        the output of Get-SfosUserActivity.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosUserActivity -Name 'Search-Activity' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosUserActivity -Name 'Search-Activity'

        Removes the user activity object. The cmdlet asks for confirmation before it writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserActivity
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Adds categories to an existing user activity object on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more categories to a user activity without removing the ones already
        stored. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the user activity to change.

        .PARAMETER Members
        Required. One or more category entries to add. Each entry is a PSCustomObject with
        an ID property (the plain-text name of the referenced object) and a Type property,
        for example @{ID='Search Engines';Type='web category'}. An entry that is already
        present, matched on ID and Type, is left unchanged.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        user activity objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosUserActivityMember -Name 'Search-Activity' -Members @([PSCustomObject]@{ID='Search Engines';Type='web category'}) -WhatIf

        Shows what the call would add without sending it to the firewall.

        .EXAMPLE
        Add-SfosUserActivityMember -Name 'Search-Activity' -Members @([PSCustomObject]@{ID='Search Engines';Type='web category'})

        Adds a web category to the user activity.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserActivity

        .LINK
        Remove-SfosUserActivityMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes categories from an existing user activity object on a Sophos Firewall.

        .DESCRIPTION
        Removes one or more categories from a user activity, keeping the remaining
        entries. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the user activity to change.

        .PARAMETER Members
        Required. One or more category entries to remove. Each entry is a PSCustomObject
        with an ID property and a Type property matching an existing entry, for example
        @{ID='Search Engines';Type='web category'}. An entry that is not present is
        ignored.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        user activity objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosUserActivityMember -Name 'Search-Activity' -Members @([PSCustomObject]@{ID='Search Engines';Type='web category'}) -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosUserActivityMember -Name 'Search-Activity' -Members @([PSCustomObject]@{ID='Search Engines';Type='web category'})

        Removes a web category from the user activity.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosUserActivity

        .LINK
        Add-SfosUserActivityMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves web filter exception objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the web filter exception objects that are defined on the firewall. A web
        filter exception lets matching traffic bypass one or more web filtering checks, for
        example HTTPS decryption or virus scanning. Use this cmdlet to review the existing
        objects or to feed them into another cmdlet through the pipeline. The cmdlet only
        reads; nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        Some exceptions are predefined by Sophos and marked with IsDefault. Check this
        property before changing objects in bulk.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter exception objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per web filter exception,
        with the properties Name, Desc, Enabled, HttpsDecrypt, VirusScan, PolicyCheck,
        ZeroDayProtection, CertValidation, EnableSrcIP, SourceIPAddress, EnableDstIP,
        DestinationIPAddress, EnableURLRegex, URLRegex, EnableWebCat, WebCategory and
        IsDefault. Returns System.Xml.XmlElement when -AsXml is used, and an empty array
        when no object matches.

        .EXAMPLE
        Get-SfosWebFilterException

        Lists every web filter exception on the firewall of the current connection.

        .EXAMPLE
        Get-SfosWebFilterException -NameLike 'Example'

        Lists all web filter exceptions whose name contains 'Example'.

        .EXAMPLE
        Get-SfosWebFilterException -NameLike 'Example' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterException

        .LINK
        Set-SfosWebFilterException
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
        [object]$Session,

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
        Creates a web filter exception on a Sophos Firewall.

        .DESCRIPTION
        Creates a web filter exception that lets matching traffic bypass one or more web
        filtering checks. At least one match criterion must be given, through
        -SourceIPAddress, -DestinationIPAddress, -URLRegex or -WebCategory. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the new exception. 1 to 60 characters. The characters ^, ;,
        apostrophe, quote and backslash are not allowed.

        .PARAMETER Desc
        Optional. Free-text description of the exception. Up to 250 characters.

        .PARAMETER Enabled
        Optional. Whether the exception is active. Valid values: on, off. Default: on.

        .PARAMETER HttpsDecrypt
        Optional. Whether HTTPS traffic matching this exception is decrypted. Valid
        values: on, off. If omitted, the firewall applies its own default.

        .PARAMETER VirusScan
        Optional. Whether matching traffic is still virus-scanned. Valid values: on, off.
        If omitted, the firewall applies its own default.

        .PARAMETER PolicyCheck
        Optional. Whether matching traffic still runs through policy checks. Valid values:
        on, off. If omitted, the firewall applies its own default.

        .PARAMETER ZeroDayProtection
        Optional. Whether Zero-day Protection still applies to matching traffic. Valid
        values: on, off. If omitted, the firewall applies its own default.

        .PARAMETER CertValidation
        Optional. Whether certificate validation still applies to matching traffic. Valid
        values: on, off. Default: on.

        .PARAMETER SourceIPAddress
        Optional. Source IP addresses or networks this exception matches.

        .PARAMETER DestinationIPAddress
        Optional. Destination IP addresses or networks this exception matches.

        .PARAMETER URLRegex
        Optional. URL regular expressions this exception matches.

        .PARAMETER WebCategory
        Optional. Web category names this exception matches.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter exception objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosWebFilterException -Name 'Example' -SourceIPAddress '10.0.1.0/24' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosWebFilterException -Name 'Example' -SourceIPAddress '10.0.1.0/24' -Desc 'Internal test range'

        Creates an exception that bypasses filtering for a source network.

        .EXAMPLE
        New-SfosWebFilterException -Name 'Example-Category' -WebCategory 'Business' -VirusScan on

        Creates an exception matching a web category, with virus scanning kept on.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $descEsc = ConvertTo-SfosXmlEscaped -Text $Desc

    # Ein Objekt ohne jedes Match-Kriterium wird von der API mit einem diagnosefreien
    # 501 (leeres <InvalidParams/>) abgelehnt. Clientseitig vorab pruefen, statt
    # einen nutzlosen Roundtrip zu machen.
    if (-not ($SourceIPAddress -or $DestinationIPAddress -or $URLRegex -or $WebCategory)) {
        throw "WebFilterException '$Name' needs at least one match criterion: -SourceIPAddress, -DestinationIPAddress, -URLRegex or -WebCategory. The Sophos API rejects an object with none of these with an undiagnostic 501 (empty <InvalidParams/>)."
    }

    # Die Enable*-Felder sind keine eigenen Parameter, sondern werden aus dem
    # Vorhandensein des jeweiligen Array-Parameters abgeleitet. So kann
    # der Aufrufer den Invalid-State "Enable*=yes ohne Daten" gar
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
        Updates a web filter exception on a Sophos Firewall.

        .DESCRIPTION
        Changes the name, checks or match criteria of an existing web filter exception.
        The cmdlet reads the current object first and sends it back complete, so a field
        you do not pass keeps its current value; pass a field explicitly, with an empty
        value if needed, to clear it. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly, and an account with write
        permission.

        Predefined exceptions are flagged IsDefault in the output of
        Get-SfosWebFilterException and can be changed like any other object. Check
        IsDefault before changing objects in bulk.

        .PARAMETER Name
        Required. Name of the web filter exception to update.

        .PARAMETER NewName
        Optional. New name for the object. 1 to 60 characters. The characters ^, ;,
        apostrophe, quote and backslash are not allowed. If omitted, the current name is
        kept.

        .PARAMETER Desc
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER Enabled
        Optional. Whether the exception is active, replacing the current value. Valid
        values: on, off. If omitted, the current value is kept.

        .PARAMETER HttpsDecrypt
        Optional. Whether HTTPS traffic matching this exception is decrypted, replacing the
        current value. Valid values: on, off. If omitted, the current value is kept.

        .PARAMETER VirusScan
        Optional. Whether matching traffic is still virus-scanned, replacing the current
        value. Valid values: on, off. If omitted, the current value is kept.

        .PARAMETER PolicyCheck
        Optional. Whether matching traffic still runs through policy checks, replacing the
        current value. Valid values: on, off. If omitted, the current value is kept.

        .PARAMETER ZeroDayProtection
        Optional. Whether Zero-day Protection still applies to matching traffic, replacing
        the current value. Valid values: on, off. If omitted, the current value is kept.

        .PARAMETER CertValidation
        Optional. Whether certificate validation still applies to matching traffic,
        replacing the current value. Valid values: on, off. If omitted, the current value
        is kept.

        .PARAMETER SourceIPAddress
        Optional. Source IP addresses or networks to store, replacing the current list. If
        omitted, the current list is kept.

        .PARAMETER DestinationIPAddress
        Optional. Destination IP addresses or networks to store, replacing the current
        list. If omitted, the current list is kept.

        .PARAMETER URLRegex
        Optional. URL regular expressions to store, replacing the current list. If omitted,
        the current list is kept.

        .PARAMETER WebCategory
        Optional. Web category names to store, replacing the current list. If omitted, the
        current list is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter exception objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter exception name and other fields can be piped in by
        property name, for example the output of Get-SfosWebFilterException.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterException -Name 'Example' -Desc 'Updated description' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterException -Name 'Example' -Desc 'Updated description'

        Updates the description. All other fields are kept unchanged.

        .EXAMPLE
        Set-SfosWebFilterException -Name 'Example' -NewName 'Example-Renamed'

        Renames the object.

        .EXAMPLE
        Get-SfosWebFilterException -NameLike 'Example' | Set-SfosWebFilterException -VirusScan on

        Turns virus scanning back on for every matching exception.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterException
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
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        # SFOS replaces the whole entity on update - anything not sent is cleared on the
        # firewall, including Desc and the DomainList entries. So read the current object
        # first and override only what the caller actually passed.
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
        # antwortet die API mit 501 und leerem <InvalidParams/>.
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
        # 501 (leeres <InvalidParams/>) abgelehnt. Clientseitig vorab pruefen, statt
        # einen nutzlosen Roundtrip zu machen - das gilt auch fuer ein Update, das die
        # letzte verbliebene Liste leert.
        if (-not ($targetSourceIPAddress -or $targetDestinationIPAddress -or $targetURLRegex -or $targetWebCategory)) {
            throw "WebFilterException '$Name' needs at least one match criterion: -SourceIPAddress, -DestinationIPAddress, -URLRegex or -WebCategory. The Sophos API rejects an object with none of these with an undiagnostic 501 (empty <InvalidParams/>)."
        }

        # Die Enable*-Felder sind keine eigenen Parameter, sondern werden aus dem
        # Vorhandensein der jeweiligen Zielliste abgeleitet. So kann der
        # Aufrufer den Invalid-State "Enable*=yes ohne Daten" gar nicht
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
        Removes a web filter exception from a Sophos Firewall.

        .DESCRIPTION
        Deletes a web filter exception by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        A predefined exception, flagged IsDefault in the output of
        Get-SfosWebFilterException, can be removed like any other object and is not
        recreated automatically. Check IsDefault before removing an object you did not
        create yourself.

        .PARAMETER Name
        Required. Name of the web filter exception to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter exception objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter exception name can be piped in by property name, for
        example the output of Get-SfosWebFilterException.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosWebFilterException -Name 'Example' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosWebFilterException -Name 'Example'

        Removes the web filter exception. The cmdlet asks for confirmation before it
        writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterException
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
# RuleList/Rule is reconstructed from the sample XML and a live GET, since the attribute
# table does not document it. SFOS replaces RuleList and every other field of the entity
# wholesale on <Set operation="update">; an element that is not sent is cleared, not left
# alone. Every write cmdlet below therefore funnels through
# ConvertTo-SfosWebFilterPolicyEntityXml with a fully resolved policy object, built either
# directly from bound parameters (New-*) or by reading the current object first and
# overriding only what the caller actually passed (Set-*, Add-/Remove-*Rule).
#
# WebFilterPolicy carries no IsDefault flag, unlike WebFilterException. A predefined policy
# such as 'Default Policy' can be overwritten by Set-/Remove-SfosWebFilterPolicy and by both
# rule cmdlets without any warning from the API.

<#
.SYNOPSIS
    Builds the <Category> XML for a single WebFilterPolicy rule category. Internal helper,
    not exported.

.DESCRIPTION
    Converts one category object (as produced by New-SfosWebFilterPolicyCategory or returned
    by Get-SfosWebFilterPolicy) into the <Category><ID>...</ID><type>...</type></Category>
    fragment SFOS expects inside a rule's <CategoryList>.

    The wire element is lowercase <type> - the same oddity as UserActivity's <type>
    child element. The object property stays PascalCase
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
    # the values are the literal words Allow/Deny. Not implemented.
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
        Retrieves web filter policy objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the web filter policy objects that are defined on the firewall. A web
        filter policy groups rules that decide how HTTP and HTTPS traffic is handled, and
        is applied to a firewall rule. Use this cmdlet to review the existing policies or
        to feed them into another cmdlet through the pipeline. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        Each returned RuleList entry has the same shape produced by
        New-SfosWebFilterPolicyRule, so a rule read back here can be reused directly with
        Add-SfosWebFilterPolicyRule or passed to Set-SfosWebFilterPolicy -Rule.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per web filter policy, with
        the properties Name, Description, DefaultAction, EnableReporting,
        DownloadFileSizeRestrictionEnabled, DownloadFileSizeRestriction,
        GoogAppDomainListEnabled, GoogAppDomainList, RuleList, EnforceSafeSearch,
        EnforceImageLicensing, YoutubeFilterEnabled, YoutubeFilterIsStrict, XFFEnabled,
        Office365Enabled, QuotaLimit, Office365TenantsList and Office365DirectoryId.
        RuleList is an array of rule objects, each with CategoryList, HTTPAction,
        HTTPSAction, FollowHTTPAction, Schedule, PolicyRuleEnabled, CCLRuleEnabled,
        ExceptionList, UserList and CCLList. Returns System.Xml.XmlElement when -AsXml is
        used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosWebFilterPolicy

        Lists every web filter policy on the firewall of the current connection.

        .EXAMPLE
        Get-SfosWebFilterPolicy -NameLike 'Basic'

        Lists all web filter policies whose name contains 'Basic'.

        .EXAMPLE
        Get-SfosWebFilterPolicy -NameLike 'Basic' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosWebFilterPolicy

        .LINK
        Set-SfosWebFilterPolicy
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
        [object]$Session,

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
        Creates a web filter policy on a Sophos Firewall.

        .DESCRIPTION
        Creates a web filter policy that controls how HTTP and HTTPS traffic is categorized
        and actioned, by web category, URL group, user activity or file type. Rules can be
        supplied at creation time with -Rule, built with New-SfosWebFilterPolicyRule, or
        added afterwards with Add-SfosWebFilterPolicyRule. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER Name
        Required. Name of the new web filter policy. 1 to 50 characters, no comma.

        .PARAMETER Description
        Optional. Free-text description of the policy. Up to 255 characters.

        .PARAMETER DefaultAction
        Required. Action applied when no rule matches. Valid values: Allow, Deny.

        .PARAMETER EnableReporting
        Optional. Whether this policy's traffic is included in reporting. Valid values:
        Enable, Disable.

        .PARAMETER DownloadFileSizeRestrictionEnabled
        Optional. Whether the download file size restriction is active. Valid values: 0, 1.

        .PARAMETER DownloadFileSizeRestriction
        Required. Maximum download size in MB. 0 to 1536.

        .PARAMETER GoogAppDomainListEnabled
        Optional. Whether the Google Apps domain restriction is active. Valid values: 0, 1.

        .PARAMETER GoogAppDomainList
        Optional. Comma-separated list of allowed Google Apps domains. Up to 256
        characters.

        .PARAMETER Rule
        Optional. Rule objects, in the order they should be evaluated by the firewall.
        Build each entry with New-SfosWebFilterPolicyRule.

        .PARAMETER EnforceSafeSearch
        Optional. Whether SafeSearch is enforced on supported search engines. Valid
        values: 0, 1.

        .PARAMETER EnforceImageLicensing
        Optional. Whether the Google image licensing filter is enforced. Valid values: 0,
        1.

        .PARAMETER YoutubeFilterEnabled
        Optional. Whether the YouTube filter is active. Valid values: 0, 1.

        .PARAMETER YoutubeFilterIsStrict
        Optional. Whether the YouTube filter uses strict mode. Valid values: 0, 1.

        .PARAMETER XFFEnabled
        Optional. Whether the X-Forwarded-For header is honored when this policy is
        applied. Valid values: 0, 1.

        .PARAMETER Office365Enabled
        Optional. Whether Office 365 tenant restriction is active for this policy. Valid
        values: 0, 1.

        .PARAMETER QuotaLimit
        Optional. Quota time limit in minutes for Quota-actioned rules. 1 to 1440.

        .PARAMETER Office365TenantsList
        Optional. Allowed Office 365 tenant identifiers for this policy.

        .PARAMETER Office365DirectoryId
        Optional. Office 365 directory ID used for tenant restriction.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosWebFilterPolicy -Name 'Basic-Policy' -DefaultAction Allow -DownloadFileSizeRestriction 0 -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosWebFilterPolicy -Name 'Basic-Policy' -DefaultAction Allow -DownloadFileSizeRestriction 0

        Creates a policy with no rules yet. Add rules afterwards with
        Add-SfosWebFilterPolicyRule.

        .EXAMPLE
        $category = New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        New-SfosWebFilterPolicy -Name 'Block-Extreme' -DefaultAction Allow -DownloadFileSizeRestriction 100 -Rule $rule

        Creates a policy with one rule built from the two builder cmdlets.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a web filter policy on a Sophos Firewall.

        .DESCRIPTION
        Changes the settings or rule list of an existing web filter policy. The cmdlet
        reads the current object first and sends it back complete, so a field you do not
        pass keeps its current value; pass a field explicitly, with an empty value if
        needed, to clear it. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with write permission.

        Predefined policies, such as 'Default Policy', are not flagged and can be
        overwritten like any other object, including their rule list. Confirm the name
        before running this against a policy you did not create yourself.

        .PARAMETER Name
        Required. Name of the web filter policy to update.

        .PARAMETER Description
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER DefaultAction
        Optional. Action applied when no rule matches, replacing the current value. Valid
        values: Allow, Deny. If omitted, the current value is kept.

        .PARAMETER EnableReporting
        Optional. Whether this policy's traffic is included in reporting, replacing the
        current value. Valid values: Enable, Disable. If omitted, the current value is
        kept.

        .PARAMETER DownloadFileSizeRestrictionEnabled
        Optional. Whether the download file size restriction is active, replacing the
        current value. Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER DownloadFileSizeRestriction
        Optional. Maximum download size in MB, replacing the current value. 0 to 1536. If
        omitted, the current value is kept.

        .PARAMETER GoogAppDomainListEnabled
        Optional. Whether the Google Apps domain restriction is active, replacing the
        current value. Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER GoogAppDomainList
        Optional. Comma-separated list of allowed Google Apps domains, replacing the
        current value. Up to 256 characters. If omitted, the current value is kept.

        .PARAMETER Rule
        Optional. Complete rule list, in the order the firewall should evaluate them,
        replacing the current list entirely. If omitted, the current rules are kept. To
        add or remove a single rule without touching the rest, use
        Add-SfosWebFilterPolicyRule or Remove-SfosWebFilterPolicyRule instead.

        .PARAMETER EnforceSafeSearch
        Optional. Whether SafeSearch is enforced on supported search engines, replacing
        the current value. Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER EnforceImageLicensing
        Optional. Whether the Google image licensing filter is enforced, replacing the
        current value. Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER YoutubeFilterEnabled
        Optional. Whether the YouTube filter is active, replacing the current value.
        Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER YoutubeFilterIsStrict
        Optional. Whether the YouTube filter uses strict mode, replacing the current
        value. Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER XFFEnabled
        Optional. Whether the X-Forwarded-For header is honored, replacing the current
        value. Valid values: 0, 1. If omitted, the current value is kept.

        .PARAMETER Office365Enabled
        Optional. Whether Office 365 tenant restriction is active for this policy,
        replacing the current value. Valid values: 0, 1. If omitted, the current value is
        kept.

        .PARAMETER QuotaLimit
        Optional. Quota time limit in minutes for Quota-actioned rules, replacing the
        current value. 1 to 1440. If omitted, the current value is kept.

        .PARAMETER Office365TenantsList
        Optional. Allowed Office 365 tenant identifiers for this policy, replacing the
        current value. If omitted, the current value is kept.

        .PARAMETER Office365DirectoryId
        Optional. Office 365 directory ID used for tenant restriction, replacing the
        current value. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter policy name and other fields can be piped in by
        property name, for example the output of Get-SfosWebFilterPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterPolicy -Name 'Basic-Policy' -DefaultAction Deny -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterPolicy -Name 'Basic-Policy' -DefaultAction Deny

        Changes the default action. Every other field, including the rule list, is kept
        unchanged.

        .EXAMPLE
        Get-SfosWebFilterPolicy -NameLike 'Basic-Policy' | Set-SfosWebFilterPolicy -Description 'Updated'

        Updates every matching policy with a new description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterPolicy
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a web filter policy from a Sophos Firewall.

        .DESCRIPTION
        Deletes a web filter policy by name. Predefined policies, such as 'Default
        Policy', are not flagged and are removed like any other object, together with
        their rule list; confirm the name before removing a policy you did not create
        yourself. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission. Remove any
        firewall rule that still references the policy first, or the firewall keeps the
        reference in place.

        .PARAMETER Name
        Required. Name of the web filter policy to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter policy name can be piped in by property name, for
        example the output of Get-SfosWebFilterPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosWebFilterPolicy -Name 'Basic-Policy' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosWebFilterPolicy -NameLike 'Basic' | Remove-SfosWebFilterPolicy

        Removes every web filter policy whose name contains 'Basic'. The cmdlet asks for
        confirmation before each write.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterPolicy
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Builds a category reference for use inside a web filter policy rule.

        .DESCRIPTION
        Creates the small object that New-SfosWebFilterPolicyRule expects for its
        -Category parameter. This cmdlet does not contact the firewall; it only builds an
        in-memory object.

        .PARAMETER ID
        Required. Plain-text name of the referenced object - a web category, URL group,
        user activity, dynamic category or file type name, matching -Type. Look the exact
        spelling up with Get-SfosWebFilterCategory, Get-SfosWebFilterURLGroup,
        Get-SfosUserActivity or Get-SfosFileType.

        .PARAMETER Type
        Required. Kind of object -ID refers to. Valid values: WebCategory, URLGroup,
        UserActivity, DynamicCategory, FileType.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with ID and Type
        properties.

        .EXAMPLE
        New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory

        Builds a reference to the predefined 'Extreme' web category.

        .EXAMPLE
        $category = New-SfosWebFilterPolicyCategory -ID 'Weapons' -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        New-SfosWebFilterPolicy -Name 'Block-Weapons' -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

        Builds a category reference and feeds it into a rule and a new policy.

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
        Builds a rule for use inside a web filter policy's rule list.

        .DESCRIPTION
        Creates the object that New-SfosWebFilterPolicy -Rule, Set-SfosWebFilterPolicy
        -Rule and Add-SfosWebFilterPolicyRule expect. This cmdlet does not contact the
        firewall; the rule only becomes part of a policy once handed to one of those
        cmdlets. The firewall evaluates rules in the order they are stored, so build them
        in the order they must apply.

        To change one field of an existing rule without resetting the rest, pipe the rule
        in through -InputObject and pass only the field you want to change; every
        parameter you do not pass then keeps the value from -InputObject instead of
        falling back to its default.

        .PARAMETER InputObject
        Optional. An existing rule to use as the base, as returned in the RuleList
        property of Get-SfosWebFilterPolicy. Only the parameters you pass explicitly
        override its values.

        .PARAMETER Category
        Required unless -InputObject is supplied. One or more category objects built
        with New-SfosWebFilterPolicyCategory.

        .PARAMETER HTTPAction
        Optional. Action for HTTP traffic matching this rule's categories. Valid values:
        Deny, Allow, Warn, Quota. Default: Deny.

        .PARAMETER HTTPSAction
        Optional. Action for HTTPS traffic matching this rule's categories. Valid values:
        Deny, Allow, Warn, Quota. Default: Deny.

        .PARAMETER FollowHTTPAction
        Optional. Whether HTTPSAction follows HTTPAction. Valid values: 0, 1. Default: 0.

        .PARAMETER Schedule
        Optional. Name of the schedule object this rule is active during. Default: 'All
        The Time'.

        .PARAMETER PolicyRuleEnabled
        Optional. Whether this rule is active. Valid values: 0, 1. Default: 1.

        .PARAMETER CCLRuleEnabled
        Optional. Whether the Cloud Application Control List is active for this rule.
        Valid values: 0, 1. Default: 0.

        .PARAMETER ExceptionFileType
        Optional. File type category names excluded from this rule.

        .PARAMETER User
        Optional. User names this rule additionally applies to.

        .PARAMETER CCL
        Optional. Cloud Application Control List entries for this rule.

        .INPUTS
        System.Management.Automation.PSCustomObject. A rule object can be piped in as
        -InputObject, for example a RuleList entry from Get-SfosWebFilterPolicy.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with CategoryList,
        HTTPAction, HTTPSAction, FollowHTTPAction, Schedule, PolicyRuleEnabled,
        CCLRuleEnabled, ExceptionList, UserList and CCLList properties, matching the shape
        Get-SfosWebFilterPolicy returns for each RuleList entry.

        .EXAMPLE
        $category = New-SfosWebFilterPolicyCategory -ID 'Extreme' -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        New-SfosWebFilterPolicy -Name 'Block-Extreme' -DefaultAction Allow -DownloadFileSizeRestriction 0 -Rule $rule

        Denies HTTP and HTTPS traffic in the 'Extreme' category, all the time.

        .EXAMPLE
        $category = New-SfosWebFilterPolicyCategory -ID 'Blocked-Sites' -Type URLGroup
        New-SfosWebFilterPolicyRule -Category $category -HTTPAction Warn -HTTPSAction Warn -Schedule 'Work hours'

        Warns on a URL group during business hours only.

        .EXAMPLE
        $policy = Get-SfosWebFilterPolicy -NameLike 'Block-Extreme'
        $edited = $policy.RuleList[0] | New-SfosWebFilterPolicyRule -HTTPAction Allow
        Set-SfosWebFilterPolicy -Name 'Block-Extreme' -Rule (@($edited) + @($policy.RuleList[1..($policy.RuleList.Count - 1)]))

        Changes the action of the first rule while keeping every other field and every
        other rule unchanged.

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
        # Same reasoning as New-SfosFirewallRuleNetworkPolicy.
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
        Appends a rule to the end of an existing web filter policy's rule list.

        .DESCRIPTION
        Reads the current web filter policy, appends the supplied rule after the existing
        ones, and writes the whole entity back, preserving the existing rules and their
        order. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission.

        Predefined policies, such as 'Default Policy', are not flagged and accept an
        appended rule like any other object; confirm the name before running this against
        a policy you did not create yourself.

        .PARAMETER Name
        Required. Name of the web filter policy to change.

        .PARAMETER Rule
        Required. Rule object to append, built with New-SfosWebFilterPolicyRule.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter policy name can be piped in by property name, for
        example the output of Get-SfosWebFilterPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        $category = New-SfosWebFilterPolicyCategory -ID 'Weapons' -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        Add-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Rule $rule -WhatIf

        Shows what the call would add without sending it to the firewall.

        .EXAMPLE
        $category = New-SfosWebFilterPolicyCategory -ID 'Weapons' -Type WebCategory
        $rule = New-SfosWebFilterPolicyRule -Category $category -HTTPAction Deny -HTTPSAction Deny
        Add-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Rule $rule

        Adds a rule blocking the 'Weapons' category to an existing policy.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a single rule from an existing web filter policy's rule list by index.

        .DESCRIPTION
        Reads the current web filter policy, drops the rule at the given zero-based index
        from its rule list, and writes the whole entity back, preserving the remaining
        rules and their order. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with write permission.

        Predefined policies, such as 'Default Policy', are not flagged and lose a rule
        like any other object; confirm the name before running this against a policy you
        did not create yourself.

        .PARAMETER Name
        Required. Name of the web filter policy to change.

        .PARAMETER Index
        Required. Zero-based position of the rule to remove within the policy's rule list,
        in the order returned by Get-SfosWebFilterPolicy. The cmdlet throws if the index
        is out of range.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The web filter policy name can be piped in by property name, for
        example the output of Get-SfosWebFilterPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Index 0 -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosWebFilterPolicyRule -Name 'Basic-Policy' -Index 0

        Removes the first rule of the policy.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves surfing quota policy objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the surfing quota policy objects that are defined on the firewall. A
        surfing quota policy limits browsing time and is either Cyclic, a recurring hour
        budget per day, week, month or year, or NonCyclic, a one-off validity window with a
        total hour budget. The firewall returns only the fields that match the policy's
        cycle type. Use this cmdlet to review the existing objects or to feed them into
        another cmdlet through the pipeline. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        You can combine several filters. The firewall itself evaluates at most one of them,
        so every filter you supply is applied again on the client. The result therefore
        always matches all filters you gave.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is
        a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text anywhere.
        Applied on the client. If omitted, the description is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        surfing quota policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per surfing quota policy,
        with the properties Name, CycleType, CycleHours, CycleMinutes, PerDay, Validity,
        MaximumHours, Minutes and Description. Returns System.Xml.XmlElement when -AsXml is
        used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosSurfingQuotaPolicy

        Lists every surfing quota policy on the firewall of the current connection.

        .EXAMPLE
        Get-SfosSurfingQuotaPolicy -NameLike 'Daily'

        Lists all surfing quota policies whose name contains 'Daily'.

        .EXAMPLE
        Get-SfosSurfingQuotaPolicy -NameLike 'Daily' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosSurfingQuotaPolicy

        .LINK
        Set-SfosSurfingQuotaPolicy
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
        [object]$Session,

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
        Creates a surfing quota policy on a Sophos Firewall.

        .DESCRIPTION
        Creates a surfing quota policy, which limits the internet browsing time allowed
        for a user. A policy is either Cyclic, a recurring hour budget per day, week,
        month or year, set with -CycleHours, -CycleMinutes and -PerDay, or NonCyclic, a
        one-off validity window with a total hour budget, set with -Validity,
        -MaximumHours and -Minutes. -CycleType selects which of the two field groups
        applies. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission.

        .PARAMETER Name
        Required. Name of the new policy. 1 to 60 characters, no comma.

        .PARAMETER CycleType
        Required. Selects which of the type-specific parameters below apply. Valid
        values: Cyclic, NonCyclic.

        .PARAMETER CycleHours
        Required when -CycleType is Cyclic. Upper limit of surfing hours per cycle.

        .PARAMETER CycleMinutes
        Required when -CycleType is Cyclic. Upper limit of surfing minutes per cycle, 0
        to 9999.

        .PARAMETER PerDay
        Required when -CycleType is Cyclic. Cycle recurrence. Valid values: Days, Weekly,
        Monthly, Yearly.

        .PARAMETER Validity
        Required when -CycleType is NonCyclic. Total number of surfing days allowed, or
        'Unlimited' for no restriction.

        .PARAMETER MaximumHours
        Required when -CycleType is NonCyclic. Total surfing hours allowed, or
        'Unlimited' for no restriction.

        .PARAMETER Minutes
        Optional, applies when -CycleType is NonCyclic. Additional surfing minutes
        allowed on top of -MaximumHours. 0 to 59.

        .PARAMETER Description
        Optional. Free-text description of the policy. Up to 255 characters.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        surfing quota policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -CycleType Cyclic -CycleHours 2 -CycleMinutes 30 -PerDay Days -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -CycleType Cyclic -CycleHours 2 -CycleMinutes 30 -PerDay Days

        Creates a Cyclic policy allowing 2 hours 30 minutes per day.

        .EXAMPLE
        New-SfosSurfingQuotaPolicy -Name 'Monthly-Quota' -CycleType NonCyclic -Validity 30 -MaximumHours 100 -Description 'One-off quota'

        Creates a NonCyclic policy allowing 100 hours over 30 days.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSurfingQuotaPolicy

        .LINK
        Set-SfosSurfingQuotaPolicy
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a surfing quota policy on a Sophos Firewall.

        .DESCRIPTION
        Changes the cycle settings or description of an existing surfing quota policy. The
        cmdlet reads the current object first and sends it back complete, so a field you do
        not pass keeps its current value. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        If -CycleType changes the policy from Cyclic to NonCyclic or back, the fields that
        belong to the new type must be supplied; the firewall does not carry values over
        from the previous type.

        .PARAMETER Name
        Required. Name of the surfing quota policy to update.

        .PARAMETER CycleType
        Required. Selects which of the type-specific parameters below apply. Valid
        values: Cyclic, NonCyclic.

        .PARAMETER CycleHours
        Optional, applies when -CycleType is Cyclic. Upper limit of surfing hours per
        cycle, replacing the current value. If omitted, the current value is kept.

        .PARAMETER CycleMinutes
        Optional, applies when -CycleType is Cyclic. Upper limit of surfing minutes per
        cycle, 0 to 9999, replacing the current value. If omitted, the current value is
        kept.

        .PARAMETER PerDay
        Optional, applies when -CycleType is Cyclic. Cycle recurrence, replacing the
        current value. Valid values: Days, Weekly, Monthly, Yearly. If omitted, the
        current value is kept.

        .PARAMETER Validity
        Optional, applies when -CycleType is NonCyclic. Total number of surfing days
        allowed, or 'Unlimited', replacing the current value. If omitted, the current
        value is kept.

        .PARAMETER MaximumHours
        Optional, applies when -CycleType is NonCyclic. Total surfing hours allowed, or
        'Unlimited', replacing the current value. If omitted, the current value is kept.

        .PARAMETER Minutes
        Optional, applies when -CycleType is NonCyclic. Additional surfing minutes
        allowed, 0 to 59, replacing the current value. If omitted, the current value is
        kept.

        .PARAMETER Description
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        surfing quota policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The surfing quota policy name and other fields can be piped in by
        property name, for example the output of Get-SfosSurfingQuotaPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -CycleType Cyclic -CycleHours 3 -CycleMinutes 0 -PerDay Days -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -CycleType Cyclic -CycleHours 3 -CycleMinutes 0 -PerDay Days

        Changes the cycle budget of the policy.

        .EXAMPLE
        Get-SfosSurfingQuotaPolicy -NameLike 'Quota' | Set-SfosSurfingQuotaPolicy -CycleType Cyclic -Description 'Revised policy'

        Updates every matching Cyclic policy with a new description.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSurfingQuotaPolicy
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        # instead, against a single parameter set.
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
        Removes a surfing quota policy from a Sophos Firewall.

        .DESCRIPTION
        Deletes a surfing quota policy by name. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission. Remove any user or user group reference to the
        policy first, or the firewall keeps the reference in place.

        .PARAMETER Name
        Required. Name of the surfing quota policy to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        surfing quota policy objects. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The surfing quota policy name can be piped in by property name, for
        example the output of Get-SfosSurfingQuotaPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosSurfingQuotaPolicy -Name 'Daily-Quota' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosSurfingQuotaPolicy -NameLike 'Quota' | Remove-SfosSurfingQuotaPolicy

        Removes every surfing quota policy whose name contains 'Quota'. The cmdlet asks
        for confirmation before each write.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosSurfingQuotaPolicy
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Returns the content condition list objects that are defined on the firewall. A
        content condition list is a named set of regular expressions that other web
        filter rules can reference by content match. Use this cmdlet to review the
        existing objects or to feed them into another cmdlet through the pipeline. The
        cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        A content condition list is identified by Key, not by Name; Set-* and Remove-*
        for this entity address the object by Key. Only Key is sent to the firewall as a
        server-side filter; -NameLike and -DescriptionLike are always applied on the
        client.

        .PARAMETER KeyLike
        Optional. Returns only objects whose key contains the given text anywhere. This
        is a substring match, not a wildcard pattern. If omitted, the key is not used to
        filter.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere.
        Applied on the client. If omitted, the name is not used to filter.

        .PARAMETER DescriptionLike
        Optional. Returns only objects whose description contains the given text
        anywhere. Applied on the client. If omitted, the description is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        content condition list objects. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per content condition
        list, with the properties Name, Key, Description and ContentList. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosContentConditionList

        Lists every content condition list on the firewall of the current connection.

        .EXAMPLE
        Get-SfosContentConditionList -KeyLike 'Quota'

        Lists all content condition lists whose key contains 'Quota'.

        .EXAMPLE
        Get-SfosContentConditionList -KeyLike 'Quota' -AsXml

        Returns the raw XML of the matching objects, for example to check a field that the
        standard output does not contain.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosContentConditionList

        .LINK
        Set-SfosContentConditionList
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
        [object]$Session,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Only Key is sent server-side. A Filter on Name fails outright for this entity, so
    # NameLike is never sent to the firewall.
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
        Creates a content condition list on a Sophos Firewall.

        .DESCRIPTION
        Creates a content condition list, a named set of regular expressions that other
        web filter rules can reference by content match. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        This cmdlet has no -Key parameter. The firewall derives the Key itself from the
        name and does not accept a supplied one. Read the actual Key back with
        Get-SfosContentConditionList after creating the object; Set-SfosContentConditionList
        and Remove-SfosContentConditionList address the object by that Key, not by Name.

        .PARAMETER Name
        Required. Name of the new content condition list. 1 to 255 characters, no comma.

        .PARAMETER Description
        Optional. Free-text description of the list. Up to 255 characters.

        .PARAMETER ContentStrings
        Optional. Regular expressions to include. Duplicate values are kept as given.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        content condition list objects. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        create.

        .EXAMPLE
        New-SfosContentConditionList -Name 'Sensitive-Terms' -ContentStrings 'foo','bar' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosContentConditionList -Name 'Sensitive-Terms' -ContentStrings 'foo','bar' -Description 'Test list'

        Creates a list with two regular expressions.

        .EXAMPLE
        New-SfosContentConditionList -Name 'Blocked-Terms'
        Add-SfosContentConditionListMember -Key (Get-SfosContentConditionList -NameLike 'Blocked-Terms').Key -ContentStrings 'baz'

        Creates an empty list and adds a member afterwards, using the Key the firewall
        assigned.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a content condition list on a Sophos Firewall.

        .DESCRIPTION
        Changes the name, description or content strings of an existing content
        condition list. The object is addressed by -Key, the value Get-SfosContentConditionList
        returns and New-SfosContentConditionList assigns on creation, not by Name. The
        cmdlet reads the current object first and sends it back complete, so a field you
        do not pass keeps its current value. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER Key
        Required. Key of the content condition list to update, as returned by
        Get-SfosContentConditionList.

        .PARAMETER Name
        Optional. New display name for the object. If omitted, the current name is kept.

        .PARAMETER ContentStrings
        Optional. Regular expressions to store, replacing the current list. If omitted,
        the current list is kept.

        .PARAMETER Description
        Optional. Description to store, replacing the current one. If omitted, the current
        description is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        content condition list objects. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The Key and other fields can be piped in by property name, for
        example the output of Get-SfosContentConditionList.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosContentConditionList -Key 'SensitiveTerms_Custom' -Description 'Updated list' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosContentConditionList -Key 'SensitiveTerms_Custom' -Description 'Updated list'

        Updates the description. The content strings are kept unchanged.

        .EXAMPLE
        Get-SfosContentConditionList -KeyLike 'Quota' | Set-SfosContentConditionList -ContentStrings 'foo','bar','baz'

        Replaces the content strings of every matching list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosContentConditionList
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Deletes a content condition list by Key, the value Get-SfosContentConditionList
        returns and New-SfosContentConditionList assigns on creation, not by Name. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission.

        .PARAMETER Key
        Required. Key of the content condition list to remove, as returned by
        Get-SfosContentConditionList.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        content condition list objects. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        System.String. The Key can be piped in by property name, for example the output of
        Get-SfosContentConditionList.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal.

        .EXAMPLE
        Remove-SfosContentConditionList -Key 'SensitiveTerms_Custom' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Get-SfosContentConditionList -KeyLike 'Quota' | Remove-SfosContentConditionList

        Removes every content condition list whose key contains 'Quota'. The cmdlet asks
        for confirmation before each write.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosContentConditionList
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Adds content strings to an existing content condition list on a Sophos Firewall.

        .DESCRIPTION
        Adds one or more regular expressions to a content condition list without removing
        the ones already stored. Duplicate values are kept as given. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission.

        .PARAMETER Key
        Required. Key of the content condition list to change, as returned by
        Get-SfosContentConditionList.

        .PARAMETER ContentStrings
        Required. One or more regular expressions to add.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        content condition list objects. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Add-SfosContentConditionListMember -Key 'SensitiveTerms_Custom' -ContentStrings 'foo' -WhatIf

        Shows what the call would add without sending it to the firewall.

        .EXAMPLE
        Add-SfosContentConditionListMember -Key 'SensitiveTerms_Custom' -ContentStrings 'foo','bar'

        Adds two regular expressions to the list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosContentConditionList

        .LINK
        Remove-SfosContentConditionListMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes content strings from an existing content condition list on a Sophos
        Firewall.

        .DESCRIPTION
        Removes one or more regular expressions from a content condition list, keeping
        the remaining entries. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with write
        permission.

        .PARAMETER Key
        Required. Key of the content condition list to change, as returned by
        Get-SfosContentConditionList.

        .PARAMETER ContentStrings
        Required. One or more regular expressions to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        content condition list objects. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Remove-SfosContentConditionListMember -Key 'SensitiveTerms_Custom' -ContentStrings 'foo' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosContentConditionListMember -Key 'SensitiveTerms_Custom' -ContentStrings 'foo','bar'

        Removes two regular expressions from the list.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosContentConditionList

        .LINK
        Add-SfosContentConditionListMember
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
# them, unlike every other entity in this module family.
#
# A partial <Set operation="update"> that omits a field can reset it rather than leaving it
# unchanged, even though the request answers success. Every Set-* cmdlet in this fragment
# therefore follows the same read-modify-write pattern as the object entities elsewhere in
# this module family: call the matching Get-* first, resolve each field to the caller's
# explicit value (via $PSBoundParameters.ContainsKey()) or otherwise the value just read
# back, and always send the complete entity. This costs one extra GET per Set, but covers
# every field regardless of which one triggers the reset.
#
# Security-relevant fields (PharmingProtection, AllowInvalidCertificate, DenyUnknownProtocol,
# Scanning, BlockUnscannableContent) additionally have no cmdlet default: with the
# read-modify-write pattern above this is what keeps a call that only wants to set one
# unrelated field from ever inventing a value for these - the value sent is always either the
# caller's explicit input or the value already on the firewall, never a cmdlet default.

#region MalwareProtection

<#
        .SYNOPSIS
        Retrieves the malware protection settings of a Sophos Firewall.

        .DESCRIPTION
        Returns the malware protection settings singleton. There is exactly one instance
        of this object per firewall. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        malware protection settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with the property
        PrimaryAntiVirusEngine. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosMalwareProtection

        Returns the current malware protection settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosMalwareProtection
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
        [object]$Session,

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
        Updates the malware protection settings of a Sophos Firewall.

        .DESCRIPTION
        Changes the primary anti-virus engine. The cmdlet reads the current settings
        first and sends them back complete, so a field you do not pass keeps its current
        value. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission.

        .PARAMETER PrimaryAntiVirusEngine
        Optional. Name of the primary anti-virus engine to use. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        malware protection settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosMalwareProtection -PrimaryAntiVirusEngine 'Sophos' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosMalwareProtection -PrimaryAntiVirusEngine 'Sophos'

        Switches the primary anti-virus engine.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosMalwareProtection
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Retrieves the web filter settings of a Sophos Firewall.

        .DESCRIPTION
        Returns the web filter settings singleton. There is exactly one instance of this
        object per firewall. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        TopImageFile and BottomImageFile (the top/bottom images of the block/warn page) can
        be uploaded with Set-SfosWebFilterSettings, but the firewall never returns them: this
        cmdlet's output has no TopImageFile or BottomImageFile property, so an uploaded image
        cannot be read back or verified through the API.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter settings. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with the properties
        WebCaching, Scanning, BlockUnscannableContent, PharmingProtection,
        OverrideDefaultWarnedMessage, DefaultWarnedMessage, OverrideDefaultDeniedMessage,
        DefaultDeniedMessage, DeniedMessageImage, DefaultFiletypeDeniedMessage,
        DefaultFiletypeWarnedMessage, OverrideDefaultOverrideMessage,
        DefaultOverrideMessage, OverrideDefaultQuotaMessage, DefaultQuotaMessage and
        PUAWhitelist. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosWebFilterSettings

        Returns the current web filter settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosWebFilterSettings
#>
function Get-SfosWebFilterSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterSettings>, a singleton
    # holding one configuration, and it has no <WebFilterSetting> child. The Sophos spelling
    # goes above PowerShell habit here; the singular concession is reserved
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
        [object]$Session,

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

    # The firewall omits elements that are at their disabled/empty state (for example
    # DefaultWarnedMessage, DefaultDeniedMessage, the filetype/override/quota message pair
    # and PUAWhitelist) instead of returning them empty. Casting a missing property to
    # [string] yields '' and an absent PUAWhitelist yields @(), so every field below still
    # has a value to read back for the read-modify-write in Set-*.
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
        Updates the web filter settings of a Sophos Firewall.

        .DESCRIPTION
        Changes scanning, message and whitelist settings of the web filter. The cmdlet
        reads the current settings first and sends them back complete, so a field you do
        not pass keeps its current value. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        TopImageFile and BottomImageFile upload the top/bottom image of the block/warn page
        alongside the request, using the multipart transport of SophosFirewall.Core
        (Invoke-SfosApi -MultipartFile). The Sophos API accepts jpg/jpeg only. These two
        fields are write-only: Get-SfosWebFilterSettings never returns them, so this cmdlet
        cannot read back or preserve a previously uploaded image, and there is no way to
        verify through the API that an upload took effect. Passing neither parameter leaves
        both image fields out of the request entirely; whether that clears a previously set
        image on the firewall is unmeasured, because there is no read path to check it with.

        .PARAMETER WebCaching
        Optional. Whether web caching is active, for example Enable or Disable,
        replacing the current value. If omitted, the current value is kept.

        .PARAMETER Scanning
        Optional. Anti-virus scanning mode, replacing the current value. If omitted, the
        current value is kept.

        .PARAMETER BlockUnscannableContent
        Optional. How content that cannot be scanned is handled, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER PharmingProtection
        Optional. Whether pharming protection is active, for example Enable or Disable,
        replacing the current value. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultWarnedMessage
        Optional. Whether the custom warned-page message is active, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER DefaultWarnedMessage
        Optional. Custom warned-page message text or HTML, replacing the current value.
        If omitted, the current value is kept.

        .PARAMETER OverrideDefaultDeniedMessage
        Optional. Whether the custom denied-page message is active, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER DefaultDeniedMessage
        Optional. Custom denied-page message text or HTML, replacing the current value.
        If omitted, the current value is kept.

        .PARAMETER DeniedMessageImage
        Optional. Image shown on the denied page, replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER DefaultFiletypeDeniedMessage
        Optional. Custom message shown when a file type is denied, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER DefaultFiletypeWarnedMessage
        Optional. Custom message shown when a file type is warned, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultOverrideMessage
        Optional. Whether the custom override-page message is active, replacing the
        current value. If omitted, the current value is kept.

        .PARAMETER DefaultOverrideMessage
        Optional. Custom override-page message text or HTML, replacing the current value.
        If omitted, the current value is kept.

        .PARAMETER OverrideDefaultQuotaMessage
        Optional. Whether the custom quota-page message is active, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER DefaultQuotaMessage
        Optional. Custom quota-page message text or HTML, replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER PUAWhitelist
        Optional. Names of potentially unwanted applications to whitelist, replacing the
        current list. If omitted, the current list is kept. Pass an empty array to clear
        it.

        .PARAMETER TopImageFile
        Optional. Path to a local jpg/jpeg file to upload as the top image of the block/warn
        page. The file must exist; a missing path throws before any request is sent. The
        firewall does not return this field on a Get, so it cannot be read back or verified.

        .PARAMETER BottomImageFile
        Optional. Path to a local jpg/jpeg file to upload as the bottom image of the
        block/warn page. The file must exist; a missing path throws before any request is
        sent. The firewall does not return this field on a Get, so it cannot be read back or
        verified.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter settings. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterSettings -WebCaching 'Enable' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterSettings -WebCaching 'Enable'

        Turns web caching on. Every other setting is kept unchanged.

        .EXAMPLE
        Set-SfosWebFilterSettings -TopImageFile 'C:\branding\top.jpg' -BottomImageFile 'C:\branding\bottom.jpg'

        Uploads new top and bottom images for the block/warn page. Every other setting is
        kept unchanged. The upload cannot be verified afterwards, because Get-SfosWebFilterSettings
        does not return these fields.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterSettings
#>
function Set-SfosWebFilterSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterSettings>, a singleton
    # holding one configuration, and it has no <WebFilterSetting> child. The Sophos spelling
    # goes above PowerShell habit here; the singular concession is reserved
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
        [string]$TopImageFile,
        [string]$BottomImageFile,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if ($PSBoundParameters.ContainsKey('TopImageFile') -and -not (Test-Path -LiteralPath $TopImageFile -PathType Leaf)) {
        throw "Failed to update WebFilterSettings: top image file not found: $TopImageFile"
    }
    if ($PSBoundParameters.ContainsKey('BottomImageFile') -and -not (Test-Path -LiteralPath $BottomImageFile -PathType Leaf)) {
        throw "Failed to update WebFilterSettings: bottom image file not found: $BottomImageFile"
    }

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
    $targetPua = @(if ($bp.ContainsKey('PUAWhitelist')) { $PUAWhitelist } else { $existing.PUAWhitelist })

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

    # TopImageFile/BottomImageFile are write-only (see help): sent only when the caller
    # passes a path, and matched to the uploaded file through the multipart contract in
    # SophosFirewall.Core - the element's text is the file's base name, and the multipart
    # field name equals the element name.
    $multipartFile = @{}
    $topImageXml = ''
    if ($PSBoundParameters.ContainsKey('TopImageFile')) {
        $multipartFile['TopImageFile'] = $TopImageFile
        $topImageXml = "<TopImageFile>$(ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $TopImageFile -Leaf))</TopImageFile>"
    }
    $bottomImageXml = ''
    if ($PSBoundParameters.ContainsKey('BottomImageFile')) {
        $multipartFile['BottomImageFile'] = $BottomImageFile
        $bottomImageXml = "<BottomImageFile>$(ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $BottomImageFile -Leaf))</BottomImageFile>"
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
    $topImageXml$bottomImageXml
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
            -InnerXml $inner -MultipartFile $multipartFile `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
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
        Retrieves the web filter protection settings of a Sophos Firewall.

        .DESCRIPTION
        Returns the web filter protection settings singleton. There is exactly one
        instance of this object per firewall. The cmdlet only reads; nothing on the
        firewall is changed. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter protection settings. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with the properties
        ScanMode, FileSizeThreshold, FTPFileSizeThreshold, AudioVideoFileScanning,
        HTTPSScanningCA, DenyUnknownProtocol, AllowInvalidCertificate,
        NoHttpsNotification, Scanning, BlockUnscannableContent, PharmingProtection,
        PUADetection and PUAWhitelist. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosWebFilterProtectionSettings

        Returns the current web filter protection settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosWebFilterProtectionSettings
#>
function Get-SfosWebFilterProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterProtectionSettings>, a singleton
    # holding one configuration, and it has no <WebFilterProtectionSetting> child. The Sophos
    # spelling goes above PowerShell habit here; the singular concession is reserved
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
        [object]$Session,

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
        Updates the web filter protection settings of a Sophos Firewall.

        .DESCRIPTION
        Changes scanning, HTTPS inspection or PUA detection settings of the web filter.
        The cmdlet reads the current settings first and sends them back complete, so a
        field you do not pass keeps its current value. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER ScanMode
        Optional. Scanning mode, replacing the current value. If omitted, the current
        value is kept.

        .PARAMETER FileSizeThreshold
        Optional. HTTP/HTTPS file size scanning threshold in KB, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER FTPFileSizeThreshold
        Optional. FTP file size scanning threshold in KB, replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER AudioVideoFileScanning
        Optional. Whether audio and video files are scanned, replacing the current value.
        If omitted, the current value is kept.

        .PARAMETER HTTPSScanningCA
        Optional. Name of the CA certificate used for HTTPS scanning, replacing the
        current value. If omitted, the current value is kept.

        .PARAMETER DenyUnknownProtocol
        Optional. Whether unknown protocols on HTTPS ports are denied, replacing the
        current value. If omitted, the current value is kept.

        .PARAMETER AllowInvalidCertificate
        Optional. Whether invalid HTTPS certificates are allowed, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER NoHttpsNotification
        Optional. Whether the HTTPS scanning notification page is suppressed, replacing
        the current value. If omitted, the current value is kept.

        .PARAMETER Scanning
        Optional. Anti-virus scanning mode, replacing the current value. If omitted, the
        current value is kept.

        .PARAMETER BlockUnscannableContent
        Optional. How content that cannot be scanned is handled, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER PharmingProtection
        Optional. Whether pharming protection is active, replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER PUADetection
        Optional. Whether detection of potentially unwanted applications is active,
        replacing the current value. If omitted, the current value is kept.

        .PARAMETER PUAWhitelist
        Optional. Names of potentially unwanted applications to whitelist, replacing the
        current list. If omitted, the current list is kept. Pass an empty array to clear
        it.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter protection settings. If omitted, the value from the current connection
        is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterProtectionSettings -ScanMode 'BatchMode' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterProtectionSettings -ScanMode 'BatchMode'

        Changes the scan mode. Every other setting, including PharmingProtection, is kept
        unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterProtectionSettings
#>
function Set-SfosWebFilterProtectionSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterProtectionSettings>, a singleton
    # holding one configuration, and it has no <WebFilterProtectionSetting> child. The Sophos
    # spelling goes above PowerShell habit here; the singular concession is reserved
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    $targetPua = @(if ($bp.ContainsKey('PUAWhitelist')) { $PUAWhitelist } else { $existing.PUAWhitelist })

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
        Retrieves the advanced web filter settings of a Sophos Firewall.

        .DESCRIPTION
        Returns the advanced web filter settings singleton, covering the web proxy port,
        its minimum TLS version and the trusted port list. There is exactly one instance
        of this object per firewall. The cmdlet only reads; nothing on the firewall is
        changed. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter advanced settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with the properties
        WebCaching, WebProxyPort, WebProxyMinimumTLSVersion and TrustedPorts. Returns
        System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosWebFilterAdvancedSettings

        Returns the current advanced web filter settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosWebFilterAdvancedSettings
#>
function Get-SfosWebFilterAdvancedSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterAdvancedSettings>, a singleton
    # holding one configuration, and it has no <WebFilterAdvancedSetting> child. The Sophos
    # spelling goes above PowerShell habit here; the singular concession is reserved
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
        [object]$Session,

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
        Updates the advanced web filter settings of a Sophos Firewall.

        .DESCRIPTION
        Changes the web proxy port, its minimum TLS version, the trusted port list or web
        caching. The cmdlet reads the current settings first and sends them back complete,
        so a field you do not pass keeps its current value. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER WebCaching
        Optional. Whether web caching is active, replacing the current value. If omitted,
        the current value is kept.

        .PARAMETER WebProxyPort
        Optional. TCP port the web proxy listens on, replacing the current value. If
        omitted, the current value is kept.

        .PARAMETER WebProxyMinimumTLSVersion
        Optional. Minimum TLS version accepted by the web proxy, replacing the current
        value. If omitted, the current value is kept.

        .PARAMETER TrustedPort
        Optional. Trusted ports or port ranges, for example '1025-65535', replacing the
        current list. If omitted, the current list is kept. Pass an empty array to clear
        it.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter advanced settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterAdvancedSettings -WebProxyPort 3128 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterAdvancedSettings -WebProxyPort 3128

        Changes the web proxy port. TrustedPort and the TLS minimum are kept unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterAdvancedSettings
#>
function Set-SfosWebFilterAdvancedSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterAdvancedSettings>, a singleton
    # holding one configuration, and it has no <WebFilterAdvancedSetting> child. The Sophos
    # spelling goes above PowerShell habit here; the singular concession is reserved
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
    $targetTrustedPorts = @(if ($bp.ContainsKey('TrustedPort')) { $TrustedPort } else { $existing.TrustedPorts })

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
        Retrieves the default web filter notification settings of a Sophos Firewall.

        .DESCRIPTION
        Returns the default web filter notification settings singleton: the free-text and
        HTML notification messages shown to end users, such as blocked-page text and
        zero-day analysis progress text. There is exactly one instance of this object per
        firewall. The API defines no fixed set of fields for this object, so the returned
        object carries one property for each field the firewall actually returns. The
        cmdlet only reads; nothing on the firewall is changed. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly.

        Each value is returned as plain text, with any embedded HTML intact, and can be
        passed back into Set-SfosDefaultWebFilterNotificationSettings unmodified.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter notification settings. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with one property per
        message field returned by the firewall. Returns System.Xml.XmlElement when -AsXml
        is used.

        .EXAMPLE
        Get-SfosDefaultWebFilterNotificationSettings

        Returns every current notification message text.

        .EXAMPLE
        (Get-SfosDefaultWebFilterNotificationSettings).Warning

        Returns the text of a single message field.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosDefaultWebFilterNotificationSettings
#>
function Get-SfosDefaultWebFilterNotificationSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DefaultWebFilterNotificationSettings>, a singleton
    # holding one configuration, and it has no <DefaultWebFilterNotificationSetting> child. The
    # Sophos spelling goes above PowerShell habit here; the singular concession is reserved
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
        [object]$Session,

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
        Updates one or more default web filter notification message fields of a Sophos
        Firewall.

        .DESCRIPTION
        Changes one or more of the free-text and HTML notification messages shown to end
        users. Because this object carries a large, firmware-defined set of message
        fields, this cmdlet takes a single -Message hashtable instead of one parameter per
        field. The cmdlet reads the current field names and values first, validates every
        key in -Message against them, and sends the whole object back complete, so a field
        you do not name in -Message keeps its current value. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission.

        .PARAMETER Message
        Required. Hashtable of field name and value pairs to update, for example
        @{ Warning = 'Warning!'; DownloadBlocked = 'This download is blocked' }. Each key
        must match a field name returned by Get-SfosDefaultWebFilterNotificationSettings;
        an unknown key makes the cmdlet throw before it sends anything. A value read back
        from Get-SfosDefaultWebFilterNotificationSettings can be passed back unmodified.
        Fields not named in the hashtable keep their current value.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter notification settings. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update, or if -Message contains a field name that does not exist.

        .EXAMPLE
        Set-SfosDefaultWebFilterNotificationSettings -Message @{ Warning = 'Achtung!' } -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDefaultWebFilterNotificationSettings -Message @{ Warning = 'Achtung!' }

        Changes a single message field. Every other field keeps its current text.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDefaultWebFilterNotificationSettings
#>
function Set-SfosDefaultWebFilterNotificationSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DefaultWebFilterNotificationSettings>, a singleton
    # holding one configuration, and it has no <DefaultWebFilterNotificationSetting> child. The
    # Sophos spelling goes above PowerShell habit here; the singular concession is reserved
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

#region WebFilterNotificationSettings

<#
        .SYNOPSIS
        Retrieves the web filter notification settings of a Sophos Firewall.

        .DESCRIPTION
        Returns the web filter notification settings singleton: whether the default warned
        and denied messages are overridden, and whether the notification page shows the
        default or a custom image. There is exactly one instance of this object per
        firewall. The cmdlet only reads; nothing on the firewall is changed. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        web filter notification settings. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .PARAMETER AsXml
        Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. An object with the properties
        OverrideDefaultWarnedMessage, OverrideDefaultDeniedMessage and DeniedMessageImage.
        Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosWebFilterNotificationSettings

        Returns the current web filter notification settings.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosWebFilterNotificationSettings
#>
function Get-SfosWebFilterNotificationSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterNotificationSettings>, a
    # singleton holding one configuration, and it has no <WebFilterNotificationSetting> child.
    # The Sophos spelling goes above PowerShell habit here; the singular concession is
    # reserved for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        # Output parameters
        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><WebFilterNotificationSettings></WebFilterNotificationSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving WebFilterNotificationSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterNotificationSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/WebFilterNotificationSettings')
    if (-not $node) {
        throw 'WebFilterNotificationSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        OverrideDefaultWarnedMessage = [string]$node.OverrideDefaultWarnedMessage
        OverrideDefaultDeniedMessage = [string]$node.OverrideDefaultDeniedMessage
        DeniedMessageImage           = [string]$node.DeniedMessageImage
    }
}

<#
        .SYNOPSIS
        Updates the web filter notification settings of a Sophos Firewall.

        .DESCRIPTION
        Changes whether the default warned or denied messages are overridden, or whether
        the notification page shows the default or a custom image. The cmdlet reads the
        current settings first and sends them back complete, so a field you do not pass
        keeps its current value. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly, and an account with write permission.

        This setting applies to every user behind the appliance. Turning an override off
        reverts the block or warning page shown to users appliance-wide; read the current
        values back with Get-SfosWebFilterNotificationSettings before changing them, so
        they can be restored.

        .PARAMETER OverrideDefaultWarnedMessage
        Optional. Whether the default warned message is overridden, replacing the current
        value. Observed values: 'Enable', 'Disable'. If omitted, the current value is kept.

        .PARAMETER OverrideDefaultDeniedMessage
        Optional. Whether the default denied message is overridden, replacing the current
        value. Observed values: 'Enable', 'Disable'. If omitted, the current value is kept.

        .PARAMETER DeniedMessageImage
        Optional. Whether the notification page shows the default or a custom image,
        replacing the current value. Observed values: 'Default', 'Custom'. If omitted, the
        current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        web filter notification settings. If omitted, the value from the current
        connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate
        is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection is
        used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosWebFilterNotificationSettings -OverrideDefaultWarnedMessage 'Enable' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosWebFilterNotificationSettings -OverrideDefaultWarnedMessage 'Enable'

        Turns on the override of the default warned message. OverrideDefaultDeniedMessage
        and DeniedMessageImage are kept unchanged.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosWebFilterNotificationSettings
#>
function Set-SfosWebFilterNotificationSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <WebFilterNotificationSettings>, a
    # singleton holding one configuration, and it has no <WebFilterNotificationSetting> child.
    # The Sophos spelling goes above PowerShell habit here; the singular concession is
    # reserved for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$OverrideDefaultWarnedMessage,
        [string]$OverrideDefaultDeniedMessage,
        [string]$DeniedMessageImage,

        # Connection parameters (optional - use stored context if not provided)
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosWebFilterNotificationSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetOverrideDefaultWarnedMessage = if ($bp.ContainsKey('OverrideDefaultWarnedMessage')) { $OverrideDefaultWarnedMessage } else { $existing.OverrideDefaultWarnedMessage }
    $targetOverrideDefaultDeniedMessage = if ($bp.ContainsKey('OverrideDefaultDeniedMessage')) { $OverrideDefaultDeniedMessage } else { $existing.OverrideDefaultDeniedMessage }
    $targetDeniedMessageImage = if ($bp.ContainsKey('DeniedMessageImage')) { $DeniedMessageImage } else { $existing.DeniedMessageImage }

    if (-not $PSCmdlet.ShouldProcess("WebFilterNotificationSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <WebFilterNotificationSettings>
    <OverrideDefaultWarnedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideDefaultWarnedMessage))</OverrideDefaultWarnedMessage>
    <OverrideDefaultDeniedMessage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetOverrideDefaultDeniedMessage))</OverrideDefaultDeniedMessage>
    <DeniedMessageImage>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDeniedMessageImage))</DeniedMessageImage>
  </WebFilterNotificationSettings>
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
        throw "Error updating WebFilterNotificationSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebFilterNotificationSettings' -Action 'update'
}

#endregion
