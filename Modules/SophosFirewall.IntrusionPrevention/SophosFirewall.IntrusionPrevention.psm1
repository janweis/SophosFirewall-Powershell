#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.IntrusionPrevention
    ==================================
    PowerShell module for managing Sophos Firewall (SFOS) intrusion prevention
    via the XML API: IPS policies and their rules, custom IPS signatures, the
    global IPS switch, IPS full signature pack, DoS settings, DoS bypass rules,
    spoof prevention and trusted MAC addresses.

    Total Functions: 34 (29 exported, 5 internal helpers) - see README.md for the full
    cmdlet table.

    Requires SophosFirewall.Core for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S)
    happens in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>


#region IPSPolicy

function ConvertTo-SfosIPSPolicyRuleXml {
    # Internal helper, not exported. Builds one <Rule> element for an IPSPolicy's RuleList.
    #
    # SignaturSelectionType is spelled exactly as the live firewall sends and accepts it -
    # missing the "e" in "Signature" is not a documentation typo, it is the real wire element
    # name, measured on both read and write against the lab appliance (create with the typo
    # spelling succeeds and round-trips; the correctly spelled element was never tried, since
    # the read side already proves what the firewall actually uses).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Rule
    )

    $ruleNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.RuleName)
    $selTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SignaturSelectionType)
    $ruleTypeEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.RuleType)
    $actionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Action)
    $smartFilterEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SmartFilter)

    $categoryXml = ''
    foreach ($item in @($Rule.CategoryList)) {
        if (-not $item) {
            continue
        }
        $categoryXml += "<Category>$(ConvertTo-SfosXmlEscaped -Text $item)</Category>"
    }

    $severityXml = ''
    foreach ($item in @($Rule.SeverityList)) {
        if (-not $item) {
            continue
        }
        $severityXml += "<Severity>$(ConvertTo-SfosXmlEscaped -Text $item)</Severity>"
    }

    $targetXml = ''
    foreach ($item in @($Rule.TargetList)) {
        if (-not $item) {
            continue
        }
        $targetXml += "<Target>$(ConvertTo-SfosXmlEscaped -Text $item)</Target>"
    }

    $platformXml = ''
    foreach ($item in @($Rule.PlatformList)) {
        if (-not $item) {
            continue
        }
        $platformXml += "<Platform>$(ConvertTo-SfosXmlEscaped -Text $item)</Platform>"
    }

    $signatureXml = ''
    foreach ($item in @($Rule.SignatureList)) {
        if (-not $item) {
            continue
        }
        $signatureXml += "<Signature>$(ConvertTo-SfosXmlEscaped -Text $item)</Signature>"
    }

    return "<Rule><RuleName>$ruleNameEsc</RuleName><SignaturSelectionType>$selTypeEsc</SignaturSelectionType><CategoryList>$categoryXml</CategoryList><SeverityList>$severityXml</SeverityList><TargetList>$targetXml</TargetList><PlatformList>$platformXml</PlatformList><SignatureList>$signatureXml</SignatureList><SmartFilter>$smartFilterEsc</SmartFilter><RuleType>$ruleTypeEsc</RuleType><Action>$actionEsc</Action></Rule>"
}

function ConvertTo-SfosIPSPolicyEntityXml {
    # Internal helper, not exported. Builds the <Set> inner XML for an IPSPolicy entity, so
    # New-, Set-SfosIPSPolicy, Add-SfosIPSPolicyRule and Remove-SfosIPSPolicyRule all send an
    # identical, complete entity body. SFOS replaces the whole entity on
    # <Set operation="update">, so the caller merges every field it wants preserved into
    # -Policy before calling this function; nothing is read back here.
    #
    # Deliberately never emits <Template>. It appears only in the vendor sample XML, has no
    # row in the attribute table, and sending it - with any value - is rejected outright with
    # a 501 naming /IPSPolicy/Template as invalid (measured against the lab firewall). Unlike
    # the FileType/Template pattern elsewhere in this project (accepted on write, silently
    # absent on read), this field is not accepted at all on this firmware.
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

    $ruleListXml = ''
    foreach ($rule in @($Policy.RuleList)) {
        if (-not $rule) {
            continue
        }
        $ruleListXml += ConvertTo-SfosIPSPolicyRuleXml -Rule $rule
    }

    return @"
<Set operation="$Operation">
  <IPSPolicy>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <RuleList>$ruleListXml</RuleList>
  </IPSPolicy>
</Set>
"@
}

<#
        .SYNOPSIS
        Retrieves IPSPolicy objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for IPSPolicy objects. By default the cmdlet
        returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        Each Rule in the returned RuleList mirrors the shape produced by
        New-SfosIPSPolicyRule, so a rule read back from Get-SfosIPSPolicy can be reused
        directly with Add-SfosIPSPolicyRule or passed to Set-SfosIPSPolicy -Rule.

        The 10 factory-default IPS policies on a fresh SFOS install (e.g. 'WAN TO LAN',
        'lantowan_strict') are returned like any other object. Treat them as read-only in
        your own scripts - Set-SfosIPSPolicy has no protection against overwriting them.

        Note: Sophos GET responses can be inconsistent regarding status elements. This
        cmdlet is designed to return an empty result when no records are found.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the
        supplied value may match anywhere in the object name). Sent to the firewall as the
        server-side filter and re-applied client-side, per the project's filtering rules.

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

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject with Name, Description and RuleList (array of rule objects with
        RuleName, SignaturSelectionType, CategoryList, SeverityList, PlatformList,
        TargetList, SignatureList, SmartFilter, RuleType, Action). A policy with no rules
        returns RuleList as @(). System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        # Retrieve all IPS policies
        Get-SfosIPSPolicy

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosIPSPolicy -NameLike "dmz"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosIPSPolicy -NameLike "dmz" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for
        user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPSPolicyRule
#>
function Get-SfosIPSPolicy {
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
  <IPSPolicy>
    $filterXml
  </IPSPolicy>
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
        throw "Error retrieving IPSPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Without this check a firewall-side error would be read as an empty result instead of
    # being reported. This also affects Set-SfosIPSPolicy, Remove-SfosIPSPolicy and the rule
    # cmdlets, which all call back into this function to read the current object.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPSPolicy[Name]' | ForEach-Object -Process {
        $_.Node
    }

    $policyObjects = foreach ($node in @($nodes)) {
        # A policy with no rules has no <RuleList> element at all (SFOS drops it rather than
        # sending an empty wrapper, measured), so $node.RuleList is $null. Without the
        # -FilterScript below, @($null.Rule) is a one-element array containing $null, not an
        # empty array.
        $rules = foreach ($ruleNode in @($node.RuleList.Rule | Where-Object -FilterScript { $_ })) {
            [PSCustomObject]@{
                RuleName              = [string]$ruleNode.RuleName
                SignaturSelectionType = [string]$ruleNode.SignaturSelectionType
                CategoryList          = [string[]]@($ruleNode.CategoryList.Category | Where-Object -FilterScript { $_ })
                SeverityList          = [string[]]@($ruleNode.SeverityList.Severity | Where-Object -FilterScript { $_ })
                PlatformList          = [string[]]@($ruleNode.PlatformList.Platform | Where-Object -FilterScript { $_ })
                TargetList            = [string[]]@($ruleNode.TargetList.Target | Where-Object -FilterScript { $_ })
                SignatureList         = [string[]]@($ruleNode.SignatureList.Signature | Where-Object -FilterScript { $_ })
                SmartFilter           = [string]$ruleNode.SmartFilter
                RuleType              = [string]$ruleNode.RuleType
                Action                = [string]$ruleNode.Action
            }
        }

        [PSCustomObject]@{
            Name        = [string]$node.Name
            Description = [string]$node.Description
            # Same $null-when-empty foreach quirk as above, guarded the same way.
            RuleList    = @($rules | Where-Object -FilterScript { $_ })
        }
    }

    # Client-side filtering. Only the first <key> of the first <Filter> is evaluated by
    # SFOS, so the requested filter is re-applied here on the returned objects.
    $policyObjects = @($policyObjects)
    if ($NameLike) {
        $policyObjects = @($policyObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($policyObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $policyObjects
}

<#
        .SYNOPSIS
        Creates a new IPSPolicy on the Sophos Firewall.

        .DESCRIPTION
        Creates an IPSPolicy object, which groups IPS signature-matching rules into a policy
        that can be assigned to a firewall rule. Rules can be supplied at creation time via
        -Rule, built with New-SfosIPSPolicyRule, or added afterwards with
        Add-SfosIPSPolicyRule. Creating a policy with no rules at all is accepted by the
        firewall (measured) - -Rule is optional.

        .PARAMETER Name
        Name of the IPS policy (1-60 characters, no commas).

        .PARAMETER Description
        Optional description.

        .PARAMETER Rule
        Zero or more rule objects, in the order they should be evaluated. Build each entry
        with New-SfosIPSPolicyRule. Omitting -Rule entirely creates a policy with an empty
        RuleList (measured), which Get-SfosIPSPolicy then reports back as RuleList = @().

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
        # Create a policy with no rules yet
        New-SfosIPSPolicy -Name "BranchOffice" -Description "Empty test policy"

        .EXAMPLE
        # Create a policy with one rule
        $rule = New-SfosIPSPolicyRule -RuleName "AllTraffic" -Category "All Categories" -Severity "All Severity" -Target "All Target" -Platform "All Platform"
        New-SfosIPSPolicy -Name "BranchOfficeIPS" -Description "One-rule test policy" -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPSPolicy

        .LINK
        New-SfosIPSPolicyRule
#>
function New-SfosIPSPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [PSCustomObject[]]$Rule,

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
        if (-not $PSCmdlet.ShouldProcess("IPSPolicy '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $policy = [PSCustomObject]@{
            Name        = $Name
            Description = $Description
            RuleList    = @($Rule)
        }

        $inner = ConvertTo-SfosIPSPolicyEntityXml -Operation 'add' -Policy $policy

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create IPSPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSPolicy' -Action 'create' -Target $Name
    }
}

<#
        .SYNOPSIS
        Updates an existing IPSPolicy object on the Sophos Firewall.

        .DESCRIPTION
        Updates an IPSPolicy object using the Sophos Firewall XML API. You can supply the
        target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current policy first and keeps
        whatever the caller does not explicitly pass.

        IMPORTANT (measured): an unrecognized value inside a Rule's nested lists (for
        example an invalid Severity) is not rejected by the firewall on update. The
        firewall silently drops just that one nested list from the Rule and still answers
        200 'Configuration applied successfully' - the top-level Add operation does reject
        an invalid RuleType with a 501, but nested list values inside Update are not
        validated the same way. Verify with Get-SfosIPSPolicy after any Set-SfosIPSPolicy
        call that touches -Rule, especially when the rule content came from something other
        than New-SfosIPSPolicyRule / a prior Get-SfosIPSPolicy.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER Rule
        Complete replacement rule list, in the order the firewall should evaluate them.
        This REPLACES the existing RuleList wholesale, exactly as the API does - it does
        not merge with the rules already on the firewall (measured: shrinking from 2 rules
        to 1, and sending no rules at all, both work as expected - RuleList is not
        append-only on this entity, unlike some other list fields in this project). Omit
        this parameter to keep the existing rules unchanged. To add or remove a single rule
        without touching the rest of the list, use Add-SfosIPSPolicyRule /
        Remove-SfosIPSPolicyRule instead.

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
        # Change only the description, RuleList is preserved
        Set-SfosIPSPolicy -Name "BranchOfficeIPS" -Description "Updated description"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosIPSPolicy -NameLike "BranchOfficeIPS" | Set-SfosIPSPolicy -Description "Updated"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for
        user input.
        No write protection for the 10 factory-default IPS policies - this cmdlet will
        overwrite one, including its RuleList, without any warning from the API. Verify
        -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPSPolicy
#>
function Set-SfosIPSPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 255)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('RuleList')]
        [PSCustomObject[]]$Rule,

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
        $existing = @(Get-SfosIPSPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPSPolicy object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) {
            $targetPolicy.Description = $Description
        }
        if ($PSBoundParameters.ContainsKey('Rule')) {
            # Wholesale replacement, matching the API - not a merge. See .PARAMETER Rule.
            $targetPolicy.RuleList = @($Rule)
        }

        $inner = ConvertTo-SfosIPSPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("IPSPolicy '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating IPSPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSPolicy' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an IPSPolicy object from the Sophos Firewall.

        .DESCRIPTION
        Removes an IPSPolicy object using the Sophos Firewall XML API. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        Deleting a policy name that does not exist answers 200 'Configuration applied
        successfully' just like a real delete (measured against the lab firewall) - the
        firewall gives no indication that nothing happened. This cmdlet therefore reads the
        object first and throws 'was not found' for a name that is not present, rather than
        trusting that response.

        .PARAMETER Name
        Name of the target policy.

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
        None. Throws an exception if removal fails, or if the named object does not exist.

        .EXAMPLE
        Remove-SfosIPSPolicy -Name "BranchOffice"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for
        user input.
        Never target the 10 factory-default IPS policies with this cmdlet.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPSPolicy
#>
function Remove-SfosIPSPolicy {
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
        # See .DESCRIPTION - a delete of a nonexistent name reports success just like a real
        # delete, so the object is confirmed present before the Remove is even attempted.
        $existing = @(Get-SfosIPSPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPSPolicy object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("IPSPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><IPSPolicy><Name>$nameEsc</Name></IPSPolicy></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove IPSPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSPolicy' -Action 'remove' -Target $Name
    }
}

<#
        .SYNOPSIS
        Builds a rule for use inside an IPSPolicy's RuleList.

        .DESCRIPTION
        Creates the object New-SfosIPSPolicy -Rule, Set-SfosIPSPolicy -Rule and
        Add-SfosIPSPolicyRule expect. Performs no API call - the rule only becomes part of a
        policy once handed to one of those cmdlets. SFOS persists rule order unchanged, so
        build rules in the order they must be evaluated.

        .PARAMETER InputObject
        An existing rule to use as the base, as returned in the RuleList of
        Get-SfosIPSPolicy. Accepts pipeline input. Only the parameters you actually supply
        override it, so a single field can be changed without disturbing the rest. Without
        it, every omitted parameter falls back to its default.

        .PARAMETER RuleName
        Name of the rule within the policy (1-70 characters). Mandatory unless -InputObject
        supplies one.

        .PARAMETER SignaturSelectionType
        'All Application' or 'Individual Application'. Default: 'All Application'. Spelled
        exactly as the wire element - see the module report for why the missing "e" is not
        a typo in this codebase. Only 'All Application' has been fully measured end to end
        (create, read back, matches). 'Individual Application' was probed structurally with
        a fictional signature ID in -Signature and accepted with a warning-level 201
        'Operation partially successful' - it was not confirmed with a real, installed
        signature ID, since no signature catalog was available for testing.

        .PARAMETER Category
        IPS signature category names, for example 'All Categories', 'os-windows',
        'server-mail'. Used when -SignaturSelectionType is 'All Application'. No client-side
        validation - the live category catalog is large and was not enumerated.

        .PARAMETER Severity
        Severity names for this rule, for example 'All Severity'. Only 'All Severity' has
        been measured directly against a Rule's SeverityList; 'Critical', 'Major',
        'Moderate', 'Minor' and 'Warning' are inferred from the Severity enum documented for
        the sibling IPSCustomSignature entity in the same feature area, not independently
        confirmed here. IMPORTANT (measured): an unrecognized value in this list is not
        rejected - Set-SfosIPSPolicy's update silently drops the whole SeverityList and
        still reports success. Stick to the validated set here specifically to avoid that.

        .PARAMETER Target
        Target names for this rule: 'All Target', 'Client' or 'Server' (all three measured
        against live default policies).

        .PARAMETER Platform
        Platform names for this rule, for example 'All Platform', 'Windows', 'Linux' (all
        three measured against live default policies; the live signature catalog most
        likely defines more, but only these three were observed). No client-side
        ValidateSet, since the full platform list was not enumerated.

        .PARAMETER Signature
        Individual signature IDs, used when -SignaturSelectionType is
        'Individual Application'. See the caveat under -SignaturSelectionType - this path
        was only probed structurally, not confirmed with a real signature ID.

        .PARAMETER SmartFilter
        Free-text search filter as stored by the web admin's rule builder UI. Always empty
        on the 10 factory-default policies; its functional purpose beyond the UI search box
        is not documented. Default: '' (empty).

        .PARAMETER RuleType
        'Default Signature' or 'Custom Signature'. Default: 'Default Signature'. Only
        'Default Signature' is used by any of the 10 factory-default policies.
        'Custom Signature' was probed structurally (accepted with code 200 even without a
        real custom signature referenced) but could not be exercised end to end, because no
        IPSCustomSignature could be created on this firmware - see New-SfosIPSCustomSignature.

        .PARAMETER Action
        'Recommended', 'Allow Packet', 'Drop Packet', 'Disable', 'Drop Session', 'Reset' or
        'Bypass Session'. Default: 'Recommended', the only value used by any of the 10
        factory-default policies. The vendor documentation also lists a cryptic value '7' in
        the same enum; per this build's task scope it was deliberately not tried against the
        live firewall and is not offered here - noted only as a documentation curiosity.

        .OUTPUTS
        PSCustomObject with RuleName, SignaturSelectionType, CategoryList, SeverityList,
        PlatformList, TargetList, SignatureList, SmartFilter, RuleType and Action properties
        - the same shape Get-SfosIPSPolicy returns for each RuleList entry.

        .EXAMPLE
        # A simple all-traffic rule using the recommended action
        New-SfosIPSPolicyRule -RuleName "AllTraffic" -Category "All Categories" -Severity "All Severity" -Target "All Target" -Platform "All Platform"

        .EXAMPLE
        # Change one field of an existing rule read back from the firewall
        $policy = Get-SfosIPSPolicy -NameLike "BranchOfficeIPS"
        $edited = $policy.RuleList[0] | New-SfosIPSPolicyRule -Action "Drop Session"
        Set-SfosIPSPolicy -Name "BranchOfficeIPS" -Rule $edited

        .NOTES
        Minimum supported PowerShell version: 5.1
        This cmdlet performs no API call; it only builds an in-memory object.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPSPolicy

        .LINK
        Add-SfosIPSPolicyRule
#>
function New-SfosIPSPolicyRule {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. This function
    # builds an in-memory object and never calls the API, so there is no state change for
    # ShouldProcess to confirm. The verb New is still correct - it creates an object that is
    # then handed to New-/Set-SfosIPSPolicy or Add-SfosIPSPolicyRule, which do declare
    # ShouldProcess.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateLength(1, 70)]
        [string]$RuleName,

        [ValidateSet('All Application', 'Individual Application')]
        [string]$SignaturSelectionType = 'All Application',

        [string[]]$Category,

        [ValidateSet('All Severity', 'Critical', 'Major', 'Moderate', 'Minor', 'Warning')]
        [string[]]$Severity,

        [ValidateSet('All Target', 'Client', 'Server')]
        [string[]]$Target,

        [string[]]$Platform,

        [string[]]$Signature,

        [string]$SmartFilter = '',

        [ValidateSet('Default Signature', 'Custom Signature')]
        [string]$RuleType = 'Default Signature',

        [ValidateSet('Recommended', 'Allow Packet', 'Drop Packet', 'Disable', 'Drop Session', 'Reset', 'Bypass Session')]
        [string]$Action = 'Recommended'
    )

    process {
        # Precedence per field: an explicitly bound parameter wins, otherwise the value from
        # -InputObject, otherwise the parameter default. The ContainsKey test is what makes
        # editing safe - without it every default would overwrite the base. Same reasoning
        # as New-SfosWebFilterPolicyRule in the Web module; see the project build rules,
        # section 5.
        if (-not $InputObject -and -not $PSBoundParameters.ContainsKey('RuleName')) {
            throw 'New-SfosIPSPolicyRule needs -RuleName, unless an existing rule is supplied through -InputObject.'
        }

        $ruleNameValue = if ($PSBoundParameters.ContainsKey('RuleName')) { $RuleName }
        elseif ($InputObject -and $InputObject.RuleName) { [string]$InputObject.RuleName }
        else { $RuleName }

        $selTypeValue = if ($PSBoundParameters.ContainsKey('SignaturSelectionType')) { $SignaturSelectionType }
        elseif ($InputObject -and $InputObject.SignaturSelectionType) { [string]$InputObject.SignaturSelectionType }
        else { $SignaturSelectionType }

        $categoryValue = if ($PSBoundParameters.ContainsKey('Category')) { @($Category) }
        elseif ($InputObject) { @($InputObject.CategoryList) }
        else { @() }

        $severityValue = if ($PSBoundParameters.ContainsKey('Severity')) { @($Severity) }
        elseif ($InputObject) { @($InputObject.SeverityList) }
        else { @() }

        $targetValue = if ($PSBoundParameters.ContainsKey('Target')) { @($Target) }
        elseif ($InputObject) { @($InputObject.TargetList) }
        else { @() }

        $platformValue = if ($PSBoundParameters.ContainsKey('Platform')) { @($Platform) }
        elseif ($InputObject) { @($InputObject.PlatformList) }
        else { @() }

        $signatureValue = if ($PSBoundParameters.ContainsKey('Signature')) { @($Signature) }
        elseif ($InputObject) { @($InputObject.SignatureList) }
        else { @() }

        $smartFilterValue = if ($PSBoundParameters.ContainsKey('SmartFilter')) { $SmartFilter }
        elseif ($InputObject -and $null -ne $InputObject.SmartFilter) { [string]$InputObject.SmartFilter }
        else { $SmartFilter }

        $ruleTypeValue = if ($PSBoundParameters.ContainsKey('RuleType')) { $RuleType }
        elseif ($InputObject -and $InputObject.RuleType) { [string]$InputObject.RuleType }
        else { $RuleType }

        $actionValue = if ($PSBoundParameters.ContainsKey('Action')) { $Action }
        elseif ($InputObject -and $InputObject.Action) { [string]$InputObject.Action }
        else { $Action }

        return [PSCustomObject]@{
            RuleName              = $ruleNameValue
            SignaturSelectionType = $selTypeValue
            CategoryList          = @($categoryValue | Where-Object -FilterScript { $_ })
            SeverityList          = @($severityValue | Where-Object -FilterScript { $_ })
            PlatformList          = @($platformValue | Where-Object -FilterScript { $_ })
            TargetList            = @($targetValue | Where-Object -FilterScript { $_ })
            SignatureList         = @($signatureValue | Where-Object -FilterScript { $_ })
            SmartFilter           = $smartFilterValue
            RuleType              = $ruleTypeValue
            Action                = $actionValue
        }
    }
}

<#
        .SYNOPSIS
        Appends a rule to the end of an existing IPSPolicy's RuleList.

        .DESCRIPTION
        Reads the current IPSPolicy, appends the supplied rule after the existing ones, and
        writes the whole entity back - SFOS replaces RuleList wholesale on update, so the
        existing rules and their order are read back first and resent unchanged alongside
        the new one.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Rule
        Rule object to append, built with New-SfosIPSPolicyRule.

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
        $rule = New-SfosIPSPolicyRule -RuleName "ExtraRule" -Category "All Categories" -Severity "All Severity" -Target "All Target" -Platform "All Platform"
        Add-SfosIPSPolicyRule -Name "BranchOfficeIPS" -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for
        user input.
        No write protection for the 10 factory-default IPS policies. Verify -Name before
        running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosIPSPolicyRule

        .LINK
        Remove-SfosIPSPolicyRule
#>
function Add-SfosIPSPolicyRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        $existing = @(Get-SfosIPSPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPSPolicy object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $targetPolicy.RuleList = @($existing[0].RuleList) + $Rule

        $inner = ConvertTo-SfosIPSPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("IPSPolicy '$($Name)' on $($params.Firewall)", 'Add rule')) {
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
            throw "Error adding a rule to IPSPolicy '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSPolicy' -Action 'add rule' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a single rule from an existing IPSPolicy's RuleList by index.

        .DESCRIPTION
        Reads the current IPSPolicy, drops the rule at the given zero-based index from its
        RuleList, and writes the whole entity back - SFOS replaces RuleList wholesale on
        update, so the remaining rules and their order are resent unchanged.

        RuleList was measured to NOT be append-only on this entity: shrinking a policy from
        two rules to one, and sending an empty RuleList wrapper, both took effect correctly
        and Get-SfosIPSPolicy read back the reduced/empty list. This differs from some other
        list fields in this project (for example WebFilterCategory's URLList), where an
        update can silently fail to shrink. This cmdlet still reads the object back after
        the update and throws if the rule count on the firewall does not match what was
        sent, rather than trusting the 200 status code alone - the same defensive pattern
        used elsewhere in this project for writes that could otherwise report success while
        changing nothing.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Index
        Zero-based position of the rule to remove within the policy's RuleList, in the
        order returned by Get-SfosIPSPolicy. Throws if out of range.

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
        None. Throws an exception if the update fails, or if the rule was not actually
        removed.

        .EXAMPLE
        # Remove the first rule of the policy
        Remove-SfosIPSPolicyRule -Name "BranchOfficeIPS" -Index 0

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for
        user input.
        No write protection for the 10 factory-default IPS policies. Verify -Name before
        running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Add-SfosIPSPolicyRule
#>
function Remove-SfosIPSPolicyRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        $existing = @(Get-SfosIPSPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPSPolicy object '$Name' was not found."
        }

        $currentRules = @($existing[0].RuleList)
        if ($Index -lt 0 -or $Index -ge $currentRules.Count) {
            throw "IPSPolicy '$Name' has $($currentRules.Count) rule(s); index $Index is out of range."
        }

        $targetRules = @()
        for ($i = 0; $i -lt $currentRules.Count; $i++) {
            if ($i -ne $Index) {
                $targetRules += $currentRules[$i]
            }
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $targetPolicy.RuleList = $targetRules

        $inner = ConvertTo-SfosIPSPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("IPSPolicy '$($Name)' on $($params.Firewall)", "Remove rule at index $Index")) {
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
            throw "Error removing rule at index $Index from IPSPolicy '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSPolicy' -Action 'remove rule' -Target $Name

        # RuleList is not append-only on this entity (measured, see .DESCRIPTION), but a 200
        # that changes nothing is exactly the failure mode this project has been bitten by
        # before (compare Remove-SfosSSLBookmark in the VPN module) - read back and throw
        # rather than trust the status code alone.
        $after = @(Get-SfosIPSPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })
        $afterCount = @($after[0].RuleList).Count
        if ($afterCount -ne $targetRules.Count) {
            throw "Removing rule at index $Index from IPSPolicy '$Name' reported success, but the firewall now reports $afterCount rule(s) instead of the expected $($targetRules.Count)."
        }
    }
}

#endregion


#region IPSCustomSignature

<#
        .SYNOPSIS
        Retrieves IPSCustomSignature objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for IPSCustomSignature objects. By default the
        cmdlet returns PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        No IPSCustomSignature could be created on the lab firewall during this module's
        build - see New-SfosIPSCustomSignature - so this cmdlet's success path was measured
        only against an empty result set. Its shape follows the same conventions as every
        other Get-Sfos* in this project and its error path (an unrecognized filter, a
        firewall-side error) is covered by the same Assert-SfosApiReturnSuccess logic used
        everywhere else, but a real record was never actually read back.

        Note: Sophos GET responses can be inconsistent regarding status elements. This
        cmdlet is designed to return an empty result when no records are found.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match (the
        supplied value may match anywhere in the object name). Sent to the firewall as the
        server-side filter and re-applied client-side, per the project's filtering rules.

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

        .PARAMETER AsXml
        Returns raw XML nodes instead of PowerShell-friendly objects.

        .OUTPUTS
        PSCustomObject with Name, Protocol, CustomRule, Severity and RecommendedAction.
        System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        Get-SfosIPSCustomSignature

        .EXAMPLE
        Get-SfosIPSCustomSignature -NameLike "Block"

        .NOTES
        Minimum supported PowerShell version: 5.1
        This module uses XML-based requests (<Get>, <Set>, <Remove>) and XML escaping for
        user input.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>
function Get-SfosIPSCustomSignature {
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
  <IPSCustomSignature>
    $filterXml
  </IPSCustomSignature>
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
        throw "Error retrieving IPSCustomSignature objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSCustomSignature' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/IPSCustomSignature[Name]' | ForEach-Object -Process {
        $_.Node
    }

    $signatureObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name              = [string]$node.Name
            Protocol          = [string]$node.Protocol
            CustomRule        = [string]$node.CustomRule
            Severity          = [string]$node.Severity
            RecommendedAction = [string]$node.RecommendedAction
        }
    }

    $signatureObjects = @($signatureObjects)
    if ($NameLike) {
        $signatureObjects = @($signatureObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($signatureObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $signatureObjects
}

<#
        .SYNOPSIS
        Creates a new IPSCustomSignature on the Sophos Firewall.

        .DESCRIPTION
        Creates an IPSCustomSignature object. UNCONFIRMED on this firmware: every add
        attempted during this module's build was rejected with a bare 501
        'Configuration parameters validation failed.', InvalidParams naming only
        /IPSCustomSignature/CustomRule. Ten syntax variants for -CustomRule were tried
        against the live firewall - classic Snort-style rules with and without classtype,
        a minimal sid-only rule, the literal dot-separated form the attribute table's cryptic
        footnote for this field seems to suggest ("To separate letters, use a dot (.)"),
        unquoted and single-quoted message text, an added priority field, a plain
        non-parenthesized form, a trailing period, and a rule using the 'flow' keyword - all
        ten were rejected identically. -Protocol, -Severity and -RecommendedAction were all
        confirmed independently valid: sending an invalid Protocol adds /Protocol to the
        same InvalidParams list, and using -Action instead of -RecommendedAction (as the
        vendor's own attribute table names the field) adds /RecommendedAction to it - see
        .PARAMETER RecommendedAction. No working -CustomRule syntax was found, so this
        cmdlet is implemented documentation-faithful, matching the vendor sample XML
        element-for-element, and is not confirmed to succeed on this firmware.

        .PARAMETER Name
        Name of the custom signature (1-15 characters, no commas).

        .PARAMETER Protocol
        'TCP', 'UDP', 'ICMP' or 'ALL'. Confirmed live: an invalid value is rejected with a
        501 naming /IPSCustomSignature/Protocol.

        .PARAMETER CustomRule
        Signature definition string. See .DESCRIPTION - no syntax that this firmware accepts
        was found; every attempt was rejected regardless of content.

        .PARAMETER Severity
        'Critical', 'Major', 'Moderate', 'Minor' or 'Warning', per the vendor documentation.
        Not independently confirmed live, because -CustomRule always blocked the create.

        .PARAMETER RecommendedAction
        'Allow Packet', 'Drop Packet', 'Drop Session', 'Reset' or 'Bypass Session'. The
        vendor's attribute table calls this field "Action" and marks it mandatory, but the
        actual XML element - confirmed live via InvalidParams - is <RecommendedAction>, as
        the vendor's own XML sample also shows. This is a table-vs-sample contradiction of
        the kind this project's build rules warn about (see CLAUDE.md section 5): the
        sample, not the table, matches the wire. The vendor doc also lists a cryptic value
        '3' in the same enum; per this build's task scope it was deliberately not tried
        against the live firewall and is not offered here - noted only as a documentation
        curiosity.

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
        None. Throws an exception if creation fails - which, on this firmware, is every
        attempt so far. See .DESCRIPTION.

        .EXAMPLE
        # Documentation-faithful call; unconfirmed to succeed on this firmware - see .DESCRIPTION
        New-SfosIPSCustomSignature -Name "BlockTelnet" -Protocol TCP -CustomRule 'alert tcp any any -> any any (msg:"probe"; sid:1000001; rev:1;)' -Severity Minor -RecommendedAction "Allow Packet"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Unconfirmed on this firmware - see .DESCRIPTION. Implemented documentation-faithful,
        matching the vendor sample element-for-element.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPSCustomSignature
#>
function New-SfosIPSCustomSignature {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('TCP', 'UDP', 'ICMP', 'ALL')]
        [string]$Protocol,

        [Parameter(Mandatory)]
        [string]$CustomRule,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'Major', 'Moderate', 'Minor', 'Warning')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('Allow Packet', 'Drop Packet', 'Drop Session', 'Reset', 'Bypass Session')]
        [string]$RecommendedAction,

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
        if (-not $PSCmdlet.ShouldProcess("IPSCustomSignature '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $protocolEsc = ConvertTo-SfosXmlEscaped -Text $Protocol
        $ruleEsc = ConvertTo-SfosXmlEscaped -Text $CustomRule
        $severityEsc = ConvertTo-SfosXmlEscaped -Text $Severity
        $actionEsc = ConvertTo-SfosXmlEscaped -Text $RecommendedAction

        $inner = @"
<Set operation="add">
  <IPSCustomSignature>
    <Name>$nameEsc</Name>
    <Protocol>$protocolEsc</Protocol>
    <CustomRule>$ruleEsc</CustomRule>
    <Severity>$severityEsc</Severity>
    <RecommendedAction>$actionEsc</RecommendedAction>
  </IPSCustomSignature>
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
            throw "Failed to create IPSCustomSignature object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSCustomSignature' -Action 'create' -Target $Name
    }
}

<#
        .SYNOPSIS
        Updates an existing IPSCustomSignature object on the Sophos Firewall.

        .DESCRIPTION
        Updates an IPSCustomSignature object using the Sophos Firewall XML API, reading the
        current object first and keeping whatever the caller does not explicitly pass -
        SFOS replaces the whole entity on update.

        UNCONFIRMED on this firmware, for the same reason as New-SfosIPSCustomSignature: no
        IPSCustomSignature could be created to update in the first place - see that
        cmdlet's .DESCRIPTION. Because Get-SfosIPSCustomSignature returns an empty result
        for every name on this firmware, calling this cmdlet against any name currently
        throws "was not found" rather than reaching the update call at all.

        .PARAMETER Name
        Name of the target custom signature.

        .PARAMETER Protocol
        'TCP', 'UDP', 'ICMP' or 'ALL'. If omitted, the existing value is kept.

        .PARAMETER CustomRule
        Signature definition string. If omitted, the existing value is kept. See
        New-SfosIPSCustomSignature for why no known-working syntax exists for this field on
        this firmware.

        .PARAMETER Severity
        'Critical', 'Major', 'Moderate', 'Minor' or 'Warning'. If omitted, the existing
        value is kept.

        .PARAMETER RecommendedAction
        'Allow Packet', 'Drop Packet', 'Drop Session', 'Reset' or 'Bypass Session'. If
        omitted, the existing value is kept. See New-SfosIPSCustomSignature's
        .PARAMETER RecommendedAction for why this is the wire element name, not "Action".

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
        None. Throws an exception if the update fails, including "was not found" for any
        name on a firmware where no IPSCustomSignature could ever be created.

        .EXAMPLE
        # Documentation-faithful call; unconfirmed to succeed on this firmware - see .DESCRIPTION
        Set-SfosIPSCustomSignature -Name "BlockTelnet" -Severity Major

        .NOTES
        Minimum supported PowerShell version: 5.1
        Unconfirmed on this firmware - see .DESCRIPTION.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPSCustomSignature
#>
function Set-SfosIPSCustomSignature {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('TCP', 'UDP', 'ICMP', 'ALL')]
        [string]$Protocol,

        [string]$CustomRule,

        [ValidateSet('Critical', 'Major', 'Moderate', 'Minor', 'Warning')]
        [string]$Severity,

        [ValidateSet('Allow Packet', 'Drop Packet', 'Drop Session', 'Reset', 'Bypass Session')]
        [string]$RecommendedAction,

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
        $existing = @(Get-SfosIPSCustomSignature -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPSCustomSignature object '$Name' was not found."
        }

        $targetProtocol = if ($PSBoundParameters.ContainsKey('Protocol')) { $Protocol } else { [string]$existing[0].Protocol }
        $targetRule = if ($PSBoundParameters.ContainsKey('CustomRule')) { $CustomRule } else { [string]$existing[0].CustomRule }
        $targetSeverity = if ($PSBoundParameters.ContainsKey('Severity')) { $Severity } else { [string]$existing[0].Severity }
        $targetAction = if ($PSBoundParameters.ContainsKey('RecommendedAction')) { $RecommendedAction } else { [string]$existing[0].RecommendedAction }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $protocolEsc = ConvertTo-SfosXmlEscaped -Text $targetProtocol
        $ruleEsc = ConvertTo-SfosXmlEscaped -Text $targetRule
        $severityEsc = ConvertTo-SfosXmlEscaped -Text $targetSeverity
        $actionEsc = ConvertTo-SfosXmlEscaped -Text $targetAction

        $inner = @"
<Set operation="update">
  <IPSCustomSignature>
    <Name>$nameEsc</Name>
    <Protocol>$protocolEsc</Protocol>
    <CustomRule>$ruleEsc</CustomRule>
    <Severity>$severityEsc</Severity>
    <RecommendedAction>$actionEsc</RecommendedAction>
  </IPSCustomSignature>
</Set>
"@

        if (-not $PSCmdlet.ShouldProcess("IPSCustomSignature '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating IPSCustomSignature object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSCustomSignature' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an IPSCustomSignature object from the Sophos Firewall.

        .DESCRIPTION
        Removes an IPSCustomSignature object using the Sophos Firewall XML API. This cmdlet
        supports ShouldProcess; use -WhatIf to preview the change.

        Like Remove-SfosIPSPolicy, deleting a name that does not exist answers 200
        'Configuration applied successfully' (measured), so this cmdlet reads the object
        first and throws 'was not found' rather than trusting that response. Because no
        IPSCustomSignature could be created on this firmware (see
        New-SfosIPSCustomSignature), this cmdlet's delete-of-an-existing-object path could
        not be exercised end to end - only the delete-of-a-nonexistent-name behaviour, and
        the pre-check that guards against it, are confirmed.

        .PARAMETER Name
        Name of the target custom signature.

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
        None. Throws an exception if removal fails, or if the named object does not exist.

        .EXAMPLE
        Remove-SfosIPSCustomSignature -Name "BlockTelnet"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Delete-of-an-existing-object path unconfirmed on this firmware - see .DESCRIPTION.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosIPSCustomSignature
#>
function Remove-SfosIPSCustomSignature {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 15)]
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
        $existing = @(Get-SfosIPSCustomSignature -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The IPSCustomSignature object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("IPSCustomSignature '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><IPSCustomSignature><Name>$nameEsc</Name></IPSCustomSignature></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove IPSCustomSignature object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSCustomSignature' -Action 'remove' -Target $Name
    }
}

#endregion

#region IPSSwitch
# Entity: IPS switch (PROTECT > Intrusion Prevention > IPS switch). Device-wide singleton -
# there is no Add/Update/Delete, just one combined Get/Set endpoint. Wire root is
# <IPSSwitch>, with a single child <Status>Enable|Disable</Status> [doc].
#
# Measured live against SFOS 22.0 (FW2 lab, 2026-08-12; the equivalent status-XPath finding
# was first measured on FW1 in an earlier session against this same module and is
# reconfirmed here):
# - On a successful Get the <Status> node carries NO 'code' attribute - it is the entity's
#   one DATA field, not an API status, exactly like Get-SfosSDWANPolicyRouteStatus's
#   ON/OFF field in the Routing module. Core's default status heuristic
#   (Status[@code or not(../Name)]) would misread it: IPSSwitch has no <Name> sibling
#   either, so the second half of that OR is also true, and the plain-text value 'Enable'
#   would be read as an unrecognised status and thrown. Get-SfosIPSSwitch therefore checks
#   explicitly for a coded Status node first (a real error/warning) and only falls back to
#   reading the value as data when no 'code' attribute is present.
# - The XPath for a genuine API error is /Response/IPSSwitch/Status[@code] - confirmed by
#   provoking an invalid value: <IPSSwitch><Status>Bogus</Status></IPSSwitch> answers code
#   501 "Configuration parameters validation failed." with
#   <InvalidParams><Params>/IPSSwitch/Status</Params></InvalidParams>.
# - operation="update" works normally for the two documented values and reports a genuine
#   coded Status (200) on success, so Set-SfosIPSSwitch uses the project's standard
#   Assert-SfosApiReturnSuccess check unmodified - only the Get side needs the special
#   handling above.
# - Write test (FW2, this run): baseline was Enable. Toggled to Disable, confirmed via Get,
#   immediately toggled back to Enable, confirmed via Get - two calls total, minimal window.
#   No admin/API access interruption was observed (unlike the SpoofPrevention LAN-zone trap
#   documented in that region below), since this switch has nothing to do with zone-based
#   traffic filtering.

<#
.SYNOPSIS
    Retrieves the device-wide IPSSwitch status from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the IPS switch (Intrusion Prevention > IPS
    switch), the master on/off switch for the whole intrusion prevention engine. Use -AsXml
    to return the raw XML node instead of a PowerShell-friendly object.

    The wire's <Status> field on this entity is DATA, not an API status - see the region
    header for why this cmdlet cannot use the project's default status heuristic unmodified.

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
    # Check whether intrusion prevention is currently switched on
    Get-SfosIPSSwitch

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall, returned Status 'Enable' matching the
    known baseline.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/ipsswitch/operations/IPSswitch.html

.LINK
    Set-SfosIPSSwitch
#>
function Get-SfosIPSSwitch {
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><IPSSwitch></IPSSwitch></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving IPSSwitch: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # See region header: a coded Status is a genuine API error/warning and goes through the
    # generic table-driven check; a code-less Status is the Enable/Disable data value.
    $codedStatus = $XmlResponse.SelectSingleNode('/Response/IPSSwitch/Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSSwitch' -Action 'get'
    }

    $node = $XmlResponse.SelectSingleNode('/Response/IPSSwitch/Status')
    if (-not $node) {
        throw 'IPSSwitch could not be retrieved from the firewall.'
    }

    $value = [string]$node.InnerText
    if ($value -ne 'Enable' -and $value -ne 'Disable') {
        throw "Sophos API returned an unrecognised IPSSwitch status: '$value'"
    }

    if ($AsXml) {
        return $XmlResponse.SelectSingleNode('/Response/IPSSwitch')
    }

    return [PSCustomObject]@{
        Status = $value
    }
}

<#
.SYNOPSIS
    Switches the device-wide intrusion prevention engine on or off.

.DESCRIPTION
    Updates the IPS switch (Intrusion Prevention > IPS switch) using the Sophos Firewall XML
    API. Supports ShouldProcess; use -WhatIf to preview. Reads the result back after a
    successful-looking write and throws if the confirmed state does not match what was
    requested.

.PARAMETER Status
    'Enable' or 'Disable' [doc]. Mandatory.

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
    None. Throws an exception if the update fails or cannot be confirmed.

.EXAMPLE
    Set-SfosIPSSwitch -Status Disable

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: toggled Disable -> confirmed -> Enable -> confirmed against the lab
    firewall, ending back at the original baseline. The error path (an invalid value
    answering code 501 at /Response/IPSSwitch/Status[@code]) was also reproduced - see the
    task report for both transcripts.
    ConfirmImpact High since 2026-08-12: device-wide IPS main switch; automation must pass
    -Confirm:$false.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/ipsswitch/operations/IPSswitch.html

.LINK
    Get-SfosIPSSwitch
#>
function Set-SfosIPSSwitch {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Status,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("IPSSwitch on $($params.Firewall)", "Set status $Status")) {
        return
    }

    $inner = @"
<Set operation="update">
  <IPSSwitch>
    <Status>$Status</Status>
  </IPSSwitch>
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
        throw "Error updating IPSSwitch: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSSwitch' -Action 'update'

    $confirmed = Get-SfosIPSSwitch -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if ($confirmed.Status -ne $Status) {
        throw "IPSSwitch update reported success but could not be confirmed on the firewall (expected Status '$Status', found '$($confirmed.Status)')."
    }
}

#endregion

#region IPSFullSignaturePack
# Entity: IPS full signature pack (PROTECT > Intrusion Prevention > IPS full signature
# pack). Device-wide singleton, wire root <IPSFullSignaturePack>, single child
# <Status>enable|disable|show</Status> - all lowercase per doc and matching the live
# baseline ('disable'), unlike IPSSwitch's Enable/Disable casing right next to it in the
# same doc section.
#
# Same DATENFELD-without-'code' trap as IPSSwitch's Status field on Get - see that region's
# header for the mechanism. Get-SfosIPSFullSignaturePack uses the identical special-case
# handling.
#
# Measured live against SFOS 22.0 (FW2 lab, 2026-08-12; write tests run under the user's
# explicit 2026-08-11 release for this entity, per the group order):
# - Status='show' -> code 500 "Operation could not be performed on Entity."
# - Status='Bogus' (invalid-value probe) -> also code 500, same message - indistinguishable
#   from the 'show' result, so 500 alone cannot be used to tell "documented-but-unsupported
#   value" from "genuinely invalid value" on this firmware.
# - Status='enable' with operation="update" -> code 500, and a follow-up Get still reported
#   'disable' - no state change.
# - Status='disable' with operation="update" (attempted immediately after, as the planned
#   revert) -> ALSO code 500, even though the target value matched the already-current
#   state - update fails uniformly for every value tried on this entity, not just invalid
#   ones.
# - operation="add" was tried as a fallback (a documented verb per CLAUDE.md SS5) with
#   Status='enable': HTTP itself returned 200, but the response body carried NO
#   <IPSFullSignaturePack> element and no <Status> at all - just the bare successful
#   <Login>. A follow-up Get confirmed nothing had changed (still 'disable'). This is a
#   genuine silent no-op with an empty, harmless-looking response - the same defect class as
#   GuestUser's edit-creates-duplicate trap and Remove-SfosSSLBookmark's no-op delete
#   documented in CLAUDE.md: a write that changes nothing and leaves nothing to hold onto.
# - Conclusion: IPSFullSignaturePack cannot be toggled through the API on this firmware by
#   any verb/value combination tried. Set-SfosIPSFullSignaturePack therefore uses
#   operation="update" only - the sole verb this project trusts per SS5 - and reliably
#   throws via the coded 500 rather than silently doing nothing. Do not "fix" this by
#   switching to operation="add": that variant is the dangerous silent no-op, not a working
#   alternative.
# - Net effect on the firewall: none. Every attempted write failed with a genuine error
#   before anything changed, so no baseline restoration was needed for this entity - see the
#   task report's Baseline section for the confirming Get.

<#
.SYNOPSIS
    Retrieves the device-wide IPSFullSignaturePack status from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the IPS full signature pack setting (Intrusion
    Prevention > IPS full signature pack). Use -AsXml to return the raw XML node instead of
    a PowerShell-friendly object.

    The wire's <Status> field on this entity is DATA, not an API status, exactly like
    IPSSwitch - see that region's header for the mechanism this cmdlet works around.

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
    # Check whether the full (as opposed to base) IPS signature pack is active
    Get-SfosIPSFullSignaturePack

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall, returned Status 'disable' matching the
    known baseline.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/ipsfullsignaturepack/operations/IPSFullSignaturePack.html

.LINK
    Set-SfosIPSFullSignaturePack
#>
function Get-SfosIPSFullSignaturePack {
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><IPSFullSignaturePack></IPSFullSignaturePack></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving IPSFullSignaturePack: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # Same DATENFELD-without-'code' pattern as IPSSwitch - see the region header.
    $codedStatus = $XmlResponse.SelectSingleNode('/Response/IPSFullSignaturePack/Status[@code]')
    if ($codedStatus) {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSFullSignaturePack' -Action 'get'
    }

    $node = $XmlResponse.SelectSingleNode('/Response/IPSFullSignaturePack/Status')
    if (-not $node) {
        throw 'IPSFullSignaturePack could not be retrieved from the firewall.'
    }

    $value = [string]$node.InnerText
    if ($value -ne 'enable' -and $value -ne 'disable') {
        throw "Sophos API returned an unrecognised IPSFullSignaturePack status: '$value'"
    }

    if ($AsXml) {
        return $XmlResponse.SelectSingleNode('/Response/IPSFullSignaturePack')
    }

    return [PSCustomObject]@{
        Status = $value
    }
}

<#
.SYNOPSIS
    Sets the device-wide IPSFullSignaturePack status on the Sophos Firewall.

.DESCRIPTION
    Updates the IPS full signature pack setting (Intrusion Prevention > IPS full signature
    pack) using the Sophos Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

    Measured broken on this firmware for every value tried, including a same-value
    'disable' re-send - see the region header for the full transcript. This cmdlet is
    implemented documentation-faithful with operation="update" (the only verb this project
    uses per CLAUDE.md SS5) and is expected to throw a code-500 error on current firmware
    rather than reporting a false success; it still confirms the result via Get afterwards
    as a safety net in case a firmware update makes the write succeed.

.PARAMETER Status
    'enable', 'disable' or 'show' [doc], all lowercase. Mandatory.

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
    None. Throws an exception if the update fails or cannot be confirmed - expected to throw
    on current firmware, see .DESCRIPTION.

.EXAMPLE
    Set-SfosIPSFullSignaturePack -Status enable

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live (with the user's explicit 2026-08-11 release for write tests on this
    entity): 'show', an invalid value, 'enable' and 'disable' were all attempted with
    operation="update" and all four answered code 500 without changing the firewall's state
    - see the region header. This cmdlet is shipped in this documented-but-broken state
    rather than switched to the operation="add" variant, which was also tried and found to
    be a silent no-op (empty 200-looking response, no state change) - a worse failure mode
    than a loud 500.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/ipsfullsignaturepack/operations/IPSFullSignaturePack.html

.LINK
    Get-SfosIPSFullSignaturePack
#>
function Set-SfosIPSFullSignaturePack {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('enable', 'disable', 'show')]
        [string]$Status,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("IPSFullSignaturePack on $($params.Firewall)", "Set status $Status")) {
        return
    }

    $inner = @"
<Set operation="update">
  <IPSFullSignaturePack>
    <Status>$Status</Status>
  </IPSFullSignaturePack>
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
        throw "Error updating IPSFullSignaturePack: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'IPSFullSignaturePack' -Action 'update'

    if ($Status -eq 'show') {
        # 'show' is not a persistent state - see the region header, where it answered the
        # same code 500 as every other value on this firmware. Nothing to confirm.
        return
    }

    $confirmed = Get-SfosIPSFullSignaturePack -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if ($confirmed.Status -ne $Status) {
        throw "IPSFullSignaturePack update reported success but could not be confirmed on the firewall (expected Status '$Status', found '$($confirmed.Status)')."
    }
}

#endregion

#region DoSSettings
# Entity: DoS Settings (PROTECT > Intrusion Prevention > DoS Settings). Device-wide
# singleton, wire root <DoSSettings>, seven blocks: SYNFlood/UDPFlood/TCPFlood/ICMPFlood
# each with a <Source> and a <Destination> child (PacketRatePerSource/Destination,
# BurstRatePerSource/Destination, ApplyFlag), plus DroppedSourceRoutedPackets/
# DisableICMPRedirectPacket/DisableARPFlooding which each carry only a <Destination><
# ApplyFlag> [doc + live-DoSSettings.xml]. All 25 documented fields are "Mandatory: No", so
# every parameter on Set-SfosDoSSettings here is optional with no default, and a full
# read-modify-write across every block is mandatory per CLAUDE.md SS5.
#
# Measured live against SFOS 22.0 (FW2 lab, 2026-08-12; reconfirms the equivalent FW1
# finding from an earlier session against this same module):
# - The status XPath for both success and failure is /Response/DoSSettings/Status[@code] -
#   confirmed with a genuinely malformed field (PacketRatePerSource='abc' answers code 400
#   "synFlood.source.packetRate: json: cannot unmarshal string into go value of type int32",
#   the field path embedded directly in the message text) and with a normal successful write
#   (code 200 "Configuration applied successfully."). No DoSSettings data field is itself
#   named <Status>, so the default ObjectName-based heuristic in Assert-SfosApiReturnSuccess
#   needs no special handling here, unlike IPSSwitch/IPSFullSignaturePack above.
# - ApplyFlag is NOT validated server-side, confirmed again on FW2: sending
#   ICMPFlood/Source/ApplyFlag='Bogus' together with an otherwise unchanged, complete
#   DoSSettings body answers code 200 "Configuration applied successfully." and a follow-up
#   Get shows the field UNCHANGED at its previous value ('Disable') - the invalid value is
#   silently discarded rather than applied or rejected. This is the reason
#   Set-SfosDoSSettings enforces ValidateSet('Enable','Disable') on every *ApplyFlag
#   parameter client-side: the API's 200 response cannot be trusted to mean "the value you
#   sent is now in effect."
# - PacketRatePerSource/Destination and BurstRatePerSource/Destination are plain int32 on
#   the wire (see the 'abc' probe above); no documented upper bound was found beyond that,
#   so Set-SfosDoSSettings only enforces the type's own range.

<#
.SYNOPSIS
    Retrieves the device-wide DoSSettings from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the DoS Settings singleton (Intrusion
    Prevention > DoS Settings): per-direction packet/burst rate limits and enable flags for
    SYN/UDP/TCP/ICMP flood protection, plus three simple enable flags for dropped
    source-routed packets, ICMP redirect packets and ARP flood protection. Use -AsXml to
    return the raw XML node instead of a PowerShell-friendly object.

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
    PSCustomObject (default) with 27 flattened properties (see .NOTES for the naming
    scheme). System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    # Check the current SYN flood packet-rate limits
    Get-SfosDoSSettings | Select-Object SYNFloodSourcePacketRate, SYNFloodDestinationPacketRate

.NOTES
    Minimum supported PowerShell version: 5.1
    Property naming scheme: '<Block>SourcePacketRate', '<Block>SourceBurstRate',
    '<Block>SourceApplyFlag', '<Block>DestinationPacketRate', '<Block>DestinationBurstRate',
    '<Block>DestinationApplyFlag' for Block in SYNFlood/UDPFlood/TCPFlood/ICMPFlood (24
    properties), plus 'DroppedSourceRoutedPacketsApplyFlag',
    'DisableICMPRedirectPacketApplyFlag' and 'DisableARPFloodingApplyFlag' (3 more) - 27
    total, matching Set-SfosDoSSettings's parameter names exactly so a caller can read a
    property name straight off this object and pass it as a Set-SfosDoSSettings parameter
    name.
    Verified live: executed against the lab firewall; all 27 values matched the saved
    baseline XML.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/DoSSettings/operations/ConfigurationDOSSettings.html

.LINK
    Set-SfosDoSSettings
#>
function Get-SfosDoSSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DoSSettings>, a singleton
    # holding one configuration, and it has no <DoSSetting> child. The project build rules,
    # section 3, put the Sophos spelling above PowerShell habit and reserve the singular
    # concession for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><DoSSettings></DoSSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DoSSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DoSSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/DoSSettings')
    if (-not $node) {
        throw 'DoSSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        SYNFloodSourcePacketRate            = [int]$node.SYNFlood.Source.PacketRatePerSource
        SYNFloodSourceBurstRate             = [int]$node.SYNFlood.Source.BurstRatePerSource
        SYNFloodSourceApplyFlag             = [string]$node.SYNFlood.Source.ApplyFlag
        SYNFloodDestinationPacketRate       = [int]$node.SYNFlood.Destination.PacketRatePerDestination
        SYNFloodDestinationBurstRate        = [int]$node.SYNFlood.Destination.BurstRatePerDestination
        SYNFloodDestinationApplyFlag        = [string]$node.SYNFlood.Destination.ApplyFlag

        UDPFloodSourcePacketRate            = [int]$node.UDPFlood.Source.PacketRatePerSource
        UDPFloodSourceBurstRate             = [int]$node.UDPFlood.Source.BurstRatePerSource
        UDPFloodSourceApplyFlag             = [string]$node.UDPFlood.Source.ApplyFlag
        UDPFloodDestinationPacketRate       = [int]$node.UDPFlood.Destination.PacketRatePerDestination
        UDPFloodDestinationBurstRate        = [int]$node.UDPFlood.Destination.BurstRatePerDestination
        UDPFloodDestinationApplyFlag        = [string]$node.UDPFlood.Destination.ApplyFlag

        TCPFloodSourcePacketRate            = [int]$node.TCPFlood.Source.PacketRatePerSource
        TCPFloodSourceBurstRate             = [int]$node.TCPFlood.Source.BurstRatePerSource
        TCPFloodSourceApplyFlag             = [string]$node.TCPFlood.Source.ApplyFlag
        TCPFloodDestinationPacketRate       = [int]$node.TCPFlood.Destination.PacketRatePerDestination
        TCPFloodDestinationBurstRate        = [int]$node.TCPFlood.Destination.BurstRatePerDestination
        TCPFloodDestinationApplyFlag        = [string]$node.TCPFlood.Destination.ApplyFlag

        ICMPFloodSourcePacketRate           = [int]$node.ICMPFlood.Source.PacketRatePerSource
        ICMPFloodSourceBurstRate            = [int]$node.ICMPFlood.Source.BurstRatePerSource
        ICMPFloodSourceApplyFlag            = [string]$node.ICMPFlood.Source.ApplyFlag
        ICMPFloodDestinationPacketRate      = [int]$node.ICMPFlood.Destination.PacketRatePerDestination
        ICMPFloodDestinationBurstRate       = [int]$node.ICMPFlood.Destination.BurstRatePerDestination
        ICMPFloodDestinationApplyFlag       = [string]$node.ICMPFlood.Destination.ApplyFlag

        DroppedSourceRoutedPacketsApplyFlag = [string]$node.DroppedSourceRoutedPackets.Destination.ApplyFlag
        DisableICMPRedirectPacketApplyFlag  = [string]$node.DisableICMPRedirectPacket.Destination.ApplyFlag
        DisableARPFloodingApplyFlag         = [string]$node.DisableARPFlooding.Destination.ApplyFlag
    }
}

<#
.SYNOPSIS
    Updates the device-wide DoSSettings on the Sophos Firewall.

.DESCRIPTION
    Updates the DoS Settings singleton (Intrusion Prevention > DoS Settings) using the
    Sophos Firewall XML API. Reads the current settings first and resends every one of the
    27 fields across all seven blocks, overriding only what the caller explicitly passed
    (read-modify-write, reaching into every nested block per CLAUDE.md SS5) - omitting a
    block on this API clears it, and every field of this entity is "Mandatory: No" per the
    doc table, so a partial write is syntactically accepted and silently destructive.
    Supports ShouldProcess; use -WhatIf to preview.

    Every *ApplyFlag parameter is validated client-side against 'Enable'/'Disable' - see the
    region header for why: the firewall does not validate this field itself and silently
    discards (not applies, not rejects) an invalid value while still answering code 200.

.PARAMETER SYNFloodSourcePacketRate
    SYN flood packet rate limit per source, in packets/second. If omitted, the current value is kept.

.PARAMETER SYNFloodSourceBurstRate
    SYN flood burst rate limit per source. If omitted, the current value is kept.

.PARAMETER SYNFloodSourceApplyFlag
    'Enable' or 'Disable' SYN flood protection per source. If omitted, the current value is kept.

.PARAMETER SYNFloodDestinationPacketRate
    SYN flood packet rate limit per destination. If omitted, the current value is kept.

.PARAMETER SYNFloodDestinationBurstRate
    SYN flood burst rate limit per destination. If omitted, the current value is kept.

.PARAMETER SYNFloodDestinationApplyFlag
    'Enable' or 'Disable' SYN flood protection per destination. If omitted, the current value is kept.

.PARAMETER UDPFloodSourcePacketRate
    UDP flood packet rate limit per source. If omitted, the current value is kept.

.PARAMETER UDPFloodSourceBurstRate
    UDP flood burst rate limit per source. If omitted, the current value is kept.

.PARAMETER UDPFloodSourceApplyFlag
    'Enable' or 'Disable' UDP flood protection per source. If omitted, the current value is kept.

.PARAMETER UDPFloodDestinationPacketRate
    UDP flood packet rate limit per destination. If omitted, the current value is kept.

.PARAMETER UDPFloodDestinationBurstRate
    UDP flood burst rate limit per destination. If omitted, the current value is kept.

.PARAMETER UDPFloodDestinationApplyFlag
    'Enable' or 'Disable' UDP flood protection per destination. If omitted, the current value is kept.

.PARAMETER TCPFloodSourcePacketRate
    TCP flood packet rate limit per source. If omitted, the current value is kept.

.PARAMETER TCPFloodSourceBurstRate
    TCP flood burst rate limit per source. If omitted, the current value is kept.

.PARAMETER TCPFloodSourceApplyFlag
    'Enable' or 'Disable' TCP flood protection per source. If omitted, the current value is kept.

.PARAMETER TCPFloodDestinationPacketRate
    TCP flood packet rate limit per destination. If omitted, the current value is kept.

.PARAMETER TCPFloodDestinationBurstRate
    TCP flood burst rate limit per destination. If omitted, the current value is kept.

.PARAMETER TCPFloodDestinationApplyFlag
    'Enable' or 'Disable' TCP flood protection per destination. If omitted, the current value is kept.

.PARAMETER ICMPFloodSourcePacketRate
    ICMP flood packet rate limit per source. If omitted, the current value is kept.

.PARAMETER ICMPFloodSourceBurstRate
    ICMP flood burst rate limit per source. If omitted, the current value is kept.

.PARAMETER ICMPFloodSourceApplyFlag
    'Enable' or 'Disable' ICMP flood protection per source. If omitted, the current value is kept.

.PARAMETER ICMPFloodDestinationPacketRate
    ICMP flood packet rate limit per destination. If omitted, the current value is kept.

.PARAMETER ICMPFloodDestinationBurstRate
    ICMP flood burst rate limit per destination. If omitted, the current value is kept.

.PARAMETER ICMPFloodDestinationApplyFlag
    'Enable' or 'Disable' ICMP flood protection per destination. If omitted, the current value is kept.

.PARAMETER DroppedSourceRoutedPacketsApplyFlag
    'Enable' or 'Disable' dropping of source-routed packets. If omitted, the current value is kept.

.PARAMETER DisableICMPRedirectPacketApplyFlag
    'Enable' or 'Disable' disabling of ICMP redirect packets. If omitted, the current value is kept.

.PARAMETER DisableARPFloodingApplyFlag
    'Enable' or 'Disable' ARP flood protection. If omitted, the current value is kept.

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
    # Change only the ICMP flood source packet rate, every other field is preserved
    Set-SfosDoSSettings -ICMPFloodSourcePacketRate 121

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the example above was executed against the lab firewall (changing the
    rate from its baseline of 120 to 121), confirmed via Get-SfosDoSSettings, then reverted
    to exactly 120 and reconfirmed - the raw XML after revert matched the saved baseline
    byte for byte. The error path (a malformed field answering code 400 with the field path
    embedded in the message) and the ApplyFlag silent-discard behaviour (code 200, value
    unchanged) were also reproduced - see the task report and the region header.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/DoSSettings/operations/ConfigurationDOSSettings.html

.LINK
    Get-SfosDoSSettings
#>
function Set-SfosDoSSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DoSSettings>, a singleton
    # holding one configuration, and it has no <DoSSetting> child. The project build rules,
    # section 3, put the Sophos spelling above PowerShell habit and reserve the singular
    # concession for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(1, 2147483647)]
        [int]$SYNFloodSourcePacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$SYNFloodSourceBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$SYNFloodSourceApplyFlag,
        [ValidateRange(1, 2147483647)]
        [int]$SYNFloodDestinationPacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$SYNFloodDestinationBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$SYNFloodDestinationApplyFlag,

        [ValidateRange(1, 2147483647)]
        [int]$UDPFloodSourcePacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$UDPFloodSourceBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$UDPFloodSourceApplyFlag,
        [ValidateRange(1, 2147483647)]
        [int]$UDPFloodDestinationPacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$UDPFloodDestinationBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$UDPFloodDestinationApplyFlag,

        [ValidateRange(1, 2147483647)]
        [int]$TCPFloodSourcePacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$TCPFloodSourceBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$TCPFloodSourceApplyFlag,
        [ValidateRange(1, 2147483647)]
        [int]$TCPFloodDestinationPacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$TCPFloodDestinationBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$TCPFloodDestinationApplyFlag,

        [ValidateRange(1, 2147483647)]
        [int]$ICMPFloodSourcePacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$ICMPFloodSourceBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$ICMPFloodSourceApplyFlag,
        [ValidateRange(1, 2147483647)]
        [int]$ICMPFloodDestinationPacketRate,
        [ValidateRange(1, 2147483647)]
        [int]$ICMPFloodDestinationBurstRate,
        [ValidateSet('Enable', 'Disable')]
        [string]$ICMPFloodDestinationApplyFlag,

        [ValidateSet('Enable', 'Disable')]
        [string]$DroppedSourceRoutedPacketsApplyFlag,
        [ValidateSet('Enable', 'Disable')]
        [string]$DisableICMPRedirectPacketApplyFlag,
        [ValidateSet('Enable', 'Disable')]
        [string]$DisableARPFloodingApplyFlag,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosDoSSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    # One ContainsKey-driven merge per field, looped rather than duplicated 27 times - the
    # property names on $existing were chosen to match these parameter names exactly (see
    # Get-SfosDoSSettings's .NOTES), so this loop is generic across all seven blocks.
    $fieldNames = @(
        'SYNFloodSourcePacketRate', 'SYNFloodSourceBurstRate', 'SYNFloodSourceApplyFlag',
        'SYNFloodDestinationPacketRate', 'SYNFloodDestinationBurstRate', 'SYNFloodDestinationApplyFlag',
        'UDPFloodSourcePacketRate', 'UDPFloodSourceBurstRate', 'UDPFloodSourceApplyFlag',
        'UDPFloodDestinationPacketRate', 'UDPFloodDestinationBurstRate', 'UDPFloodDestinationApplyFlag',
        'TCPFloodSourcePacketRate', 'TCPFloodSourceBurstRate', 'TCPFloodSourceApplyFlag',
        'TCPFloodDestinationPacketRate', 'TCPFloodDestinationBurstRate', 'TCPFloodDestinationApplyFlag',
        'ICMPFloodSourcePacketRate', 'ICMPFloodSourceBurstRate', 'ICMPFloodSourceApplyFlag',
        'ICMPFloodDestinationPacketRate', 'ICMPFloodDestinationBurstRate', 'ICMPFloodDestinationApplyFlag',
        'DroppedSourceRoutedPacketsApplyFlag', 'DisableICMPRedirectPacketApplyFlag', 'DisableARPFloodingApplyFlag'
    )

    $t = @{}
    foreach ($fieldName in $fieldNames) {
        if ($PSBoundParameters.ContainsKey($fieldName)) {
            $t[$fieldName] = $PSBoundParameters[$fieldName]
        }
        else {
            $t[$fieldName] = $existing.$fieldName
        }
    }

    if (-not $PSCmdlet.ShouldProcess("DoSSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <DoSSettings>
    <SYNFlood>
      <Source>
        <PacketRatePerSource>$($t.SYNFloodSourcePacketRate)</PacketRatePerSource>
        <BurstRatePerSource>$($t.SYNFloodSourceBurstRate)</BurstRatePerSource>
        <ApplyFlag>$($t.SYNFloodSourceApplyFlag)</ApplyFlag>
      </Source>
      <Destination>
        <PacketRatePerDestination>$($t.SYNFloodDestinationPacketRate)</PacketRatePerDestination>
        <BurstRatePerDestination>$($t.SYNFloodDestinationBurstRate)</BurstRatePerDestination>
        <ApplyFlag>$($t.SYNFloodDestinationApplyFlag)</ApplyFlag>
      </Destination>
    </SYNFlood>
    <UDPFlood>
      <Source>
        <PacketRatePerSource>$($t.UDPFloodSourcePacketRate)</PacketRatePerSource>
        <BurstRatePerSource>$($t.UDPFloodSourceBurstRate)</BurstRatePerSource>
        <ApplyFlag>$($t.UDPFloodSourceApplyFlag)</ApplyFlag>
      </Source>
      <Destination>
        <PacketRatePerDestination>$($t.UDPFloodDestinationPacketRate)</PacketRatePerDestination>
        <BurstRatePerDestination>$($t.UDPFloodDestinationBurstRate)</BurstRatePerDestination>
        <ApplyFlag>$($t.UDPFloodDestinationApplyFlag)</ApplyFlag>
      </Destination>
    </UDPFlood>
    <TCPFlood>
      <Source>
        <PacketRatePerSource>$($t.TCPFloodSourcePacketRate)</PacketRatePerSource>
        <BurstRatePerSource>$($t.TCPFloodSourceBurstRate)</BurstRatePerSource>
        <ApplyFlag>$($t.TCPFloodSourceApplyFlag)</ApplyFlag>
      </Source>
      <Destination>
        <PacketRatePerDestination>$($t.TCPFloodDestinationPacketRate)</PacketRatePerDestination>
        <BurstRatePerDestination>$($t.TCPFloodDestinationBurstRate)</BurstRatePerDestination>
        <ApplyFlag>$($t.TCPFloodDestinationApplyFlag)</ApplyFlag>
      </Destination>
    </TCPFlood>
    <ICMPFlood>
      <Source>
        <PacketRatePerSource>$($t.ICMPFloodSourcePacketRate)</PacketRatePerSource>
        <BurstRatePerSource>$($t.ICMPFloodSourceBurstRate)</BurstRatePerSource>
        <ApplyFlag>$($t.ICMPFloodSourceApplyFlag)</ApplyFlag>
      </Source>
      <Destination>
        <PacketRatePerDestination>$($t.ICMPFloodDestinationPacketRate)</PacketRatePerDestination>
        <BurstRatePerDestination>$($t.ICMPFloodDestinationBurstRate)</BurstRatePerDestination>
        <ApplyFlag>$($t.ICMPFloodDestinationApplyFlag)</ApplyFlag>
      </Destination>
    </ICMPFlood>
    <DroppedSourceRoutedPackets>
      <Destination>
        <ApplyFlag>$($t.DroppedSourceRoutedPacketsApplyFlag)</ApplyFlag>
      </Destination>
    </DroppedSourceRoutedPackets>
    <DisableICMPRedirectPacket>
      <Destination>
        <ApplyFlag>$($t.DisableICMPRedirectPacketApplyFlag)</ApplyFlag>
      </Destination>
    </DisableICMPRedirectPacket>
    <DisableARPFlooding>
      <Destination>
        <ApplyFlag>$($t.DisableARPFloodingApplyFlag)</ApplyFlag>
      </Destination>
    </DisableARPFlooding>
  </DoSSettings>
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
        throw "Error updating DoSSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DoSSettings' -Action 'update'
}

#endregion

#region SpoofPrevention
# Entity: Spoof Prevention (PROTECT > Intrusion Prevention > Spoof Prevention). Device-wide
# singleton. Wire root <SpoofPrevention> wraps a child of the SAME name holding the main
# switch: <SpoofPrevention><SpoofPrevention>Enable|Disable</SpoofPrevention>...</
# SpoofPrevention> [doc sample + live-SpoofPrevention.xml]. When the switch is Enable, three
# independent filter blocks may each be turned on for a list of zones:
# <IPSpoofing><EnableOnZone><Zone>...</Zone>...</EnableOnZone></IPSpoofing>, and the same
# shape for <MACFilter> and <IPMACFilter>. An additional flat field
# <RestrictUnknownIPOnTrustedMAC>Enable|Disable</RestrictUnknownIPOnTrustedMAC> sits beside
# the three blocks.
#
# CRITICAL MEASURED FINDING, measured once and deliberately not retested (see below):
# enabling IPSpoofing for the zone that carries the management/API interface, on a
# topology where that interface shares its subnet with another interface of a different
# zone, made the firewall drop its own admin/API traffic on that interface as spoofed -
# the API and admin connection was lost outright and the appliance had to be recovered
# through an out-of-band path. This is exactly the scenario the IP-spoofing filter is
# designed to catch (asymmetric routing on a shared subnet across two interfaces of
# different zones), so it is a real, reproducible risk on any topology with the same
# shared-subnet layout, not a fluke.
#
# Because of that finding, this run tests Spoof Prevention ONLY with IPSpoofing enabled
# for a single zone that carries no admin/API path, never the management zone.
# MACFilter/IPMACFilter are built structurally (same EnableOnZone/Zone shape, confirmed by
# the working IPSpoofing write below) but their own zone-list write path was not separately
# exercised - see .NOTES on Set-SfosSpoofPrevention.
#
# Measured live against SFOS 22.0 (FW2 lab, 2026-08-12):
# - Status-XPath for a real API error is /Response/SpoofPrevention/Status[@code] - confirmed
#   by sending the main switch value 'Bogus': answers code 400 '"Invalid request."' (the
#   quotes are literally part of the message text on the wire).
# - operation="update" with SpoofPrevention (main switch) = 'Enable', an empty
#   RestrictUnknownIPOnTrustedMAC = 'Disable', IPSpoofing/EnableOnZone/Zone = 'DMZ', and
#   empty (childless) EnableOnZone wrappers for MACFilter/IPMACFilter answers code 200 and a
#   follow-up Get echoes back exactly SpoofPrevention=Enable,
#   RestrictUnknownIPOnTrustedMAC=Disable, IPSpoofing/EnableOnZone/Zone=DMZ - and OMITS the
#   MACFilter/IPMACFilter wrappers entirely, since their EnableOnZone had no <Zone>
#   children. Reachability (a live Get-SfosZone call through the same session) was
#   reconfirmed immediately afterwards - no admin/API impact from a DMZ-only zone.
# - Reverting with operation="update" and ONLY <SpoofPrevention>Disable</SpoofPrevention> -
#   no RestrictUnknownIPOnTrustedMAC, no IPSpoofing/MACFilter/IPMACFilter elements at all -
#   answered code 200 and a follow-up Get returned exactly the pre-test baseline
#   (<SpoofPrevention><SpoofPrevention>Disable</SpoofPrevention></SpoofPrevention>, nothing
#   else), byte-for-byte identical to the saved baseline file. Disabling the main switch
#   therefore clears/ignores every other field regardless of what was previously configured.
#   This measured behaviour is deliberately mirrored in Set-SfosSpoofPrevention's own wire
#   building below - see its .DESCRIPTION - rather than guessed at with an unverified
#   "Disable plus full field set" combination.

<#
.SYNOPSIS
    Internal helper: builds the <EnableOnZone> XML fragment for one Spoof Prevention filter
    block from a zone name list. Not exported.

.DESCRIPTION
    Shared by the IPSpoofing/MACFilter/IPMACFilter blocks inside Set-SfosSpoofPrevention -
    all three use the identical <EnableOnZone><Zone>...</Zone>...</EnableOnZone> shape
    [doc sample, confirmed live for IPSpoofing]. An empty list produces a childless, but
    still present, <EnableOnZone></EnableOnZone> - matching what was sent (and accepted) for
    MACFilter/IPMACFilter during the live IPSpoofing-only write test.
#>
function ConvertTo-SfosSpoofPreventionZoneListXml {
    param([string[]]$ZoneList)

    $zonesXml = ''
    foreach ($zone in @($ZoneList)) {
        if (-not $zone) { continue }
        $zoneEsc = ConvertTo-SfosXmlEscaped -Text $zone
        $zonesXml += "<Zone>$zoneEsc</Zone>"
    }
    return "<EnableOnZone>$zonesXml</EnableOnZone>"
}

<#
.SYNOPSIS
    Retrieves the device-wide SpoofPrevention settings from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the Spoof Prevention singleton (Intrusion
    Prevention > Spoof Prevention): the main on/off switch, the RestrictUnknownIPOnTrustedMAC
    flag, and the three per-zone filter lists (IPSpoofing, MACFilter, IPMACFilter). Use
    -AsXml to return the raw XML node instead of a PowerShell-friendly object.

    When the main switch is Disable, the firewall omits every other field from the response
    (measured - see the region header), so RestrictUnknownIPOnTrustedMAC and all three zone
    lists read back empty/blank in that state, not because they were cleared but because
    they were never returned at all.

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
    # Check whether spoof prevention is on, and if so, for which zones
    Get-SfosSpoofPrevention

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall in both the Disable baseline state and
    the Enable/DMZ-only test state, matching the raw XML captured in both cases.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/SpoofPreventionSettings/operations/ConfigureSpoofPrevention.html

.LINK
    Set-SfosSpoofPrevention
#>
function Get-SfosSpoofPrevention {
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><SpoofPrevention></SpoofPrevention></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SpoofPrevention: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SpoofPrevention' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SpoofPrevention')
    if (-not $node) {
        throw 'SpoofPrevention could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $ipSpoofingZones = @()
    if ($node.IPSpoofing -and $node.IPSpoofing.EnableOnZone -and $node.IPSpoofing.EnableOnZone.Zone) {
        $ipSpoofingZones = @($node.IPSpoofing.EnableOnZone.Zone)
    }

    $macFilterZones = @()
    if ($node.MACFilter -and $node.MACFilter.EnableOnZone -and $node.MACFilter.EnableOnZone.Zone) {
        $macFilterZones = @($node.MACFilter.EnableOnZone.Zone)
    }

    $ipMacFilterZones = @()
    if ($node.IPMACFilter -and $node.IPMACFilter.EnableOnZone -and $node.IPMACFilter.EnableOnZone.Zone) {
        $ipMacFilterZones = @($node.IPMACFilter.EnableOnZone.Zone)
    }

    return [PSCustomObject]@{
        Status                        = [string]$node.SpoofPrevention
        RestrictUnknownIPOnTrustedMAC = [string]$node.RestrictUnknownIPOnTrustedMAC
        IPSpoofingZoneList            = [string[]]$ipSpoofingZones
        MACFilterZoneList             = [string[]]$macFilterZones
        IPMACFilterZoneList           = [string[]]$ipMacFilterZones
    }
}

<#
.SYNOPSIS
    Updates the device-wide SpoofPrevention settings on the Sophos Firewall.

.DESCRIPTION
    Updates the Spoof Prevention singleton (Intrusion Prevention > Spoof Prevention) using
    the Sophos Firewall XML API. Reads the current settings first and resends only what is
    needed (read-modify-write), overriding only what the caller explicitly passed. Supports
    ShouldProcess; use -WhatIf to preview.

    WARNING - measured lockout risk: enabling IPSpoofing (or, presumably, MACFilter/
    IPMACFilter, not separately tested) for the zone that carries the firewall's own admin/
    API traffic, on a topology where that zone's interface shares a subnet with another
    interface of a different zone, causes the firewall to treat its own management traffic
    as spoofed and drop it. This was measured on a live appliance and made it unreachable
    over the network until recovered through an out-of-band path - see the region header.
    Before enabling any zone here, confirm
    that zone's interface does not share a subnet with the interface you are connected
    through, or you may lock yourself out with no way back in except physical/console access.

    Wire shape mirrors what was measured live rather than the full documented structure at
    all times: when the resolved target -Status is 'Disable', ONLY
    <SpoofPrevention>Disable</SpoofPrevention> is sent - RestrictUnknownIPOnTrustedMAC and
    all three zone lists are omitted entirely, matching the measured firewall behaviour that
    disabling the main switch clears/ignores those fields regardless of what is sent
    alongside it. When the resolved target -Status is 'Enable', RestrictUnknownIPOnTrustedMAC
    and all three EnableOnZone blocks are always sent (defaulting
    RestrictUnknownIPOnTrustedMAC to 'Disable' if neither passed nor previously set, since
    the API never returns a value for it in the Disable state to read back). This avoids the
    untested combination of 'Disable' sent together with a populated zone list.

.PARAMETER Status
    'Enable' or 'Disable' for the main Spoof Prevention switch [doc sample; the doc's
    attribute table instead lists lowercase 'on'/'off' for the same field - see
    ips-doku-inventar.md for the full contradiction]. If omitted, the current value is kept.

.PARAMETER RestrictUnknownIPOnTrustedMAC
    'Enable' or 'Disable' [doc]. Only meaningful (and only sent) when the resolved -Status is
    'Enable' - see .DESCRIPTION. If omitted, the current value is kept, defaulting to
    'Disable' if there is no current value to read (i.e. the entity was Disable beforehand).

.PARAMETER IPSpoofingZoneList
    Zone names to enable IP spoofing prevention for. Only sent when the resolved -Status is
    'Enable'. If omitted, the current list is kept. Pass an empty array to clear it. See the
    WARNING in .DESCRIPTION before including any zone that carries your own admin/API
    traffic.

.PARAMETER MACFilterZoneList
    Zone names to enable MAC filtering for. Only sent when the resolved -Status is 'Enable'.
    If omitted, the current list is kept. Pass an empty array to clear it. Structural only in
    this project's live verification - the write path was exercised for IPSpoofing, not
    separately for this block. See the WARNING in .DESCRIPTION: the same lockout mechanism
    plausibly applies here too, since MAC filtering can also drop traffic from the zone
    carrying your own session.

.PARAMETER IPMACFilterZoneList
    Zone names to enable combined IP+MAC filtering for. Only sent when the resolved -Status
    is 'Enable'. If omitted, the current list is kept. Pass an empty array to clear it.
    Structural only - see -MACFilterZoneList's note; the same caution applies.

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
    # Enable IP spoofing prevention for the DMZ zone only - never a zone carrying your own
    # admin/API session, see the WARNING in .DESCRIPTION
    Set-SfosSpoofPrevention -Status Enable -IPSpoofingZoneList 'DMZ'

.EXAMPLE
    # Turn Spoof Prevention back off entirely
    Set-SfosSpoofPrevention -Status Disable

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: both examples above were executed against the lab firewall in sequence
    (Enable/DMZ, confirmed via Get-SfosSpoofPrevention and a reachability probe through the
    same session, then Disable, reconfirmed byte-for-byte against the saved pre-test
    baseline XML). The error path (an invalid main-switch value answering code 400) was also
    reproduced - see the task report and the region header. The zone 'LAN' was never sent in
    this or any prior verification run of this cmdlet, per the explicit prohibition in this
    task's group order.
    ConfirmImpact High since 2026-08-12: enabling IPSpoofing on the management zone caused a
    measured, unrecoverable-remote lock-out; automation must pass -Confirm:$false.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/SpoofPreventionSettings/operations/ConfigureSpoofPrevention.html

.LINK
    Get-SfosSpoofPrevention
#>
function Set-SfosSpoofPrevention {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$Status,

        [ValidateSet('Enable', 'Disable')]
        [string]$RestrictUnknownIPOnTrustedMAC,

        [string[]]$IPSpoofingZoneList,

        [string[]]$MACFilterZoneList,

        [string[]]$IPMACFilterZoneList,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    $bp = $PSBoundParameters

    $existing = Get-SfosSpoofPrevention -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $targetStatus = if ($bp.ContainsKey('Status')) { $Status } else { $existing.Status }

    if (-not $PSCmdlet.ShouldProcess("SpoofPrevention on $($params.Firewall)", "Update (target status $targetStatus)")) {
        return
    }

    if ($targetStatus -eq 'Disable') {
        # See .DESCRIPTION: disabling the main switch clears/ignores every other field on
        # this firewall [measured], so nothing else is sent - matching exactly what was
        # verified to restore the pristine baseline.
        $inner = @'
<Set operation="update">
  <SpoofPrevention>
    <SpoofPrevention>Disable</SpoofPrevention>
  </SpoofPrevention>
</Set>
'@
    }
    else {
        $targetRestrict = if ($bp.ContainsKey('RestrictUnknownIPOnTrustedMAC')) { $RestrictUnknownIPOnTrustedMAC } else { $existing.RestrictUnknownIPOnTrustedMAC }
        if (-not $targetRestrict) {
            # No observed value to preserve (the entity omits this field entirely while
            # Disable) - default to the safer 'Disable' rather than sending an empty element.
            $targetRestrict = 'Disable'
        }

        # @() wraps the whole if/else: a one-element array from a branch unrolls to a scalar
        # on assignment (measured on PS 5.1; two real data-loss bugs of this class were fixed 2026-08-12).
        $targetIPSpoofing = @(if ($bp.ContainsKey('IPSpoofingZoneList')) { $IPSpoofingZoneList } else { $existing.IPSpoofingZoneList })
        $targetMACFilter = @(if ($bp.ContainsKey('MACFilterZoneList')) { $MACFilterZoneList } else { $existing.MACFilterZoneList })
        $targetIPMACFilter = @(if ($bp.ContainsKey('IPMACFilterZoneList')) { $IPMACFilterZoneList } else { $existing.IPMACFilterZoneList })

        $ipSpoofingXml = ConvertTo-SfosSpoofPreventionZoneListXml -ZoneList $targetIPSpoofing
        $macFilterXml = ConvertTo-SfosSpoofPreventionZoneListXml -ZoneList $targetMACFilter
        $ipMacFilterXml = ConvertTo-SfosSpoofPreventionZoneListXml -ZoneList $targetIPMACFilter

        $inner = @"
<Set operation="update">
  <SpoofPrevention>
    <SpoofPrevention>Enable</SpoofPrevention>
    <RestrictUnknownIPOnTrustedMAC>$targetRestrict</RestrictUnknownIPOnTrustedMAC>
    <IPSpoofing>$ipSpoofingXml</IPSpoofing>
    <MACFilter>$macFilterXml</MACFilter>
    <IPMACFilter>$ipMacFilterXml</IPMACFilter>
  </SpoofPrevention>
</Set>
"@
    }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error updating SpoofPrevention: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SpoofPrevention' -Action 'update'
}

#endregion

#region DoSBypassRules
# Entity: DoS Bypass Rule (PROTECT > Intrusion Prevention > DoS Bypass Rules).
# Wire root element is the plural <DoSBypassRules> for both the container and every
# individual record - there is no <Name> field and no other single-value key at all; a
# record is identified purely by the combination of all six fields.
#
# Measured live against SFOS 22.0 (lab, 2026-08-11), all with 0 pre-existing records:
# - Multiple records come back as sibling <DoSBypassRules> elements directly under
#   <Response>, exactly like the single-record case - there is no further wrapper.
# - Server-side filtering is not merely "unsupported key returns everything" as with most
#   other entities in this project - it is broken outright: sending ANY <Filter> (even one
#   that server-side matches an existing record) answers code 404 "The requested resource
#   could not be found" instead of the filtered rows. Get-SfosDoSBypassRule therefore never
#   sends a <Filter> at all; every -*Like parameter is client-side only.
# - SourcePort/DestinationPort are genuinely mandatory for Protocol TCP/UDP: omitting them
#   answers code 400 "sourcePort and destinationPort are required for ipVersion ipv4 with
#   protocol: tcp". For Protocol ICMP/AllProtocol they are accepted if sent (including the
#   literal '*') but are never stored - a follow-up Get shows no SourcePort/DestinationPort
#   element at all for those records. New-/Set-SfosDoSBypassRule therefore always send both
#   ports (default '*', which the doc explicitly allows as a value) rather than branching on
#   Protocol - the firewall silently drops them for ICMP/AllProtocol either way.
# - operation="update" together with the documented <OldConfiguration> wrapper (repeating
#   the full old record) works and changes exactly the targeted record - no need to fall
#   back to operation="edit" (and its GuestUser-style duplicate-on-edit risk) for this
#   entity. Updating a record that does not exist (wrong OldConfiguration) answers code 500
#   "Operation could not be performed on Entity." - a genuine failure, not a 200 no-op, so
#   Set-SfosDoSBypassRule does not need a pre-existence Get for correctness.
# - Delete is the opposite: it silently no-ops. Deleting by only the three fields the
#   documentation marks mandatory (IPFamily, SourcePort, DestinationPort) answers code 200
#   and deletes nothing when a second record shares those three values but differs in
#   SourceIPNetmask/DestinationIPNetmask/Protocol - the two "duplicates" from the docs'
#   own Delete table are not actually sufficient to disambiguate. Only sending the complete
#   six-field record removed the intended one and left its near-duplicate untouched.
#   Deleting a record that does not exist at all also answers 200 and changes nothing.
#   Remove-SfosDoSBypassRule therefore reads the current list first, matches the full
#   six-field key client-side (SourcePort/DestinationPort default to '*' to match what a
#   ICMP/AllProtocol record reports back empty), throws "not found" up front if there is no
#   match, and after the Remove call re-reads and throws if the record is still present.
# - The status node is always /Response/DoSBypassRules/Status[@code] for Add, Update and
#   Remove alike - measured by provoking an invalid IPFamily value (code 400) and an
#   invalid OldConfiguration on Update (code 500). Since no data record of this entity ever
#   carries a <Status> child, Core's default ObjectName-based heuristic
#   (Status[@code or not(../Name)]) is safe to use unmodified.
# - A record created with a wildcard netmask (SourceIPNetmask/DestinationIPNetmask left at
#   the default '*') is echoed back by Get as the literal string 'any', not '*'. That is a
#   Get-side display artifact only: sending 'any' back inside <OldConfiguration> on Update,
#   or as a Remove identifying field, answers code 500 even though the record is genuinely
#   present - only the literal '*' is accepted for identification on write. First found by
#   piping Get-SfosDoSBypassRule straight into Set-SfosDoSBypassRule and getting a 500 for
#   an object that plainly existed. ConvertTo-SfosDoSBypassNetmaskWire (private helper)
#   translates 'any' back to '*' inside Set-/Remove-SfosDoSBypassRule and the identity
#   matcher, so piping Get output into either cmdlet works correctly.

<#
.SYNOPSIS
    Retrieves DoSBypassRules objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for DoS Bypass Rule objects (Intrusion Prevention >
    DoS Bypass Rules). By default the cmdlet returns PowerShell-friendly objects. Use -AsXml
    to return the raw XML nodes.

    This entity has no Name field and no working server-side filter of any kind - sending a
    <Filter> element answers code 404 even for a filter that server-side matches an existing
    record [measured]. Every -*Like parameter here is therefore client-side only; no filter
    is ever sent to the firewall.

.PARAMETER IPFamilyLike
    Filters by IPFamily, substring match. Client-side only.

.PARAMETER SourceIPNetmaskLike
    Filters by SourceIPNetmask, substring match. Client-side only.

.PARAMETER DestinationIPNetmaskLike
    Filters by DestinationIPNetmask, substring match. Client-side only.

.PARAMETER ProtocolLike
    Filters by Protocol, substring match. Client-side only.

.PARAMETER SourcePortLike
    Filters by SourcePort, substring match. Client-side only. Records for Protocol
    ICMP/AllProtocol never carry a SourcePort and are matched against an empty string.

.PARAMETER DestinationPortLike
    Filters by DestinationPort, substring match. Client-side only. Records for Protocol
    ICMP/AllProtocol never carry a DestinationPort and are matched against an empty string.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    # List every DoS bypass rule
    Get-SfosDoSBypassRule

.EXAMPLE
    # Find every TCP bypass rule
    Get-SfosDoSBypassRule -ProtocolLike 'TCP'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: an empty firewall answers HTTP 200 with
    '<DoSBypassRules><Status>No. of records Zero.</Status></DoSBypassRules>' - a normal empty
    result, not an error; this cmdlet returns @() for it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/DoSBypassRule/DoSBypassRule.html

.LINK
    New-SfosDoSBypassRule
#>
function Get-SfosDoSBypassRule {
    [CmdletBinding()]
    param(
        [string]$IPFamilyLike,
        [string]$SourceIPNetmaskLike,
        [string]$DestinationIPNetmaskLike,
        [string]$ProtocolLike,
        [string]$SourcePortLike,
        [string]$DestinationPortLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # No <Filter> is ever sent - see the region header for why.
    $inner = @"
<Get>
  <DoSBypassRules>
  </DoSBypassRules>
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
        throw "Error retrieving DoSBypassRules objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DoSBypassRules' -Action 'get'

    # No <Name> exists on this entity; a data record is any <DoSBypassRules> node that
    # carries an <IPFamily> child - the status-only empty-result node does not.
    $nodes = @(Select-Xml -Xml $XmlResponse -XPath '/Response/DoSBypassRules[IPFamily]' | ForEach-Object -Process { $_.Node })

    $keepMask = for ($i = 0; $i -lt $nodes.Count; $i++) {
        $node = $nodes[$i]
        $obj = [PSCustomObject]@{
            IPFamily              = [string]$node.IPFamily
            SourceIPNetmask       = [string]$node.SourceIPNetmask
            DestinationIPNetmask  = [string]$node.DestinationIPNetmask
            Protocol              = [string]$node.Protocol
            SourcePort            = [string]$node.SourcePort
            DestinationPort       = [string]$node.DestinationPort
        }

        $keep = $true
        if ($IPFamilyLike -and $obj.IPFamily -notlike "*$IPFamilyLike*") { $keep = $false }
        if ($SourceIPNetmaskLike -and $obj.SourceIPNetmask -notlike "*$SourceIPNetmaskLike*") { $keep = $false }
        if ($DestinationIPNetmaskLike -and $obj.DestinationIPNetmask -notlike "*$DestinationIPNetmaskLike*") { $keep = $false }
        if ($ProtocolLike -and $obj.Protocol -notlike "*$ProtocolLike*") { $keep = $false }
        if ($SourcePortLike -and $obj.SourcePort -notlike "*$SourcePortLike*") { $keep = $false }
        if ($DestinationPortLike -and $obj.DestinationPort -notlike "*$DestinationPortLike*") { $keep = $false }

        [PSCustomObject]@{ Keep = $keep; Object = $obj; Node = $node }
    }

    $kept = @($keepMask | Where-Object -FilterScript { $_.Keep })

    if ($AsXml) {
        return @($kept | ForEach-Object -Process { $_.Node })
    }

    return @($kept | ForEach-Object -Process { $_.Object })
}

<#
.SYNOPSIS
    Internal helper: normalizes a DoSBypassRules netmask value for identity comparison
    and for the wire. Not exported.

.DESCRIPTION
    Get-SfosDoSBypassRule reports a wildcard netmask back as the literal string 'any', but
    Set-SfosDoSBypassRule's <OldConfiguration> and Remove-SfosDoSBypassRule's identifying
    fields only match against the literal '*' - sending 'any' back in either of those
    answers code 500 "Operation could not be performed on Entity." even though the record
    is genuinely present [measured]. 'any' is a Get-side display artifact, never a value
    accepted on write. This makes piping Get-SfosDoSBypassRule straight into Set-*/Remove-*
    safe.
#>
function ConvertTo-SfosDoSBypassNetmaskWire {
    param([string]$Value)

    if ($Value -eq 'any') { return '*' }
    return $Value
}

<#
.SYNOPSIS
    Internal helper: tests whether a Get-SfosDoSBypassRule record matches a given
    six-field identity. Not exported.

.DESCRIPTION
    SourcePort/DestinationPort compare against '*' when the record has none, since that
    is the value ICMP/AllProtocol records are addressed by on Remove [measured - see the
    region header]. SourceIPNetmask/DestinationIPNetmask are normalized through
    ConvertTo-SfosDoSBypassNetmaskWire on both sides so a record whose wildcard netmask
    Get reports as 'any' still matches an identity expressed with the literal '*'.
#>
function Test-SfosDoSBypassRuleIdentity {
    param(
        [Parameter(Mandatory)][PSCustomObject]$Record,
        [Parameter(Mandatory)][string]$IPFamily,
        [Parameter(Mandatory)][string]$SourceIPNetmask,
        [Parameter(Mandatory)][string]$DestinationIPNetmask,
        [Parameter(Mandatory)][string]$Protocol,
        [Parameter(Mandatory)][string]$SourcePort,
        [Parameter(Mandatory)][string]$DestinationPort
    )

    $normSourceNet = ConvertTo-SfosDoSBypassNetmaskWire -Value $SourceIPNetmask
    $normDestNet = ConvertTo-SfosDoSBypassNetmaskWire -Value $DestinationIPNetmask
    $normSourcePort = if ($SourcePort) { $SourcePort } else { '*' }
    $normDestPort = if ($DestinationPort) { $DestinationPort } else { '*' }

    $recSourceNet = ConvertTo-SfosDoSBypassNetmaskWire -Value $Record.SourceIPNetmask
    $recDestNet = ConvertTo-SfosDoSBypassNetmaskWire -Value $Record.DestinationIPNetmask
    $recSourcePort = if ($Record.SourcePort) { $Record.SourcePort } else { '*' }
    $recDestinationPort = if ($Record.DestinationPort) { $Record.DestinationPort } else { '*' }

    return ($Record.IPFamily -eq $IPFamily) -and
    ($recSourceNet -eq $normSourceNet) -and
    ($recDestNet -eq $normDestNet) -and
    ($Record.Protocol -eq $Protocol) -and
    ($recSourcePort -eq $normSourcePort) -and
    ($recDestinationPort -eq $normDestPort)
}

<#
.SYNOPSIS
    Creates a new DoSBypassRules object on the Sophos Firewall.

.DESCRIPTION
    Creates a DoS Bypass Rule (Intrusion Prevention > DoS Bypass Rules) using the Sophos
    Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

    SourcePort and DestinationPort are always sent, defaulting to '*' - the doc-documented
    wildcard value - regardless of -Protocol. They are genuinely mandatory on the wire for
    TCP/UDP [measured: omitting them for Protocol TCP answers code 400 "sourcePort and
    destinationPort are required..."]; for ICMP/AllProtocol they are accepted but silently
    not stored [measured], so sending the default is harmless there too.

.PARAMETER IPFamily
    'IPv4' or 'IPv6' [doc]. Mandatory.

.PARAMETER SourceIPNetmask
    Source IP or IP/netmask to bypass, or '*' for any [doc]. Default '*'. Max 45 characters.

.PARAMETER DestinationIPNetmask
    Destination IP or IP/netmask to bypass, or '*' for any [doc]. Default '*'. Max 45
    characters.

.PARAMETER Protocol
    'TCP', 'UDP', 'AllProtocol' or 'ICMP' [doc]. Default 'TCP'.

.PARAMETER SourcePort
    Source port, 1-65535, or '*' for any [doc]. Default '*'. See .DESCRIPTION for why this
    is always sent regardless of -Protocol.

.PARAMETER DestinationPort
    Destination port, 1-65535, or '*' for any [doc]. Default '*'. See .DESCRIPTION for why
    this is always sent regardless of -Protocol.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    # Bypass DoS protection for TCP traffic between two private test subnets on ports 2201/2202
    New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202

.EXAMPLE
    # Bypass DoS protection for all ICMP traffic from a private test subnet
    New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -Protocol ICMP

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: both examples above were executed against the lab firewall, answered code
    201 ('Configuration applied successfully', the documented partial-success/warning code -
    the object is present and correctly shaped on a subsequent Get either way), and were
    removed again after verification - see the task report for the full transcript.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/DoSBypassRule/operations/AddDOSByPassRules%26EditDOSByPassRules.html

.LINK
    Get-SfosDoSBypassRule
#>
function New-SfosDoSBypassRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [ValidateLength(1, 45)]
        [string]$SourceIPNetmask = '*',

        [ValidateLength(1, 45)]
        [string]$DestinationIPNetmask = '*',

        [ValidateSet('TCP', 'UDP', 'AllProtocol', 'ICMP')]
        [string]$Protocol = 'TCP',

        [ValidatePattern('^(\*|[1-9][0-9]{0,4})$')]
        [string]$SourcePort = '*',

        [ValidatePattern('^(\*|[1-9][0-9]{0,4})$')]
        [string]$DestinationPort = '*',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $target = "$IPFamily/$Protocol $SourceIPNetmask->$DestinationIPNetmask ($SourcePort->$DestinationPort)"

    if (-not $PSCmdlet.ShouldProcess("DoSBypassRules '$target' on $($params.Firewall)", 'Create')) {
        return
    }

    $srcNetEsc = ConvertTo-SfosXmlEscaped -Text $SourceIPNetmask
    $dstNetEsc = ConvertTo-SfosXmlEscaped -Text $DestinationIPNetmask
    $srcPortEsc = ConvertTo-SfosXmlEscaped -Text $SourcePort
    $dstPortEsc = ConvertTo-SfosXmlEscaped -Text $DestinationPort

    $inner = @"
<Set operation="add">
  <DoSBypassRules>
    <IPFamily>$IPFamily</IPFamily>
    <SourceIPNetmask>$srcNetEsc</SourceIPNetmask>
    <DestinationIPNetmask>$dstNetEsc</DestinationIPNetmask>
    <Protocol>$Protocol</Protocol>
    <SourcePort>$srcPortEsc</SourcePort>
    <DestinationPort>$dstPortEsc</DestinationPort>
  </DoSBypassRules>
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
        throw "Error creating DoSBypassRules object '$target': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DoSBypassRules' -Action 'create' -Target $target
}

<#
.SYNOPSIS
    Updates an existing DoSBypassRules object on the Sophos Firewall.

.DESCRIPTION
    Updates a DoS Bypass Rule using the documented <OldConfiguration> mechanism
    (operation="update", the current six-field identity repeated inside <OldConfiguration>) -
    measured working live, unlike the undocumented operation="edit" this doc page also
    describes in its operation name (which this cmdlet deliberately does not use, per the
    project rule to only use "add"/"update" unless "edit" has been separately verified safe).

    This entity has no independent Get before the write: the caller supplies the complete
    current six-field identity as mandatory parameters (typically via
    Get-SfosDoSBypassRule | Set-SfosDoSBypassRule), which together with the -New* parameters
    (only overriding what was explicitly bound) already implements read-modify-write without
    a second round trip - there is no field on this entity that a Get could reveal beyond
    these six. Updating a record whose current identity does not match anything on the
    firewall answers code 500 "Operation could not be performed on Entity." [measured] - a
    genuine failure, not a silent no-op, so no extra existence check is added.

.PARAMETER IPFamily
    Current IPFamily of the rule to update. Mandatory; accepts pipeline input by property
    name.

.PARAMETER SourceIPNetmask
    Current SourceIPNetmask of the rule to update. Default '*' (matches a rule created
    without an explicit value).

.PARAMETER DestinationIPNetmask
    Current DestinationIPNetmask of the rule to update. Default '*'.

.PARAMETER Protocol
    Current Protocol of the rule to update. Default 'TCP'.

.PARAMETER SourcePort
    Current SourcePort of the rule to update. Default '*' (also matches an ICMP/AllProtocol
    record, which Get-SfosDoSBypassRule reports back as an empty string here rather than
    '*' - pass the value exactly as Get returned it when piping).

.PARAMETER DestinationPort
    Current DestinationPort of the rule to update. Default '*'.

.PARAMETER NewIPFamily
    New IPFamily. If omitted, the current value is kept.

.PARAMETER NewSourceIPNetmask
    New SourceIPNetmask. If omitted, the current value is kept.

.PARAMETER NewDestinationIPNetmask
    New DestinationIPNetmask. If omitted, the current value is kept.

.PARAMETER NewProtocol
    New Protocol. If omitted, the current value is kept.

.PARAMETER NewSourcePort
    New SourcePort. If omitted, the current value is kept.

.PARAMETER NewDestinationPort
    New DestinationPort. If omitted, the current value is kept.

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
    # Widen the destination netmask of an existing ICMP bypass rule
    Set-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -DestinationIPNetmask '10.99.94.0/24' -Protocol ICMP -NewSourceIPNetmask '10.99.85.0/24'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: created a test ICMP rule, updated its SourceIPNetmask only via this
    exact call shape, re-read it and confirmed the new netmask while Protocol/
    DestinationIPNetmask were unchanged, then removed it - see the task report.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/DoSBypassRule/operations/AddDOSByPassRules%26EditDOSByPassRules.html

.LINK
    Get-SfosDoSBypassRule
#>
function Set-SfosDoSBypassRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SourceIPNetmask = '*',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DestinationIPNetmask = '*',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('TCP', 'UDP', 'AllProtocol', 'ICMP')]
        [string]$Protocol = 'TCP',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SourcePort = '*',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DestinationPort = '*',

        [ValidateSet('IPv4', 'IPv6')]
        [string]$NewIPFamily,

        [ValidateLength(1, 45)]
        [string]$NewSourceIPNetmask,

        [ValidateLength(1, 45)]
        [string]$NewDestinationIPNetmask,

        [ValidateSet('TCP', 'UDP', 'AllProtocol', 'ICMP')]
        [string]$NewProtocol,

        [ValidatePattern('^(\*|[1-9][0-9]{0,4})$')]
        [string]$NewSourcePort,

        [ValidatePattern('^(\*|[1-9][0-9]{0,4})$')]
        [string]$NewDestinationPort,

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
        $bp = $PSBoundParameters

        # Normalize identity fields before anything else: Get-SfosDoSBypassRule reports a
        # wildcard netmask back as 'any' and an unset port as '', neither of which the
        # firewall's <OldConfiguration> match accepts - only the literal '*' does
        # [measured]. This makes 'Get-SfosDoSBypassRule | Set-SfosDoSBypassRule' safe.
        $SourceIPNetmask = ConvertTo-SfosDoSBypassNetmaskWire -Value $SourceIPNetmask
        $DestinationIPNetmask = ConvertTo-SfosDoSBypassNetmaskWire -Value $DestinationIPNetmask
        if (-not $SourcePort) { $SourcePort = '*' }
        if (-not $DestinationPort) { $DestinationPort = '*' }

        $targetIPFamily = if ($bp.ContainsKey('NewIPFamily')) { $NewIPFamily } else { $IPFamily }
        $targetSourceNet = if ($bp.ContainsKey('NewSourceIPNetmask')) { $NewSourceIPNetmask } else { $SourceIPNetmask }
        $targetDestNet = if ($bp.ContainsKey('NewDestinationIPNetmask')) { $NewDestinationIPNetmask } else { $DestinationIPNetmask }
        $targetProtocol = if ($bp.ContainsKey('NewProtocol')) { $NewProtocol } else { $Protocol }
        $targetSourcePort = if ($bp.ContainsKey('NewSourcePort')) { $NewSourcePort } else { $SourcePort }
        $targetDestPort = if ($bp.ContainsKey('NewDestinationPort')) { $NewDestinationPort } else { $DestinationPort }

        $current = "$IPFamily/$Protocol $SourceIPNetmask->$DestinationIPNetmask ($SourcePort->$DestinationPort)"

        if (-not $PSCmdlet.ShouldProcess("DoSBypassRules '$current' on $($params.Firewall)", 'Update')) {
            return
        }

        $oldSrcNetEsc = ConvertTo-SfosXmlEscaped -Text $SourceIPNetmask
        $oldDstNetEsc = ConvertTo-SfosXmlEscaped -Text $DestinationIPNetmask
        $oldSrcPortEsc = ConvertTo-SfosXmlEscaped -Text $SourcePort
        $oldDstPortEsc = ConvertTo-SfosXmlEscaped -Text $DestinationPort

        $newSrcNetEsc = ConvertTo-SfosXmlEscaped -Text $targetSourceNet
        $newDstNetEsc = ConvertTo-SfosXmlEscaped -Text $targetDestNet
        $newSrcPortEsc = ConvertTo-SfosXmlEscaped -Text $targetSourcePort
        $newDstPortEsc = ConvertTo-SfosXmlEscaped -Text $targetDestPort

        $inner = @"
<Set operation="update">
  <DoSBypassRules>
    <IPFamily>$targetIPFamily</IPFamily>
    <SourceIPNetmask>$newSrcNetEsc</SourceIPNetmask>
    <DestinationIPNetmask>$newDstNetEsc</DestinationIPNetmask>
    <Protocol>$targetProtocol</Protocol>
    <SourcePort>$newSrcPortEsc</SourcePort>
    <DestinationPort>$newDstPortEsc</DestinationPort>
    <OldConfiguration>
      <IPFamily>$IPFamily</IPFamily>
      <SourceIPNetmask>$oldSrcNetEsc</SourceIPNetmask>
      <DestinationIPNetmask>$oldDstNetEsc</DestinationIPNetmask>
      <Protocol>$Protocol</Protocol>
      <SourcePort>$oldSrcPortEsc</SourcePort>
      <DestinationPort>$oldDstPortEsc</DestinationPort>
    </OldConfiguration>
  </DoSBypassRules>
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
            throw "Error updating DoSBypassRules object '$current': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DoSBypassRules' -Action 'update' -Target $current
    }
}

<#
.SYNOPSIS
    Removes a DoSBypassRules object from the Sophos Firewall.

.DESCRIPTION
    Removes a DoS Bypass Rule using the Sophos Firewall XML API. Supports ShouldProcess; use
    -WhatIf to preview.

    This entity's Remove is a documented-but-broken no-op in two ways [measured, see the
    region header]: deleting by only the three fields the docs mark mandatory
    (IPFamily/SourcePort/DestinationPort) answers 200 and deletes nothing when a
    near-duplicate record exists, and deleting a record that does not exist at all also
    answers 200. This cmdlet therefore (1) reads the current list first and throws "not
    found" if no record matches the full six-field identity, (2) sends the complete
    six-field record - not just the three documented ones - to the Remove call, and (3)
    re-reads afterwards and throws if the record is still present.

.PARAMETER IPFamily
    IPFamily of the rule to remove. Mandatory; accepts pipeline input by property name.

.PARAMETER SourceIPNetmask
    SourceIPNetmask of the rule to remove. Default '*'.

.PARAMETER DestinationIPNetmask
    DestinationIPNetmask of the rule to remove. Default '*'.

.PARAMETER Protocol
    Protocol of the rule to remove. Default 'TCP'.

.PARAMETER SourcePort
    SourcePort of the rule to remove. Default '*'. Pass the value exactly as
    Get-SfosDoSBypassRule returned it (empty string for ICMP/AllProtocol records) when
    piping.

.PARAMETER DestinationPort
    DestinationPort of the rule to remove. Default '*'.

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
    None. Throws an exception if the removal fails or if the object is still present
    afterwards.

.EXAMPLE
    Remove-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removed a test rule created for this purpose, confirmed gone with a
    follow-up Get, then confirmed the "not found" error path against an identity that never
    existed. See the task report for the full transcript, including the reproduced 200
    no-op this cmdlet works around.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/DoSBypassRule/operations/Delete%20DOS%20ByPass%20Rule.html

.LINK
    Get-SfosDoSBypassRule
#>
function Remove-SfosDoSBypassRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SourceIPNetmask = '*',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DestinationIPNetmask = '*',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('TCP', 'UDP', 'AllProtocol', 'ICMP')]
        [string]$Protocol = 'TCP',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SourcePort = '*',

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$DestinationPort = '*',

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
        # Normalize identity fields before anything else - see Set-SfosDoSBypassRule's
        # matching comment; the same 'any'/'' vs '*' mismatch applies to Remove's own
        # identifying fields [measured].
        $SourceIPNetmask = ConvertTo-SfosDoSBypassNetmaskWire -Value $SourceIPNetmask
        $DestinationIPNetmask = ConvertTo-SfosDoSBypassNetmaskWire -Value $DestinationIPNetmask
        if (-not $SourcePort) { $SourcePort = '*' }
        if (-not $DestinationPort) { $DestinationPort = '*' }

        $target = "$IPFamily/$Protocol $SourceIPNetmask->$DestinationIPNetmask ($SourcePort->$DestinationPort)"

        $existing = @(Get-SfosDoSBypassRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { Test-SfosDoSBypassRuleIdentity -Record $_ -IPFamily $IPFamily -SourceIPNetmask $SourceIPNetmask -DestinationIPNetmask $DestinationIPNetmask -Protocol $Protocol -SourcePort $SourcePort -DestinationPort $DestinationPort })

        if ($existing.Count -eq 0) {
            throw "The DoSBypassRules object '$target' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("DoSBypassRules '$target' on $($params.Firewall)", 'Remove')) {
            return
        }

        $srcNetEsc = ConvertTo-SfosXmlEscaped -Text $SourceIPNetmask
        $dstNetEsc = ConvertTo-SfosXmlEscaped -Text $DestinationIPNetmask
        $srcPortEsc = ConvertTo-SfosXmlEscaped -Text $SourcePort
        $dstPortEsc = ConvertTo-SfosXmlEscaped -Text $DestinationPort

        $inner = @"
<Remove>
  <DoSBypassRules>
    <IPFamily>$IPFamily</IPFamily>
    <SourceIPNetmask>$srcNetEsc</SourceIPNetmask>
    <DestinationIPNetmask>$dstNetEsc</DestinationIPNetmask>
    <Protocol>$Protocol</Protocol>
    <SourcePort>$srcPortEsc</SourcePort>
    <DestinationPort>$dstPortEsc</DestinationPort>
  </DoSBypassRules>
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
            throw "Error removing DoSBypassRules object '$target': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DoSBypassRules' -Action 'remove' -Target $target

        # The API answers 200 for a no-op delete on this entity [measured] - re-read and
        # throw if the record is still there rather than trusting the status code alone.
        $stillPresent = @(Get-SfosDoSBypassRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { Test-SfosDoSBypassRuleIdentity -Record $_ -IPFamily $IPFamily -SourceIPNetmask $SourceIPNetmask -DestinationIPNetmask $DestinationIPNetmask -Protocol $Protocol -SourcePort $SourcePort -DestinationPort $DestinationPort })

        if ($stillPresent.Count -gt 0) {
            throw "Removing DoSBypassRules object '$target' answered success but the object is still present on the firewall."
        }
    }
}

#endregion

#region TrustedMAC
# Entity: Trusted MAC (PROTECT > Intrusion Prevention > Trusted MAC), used together with
# Spoof Prevention's RestrictUnknownIPOnTrustedMAC setting. Wire root element is
# <TrustedMAC> (singular, unlike DoSBypassRules); a record is identified by MACAddress,
# which acts as this entity's key even though the documentation never calls it that.
#
# Measured live against SFOS 22.0 (lab, 2026-08-11), all with 0 pre-existing records:
# - Multiple records come back as sibling <TrustedMAC> elements under <Response>, same
#   shape as the single-record case.
# - The server-side filter on MACAddress does not work: a <Filter> with
#   <key name="MACAddress" criteria="like"> returns every record regardless of whether it
#   matches, the same "unsupported key answers everything" failure mode documented in
#   CLAUDE.md for other entities. Get-SfosTrustedMAC therefore never sends a <Filter>.
# - IPV4Address/IPV6Address round-trip exactly as sent, including a genuine multi-value CSV
#   ("10.99.60.30,10.99.60.31" came back unchanged) - they are kept as plain strings here,
#   matching the wire's own CSV type, rather than split into arrays.
# - AssociateIP accepts any string without validation ('Enable' and even a nonsense value
#   both answered 201) and is never returned by a subsequent Get - there is no way to
#   observe what, if anything, it actually does. Per the project's FileType/Template
#   precedent (CLAUDE.md section 5: "Where the API offers a write-only field, leave it off the
#   Set-* rather than pretending"), this field is not exposed by New-/Set-SfosTrustedMAC at
#   all rather than accepting a value nobody can verify.
# - IPV4Association with an invalid value (e.g. 'Bogus') is also not rejected - it is
#   silently coerced to 'None' - so no client-side ValidateSet blocks it here beyond the
#   three documented values, and this quirk is left to the API rather than guessed at
#   further.
# - operation="update" with the documented <OldConfiguration><MACAddress> wrapper works and
#   can rename the MACAddress itself (the top-level <MACAddress> becomes the record's new
#   key) - measured by renaming a test record from 00:16:76:00:00:02 to
#   00:16:76:00:00:99 and confirming both the old key is gone and the new one carries the
#   unchanged IPV4Address. Updating a MACAddress that does not exist answers code 404
#   "Trusted MAC not found" - a genuine failure, not a silent no-op.
# - Deleting by MACAddress alone (the only documented Delete field) correctly removes
#   exactly that record and nothing else - no duplicate-identity trap like DoSBypassRules.
#   Deleting a MACAddress that does not exist answers code 500 "Deleted some configurations.
#   Couldn't delete all." - also a genuine failure.
# - The status node is always /Response/TrustedMAC/Status[@code] for Add, Update and Remove
#   alike - measured by provoking an invalid MAC address format (code 400) and an unknown
#   OldConfiguration MACAddress on Update (code 404). No data record ever carries a <Status>
#   child, so Core's default ObjectName-based heuristic is safe unmodified.
# - Upload Trusted MAC List (root <Upload_TrustedMAC>, field TrustedMACListFile) is a
#   genuine multipart file upload per its own doc page ("{name of file passed in
#   multipart}"). Invoke-SfosApi only builds the single urlencoded 'reqxml=' POST body this
#   project uses everywhere else - it has no multipart transport, the same blocker recorded
#   for SiteToSiteClient's ServerConfigurationFile in CLAUDE.md. No Upload-SfosTrustedMACList
#   cmdlet was built; see the task report.

<#
.SYNOPSIS
    Retrieves TrustedMAC objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for Trusted MAC objects (Intrusion Prevention >
    Trusted MAC). By default the cmdlet returns PowerShell-friendly objects. Use -AsXml to
    return the raw XML nodes.

    The server-side filter on MACAddress does not work - it returns every record regardless
    of match [measured]. -MACAddressLike is therefore client-side only; no filter is ever
    sent to the firewall.

.PARAMETER MACAddressLike
    Filters by MACAddress, substring match. Client-side only.

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
    Returns the raw XML nodes instead of PowerShell-friendly objects.

.OUTPUTS
    PSCustomObject[] (default). System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    # List every trusted MAC entry
    Get-SfosTrustedMAC

.EXAMPLE
    # Find entries in the documented vendor test range
    Get-SfosTrustedMAC -MACAddressLike '00:16:76'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: an empty firewall answers HTTP 200 with
    '<TrustedMAC><Status>No. of records Zero.</Status></TrustedMAC>' - a normal empty
    result, not an error; this cmdlet returns @() for it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/TrustedMAC/TrustedMAC.html

.LINK
    New-SfosTrustedMAC
#>
function Get-SfosTrustedMAC {
    [CmdletBinding()]
    param(
        [string]$MACAddressLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # No <Filter> is ever sent - see the region header for why.
    $inner = @"
<Get>
  <TrustedMAC>
  </TrustedMAC>
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
        throw "Error retrieving TrustedMAC objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TrustedMAC' -Action 'get'

    $nodes = @(Select-Xml -Xml $XmlResponse -XPath '/Response/TrustedMAC[MACAddress]' | ForEach-Object -Process { $_.Node })

    $objects = foreach ($node in $nodes) {
        [PSCustomObject]@{
            MACAddress      = [string]$node.MACAddress
            IPV4Association = [string]$node.IPV4Association
            IPV4Address     = [string]$node.IPV4Address
            IPV6Association = [string]$node.IPV6Association
            IPV6Address     = [string]$node.IPV6Address
        }
    }

    $objects = @($objects)
    if ($MACAddressLike) {
        $keep = @()
        $keptNodes = @()
        for ($i = 0; $i -lt $objects.Count; $i++) {
            if ($objects[$i].MACAddress -like "*$MACAddressLike*") {
                $keep += $objects[$i]
                $keptNodes += $nodes[$i]
            }
        }
        $objects = @($keep)
        $nodes = @($keptNodes)
    }

    if ($AsXml) {
        return @($nodes)
    }

    return $objects
}

<#
.SYNOPSIS
    Creates a new TrustedMAC object on the Sophos Firewall.

.DESCRIPTION
    Creates a Trusted MAC entry (Intrusion Prevention > Trusted MAC) using the Sophos
    Firewall XML API. Supports ShouldProcess; use -WhatIf to preview.

    Has no -AssociateIP parameter - see the region header for why (write-only,
    unvalidated, never observable through Get).

.PARAMETER MACAddress
    MAC address to trust, for example '00:16:76:00:00:01' [doc]. Mandatory. Max 17
    characters.

.PARAMETER IPV4Association
    'Static', 'DHCP' or 'None' [doc]. Default 'Static'.

.PARAMETER IPV4Address
    IPv4 address(es) for the IP-MAC binding, comma-separated for multiple values [doc].
    Optional.

.PARAMETER IPV6Association
    'Static', 'DHCP' or 'None' [doc]. Default 'Static'.

.PARAMETER IPV6Address
    IPv6 address(es) for the IP-MAC binding, comma-separated for multiple values [doc].
    Optional.

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
    None. Throws an exception if creation fails.

.EXAMPLE
    New-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Association Static -IPV4Address '10.99.60.10'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the example above was executed against the lab firewall, answered code
    201, and the object was confirmed present and correctly shaped on a subsequent Get, then
    removed - see the task report for the full transcript.

    -IPV4Association/-IPV6Association have no fixed default despite the doc table naming
    'Static' as the default for both: sending Association=Static together with an empty
    address (the doc's own default combination when only one address family is used)
    answers code 400 "IPv6 address[0] validation failed" [measured] - a real trap the doc's
    stated default walks straight into. This cmdlet instead defaults each association to
    'Static' only when the matching address parameter was actually given, and to 'None'
    otherwise - matching what the firewall itself reports back for an omitted family.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/TrustedMAC/operations/AddTrustedMAC%26UpdateTrustedMAC.html

.LINK
    Get-SfosTrustedMAC
#>
function New-SfosTrustedMAC {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 17)]
        [ValidatePattern('^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$')]
        [string]$MACAddress,

        [ValidateSet('Static', 'DHCP', 'None')]
        [string]$IPV4Association,

        [string]$IPV4Address = '',

        [ValidateSet('Static', 'DHCP', 'None')]
        [string]$IPV6Association,

        [string]$IPV6Address = '',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("TrustedMAC '$MACAddress' on $($params.Firewall)", 'Create')) {
        return
    }

    # See .NOTES: 'Static' with no address answers 400, so the association only defaults to
    # 'Static' when its matching address was actually supplied.
    if (-not $PSBoundParameters.ContainsKey('IPV4Association')) {
        $IPV4Association = if ($IPV4Address) { 'Static' } else { 'None' }
    }
    if (-not $PSBoundParameters.ContainsKey('IPV6Association')) {
        $IPV6Association = if ($IPV6Address) { 'Static' } else { 'None' }
    }

    $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress
    $ipv4AddrEsc = ConvertTo-SfosXmlEscaped -Text $IPV4Address
    $ipv6AddrEsc = ConvertTo-SfosXmlEscaped -Text $IPV6Address

    $inner = @"
<Set operation="add">
  <TrustedMAC>
    <MACAddress>$macEsc</MACAddress>
    <IPV4Association>$IPV4Association</IPV4Association>
    <IPV4Address>$ipv4AddrEsc</IPV4Address>
    <IPV6Association>$IPV6Association</IPV6Association>
    <IPV6Address>$ipv6AddrEsc</IPV6Address>
  </TrustedMAC>
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
        throw "Error creating TrustedMAC object '$MACAddress': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TrustedMAC' -Action 'create' -Target $MACAddress
}

<#
.SYNOPSIS
    Updates an existing TrustedMAC object on the Sophos Firewall, optionally renaming its
    MAC address.

.DESCRIPTION
    Updates a Trusted MAC entry using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

    -NewMACAddress renames the entry: the current -MACAddress is sent inside the documented
    <OldConfiguration> wrapper to identify the record, and -NewMACAddress (if given) becomes
    the new top-level <MACAddress> - measured working live, including on the record's own
    key field, which most entities in this project cannot rename.

.PARAMETER MACAddress
    Current MAC address of the entry to update. Mandatory; accepts pipeline input by
    property name.

.PARAMETER NewMACAddress
    New MAC address to rename the entry to. If omitted, the MAC address is kept unchanged.

.PARAMETER IPV4Association
    'Static', 'DHCP' or 'None'. If omitted, the existing value is kept.

.PARAMETER IPV4Address
    IPv4 address(es), comma-separated for multiple values. If omitted, the existing value is
    kept.

.PARAMETER IPV6Association
    'Static', 'DHCP' or 'None'. If omitted, the existing value is kept.

.PARAMETER IPV6Address
    IPv6 address(es), comma-separated for multiple values. If omitted, the existing value is
    kept.

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
    # Change only the bound IPv4 address, everything else is preserved
    Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Address '10.99.60.20'

.EXAMPLE
    # Rename the MAC address itself
    Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:02' -NewMACAddress '00:16:76:00:00:99'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: both examples above were executed against test entries created for this
    purpose - the rename in the second example was confirmed by the old MAC no longer
    appearing on a follow-up Get and the new one carrying the unchanged IPV4Address - then
    removed. See the task report for the full transcript.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/TrustedMAC/operations/AddTrustedMAC%26UpdateTrustedMAC.html

.LINK
    Get-SfosTrustedMAC
#>
function Set-SfosTrustedMAC {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$MACAddress,

        [ValidateLength(1, 17)]
        [ValidatePattern('^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$')]
        [string]$NewMACAddress,

        [ValidateSet('Static', 'DHCP', 'None')]
        [string]$IPV4Association,

        [string]$IPV4Address,

        [ValidateSet('Static', 'DHCP', 'None')]
        [string]$IPV6Association,

        [string]$IPV6Address,

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
        $bp = $PSBoundParameters

        $existing = @(Get-SfosTrustedMAC -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -MACAddressLike $MACAddress `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.MACAddress -eq $MACAddress })

        if ($existing.Count -eq 0) {
            throw "The TrustedMAC object '$MACAddress' was not found."
        }
        $current = $existing[0]

        $targetMAC = if ($bp.ContainsKey('NewMACAddress')) { $NewMACAddress } else { $MACAddress }
        $targetIPV4Assoc = if ($bp.ContainsKey('IPV4Association')) { $IPV4Association } else { $current.IPV4Association }
        $targetIPV4Addr = if ($bp.ContainsKey('IPV4Address')) { $IPV4Address } else { $current.IPV4Address }
        $targetIPV6Assoc = if ($bp.ContainsKey('IPV6Association')) { $IPV6Association } else { $current.IPV6Association }
        $targetIPV6Addr = if ($bp.ContainsKey('IPV6Address')) { $IPV6Address } else { $current.IPV6Address }

        if (-not $PSCmdlet.ShouldProcess("TrustedMAC '$MACAddress' on $($params.Firewall)", 'Update')) {
            return
        }

        $oldMacEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress
        $newMacEsc = ConvertTo-SfosXmlEscaped -Text $targetMAC
        $ipv4AddrEsc = ConvertTo-SfosXmlEscaped -Text $targetIPV4Addr
        $ipv6AddrEsc = ConvertTo-SfosXmlEscaped -Text $targetIPV6Addr

        $inner = @"
<Set operation="update">
  <TrustedMAC>
    <MACAddress>$newMacEsc</MACAddress>
    <IPV4Association>$targetIPV4Assoc</IPV4Association>
    <IPV4Address>$ipv4AddrEsc</IPV4Address>
    <IPV6Association>$targetIPV6Assoc</IPV6Association>
    <IPV6Address>$ipv6AddrEsc</IPV6Address>
    <OldConfiguration>
      <MACAddress>$oldMacEsc</MACAddress>
    </OldConfiguration>
  </TrustedMAC>
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
            throw "Error updating TrustedMAC object '$MACAddress': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TrustedMAC' -Action 'update' -Target $MACAddress
    }
}

<#
.SYNOPSIS
    Removes a TrustedMAC object from the Sophos Firewall.

.DESCRIPTION
    Removes a Trusted MAC entry using the Sophos Firewall XML API. Reads the object first
    and throws a clear "not found" error if it does not exist, rather than passing through
    the firewall's own answer for that case [measured: Remove on a nonexistent MACAddress
    answers code 500 "Deleted some configurations. Couldn't delete all." - which already
    fails closed, but names no specific object]. Supports ShouldProcess; use -WhatIf to
    preview.

.PARAMETER MACAddress
    MAC address of the entry to remove. Mandatory; accepts pipeline input by property name.

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
    None. Throws an exception if the removal fails.

.EXAMPLE
    Remove-SfosTrustedMAC -MACAddress '00:16:76:00:00:01'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: removed a test entry created for this purpose, confirmed gone with a
    follow-up Get, then confirmed the "not found" error path against a MAC address that
    never existed. Unlike DoSBypassRules, Remove on this entity correctly deletes exactly
    the targeted record with only its documented key (MACAddress) - no full-field
    workaround needed. See the task report.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Intrusion%20Prevention/TrustedMAC/operations/Delete%20Trusted%20MAC.html

.LINK
    Get-SfosTrustedMAC
#>
function Remove-SfosTrustedMAC {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$MACAddress,

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
        $existing = @(Get-SfosTrustedMAC -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -MACAddressLike $MACAddress `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.MACAddress -eq $MACAddress })

        if ($existing.Count -eq 0) {
            throw "The TrustedMAC object '$MACAddress' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("TrustedMAC '$MACAddress' on $($params.Firewall)", 'Remove')) {
            return
        }

        $macEsc = ConvertTo-SfosXmlEscaped -Text $MACAddress

        $inner = @"
<Remove>
  <TrustedMAC>
    <MACAddress>$macEsc</MACAddress>
  </TrustedMAC>
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
            throw "Error removing TrustedMAC object '$MACAddress': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'TrustedMAC' -Action 'remove' -Target $MACAddress
    }
}

<#
.SYNOPSIS
    Exports all TrustedMAC objects to a CSV or JSON file.

.DESCRIPTION
    Retrieves all TrustedMAC objects from the Sophos Firewall and exports them to a file at
    the specified path. If the file already exists, an error is thrown unless -Overwrite is
    used.

.PARAMETER FilePath
    Full path to the output file.

.PARAMETER Format
    Export format: 'AsCSV' (default) or 'AsJSON'.

.PARAMETER Overwrite
    Overwrites the file if it already exists.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

.PARAMETER Port
    Management/API port number (typically 4444). If omitted, uses the stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, uses the stored connection context.

.PARAMETER Password
    Password for API authentication. If omitted, uses the stored connection context.

.PARAMETER SkipCertificateCheck
    Skip SSL/TLS certificate validation for self-signed certificates.

.OUTPUTS
    None. Writes the output file.

.EXAMPLE
    Export-SfosTrustedMACs -FilePath 'C:\Exports\SophosTrustedMACs.csv'

.NOTES
    Minimum supported PowerShell version: 5.1
    This function depends on Get-SfosTrustedMAC to retrieve the data. IPV4Address/
    IPV6Address are already plain CSV strings on the wire (see the region header), so no
    array flattening is needed before Export-Csv - unlike Export-SfosIPHosts'
    HostGroupList.

.LINK
    Get-SfosTrustedMAC
#>
function Export-SfosTrustedMACs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [string]$Format = 'AsCSV',

        [switch]$Overwrite,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    if (Test-Path -Path $FilePath) {
        if ($Overwrite) {
            Remove-Item -Path $FilePath -Force
        }
        else {
            throw "The file '$FilePath' already exists. Please specify a different file name."
        }
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $entries = Get-SfosTrustedMAC -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    try {
        if ($Format -eq 'AsCSV') {
            $entries | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            $entries | ConvertTo-Json | Out-File -FilePath $FilePath -Encoding UTF8
        }

        Write-Information "Exported TrustedMAC entries to '$FilePath' successfully." -InformationAction Continue
    }
    catch {
        throw "Failed to export TrustedMAC entries to '$FilePath': $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Imports TrustedMAC objects from a CSV or JSON file.

.DESCRIPTION
    Reads TrustedMAC entries from a file previously written by Export-SfosTrustedMACs (or
    matching its column layout) and creates them on the Sophos Firewall using
    New-SfosTrustedMAC. Rows without a MACAddress, or with one already starting with '#',
    are skipped.

.PARAMETER FilePath
    Full path to the input file.

.PARAMETER Format
    Import format: 'AsCSV' (default) or 'AsJSON'.

.PARAMETER Firewall
    Sophos Firewall hostname or IP address. If omitted, uses the stored connection context.

.PARAMETER Port
    Management/API port number (typically 4444). If omitted, uses the stored connection context.

.PARAMETER Username
    Username for API authentication. If omitted, uses the stored connection context.

.PARAMETER Password
    Password for API authentication. If omitted, uses the stored connection context.

.PARAMETER SkipCertificateCheck
    Skip SSL/TLS certificate validation for self-signed certificates.

.OUTPUTS
    None. Creates TrustedMAC objects on the Sophos Firewall.

.EXAMPLE
    Import-SfosTrustedMACs -FilePath 'C:\Imports\SophosTrustedMACs.csv'

.NOTES
    Minimum supported PowerShell version: 5.1
    This function depends on New-SfosTrustedMAC to create the objects.

.LINK
    New-SfosTrustedMAC
#>
function Import-SfosTrustedMACs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('AsCSV', 'AsJSON')]
        [string]$Format = 'AsCSV',

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck
    )

    if (-not (Test-Path -Path $FilePath)) {
        throw "The file '$FilePath' was not found."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    try {
        if ($Format -eq 'AsCSV') {
            $entries = Import-Csv -Path $FilePath -Encoding UTF8
        }
        else {
            $entries = Get-Content -Path $FilePath -Raw -Encoding UTF8 | ConvertFrom-Json
        }
    }
    catch {
        throw "Failed to import TrustedMAC entries from '$FilePath': $($_.Exception.Message)"
    }

    foreach ($entry in $entries) {

        if (-not $entry.MACAddress) {
            Write-Information "Skipping entry without MACAddress." -InformationAction Continue
            continue
        }

        if ($entry.MACAddress.StartsWith('#')) {
            Write-Information "Skipping commented entry: $($entry.MACAddress)" -InformationAction Continue
            continue
        }

        try {
            $newParams = @{
                MACAddress            = $entry.MACAddress
                Firewall              = $params.Firewall
                Port                  = $params.Port
                Username              = $params.Username
                Password              = $params.Password
                SkipCertificateCheck  = $params.SkipCertificateCheck
            }
            if ($entry.IPV4Association) { $newParams.IPV4Association = $entry.IPV4Association }
            if ($entry.IPV4Address) { $newParams.IPV4Address = $entry.IPV4Address }
            if ($entry.IPV6Association) { $newParams.IPV6Association = $entry.IPV6Association }
            if ($entry.IPV6Address) { $newParams.IPV6Address = $entry.IPV6Address }

            New-SfosTrustedMAC @newParams
            Write-Information "Imported TrustedMAC '$($entry.MACAddress)'." -InformationAction Continue
        }
        catch {
            Write-Warning "Failed to import TrustedMAC '$($entry.MACAddress)': $($_.Exception.Message)"
        }
    }
}

#endregion

# NOT built: Upload-SfosTrustedMACList (operation root <Upload_TrustedMAC>, field
# TrustedMACListFile). Its own doc page shows the field's placeholder as
# "{name of file passed in multipart}" - a genuine multipart file upload, the same
# transport this project's Core module does not implement (Invoke-SfosApi only builds the
# single urlencoded 'reqxml=' POST body). Building it would require either extending Core
# with a second, multipart-capable transport (out of scope for this fragment, and a
# decision that affects every module, not just this one) or silently sending the CSV
# content as if it were the file name, which would not work and would misrepresent the
# operation's contract. See the task report.

