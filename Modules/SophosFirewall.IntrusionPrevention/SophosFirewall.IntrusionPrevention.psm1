#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.3.2' }

<#
    SophosFirewall.IntrusionPrevention
    ==================================
    PowerShell module for managing Sophos Firewall (SFOS) intrusion prevention
    via the XML API: IPS policies and their rules, custom IPS signatures, the
    global IPS switch, IPS full signature pack, DoS settings, DoS bypass rules,
    spoof prevention and trusted MAC addresses.

    Total Functions: 35 (30 exported, 5 internal helpers) - see README.md for the full
    cmdlet table.

    Requires SophosFirewall.Core for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S)
    happens in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>


#region IPSPolicy

function ConvertTo-SfosIPSPolicyRuleXml {
    <#
        .SYNOPSIS
        Builds the XML for one IPSPolicy rule.

        .DESCRIPTION
        Converts a rule object into the Rule element used inside an IPSPolicy RuleList. The
        wire element for signature selection is spelled SignaturSelectionType, missing the
        letter e in Signature. This is the element name the firewall itself sends and
        accepts on both read and write, not a spelling mistake in this module.

        .PARAMETER Rule
        Required. The rule object to convert, with the same properties as a rule returned by
        Get-SfosIPSPolicy.
    #>
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
    <#
        .SYNOPSIS
        Builds the Set request XML for an IPSPolicy entity.

        .DESCRIPTION
        Builds a complete IPSPolicy entity body, used by New-SfosIPSPolicy,
        Set-SfosIPSPolicy, Add-SfosIPSPolicyRule and Remove-SfosIPSPolicyRule so all four
        send an identical request shape. The firewall replaces the whole entity on an
        update, so the caller merges every field it wants to keep into -Policy before
        calling this function; the function itself does not read the current object back.

        The Template field is never sent. It appears only in the vendor sample XML, not in
        the parameter table, and the firewall rejects it outright with any value.

        .PARAMETER Operation
        Required. The Set operation to perform: add or update.

        .PARAMETER Policy
        Required. The complete policy object to send, including every rule to keep.
    #>
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
        Retrieves IPS policy objects from a Sophos Firewall.

        .DESCRIPTION
        Returns the intrusion prevention policies defined on the firewall. An IPS policy
        holds a list of rules that select which signatures apply, and is assigned to
        firewall rules to inspect their traffic. Use this cmdlet to review existing
        policies, to feed them into another cmdlet through the pipeline, or to copy them to
        a second firewall. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        Each rule in the returned RuleList has the same shape that New-SfosIPSPolicyRule
        produces, so a rule read back here can be reused directly with
        Add-SfosIPSPolicyRule or passed to Set-SfosIPSPolicy.

        The factory-default IPS policies that ship with the firewall, for example
        'WAN TO LAN' or 'lantowan_strict', are returned like any other object. Treat them
        as read-only in your own scripts; Set-SfosIPSPolicy does not protect them from
        being overwritten.

        .PARAMETER NameLike
        Optional. Returns only policies whose name contains the given text anywhere. This
        is a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for IPS
        policies. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per IPS policy, with the
        properties Name, Description and RuleList. Each entry in RuleList carries RuleName,
        SignaturSelectionType, CategoryList, SeverityList, TargetList, PlatformList,
        SignatureList, SmartFilter, RuleType and Action. A policy with no rules returns
        RuleList as an empty array. Returns System.Xml.XmlElement when -AsXml is used, and
        an empty array when no object matches.

        .EXAMPLE
        Get-SfosIPSPolicy

        Lists every IPS policy on the firewall of the current connection.

        .EXAMPLE
        Get-SfosIPSPolicy -NameLike 'dmz'

        Lists all IPS policies whose name contains 'dmz'.

        .EXAMPLE
        Get-SfosIPSPolicy -NameLike 'dmz' -AsXml

        Returns the raw XML of the matching policies, for example to check a field that the
        standard output does not contain.

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
        # sending an empty wrapper), so $node.RuleList is $null. Without the -FilterScript
        # below, @($null.Rule) is a one-element array containing $null, not an empty array.
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
        Creates an IPS policy on a Sophos Firewall.

        .DESCRIPTION
        Creates an IPS policy, which groups intrusion prevention rules and can then be
        assigned to a firewall rule. Rules can be supplied at creation time with -Rule,
        built beforehand with New-SfosIPSPolicyRule, or added afterwards with
        Add-SfosIPSPolicyRule. Creating a policy with no rules is accepted; -Rule is
        optional. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission for IPS
        policies.

        .PARAMETER Name
        Required. Name of the new IPS policy, 1 to 60 characters, no commas.

        .PARAMETER Description
        Optional. Free-text description of the policy. If omitted, the policy is created
        without a description.

        .PARAMETER Rule
        Optional. Zero or more rule objects, in the order they should be evaluated. Build
        each entry with New-SfosIPSPolicyRule. If omitted, the policy is created with an
        empty rule list.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        policies. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. The Name and Description can be bound from pipeline objects by
        property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosIPSPolicy -Name 'BranchOffice' -Description 'Empty test policy' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosIPSPolicy -Name 'BranchOffice' -Description 'Empty test policy'

        Creates an IPS policy with no rules. Rules can be added later with
        Add-SfosIPSPolicyRule.

        .EXAMPLE
        $rule = New-SfosIPSPolicyRule -RuleName 'AllTraffic' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
        New-SfosIPSPolicy -Name 'BranchOfficeIPS' -Description 'One-rule policy' -Rule $rule

        Creates an IPS policy with a single rule.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an IPS policy on a Sophos Firewall.

        .DESCRIPTION
        Updates an existing IPS policy. You can supply the target name directly or through
        the pipeline. The cmdlet reads the current policy first and keeps whatever the
        caller does not explicitly pass, except for -Rule, which replaces the whole rule
        list. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission for IPS
        policies.

        The factory-default IPS policies that ship with the firewall carry no protection
        flag. Updating one of them overwrites its rule list with no warning from the API;
        check -Name before running this against a shared or production policy.

        .PARAMETER Name
        Required. Name of the policy to update.

        .PARAMETER Description
        Optional. Free-text description of the policy. If omitted, the current description
        is kept.

        .PARAMETER Rule
        Optional. Complete replacement rule list, in the order the firewall should
        evaluate them. Replaces the existing rule list entirely; it does not merge with
        the rules already on the firewall. If omitted, the existing rules are kept. To add
        or remove a single rule without touching the rest of the list, use
        Add-SfosIPSPolicyRule or Remove-SfosIPSPolicyRule instead.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        policies. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. The Name and Description can be bound from pipeline objects by
        property name, for example the output of Get-SfosIPSPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosIPSPolicy -Name 'BranchOfficeIPS' -Description 'Updated description' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosIPSPolicy -Name 'BranchOfficeIPS' -Description 'Updated description'

        Changes only the description; the rule list is preserved.

        .EXAMPLE
        Get-SfosIPSPolicy -NameLike 'BranchOfficeIPS' | Set-SfosIPSPolicy -Description 'Updated'

        Updates the matching policy using pipeline input.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes an IPS policy from a Sophos Firewall.

        .DESCRIPTION
        Deletes an IPS policy by name. The cmdlet checks that the policy exists before
        removing it and throws if the name is not found. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for IPS policies. Never target one of the
        factory-default IPS policies with this cmdlet.

        .PARAMETER Name
        Required. Name of the policy to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        policies. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. Name can be bound from the pipeline, including by property name, for
        example the output of Get-SfosIPSPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal or the policy does not exist.

        .EXAMPLE
        Remove-SfosIPSPolicy -Name 'BranchOffice' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosIPSPolicy -Name 'BranchOffice'

        Removes the named IPS policy. The cmdlet asks for confirmation before it writes.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Builds a rule object for an IPS policy's rule list.

        .DESCRIPTION
        Creates the rule object that New-SfosIPSPolicy, Set-SfosIPSPolicy and
        Add-SfosIPSPolicyRule expect for their -Rule parameter. The cmdlet makes no API
        call; the rule becomes part of a policy only once it is handed to one of those
        cmdlets. The firewall keeps rule order unchanged, so build rules in the order they
        must be evaluated.

        .PARAMETER InputObject
        Optional. An existing rule to use as the base, for example one entry from the
        RuleList that Get-SfosIPSPolicy returns. Accepts pipeline input. Only the
        parameters you actually supply override the base object, so a single field can be
        changed without disturbing the rest. Without it, every omitted parameter falls back
        to its default.

        .PARAMETER RuleName
        Required, unless -InputObject supplies one. Name of the rule within the policy, 1
        to 70 characters.

        .PARAMETER SignaturSelectionType
        Optional. Either 'All Application' or 'Individual Application'. 'All Application'
        selects signatures by category, severity, target and platform. 'Individual
        Application' selects specific signature IDs through -Signature. Default: 'All
        Application'.

        .PARAMETER Category
        Optional. IPS signature category names, for example 'All Categories',
        'os-windows' or 'server-mail'. Used when -SignaturSelectionType is
        'All Application'. If omitted, no category is set.

        .PARAMETER Severity
        Optional. Severity names for this rule: 'All Severity', 'Critical', 'Major',
        'Moderate', 'Minor' or 'Warning'. If omitted, no severity is set.

        .PARAMETER Target
        Optional. Target names for this rule: 'All Target', 'Client' or 'Server'. If
        omitted, no target is set.

        .PARAMETER Platform
        Optional. Platform names for this rule, for example 'All Platform', 'Windows' or
        'Linux'. If omitted, no platform is set.

        .PARAMETER Signature
        Optional. Individual signature IDs, used when -SignaturSelectionType is
        'Individual Application'. If omitted, no signature is set.

        .PARAMETER SmartFilter
        Optional. Free-text search filter as stored by the web admin's rule builder.
        Default: an empty string.

        .PARAMETER RuleType
        Optional. Either 'Default Signature' or 'Custom Signature'. Default:
        'Default Signature'.

        .PARAMETER Action
        Optional. One of 'Recommended', 'Allow Packet', 'Drop Packet', 'Disable',
        'Drop Session', 'Reset' or 'Bypass Session'. Default: 'Recommended'.

        .INPUTS
        System.Management.Automation.PSCustomObject. InputObject can be bound from the
        pipeline, for example one entry of the RuleList returned by Get-SfosIPSPolicy.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. A rule object with the properties
        RuleName, SignaturSelectionType, CategoryList, SeverityList, PlatformList,
        TargetList, SignatureList, SmartFilter, RuleType and Action, matching the shape
        Get-SfosIPSPolicy returns for each RuleList entry.

        .EXAMPLE
        New-SfosIPSPolicyRule -RuleName 'AllTraffic' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'

        Builds a rule that matches all traffic with the recommended action.

        .EXAMPLE
        $policy = Get-SfosIPSPolicy -NameLike 'BranchOfficeIPS'
        $edited = $policy.RuleList[0] | New-SfosIPSPolicyRule -Action 'Drop Session'
        Set-SfosIPSPolicy -Name 'BranchOfficeIPS' -Rule $edited

        Changes only the action of an existing rule and writes the updated rule back.

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
        # editing safe - without it every default would overwrite the base.
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
        Appends a rule to an existing IPS policy.

        .DESCRIPTION
        Reads the current IPS policy, appends the supplied rule after the existing ones,
        and writes the whole rule list back in one request. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for IPS policies. No write protection exists for the
        factory-default IPS policies; check -Name before running this against a shared or
        production policy.

        .PARAMETER Name
        Required. Name of the target policy.

        .PARAMETER Rule
        Required. Rule object to append, built with New-SfosIPSPolicyRule.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        policies. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. Name can be bound from pipeline objects by property name, for
        example the output of Get-SfosIPSPolicy.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        $rule = New-SfosIPSPolicyRule -RuleName 'ExtraRule' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
        Add-SfosIPSPolicyRule -Name 'BranchOfficeIPS' -Rule $rule -WhatIf

        Shows what the call would add without sending it to the firewall.

        .EXAMPLE
        $rule = New-SfosIPSPolicyRule -RuleName 'ExtraRule' -Category 'All Categories' -Severity 'All Severity' -Target 'All Target' -Platform 'All Platform'
        Add-SfosIPSPolicyRule -Name 'BranchOfficeIPS' -Rule $rule

        Appends the rule to the end of the policy's rule list.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a single rule from an IPS policy by index.

        .DESCRIPTION
        Reads the current IPS policy, drops the rule at the given zero-based index from its
        rule list, and writes the whole rule list back in one request. The cmdlet reads the
        policy back afterwards and throws if the rule count on the firewall does not match
        what was sent, rather than trusting a success status alone. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for IPS policies. No write
        protection exists for the factory-default IPS policies; check -Name before running
        this against a shared or production policy.

        .PARAMETER Name
        Required. Name of the target policy.

        .PARAMETER Index
        Required. Zero-based position of the rule to remove within the policy's rule list,
        in the order returned by Get-SfosIPSPolicy. Throws if the index is out of range.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        policies. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update or the rule was not actually removed.

        .EXAMPLE
        Remove-SfosIPSPolicyRule -Name 'BranchOfficeIPS' -Index 0 -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosIPSPolicyRule -Name 'BranchOfficeIPS' -Index 0

        Removes the first rule of the policy.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

        # A 200 response can mean the rule list was not actually shortened, so the policy is
        # read back and the rule count checked rather than trusting the status code alone.
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
        Retrieves custom IPS signatures from a Sophos Firewall.

        .DESCRIPTION
        Returns the custom intrusion prevention signatures defined on the firewall. A
        custom signature holds a rule pattern that IPS matches against traffic, alongside a
        severity and a recommended action. The cmdlet only reads; nothing on the firewall
        is changed. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly.

        .PARAMETER NameLike
        Optional. Returns only signatures whose name contains the given text anywhere. This
        is a substring match, not a wildcard pattern. If omitted, the name is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for IPS
        signatures. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per signature, with the
        properties Name, Protocol, CustomRule, Severity and RecommendedAction. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no object
        matches.

        .EXAMPLE
        Get-SfosIPSCustomSignature

        Lists every custom IPS signature on the firewall of the current connection.

        .EXAMPLE
        Get-SfosIPSCustomSignature -NameLike 'Block'

        Lists all custom signatures whose name contains 'Block'.

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
        Creates a custom IPS signature on a Sophos Firewall.

        .DESCRIPTION
        Creates a custom intrusion prevention signature from a protocol, a rule string, a
        severity and a recommended action. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for IPS signatures. The current firmware does not
        accept any custom rule syntax for this cmdlet; every create request is rejected.

        .PARAMETER Name
        Required. Name of the custom signature, 1 to 15 characters, no commas.

        .PARAMETER Protocol
        Required. One of 'TCP', 'UDP', 'ICMP' or 'ALL'.

        .PARAMETER CustomRule
        Required. Signature definition string.

        .PARAMETER Severity
        Required. One of 'Critical', 'Major', 'Moderate', 'Minor' or 'Warning'.

        .PARAMETER RecommendedAction
        Required. One of 'Allow Packet', 'Drop Packet', 'Drop Session', 'Reset' or
        'Bypass Session'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        signatures. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. Name can be bound from pipeline objects by property name.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        $rule = Get-Content -Path 'C:\rules\block-telnet.txt' -Raw
        New-SfosIPSCustomSignature -Name 'BlockTelnet' -Protocol TCP -CustomRule $rule -Severity Minor -RecommendedAction 'Allow Packet' -WhatIf

        Reads a signature rule in Snort syntax from a file and shows what the call would
        create, without sending it to the firewall. Keeping the rule in a file avoids
        quoting problems, because the rule text contains characters that a shell would
        otherwise interpret.

        .EXAMPLE
        $rule = Get-Content -Path 'C:\rules\block-telnet.txt' -Raw
        New-SfosIPSCustomSignature -Name 'BlockTelnet' -Protocol TCP -CustomRule $rule -Severity Minor -RecommendedAction 'Allow Packet'

        Creates a custom IPS signature from a rule file.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a custom IPS signature on a Sophos Firewall.

        .DESCRIPTION
        Updates an existing custom intrusion prevention signature. The cmdlet reads the
        current object first and keeps whatever the caller does not explicitly pass. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission for IPS signatures. The
        current firmware does not accept any custom rule syntax for the underlying create,
        so no custom signature can exist to update.

        .PARAMETER Name
        Required. Name of the signature to update.

        .PARAMETER Protocol
        Optional. One of 'TCP', 'UDP', 'ICMP' or 'ALL'. If omitted, the current value is
        kept.

        .PARAMETER CustomRule
        Optional. Signature definition string. If omitted, the current value is kept.

        .PARAMETER Severity
        Optional. One of 'Critical', 'Major', 'Moderate', 'Minor' or 'Warning'. If omitted,
        the current value is kept.

        .PARAMETER RecommendedAction
        Optional. One of 'Allow Packet', 'Drop Packet', 'Drop Session', 'Reset' or
        'Bypass Session'. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        signatures. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. Name can be bound from the pipeline, including by property name, for
        example the output of Get-SfosIPSCustomSignature.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update or the signature does not exist.

        .EXAMPLE
        Set-SfosIPSCustomSignature -Name 'BlockTelnet' -Severity Major -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosIPSCustomSignature -Name 'BlockTelnet' -Severity Major

        Updates the severity of the named signature.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a custom IPS signature from a Sophos Firewall.

        .DESCRIPTION
        Deletes a custom intrusion prevention signature by name. The cmdlet checks that the
        signature exists before removing it and throws if the name is not found. It needs
        an open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for IPS signatures.

        .PARAMETER Name
        Required. Name of the signature to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for IPS
        signatures. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. Name can be bound from the pipeline, including by property name, for
        example the output of Get-SfosIPSCustomSignature.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal or the signature does not exist.

        .EXAMPLE
        Remove-SfosIPSCustomSignature -Name 'BlockTelnet' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosIPSCustomSignature -Name 'BlockTelnet'

        Removes the named custom signature.

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
# <IPSSwitch>, with a single child <Status>Enable|Disable</Status>.
#
# On a successful Get the <Status> node carries no code attribute - it is the entity's one
# data field, not an API status. Core's default status heuristic would misread it, since
# IPSSwitch has no <Name> sibling either. Get-SfosIPSSwitch therefore checks explicitly for a
# coded Status node first (a real error or warning) and only falls back to reading the value
# as data when no code attribute is present. The XPath for a genuine API error is
# /Response/IPSSwitch/Status[@code]. operation="update" reports a genuine coded Status on
# success, so Set-SfosIPSSwitch uses the standard success check unmodified - only the Get
# side needs the special handling above.

<#
        .SYNOPSIS
        Retrieves the intrusion prevention master switch state from a Sophos Firewall.

        .DESCRIPTION
        Returns whether the intrusion prevention engine is currently switched on or off for
        the whole appliance. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        IPS switch. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML node sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with the property Status,
        either 'Enable' or 'Disable'. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosIPSSwitch

        Shows whether intrusion prevention is currently switched on.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [object]$Session,

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
        Switches intrusion prevention on or off for a Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide IPS master switch. The cmdlet reads the result back after
        the write and throws if the confirmed state does not match what was requested. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission for the IPS switch. This
        switch affects intrusion prevention for the whole appliance; automated use should
        pass -Confirm:$false deliberately.

        .PARAMETER Status
        Required. Either 'Enable' or 'Disable'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        IPS switch. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update or the confirmed state does not match what was requested.

        .EXAMPLE
        Set-SfosIPSSwitch -Status Disable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosIPSSwitch -Status Disable

        Switches off intrusion prevention. The cmdlet asks for confirmation before it
        writes.

        .EXAMPLE
        Set-SfosIPSSwitch -Status Enable -Confirm:$false

        Switches on intrusion prevention without asking for confirmation, for use in
        scripts.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
# <Status>enable|disable|show</Status>, all lowercase.
#
# Same data-field-without-code trap as IPSSwitch's Status field on Get - see that region's
# header for the mechanism. Get-SfosIPSFullSignaturePack uses the identical special-case
# handling.
#
# The firmware does not currently accept a write to this entity through operation="update":
# every value answers a code 500 and the state does not change. Set-SfosIPSFullSignaturePack
# uses operation="update" so a failed write is reported loudly; operation="add" is a silent
# no-op on this entity (HTTP 200, no state change, no error) and must not be used as a
# workaround.

<#
        .SYNOPSIS
        Retrieves the IPS full signature pack status from a Sophos Firewall.

        .DESCRIPTION
        Returns whether the full intrusion prevention signature pack is currently enabled
        for the appliance, as opposed to the base pack. The cmdlet only reads; nothing on
        the firewall is changed. It needs an open connection from Connect-SfosFirewall, or
        the connection parameters supplied directly.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for the
        signature pack setting. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML node sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with the property Status,
        either 'enable' or 'disable'. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosIPSFullSignaturePack

        Shows whether the full IPS signature pack is currently active.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [object]$Session,

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
        Sets the IPS full signature pack status on a Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide setting that switches between the base and the full
        intrusion prevention signature pack. The cmdlet reads the result back afterwards.
        The current firmware rejects every write to this setting, so this cmdlet is
        expected to fail; it is documentation-faithful and kept for firmware that accepts
        the write. It needs an open connection from Connect-SfosFirewall, or the connection
        parameters supplied directly, and an account with write permission for the
        signature pack setting.

        .PARAMETER Status
        Required. One of 'enable', 'disable' or 'show', all lowercase.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for the
        signature pack setting. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update or the confirmed state does not match what was requested.

        .EXAMPLE
        Set-SfosIPSFullSignaturePack -Status enable -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosIPSFullSignaturePack -Status enable

        Requests the full signature pack. The cmdlet asks for confirmation before it
        writes.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
# BurstRatePerSource/Destination, ApplyFlag), plus DroppedSourceRoutedPackets,
# DisableICMPRedirectPacket and DisableARPFlooding, which each carry only a
# <Destination><ApplyFlag>. Every field is optional on the wire, so every parameter on
# Set-SfosDoSSettings is optional with no default, and a full read-modify-write across every
# block is mandatory.
#
# The status XPath for both success and failure is /Response/DoSSettings/Status[@code]; no
# DoSSettings data field is itself named <Status>, so the default status heuristic needs no
# special handling here.
#
# ApplyFlag is not validated server-side: an invalid value is silently discarded rather than
# applied or rejected, and the write still answers success. Set-SfosDoSSettings therefore
# enforces ValidateSet('Enable','Disable') on every *ApplyFlag parameter client-side, since
# the API's success response does not mean the value actually took effect.

<#
        .SYNOPSIS
        Retrieves the DoS protection settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide denial-of-service protection settings: per-direction packet
        and burst rate limits and enable flags for SYN, UDP, TCP and ICMP flood protection,
        plus enable flags for dropped source-routed packets, ICMP redirect packets and ARP
        flood protection. The cmdlet only reads; nothing on the firewall is changed. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        Property names follow the pattern '<Block>SourcePacketRate',
        '<Block>SourceBurstRate', '<Block>SourceApplyFlag', '<Block>DestinationPacketRate',
        '<Block>DestinationBurstRate' and '<Block>DestinationApplyFlag' for each of
        SYNFlood, UDPFlood, TCPFlood and ICMPFlood, plus
        DroppedSourceRoutedPacketsApplyFlag, DisableICMPRedirectPacketApplyFlag and
        DisableARPFloodingApplyFlag. These names match the parameters of Set-SfosDoSSettings
        exactly, so a property read here can be passed straight back as a parameter name.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for DoS
        settings. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML node sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object with 27 properties covering
        every DoS protection field. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosDoSSettings | Select-Object SYNFloodSourcePacketRate, SYNFloodDestinationPacketRate

        Shows the current SYN flood packet rate limits.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Set-SfosDoSSettings
#>
function Get-SfosDoSSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DoSSettings>, a singleton
    # holding one configuration, and it has no <DoSSetting> child. The Sophos spelling
    # goes above PowerShell habit here; the singular concession is reserved
    # for elements that really do wrap a list, such as <Services> around <Service>.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding()]
    param(
        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

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
        Updates the DoS protection settings on a Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide denial-of-service protection settings. The cmdlet reads the
        current settings first and resends every field across all seven blocks, overriding
        only what the caller explicitly passed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for DoS settings.

        .PARAMETER SYNFloodSourcePacketRate
        Optional. SYN flood packet rate limit per source, in packets per second. If
        omitted, the current value is kept.

        .PARAMETER SYNFloodSourceBurstRate
        Optional. SYN flood burst rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER SYNFloodSourceApplyFlag
        Optional. Either 'Enable' or 'Disable' SYN flood protection per source. If omitted,
        the current value is kept.

        .PARAMETER SYNFloodDestinationPacketRate
        Optional. SYN flood packet rate limit per destination. If omitted, the current
        value is kept.

        .PARAMETER SYNFloodDestinationBurstRate
        Optional. SYN flood burst rate limit per destination. If omitted, the current value
        is kept.

        .PARAMETER SYNFloodDestinationApplyFlag
        Optional. Either 'Enable' or 'Disable' SYN flood protection per destination. If
        omitted, the current value is kept.

        .PARAMETER UDPFloodSourcePacketRate
        Optional. UDP flood packet rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER UDPFloodSourceBurstRate
        Optional. UDP flood burst rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER UDPFloodSourceApplyFlag
        Optional. Either 'Enable' or 'Disable' UDP flood protection per source. If omitted,
        the current value is kept.

        .PARAMETER UDPFloodDestinationPacketRate
        Optional. UDP flood packet rate limit per destination. If omitted, the current
        value is kept.

        .PARAMETER UDPFloodDestinationBurstRate
        Optional. UDP flood burst rate limit per destination. If omitted, the current value
        is kept.

        .PARAMETER UDPFloodDestinationApplyFlag
        Optional. Either 'Enable' or 'Disable' UDP flood protection per destination. If
        omitted, the current value is kept.

        .PARAMETER TCPFloodSourcePacketRate
        Optional. TCP flood packet rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER TCPFloodSourceBurstRate
        Optional. TCP flood burst rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER TCPFloodSourceApplyFlag
        Optional. Either 'Enable' or 'Disable' TCP flood protection per source. If omitted,
        the current value is kept.

        .PARAMETER TCPFloodDestinationPacketRate
        Optional. TCP flood packet rate limit per destination. If omitted, the current
        value is kept.

        .PARAMETER TCPFloodDestinationBurstRate
        Optional. TCP flood burst rate limit per destination. If omitted, the current value
        is kept.

        .PARAMETER TCPFloodDestinationApplyFlag
        Optional. Either 'Enable' or 'Disable' TCP flood protection per destination. If
        omitted, the current value is kept.

        .PARAMETER ICMPFloodSourcePacketRate
        Optional. ICMP flood packet rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER ICMPFloodSourceBurstRate
        Optional. ICMP flood burst rate limit per source. If omitted, the current value is
        kept.

        .PARAMETER ICMPFloodSourceApplyFlag
        Optional. Either 'Enable' or 'Disable' ICMP flood protection per source. If
        omitted, the current value is kept.

        .PARAMETER ICMPFloodDestinationPacketRate
        Optional. ICMP flood packet rate limit per destination. If omitted, the current
        value is kept.

        .PARAMETER ICMPFloodDestinationBurstRate
        Optional. ICMP flood burst rate limit per destination. If omitted, the current
        value is kept.

        .PARAMETER ICMPFloodDestinationApplyFlag
        Optional. Either 'Enable' or 'Disable' ICMP flood protection per destination. If
        omitted, the current value is kept.

        .PARAMETER DroppedSourceRoutedPacketsApplyFlag
        Optional. Either 'Enable' or 'Disable' dropping of source-routed packets. If
        omitted, the current value is kept.

        .PARAMETER DisableICMPRedirectPacketApplyFlag
        Optional. Either 'Enable' or 'Disable' disabling of ICMP redirect packets. If
        omitted, the current value is kept.

        .PARAMETER DisableARPFloodingApplyFlag
        Optional. Either 'Enable' or 'Disable' ARP flood protection. If omitted, the current
        value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for DoS
        settings. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosDoSSettings -ICMPFloodSourcePacketRate 121 -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDoSSettings -ICMPFloodSourcePacketRate 121

        Changes only the ICMP flood source packet rate; every other field is preserved.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosDoSSettings
#>
function Set-SfosDoSSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is not a plural container here
    # but the name of the entity itself - the API element is <DoSSettings>, a singleton
    # holding one configuration, and it has no <DoSSetting> child. The Sophos spelling
    # goes above PowerShell habit here; the singular concession is reserved
    # for elements that really do wrap a list, such as <Services> around <Service>.
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
# singleton. Wire root <SpoofPrevention> wraps a child of the same name holding the main
# switch: <SpoofPrevention><SpoofPrevention>Enable|Disable</SpoofPrevention>...
# </SpoofPrevention>. When the switch is Enable, three independent filter blocks may each be
# turned on for a list of zones: <IPSpoofing><EnableOnZone><Zone>...</Zone>...
# </EnableOnZone></IPSpoofing>, and the same shape for <MACFilter> and <IPMACFilter>. An
# additional flat field <RestrictUnknownIPOnTrustedMAC>Enable|Disable</RestrictUnknownIPOnTrustedMAC>
# sits beside the three blocks.
#
# The status XPath for a real API error is /Response/SpoofPrevention/Status[@code].
# Disabling the main switch clears every other field regardless of what was previously
# configured; a disabling update therefore sends only the main switch and omits the other
# elements entirely.

<#
        .SYNOPSIS
        Builds the EnableOnZone XML fragment for one Spoof Prevention filter block.

        .DESCRIPTION
        Shared by the IPSpoofing, MACFilter and IPMACFilter blocks inside
        Set-SfosSpoofPrevention, which all use the identical
        EnableOnZone/Zone shape. An empty list produces a childless, but still present,
        EnableOnZone element.

        .PARAMETER ZoneList
        Zone names to enable the filter for. An empty or omitted list produces a childless
        EnableOnZone element.
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
        Retrieves the spoof prevention settings from a Sophos Firewall.

        .DESCRIPTION
        Returns the device-wide spoof prevention configuration: the main on/off switch, the
        RestrictUnknownIPOnTrustedMAC flag, and the three per-zone filter lists (IPSpoofing,
        MACFilter, IPMACFilter). The cmdlet only reads; nothing on the firewall is changed.
        It needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        When the main switch is Disable, the firewall omits every other field from the
        response, so RestrictUnknownIPOnTrustedMAC and all three zone lists read back empty
        in that state, not because they were cleared but because they were never returned.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for spoof
        prevention settings. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML node sent by the firewall instead of a PowerShell
        object.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object describing the current
        spoof prevention configuration. Returns System.Xml.XmlElement when -AsXml is used.

        .EXAMPLE
        Get-SfosSpoofPrevention

        Shows whether spoof prevention is on, and for which zones.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [object]$Session,

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
        Updates the spoof prevention settings on a Sophos Firewall.

        .DESCRIPTION
        Updates the device-wide spoof prevention configuration. The cmdlet reads the
        current settings first and resends only what is needed, overriding only what the
        caller explicitly passed. When the resolved target status is 'Disable', only the
        main switch is sent; RestrictUnknownIPOnTrustedMAC and all three zone lists are
        omitted, matching the firewall's own behaviour of clearing those fields whenever
        the main switch is off. When the resolved target status is 'Enable',
        RestrictUnknownIPOnTrustedMAC and all three zone lists are always sent. It needs an
        open connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for spoof prevention settings.

        Enabling IP spoofing prevention for the zone that carries the firewall's own
        management or API interface can make the appliance treat its own admin and API
        traffic as spoofed and drop it, cutting off remote access. Recovery then requires
        local access to the appliance. Confirm that the zone you enable does not carry the
        interface you are connected through before running this cmdlet.

        .PARAMETER Status
        Optional. Either 'Enable' or 'Disable' for the main spoof prevention switch. If
        omitted, the current value is kept.

        .PARAMETER RestrictUnknownIPOnTrustedMAC
        Optional. Either 'Enable' or 'Disable'. Only sent when the resolved -Status is
        'Enable'. If omitted, the current value is kept, defaulting to 'Disable' if there
        is no current value to read.

        .PARAMETER IPSpoofingZoneList
        Optional. Zone names to enable IP spoofing prevention for. Only sent when the
        resolved -Status is 'Enable'. If omitted, the current list is kept. Pass an empty
        array to clear it. Never include the zone that carries your own admin or API
        connection.

        .PARAMETER MACFilterZoneList
        Optional. Zone names to enable MAC filtering for. Only sent when the resolved
        -Status is 'Enable'. If omitted, the current list is kept. Pass an empty array to
        clear it. The same lock-out risk as -IPSpoofingZoneList applies.

        .PARAMETER IPMACFilterZoneList
        Optional. Zone names to enable combined IP and MAC filtering for. Only sent when
        the resolved -Status is 'Enable'. If omitted, the current list is kept. Pass an
        empty array to clear it. The same lock-out risk as -IPSpoofingZoneList applies.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        spoof prevention settings. If omitted, the value from the current connection is
        used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosSpoofPrevention -Status Enable -IPSpoofingZoneList 'DMZ' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosSpoofPrevention -Status Enable -IPSpoofingZoneList 'DMZ'

        Enables IP spoofing prevention for the DMZ zone only. The cmdlet asks for
        confirmation before it writes.

        .EXAMPLE
        Set-SfosSpoofPrevention -Status Disable -Confirm:$false

        Turns spoof prevention off entirely without asking for confirmation, for use in
        scripts.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        # See .DESCRIPTION: disabling the main switch clears every other field, so nothing
        # else is sent.
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

        # @() must wrap the whole if/else: a one-element array from a branch
        # unrolls to a scalar on assignment.
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
# individual record - there is no <Name> field and no other single-value key; a record is
# identified purely by the combination of all six fields.
#
# Multiple records come back as sibling <DoSBypassRules> elements directly under
# <Response>, with no further wrapper. Server-side filtering does not work for this entity:
# sending any <Filter> answers code 404 instead of the filtered rows, so
# Get-SfosDoSBypassRule never sends a <Filter>; every -*Like parameter is client-side only.
#
# SourcePort and DestinationPort are mandatory on the wire for Protocol TCP/UDP. For
# Protocol ICMP/AllProtocol they are accepted if sent but never stored, so New-/
# Set-SfosDoSBypassRule always send both ports (default '*') rather than branching on
# Protocol.
#
# Update uses the documented <OldConfiguration> wrapper, repeating the full old record, and
# fails loudly for a record that does not exist. Delete behaves differently: sending only
# the three fields the documentation marks mandatory can silently delete nothing when a
# second record shares those three values but differs in the rest, and deleting a record
# that does not exist also answers success without changing anything. Remove-SfosDoSBypassRule
# therefore reads the current list first, matches the full six-field key client-side, throws
# if there is no match, and re-reads afterwards to confirm the record is gone.
#
# The status node is always /Response/DoSBypassRules/Status[@code] for Add, Update and
# Remove alike; no data record of this entity carries a <Status> child, so the default
# status heuristic is safe to use unmodified.
#
# A record created with a wildcard netmask is echoed back by Get as the literal string
# 'any', not '*'. Only the literal '*' is accepted when identifying a record on write, so
# ConvertTo-SfosDoSBypassNetmaskWire translates 'any' back to '*' inside Set-/
# Remove-SfosDoSBypassRule and the identity matcher, letting Get output be piped into either
# cmdlet directly.

<#
        .SYNOPSIS
        Retrieves DoS bypass rules from a Sophos Firewall.

        .DESCRIPTION
        Returns the DoS bypass rules defined on the firewall. A DoS bypass rule exempts
        matching traffic from denial-of-service protection. The cmdlet only reads; nothing
        on the firewall is changed. It needs an open connection from Connect-SfosFirewall,
        or the connection parameters supplied directly. This entity has no name field and
        no working server-side filter, so every filter parameter is applied on the client.

        .PARAMETER IPFamilyLike
        Optional. Returns only rules whose IP family contains the given text anywhere. If
        omitted, IP family is not used to filter.

        .PARAMETER SourceIPNetmaskLike
        Optional. Returns only rules whose source netmask contains the given text anywhere.
        If omitted, the source netmask is not used to filter.

        .PARAMETER DestinationIPNetmaskLike
        Optional. Returns only rules whose destination netmask contains the given text
        anywhere. If omitted, the destination netmask is not used to filter.

        .PARAMETER ProtocolLike
        Optional. Returns only rules whose protocol contains the given text anywhere. If
        omitted, the protocol is not used to filter.

        .PARAMETER SourcePortLike
        Optional. Returns only rules whose source port contains the given text anywhere.
        Rules for protocol ICMP or AllProtocol carry no source port and are matched against
        an empty string. If omitted, the source port is not used to filter.

        .PARAMETER DestinationPortLike
        Optional. Returns only rules whose destination port contains the given text
        anywhere. Rules for protocol ICMP or AllProtocol carry no destination port and are
        matched against an empty string. If omitted, the destination port is not used to
        filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for DoS
        bypass rules. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per rule. Returns
        System.Xml.XmlElement when -AsXml is used, and an empty array when no rule exists.

        .EXAMPLE
        Get-SfosDoSBypassRule

        Lists every DoS bypass rule on the firewall of the current connection.

        .EXAMPLE
        Get-SfosDoSBypassRule -ProtocolLike 'TCP'

        Lists every TCP DoS bypass rule.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [object]$Session,

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
        Normalizes a DoS bypass rule netmask value for identity comparison and for the wire.

        .DESCRIPTION
        Get-SfosDoSBypassRule reports a wildcard netmask back as the literal string 'any',
        but Set-SfosDoSBypassRule's OldConfiguration and Remove-SfosDoSBypassRule's
        identifying fields only match against the literal '*'. 'any' is a Get-side display
        value only, never accepted on write. This makes piping Get-SfosDoSBypassRule
        straight into Set-SfosDoSBypassRule or Remove-SfosDoSBypassRule work correctly.

        .PARAMETER Value
        Netmask value to normalize.
    #>
function ConvertTo-SfosDoSBypassNetmaskWire {
    param([string]$Value)

    if ($Value -eq 'any') { return '*' }
    return $Value
}

<#
        .SYNOPSIS
        Tests whether a DoS bypass rule record matches a given six-field identity.

        .DESCRIPTION
        Used by Set-SfosDoSBypassRule and Remove-SfosDoSBypassRule to find the record a
        caller means, since this entity has no name field. SourcePort and DestinationPort
        compare against '*' when the record has none, matching how ICMP and AllProtocol
        records are addressed on Remove. SourceIPNetmask and DestinationIPNetmask are
        normalized through ConvertTo-SfosDoSBypassNetmaskWire on both sides.

        .PARAMETER Record
        The record to test, as returned by Get-SfosDoSBypassRule.

        .PARAMETER IPFamily
        IP family to match.

        .PARAMETER SourceIPNetmask
        Source netmask to match.

        .PARAMETER DestinationIPNetmask
        Destination netmask to match.

        .PARAMETER Protocol
        Protocol to match.

        .PARAMETER SourcePort
        Source port to match.

        .PARAMETER DestinationPort
        Destination port to match.
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
        Creates a DoS bypass rule on a Sophos Firewall.

        .DESCRIPTION
        Creates a rule that exempts matching traffic from denial-of-service protection.
        SourcePort and DestinationPort are always sent, defaulting to '*', regardless of
        -Protocol; they are mandatory on the wire for TCP and UDP, and are accepted but not
        stored for ICMP and AllProtocol. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for DoS bypass rules.

        .PARAMETER IPFamily
        Required. Either 'IPv4' or 'IPv6'.

        .PARAMETER SourceIPNetmask
        Optional. Source IP or IP/netmask to bypass, or '*' for any. Maximum 45 characters.
        Default: '*'.

        .PARAMETER DestinationIPNetmask
        Optional. Destination IP or IP/netmask to bypass, or '*' for any. Maximum 45
        characters. Default: '*'.

        .PARAMETER Protocol
        Optional. One of 'TCP', 'UDP', 'AllProtocol' or 'ICMP'. Default: 'TCP'.

        .PARAMETER SourcePort
        Optional. Source port, 1 to 65535, or '*' for any. Default: '*'.

        .PARAMETER DestinationPort
        Optional. Destination port, 1 to 65535, or '*' for any. Default: '*'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for DoS
        bypass rules. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202 -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202

        Bypasses DoS protection for TCP traffic between two subnets on the given ports.

        .EXAMPLE
        New-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -Protocol ICMP

        Bypasses DoS protection for all ICMP traffic from a subnet.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates an existing DoS bypass rule on a Sophos Firewall.

        .DESCRIPTION
        Updates a DoS bypass rule using the documented OldConfiguration mechanism, which
        repeats the current six-field identity alongside the new values. This entity has no
        single name field, so the caller supplies the complete current identity as
        mandatory parameters, typically through
        Get-SfosDoSBypassRule | Set-SfosDoSBypassRule. Only the -New* parameters that are
        explicitly bound override the current value; the rest are kept. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for DoS bypass rules.

        .PARAMETER IPFamily
        Required. Current IP family of the rule to update. Accepts pipeline input by
        property name.

        .PARAMETER SourceIPNetmask
        Optional. Current source netmask of the rule to update. Default: '*'.

        .PARAMETER DestinationIPNetmask
        Optional. Current destination netmask of the rule to update. Default: '*'.

        .PARAMETER Protocol
        Optional. Current protocol of the rule to update. Default: 'TCP'.

        .PARAMETER SourcePort
        Optional. Current source port of the rule to update. Default: '*'. For a rule of
        protocol ICMP or AllProtocol, pass the value exactly as Get-SfosDoSBypassRule
        returned it.

        .PARAMETER DestinationPort
        Optional. Current destination port of the rule to update. Default: '*'.

        .PARAMETER NewIPFamily
        Optional. New IP family. If omitted, the current value is kept.

        .PARAMETER NewSourceIPNetmask
        Optional. New source netmask. If omitted, the current value is kept.

        .PARAMETER NewDestinationIPNetmask
        Optional. New destination netmask. If omitted, the current value is kept.

        .PARAMETER NewProtocol
        Optional. New protocol. If omitted, the current value is kept.

        .PARAMETER NewSourcePort
        Optional. New source port. If omitted, the current value is kept.

        .PARAMETER NewDestinationPort
        Optional. New destination port. If omitted, the current value is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for DoS
        bypass rules. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.Management.Automation.PSCustomObject. IPFamily and the other identifying
        parameters can be bound from pipeline objects by property name, for example the
        output of Get-SfosDoSBypassRule.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -DestinationIPNetmask '10.99.94.0/24' -Protocol ICMP -NewSourceIPNetmask '10.99.85.0/24' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.95.0/24' -DestinationIPNetmask '10.99.94.0/24' -Protocol ICMP -NewSourceIPNetmask '10.99.85.0/24'

        Widens the source netmask of an existing ICMP bypass rule.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        $bp = $PSBoundParameters

        # Normalize identity fields before anything else: Get-SfosDoSBypassRule reports a
        # wildcard netmask back as 'any' and an unset port as '', neither of which the
        # firewall's <OldConfiguration> match accepts - only the literal '*' does. This makes
        # 'Get-SfosDoSBypassRule | Set-SfosDoSBypassRule' safe.
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
        Removes a DoS bypass rule from a Sophos Firewall.

        .DESCRIPTION
        Deletes a DoS bypass rule identified by its full six-field identity. The cmdlet
        reads the current list first and throws if no record matches, sends the complete
        identity to the removal call, and reads the list back afterwards to confirm the
        record is gone. It needs an open connection from Connect-SfosFirewall, or the
        connection parameters supplied directly, and an account with write permission for
        DoS bypass rules.

        .PARAMETER IPFamily
        Required. IP family of the rule to remove. Accepts pipeline input by property name.

        .PARAMETER SourceIPNetmask
        Optional. Source netmask of the rule to remove. Default: '*'.

        .PARAMETER DestinationIPNetmask
        Optional. Destination netmask of the rule to remove. Default: '*'.

        .PARAMETER Protocol
        Optional. Protocol of the rule to remove. Default: 'TCP'.

        .PARAMETER SourcePort
        Optional. Source port of the rule to remove. Default: '*'. For a rule of protocol
        ICMP or AllProtocol, pass the value exactly as Get-SfosDoSBypassRule returned it.

        .PARAMETER DestinationPort
        Optional. Destination port of the rule to remove. Default: '*'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for DoS
        bypass rules. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.Management.Automation.PSCustomObject. IPFamily and the other identifying
        parameters can be bound from pipeline objects by property name, for example the
        output of Get-SfosDoSBypassRule.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal or the rule is still present afterwards.

        .EXAMPLE
        Remove-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202 -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosDoSBypassRule -IPFamily IPv4 -SourceIPNetmask '10.99.98.0/24' -DestinationIPNetmask '10.99.99.0/24' -Protocol TCP -SourcePort 2201 -DestinationPort 2202

        Removes the matching DoS bypass rule.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
    }

    process {
        # Normalize identity fields before anything else - see Set-SfosDoSBypassRule's
        # matching comment; the same 'any'/'' vs '*' mismatch applies to Remove's own
        # identifying fields.
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

        # The API can answer success for a delete that removed nothing on this entity -
        # re-read and throw if the record is still there rather than trusting the status
        # code alone.
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
# Multiple records come back as sibling <TrustedMAC> elements under <Response>. The
# server-side filter on MACAddress does not work: it returns every record regardless of
# match, so Get-SfosTrustedMAC never sends a <Filter>. IPV4Address and IPV6Address round-trip
# exactly as sent, including a comma-separated multi-value list, and are kept as plain
# strings here rather than split into arrays.
#
# AssociateIP accepts any value without validation and is never returned by a subsequent
# Get, so there is no way to observe what it does; New-/Set-SfosTrustedMAC do not expose it.
# IPV4Association and IPV6Association silently coerce an invalid value to 'None' rather than
# rejecting it.
#
# operation="update" with the documented OldConfiguration/MACAddress wrapper can rename the
# MACAddress itself, since the top-level MACAddress becomes the record's new key. Updating a
# MACAddress that does not exist fails loudly. Deleting by MACAddress alone removes exactly
# that record; deleting one that does not exist also fails loudly. The status node is always
# /Response/TrustedMAC/Status[@code] for Add, Update and Remove alike; no data record ever
# carries a <Status> child, so the default status heuristic is safe unmodified.
#
# Import-SfosTrustedMACList uploads a trusted MAC list file via the Upload_TrustedMAC
# operation, a genuine multipart file upload; the transport contract is documented with
# the Core module. Measured status path and error behaviour are recorded with this module.

<#
        .SYNOPSIS
        Retrieves trusted MAC entries from a Sophos Firewall.

        .DESCRIPTION
        Returns the trusted MAC address entries defined on the firewall, used together with
        the RestrictUnknownIPOnTrustedMAC spoof prevention setting. The cmdlet only reads;
        nothing on the firewall is changed. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly. The
        server-side filter on MAC address does not work, so -MACAddressLike is applied on
        the client.

        .PARAMETER MACAddressLike
        Optional. Returns only entries whose MAC address contains the given text anywhere.
        If omitted, the MAC address is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per entry, with the
        properties MACAddress, IPV4Association, IPV4Address, IPV6Association and
        IPV6Address. Returns System.Xml.XmlElement when -AsXml is used, and an empty array
        when no entry matches.

        .EXAMPLE
        Get-SfosTrustedMAC

        Lists every trusted MAC entry on the firewall of the current connection.

        .EXAMPLE
        Get-SfosTrustedMAC -MACAddressLike '00:16:76'

        Lists all trusted MAC entries whose address contains '00:16:76'.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [object]$Session,

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
        Creates a trusted MAC entry on a Sophos Firewall.

        .DESCRIPTION
        Creates a MAC address entry that is exempted from spoof prevention's unknown-IP
        restriction. If -IPV4Association or -IPV6Association is not passed, it defaults to
        'Static' when the matching address parameter is given, and to 'None' otherwise. It
        needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly, and an account with write permission for trusted MAC entries.

        .PARAMETER MACAddress
        Required. MAC address to trust, for example '00:16:76:00:00:01'. Maximum 17
        characters.

        .PARAMETER IPV4Association
        Optional. One of 'Static', 'DHCP' or 'None'. If omitted, defaults to 'Static' when
        -IPV4Address is given, otherwise to 'None'.

        .PARAMETER IPV4Address
        Optional. IPv4 address or comma-separated addresses for the IP-MAC binding.

        .PARAMETER IPV6Association
        Optional. One of 'Static', 'DHCP' or 'None'. If omitted, defaults to 'Static' when
        -IPV6Address is given, otherwise to 'None'.

        .PARAMETER IPV6Address
        Optional. IPv6 address or comma-separated addresses for the IP-MAC binding.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        creation.

        .EXAMPLE
        New-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Association Static -IPV4Address '10.99.60.10' -WhatIf

        Shows what the call would create without sending it to the firewall.

        .EXAMPLE
        New-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Association Static -IPV4Address '10.99.60.10'

        Creates a trusted MAC entry with a static IPv4 binding.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Updates a trusted MAC entry on a Sophos Firewall, optionally renaming its address.

        .DESCRIPTION
        Updates an existing trusted MAC entry. The cmdlet reads the current object first
        and resends every field, overriding only what the caller explicitly passed.
        -NewMACAddress renames the entry: the current -MACAddress identifies the record,
        and -NewMACAddress, if given, becomes its new address. It needs an open connection
        from Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for trusted MAC entries.

        .PARAMETER MACAddress
        Required. Current MAC address of the entry to update. Accepts pipeline input by
        property name.

        .PARAMETER NewMACAddress
        Optional. New MAC address to rename the entry to. If omitted, the MAC address is
        kept unchanged.

        .PARAMETER IPV4Association
        Optional. One of 'Static', 'DHCP' or 'None'. If omitted, the current value is kept.

        .PARAMETER IPV4Address
        Optional. IPv4 address or comma-separated addresses. If omitted, the current value
        is kept.

        .PARAMETER IPV6Association
        Optional. One of 'Static', 'DHCP' or 'None'. If omitted, the current value is kept.

        .PARAMETER IPV6Address
        Optional. IPv6 address or comma-separated addresses. If omitted, the current value
        is kept.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. MACAddress can be bound from the pipeline, including by property
        name, for example the output of Get-SfosTrustedMAC.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        update.

        .EXAMPLE
        Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Address '10.99.60.20' -WhatIf

        Shows what the call would change without sending it to the firewall.

        .EXAMPLE
        Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -IPV4Address '10.99.60.20'

        Changes only the bound IPv4 address; everything else is preserved.

        .EXAMPLE
        Set-SfosTrustedMAC -MACAddress '00:16:76:00:00:02' -NewMACAddress '00:16:76:00:00:99'

        Renames the entry to a new MAC address.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Removes a trusted MAC entry from a Sophos Firewall.

        .DESCRIPTION
        Deletes a trusted MAC entry by address. The cmdlet checks that the entry exists
        before removing it and throws if the address is not found. It needs an open
        connection from Connect-SfosFirewall, or the connection parameters supplied
        directly, and an account with write permission for trusted MAC entries.

        .PARAMETER MACAddress
        Required. MAC address of the entry to remove.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        System.String. MACAddress can be bound from the pipeline, including by property
        name, for example the output of Get-SfosTrustedMAC.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        removal or the entry does not exist.

        .EXAMPLE
        Remove-SfosTrustedMAC -MACAddress '00:16:76:00:00:01' -WhatIf

        Shows what the call would remove without sending it to the firewall.

        .EXAMPLE
        Remove-SfosTrustedMAC -MACAddress '00:16:76:00:00:01'

        Removes the named trusted MAC entry.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Exports trusted MAC entries from a Sophos Firewall to a file.

        .DESCRIPTION
        Retrieves every trusted MAC entry from the firewall using Get-SfosTrustedMAC and
        writes them to a CSV or JSON file at the given path, for backup or transfer to
        another firewall with Import-SfosTrustedMACs. If the file already exists, an error
        is thrown unless -Overwrite is used. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly.

        .PARAMETER FilePath
        Required. Full path to the output file.

        .PARAMETER Format
        Optional. Export format, either 'AsCSV' or 'AsJSON'. Default: 'AsCSV'.

        .PARAMETER Overwrite
        Optional. Overwrites the file if it already exists. If omitted, an existing file
        causes an error.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes the output file and raises an error if the file cannot be
        written.

        .EXAMPLE
        Export-SfosTrustedMACs -FilePath 'C:\Exports\SophosTrustedMACs.csv'

        Exports every trusted MAC entry to a CSV file.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
        [switch]$SkipCertificateCheck,

        [object]$Session
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
        Imports trusted MAC entries into a Sophos Firewall from a file.

        .DESCRIPTION
        Reads trusted MAC entries from a CSV or JSON file previously written by
        Export-SfosTrustedMACs, or matching its column layout, and creates them on the
        firewall using New-SfosTrustedMAC. Rows without a MAC address, or whose MAC address
        starts with '#', are skipped. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an
        account with write permission for trusted MAC entries. Unlike
        Import-SfosTrustedMACList, this cmdlet parses the file itself on this machine and
        calls New-SfosTrustedMAC once per row, rather than uploading the file to the
        firewall.

        .PARAMETER FilePath
        Required. Full path to the input file.

        .PARAMETER Format
        Optional. Import format, either 'AsCSV' or 'AsJSON'. Default: 'AsCSV'.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet creates trusted MAC entries on the firewall and raises an error
        for a row it cannot create.

        .EXAMPLE
        Import-SfosTrustedMACs -FilePath 'C:\Imports\SophosTrustedMACs.csv'

        Creates a trusted MAC entry for every valid row in the file.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        New-SfosTrustedMAC
#>
function Import-SfosTrustedMACs {
    [CmdletBinding(SupportsShouldProcess)]
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
        [switch]$SkipCertificateCheck,

        [object]$Session
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

        if (-not $PSCmdlet.ShouldProcess("TrustedMAC '$($entry.MACAddress)' on $($params.Firewall)", 'Create')) {
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

<#
        .SYNOPSIS
        Uploads a trusted MAC list file to a Sophos Firewall.

        .DESCRIPTION
        Sends one local file to the firewall through the Upload_TrustedMAC API operation, a
        genuine multipart file upload, and lets the firewall parse and import the entries
        itself. Unlike Import-SfosTrustedMACs, this cmdlet never reads the file's content on
        this machine and does not call New-SfosTrustedMAC - the file goes to the firewall
        unopened, and the firewall does the importing. It needs an open connection from
        Connect-SfosFirewall, or the connection parameters supplied directly, and an account
        with write permission for trusted MAC entries.

        .PARAMETER FilePath
        Required. Path to the local trusted MAC list file to upload. The firewall requires a
        CSV with the header row 'MAC Address, IP Association, IP Address' and rejects any
        other header with a 400 error naming it.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from
        the current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs write permission for
        trusted MAC entries. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from
        the current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the
        certificate is validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that
        was registered with Connect-SfosFirewall -Name. Use it to address a specific
        firewall when you work with more than one at a time. Any connection parameter you
        pass explicitly still takes precedence. If omitted, the stored default connection
        is used.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        None. The cmdlet writes no output and raises an error if the firewall rejects the
        upload.

        .EXAMPLE
        Import-SfosTrustedMACList -FilePath 'C:\Lists\TrustedMAC.csv' -WhatIf

        Shows what the call would upload without sending it to the firewall.

        .EXAMPLE
        Import-SfosTrustedMACList -FilePath 'C:\Lists\TrustedMAC.csv'

        Uploads the file and lets the firewall import its entries.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

        .LINK
        Get-SfosTrustedMAC

        .LINK
        Import-SfosTrustedMACs
#>
function Import-SfosTrustedMACList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "The file '$FilePath' was not found."
    }

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("Trusted MAC list file '$FilePath' on $($params.Firewall)", 'Upload')) {
        return
    }

    $fileNameEsc = ConvertTo-SfosXmlEscaped -Text (Split-Path -Path $FilePath -Leaf)

    $inner = "<Set operation=`"add`"><Upload_TrustedMAC><TrustedMACListFile>$fileNameEsc</TrustedMACListFile></Upload_TrustedMAC></Set>"

    $multipartFile = @{ TrustedMACListFile = $FilePath }

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -MultipartFile $multipartFile `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to upload trusted MAC list file '$FilePath': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Upload_TrustedMAC' -Action 'upload' -Target (Split-Path -Path $FilePath -Leaf)
}

#endregion

