#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.Applications
    ===========================
    PowerShell module for managing Sophos Firewall (SFOS) application control
    via the XML API: application filter policies and their rules, application
    objects, application categories with QoS assignment, application
    classification assignments (single and batch) and the application
    classification switch.

    Total Functions: 24 (20 exported, 4 internal helpers) - see
    README.md for the full cmdlet table.

    Requires SophosFirewall.Core for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S)
    happens in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>


#region ApplicationFilterPolicy / ApplicationObject shared helper

function ConvertTo-SfosAppFilterListXml {
    # Internal helper, not exported. Builds the shared CategoryList/RiskList/
    # CharacteristicsList/TechnologyList/ClassificationList/ApplicationList block used both
    # inside an ApplicationFilterPolicy Rule and inside a standalone ApplicationObject - the
    # two entities share this exact nested list shape [doc: both sample XMLs use identical
    # *List wrappers].
    #
    # IMPORTANT (measured against the lab firewall, both entities): CategoryList, RiskList,
    # CharacteristicsList, TechnologyList and ClassificationList are NOT settable data - they
    # are read-only, server-computed tags:
    #   - When -SelectAllRule is 'Disable' (an explicit -Application list is used), the
    #     firewall ignores whatever is sent for these five lists and instead recomputes them
    #     from the real signature metadata of the applications actually in ApplicationList.
    #     Sending a fabricated Category/Risk/Characteristics/Technology value has zero effect
    #     - it is silently replaced, not rejected (200, no error). ClassificationList was never
    #     observed populated in this state (it appears to require the application to carry an
    #     assignment from ApplicationClassificationAssignment, an entity outside the scope of
    #     this module group - not investigated further here).
    #   - When -SelectAllRule is 'Enable' and CategoryList/RiskList/CharacteristicsList/
    #     TechnologyList carries at least one value the firewall recognizes, ApplicationList is
    #     itself recomputed as every application matching that criterion (can run into the
    #     hundreds) - whatever was sent in -Application is discarded, not merged.
    #   - When -SelectAllRule is 'Enable' but none of those criteria lists contains a value the
    #     firewall recognizes (an invented category name, for example), they are silently
    #     dropped entirely (no error) and -Application is kept exactly as sent.
    #   - When -SelectAllRule is 'Disable' and -Application is NOT sent at all, the entire Rule
    #     is silently dropped from the policy's RuleList on write (200, but the rule vanishes) -
    #     an explicit -Application list is mandatory whenever -SelectAllRule is 'Disable'.
    # This helper therefore still emits CategoryList/RiskList/CharacteristicsList/
    # TechnologyList exactly as the caller supplied them (so the 'Enable' + criteria selection
    # mode keeps working, which DOES take effect), but every function that surfaces these
    # parameters documents in its own help that they are ignored/overwritten in 'Disable' mode.
    # ClassificationList is intentionally never emitted - it was never observed as a working
    # write path in either mode and inventing an untested element risks the CountryHostGroup
    # class of defect.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string[]]$Category,
        [string[]]$Risk,
        [string[]]$Characteristics,
        [string[]]$Technology,
        [string[]]$Application
    )

    $categoryXml = ''
    foreach ($item in @($Category)) {
        if (-not $item) { continue }
        $categoryXml += "<Category>$(ConvertTo-SfosXmlEscaped -Text $item)</Category>"
    }

    $riskXml = ''
    foreach ($item in @($Risk)) {
        if (-not $item) { continue }
        $riskXml += "<Risk>$(ConvertTo-SfosXmlEscaped -Text $item)</Risk>"
    }

    $characteristicsXml = ''
    foreach ($item in @($Characteristics)) {
        if (-not $item) { continue }
        $characteristicsXml += "<Characteristics>$(ConvertTo-SfosXmlEscaped -Text $item)</Characteristics>"
    }

    $technologyXml = ''
    foreach ($item in @($Technology)) {
        if (-not $item) { continue }
        $technologyXml += "<Technology>$(ConvertTo-SfosXmlEscaped -Text $item)</Technology>"
    }

    $applicationXml = ''
    foreach ($item in @($Application)) {
        if (-not $item) { continue }
        $applicationXml += "<Application>$(ConvertTo-SfosXmlEscaped -Text $item)</Application>"
    }

    $xml = ''
    if ($categoryXml) { $xml += "<CategoryList>$categoryXml</CategoryList>" }
    if ($riskXml) { $xml += "<RiskList>$riskXml</RiskList>" }
    if ($characteristicsXml) { $xml += "<CharacteristicsList>$characteristicsXml</CharacteristicsList>" }
    if ($technologyXml) { $xml += "<TechnologyList>$technologyXml</TechnologyList>" }
    $xml += "<ApplicationList>$applicationXml</ApplicationList>"

    return $xml
}

#endregion


#region ApplicationFilterPolicy

function ConvertTo-SfosApplicationFilterPolicyRuleXml {
    # Internal helper, not exported. Builds one <Rule> element for an ApplicationFilterPolicy's
    # RuleList, using the shared ConvertTo-SfosAppFilterListXml helper for the six nested
    # selection lists.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Rule
    )

    $selectAllEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SelectAllRule)
    $smartFilterEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SmartFilter)
    $actionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Action)
    $scheduleEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Schedule)

    $listXml = ConvertTo-SfosAppFilterListXml -Category $Rule.CategoryList -Risk $Rule.RiskList `
        -Characteristics $Rule.CharacteristicsList -Technology $Rule.TechnologyList `
        -Application $Rule.ApplicationList

    return "<Rule><SelectAllRule>$selectAllEsc</SelectAllRule>$listXml<SmartFilter>$smartFilterEsc</SmartFilter><Action>$actionEsc</Action><Schedule>$scheduleEsc</Schedule></Rule>"
}

function ConvertTo-SfosApplicationFilterPolicyEntityXml {
    # Internal helper, not exported. Builds the <Set> inner XML for an ApplicationFilterPolicy
    # entity, so New-, Set-SfosApplicationFilterPolicy, Add-SfosApplicationFilterPolicyRule and
    # Remove-SfosApplicationFilterPolicyRule all send an identical, complete entity body. SFOS
    # replaces the whole entity on <Set operation="update">, so the caller merges every field it
    # wants preserved into -Policy before calling this function; nothing is read back here.
    #
    # Deliberately never emits <Template> - it appears only in the vendor sample XML (with the
    # comment "if set, ignores DefaultAction/RuleList"), has no row in the attribute table, and
    # sending it - with the documented value 'AllowAll' - is rejected outright with a 501 naming
    # /ApplicationFilterPolicy/Template as invalid [measured against the lab firewall]. Same
    # finding, same non-parameter decision as IPSPolicy's Template field in the sibling module.
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
    $defaultActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DefaultAction)
    $microAppEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.MicroAppSupport)

    $ruleListXml = ''
    foreach ($rule in @($Policy.RuleList)) {
        if (-not $rule) { continue }
        $ruleListXml += ConvertTo-SfosApplicationFilterPolicyRuleXml -Rule $rule
    }

    return @"
<Set operation="$Operation">
  <ApplicationFilterPolicy>
    <Name>$nameEsc</Name>
    <Description>$descEsc</Description>
    <DefaultAction>$defaultActionEsc</DefaultAction>
    <MicroAppSupport>$microAppEsc</MicroAppSupport>
    <RuleList>$ruleListXml</RuleList>
  </ApplicationFilterPolicy>
</Set>
"@
}

<#
        .SYNOPSIS
        Retrieves ApplicationFilterPolicy objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ApplicationFilterPolicy objects (PROTECT >
        Applications > "APP Filter Policy" in the web admin - the menu label drops the word
        "Filter" and changes casing versus the wire element name, a doc-only naming
        inconsistency [doc]). By default the cmdlet returns PowerShell-friendly objects. Use
        -AsXml to return the raw XML nodes.

        Each Rule in the returned RuleList mirrors the shape produced by
        New-SfosApplicationFilterPolicyRule, so a rule read back from this cmdlet can be reused
        directly with Add-SfosApplicationFilterPolicyRule or passed to
        Set-SfosApplicationFilterPolicy -Rule.

        There are 7 factory-default policies on SFOS 22.0 ('Allow All', 'Deny All' and five
        'Block ...' policies). Treat them as read-only in your own scripts -
        Set-SfosApplicationFilterPolicy has no protection against overwriting one.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match. Sent to the
        firewall as the server-side filter and re-applied client-side, per the project's
        filtering rules.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        PSCustomObject with Name, Description, DefaultAction, MicroAppSupport and RuleList
        (array of rule objects with SelectAllRule, CategoryList, RiskList,
        CharacteristicsList, TechnologyList, ApplicationList, SmartFilter, Action, Schedule).
        A policy with no rules returns RuleList as @(). System.Xml.XmlElement when -AsXml is
        specified.

        .EXAMPLE
        # Retrieve all application filter policies
        Get-SfosApplicationFilterPolicy

        .EXAMPLE
        # Filter by name (substring match)
        Get-SfosApplicationFilterPolicy -NameLike "Block"

        .EXAMPLE
        # Return raw XML for troubleshooting
        Get-SfosApplicationFilterPolicy -NameLike "Allow All" -AsXml

        .NOTES
        Minimum supported PowerShell version: 5.1
        ClassificationList is never populated in any measurement made for this build (see the
        internal ConvertTo-SfosAppFilterListXml helper) and is therefore not exposed as a
        RuleList property - there was nothing to round-trip.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/ApplicationFilterPolicy.html

        .LINK
        New-SfosApplicationFilterPolicyRule
#>
function Get-SfosApplicationFilterPolicy {
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
  <ApplicationFilterPolicy>
    $filterXml
  </ApplicationFilterPolicy>
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
        throw "Error retrieving ApplicationFilterPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ApplicationFilterPolicy[Name]' | ForEach-Object -Process {
        $_.Node
    }

    $policyObjects = foreach ($node in @($nodes)) {
        # A policy with no rules has no <RuleList> element at all (SFOS drops it rather than
        # sending an empty wrapper, measured), so $node.RuleList is $null. Without the
        # -FilterScript below, @($null.Rule) is a one-element array containing $null.
        $rules = foreach ($ruleNode in @($node.RuleList.Rule | Where-Object -FilterScript { $_ })) {
            [PSCustomObject]@{
                SelectAllRule       = [string]$ruleNode.SelectAllRule
                CategoryList        = [string[]]@($ruleNode.CategoryList.Category | Where-Object -FilterScript { $_ })
                RiskList            = [string[]]@($ruleNode.RiskList.Risk | Where-Object -FilterScript { $_ })
                CharacteristicsList = [string[]]@($ruleNode.CharacteristicsList.Characteristics | Where-Object -FilterScript { $_ })
                TechnologyList      = [string[]]@($ruleNode.TechnologyList.Technology | Where-Object -FilterScript { $_ })
                ApplicationList     = [string[]]@($ruleNode.ApplicationList.Application | Where-Object -FilterScript { $_ })
                SmartFilter         = [string]$ruleNode.SmartFilter
                Action              = [string]$ruleNode.Action
                Schedule            = [string]$ruleNode.Schedule
            }
        }

        [PSCustomObject]@{
            Name             = [string]$node.Name
            Description      = [string]$node.Description
            DefaultAction    = [string]$node.DefaultAction
            MicroAppSupport  = [string]$node.MicroAppSupport
            RuleList         = @($rules | Where-Object -FilterScript { $_ })
        }
    }

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
        Creates a new ApplicationFilterPolicy on the Sophos Firewall.

        .DESCRIPTION
        Creates an ApplicationFilterPolicy object, which groups application-matching rules
        into a policy that can be assigned to a firewall rule. Rules can be supplied at
        creation time via -Rule, built with New-SfosApplicationFilterPolicyRule, or added
        afterwards with Add-SfosApplicationFilterPolicyRule. Creating a policy with no rules
        at all is accepted by the firewall (measured) - -Rule is optional.

        .PARAMETER Name
        Name of the policy (1-60 characters, no commas) [doc].

        .PARAMETER Description
        Optional description (max 1000 characters) [doc].

        .PARAMETER DefaultAction
        'Allow' or 'Deny' - the action for traffic that matches no rule [doc]. IMPORTANT
        (measured): this value is only honored at creation time. Every subsequent
        Set-SfosApplicationFilterPolicy call silently keeps the value set here, no matter
        what is sent for -DefaultAction on the update - see Set-SfosApplicationFilterPolicy's
        .NOTES. Choose it carefully; it cannot be changed later through this API.

        .PARAMETER MicroAppSupport
        'True' or 'False' [doc]. IMPORTANT (measured): the firewall always reports this as
        'True' regardless of what is sent, on both add and update - every attempt to create
        or set it to 'False' in this build's testing came back 'True'. Default 'True', to
        match what the firewall actually does.

        .PARAMETER Rule
        Zero or more rule objects, in the order they should be evaluated. Build each entry
        with New-SfosApplicationFilterPolicyRule. Omitting -Rule entirely creates a policy
        with an empty RuleList (measured), which Get-SfosApplicationFilterPolicy then reports
        back as RuleList = @().

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        New-SfosApplicationFilterPolicy -Name "BranchOfficeApps" -Description "Empty test policy" -DefaultAction Allow

        .EXAMPLE
        # Create a policy with one rule that blocks a specific named application
        $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application "Lantern" -Action Deny -Schedule "All The Time"
        New-SfosApplicationFilterPolicy -Name "BranchOfficeBlockLantern" -DefaultAction Allow -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/operations/Appfilterpolicyaddfromapi%26Appfilterpolicyedit.html

        .LINK
        Get-SfosApplicationFilterPolicy

        .LINK
        New-SfosApplicationFilterPolicyRule
#>
function New-SfosApplicationFilterPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 1000)]
        [string]$Description,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateSet('Allow', 'Deny')]
        [string]$DefaultAction,

        [ValidateSet('True', 'False')]
        [string]$MicroAppSupport = 'True',

        [PSCustomObject[]]$Rule,

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
        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterPolicy '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $policy = [PSCustomObject]@{
            Name            = $Name
            Description     = $Description
            DefaultAction   = $DefaultAction
            MicroAppSupport = $MicroAppSupport
            RuleList        = @($Rule)
        }

        $inner = ConvertTo-SfosApplicationFilterPolicyEntityXml -Operation 'add' -Policy $policy

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create ApplicationFilterPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterPolicy' -Action 'create' -Target $Name
    }
}

<#
        .SYNOPSIS
        Updates an existing ApplicationFilterPolicy object on the Sophos Firewall.

        .DESCRIPTION
        Updates an ApplicationFilterPolicy object using the Sophos Firewall XML API. You can
        supply the target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current policy first and keeps
        whatever the caller does not explicitly pass.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Description
        Optional description text. If omitted, the existing description is kept.

        .PARAMETER DefaultAction
        'Allow' or 'Deny' [doc]. IMPORTANT (measured): sending this parameter has NO EFFECT.
        The firewall silently keeps whatever DefaultAction was set when the policy was
        created, no matter what value is sent here - reproduced across repeated updates with
        both 'Allow' and 'Deny'. The parameter is still accepted (and, per the project's
        read-modify-write rule, always resent with the current value so nothing else about
        the request looks incomplete) so that a caller's intent is visible in their script,
        but it will not change the policy on this firmware. There is no way to change
        DefaultAction after creation through this API - recreate the policy instead.

        .PARAMETER MicroAppSupport
        'True' or 'False' [doc]. IMPORTANT (measured): the firewall always reports this as
        'True' after any write, regardless of what is sent - see
        New-SfosApplicationFilterPolicy's .PARAMETER MicroAppSupport for the same finding on
        create.

        .PARAMETER Rule
        Complete replacement rule list, in the order the firewall should evaluate them. This
        REPLACES the existing RuleList wholesale, exactly as the API does - it does not merge
        with the rules already on the firewall (measured: shrinking from 2 rules to 1, and
        sending an empty RuleList, both work as expected - RuleList is not append-only on
        this entity). Omit this parameter to keep the existing rules unchanged. To add or
        remove a single rule without touching the rest of the list, use
        Add-SfosApplicationFilterPolicyRule / Remove-SfosApplicationFilterPolicyRule instead.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        # Change only the description, RuleList and DefaultAction are preserved
        Set-SfosApplicationFilterPolicy -Name "BranchOfficeApps" -Description "Updated description" -DefaultAction Allow

        .EXAMPLE
        # Update using pipeline input
        Get-SfosApplicationFilterPolicy -NameLike "BranchOfficeApps" | Set-SfosApplicationFilterPolicy -Description "Updated"

        .NOTES
        Minimum supported PowerShell version: 5.1
        No write protection for the 7 factory-default application filter policies - this
        cmdlet will overwrite one, including its RuleList, without any warning from the API.
        Verify -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/operations/Appfilterpolicyaddfromapi%26Appfilterpolicyedit.html

        .LINK
        Get-SfosApplicationFilterPolicy
#>
function Set-SfosApplicationFilterPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 1000)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Allow', 'Deny')]
        [string]$DefaultAction,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('True', 'False')]
        [string]$MicroAppSupport,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('RuleList')]
        [PSCustomObject[]]$Rule,

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
        $existing = @(Get-SfosApplicationFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterPolicy object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Description')) {
            $targetPolicy.Description = $Description
        }
        if ($PSBoundParameters.ContainsKey('DefaultAction')) {
            # No-op on this firmware once the policy exists - see .PARAMETER DefaultAction.
            # Still forwarded so the request reflects what the caller asked for.
            $targetPolicy.DefaultAction = $DefaultAction
        }
        if ($PSBoundParameters.ContainsKey('MicroAppSupport')) {
            $targetPolicy.MicroAppSupport = $MicroAppSupport
        }
        if ($PSBoundParameters.ContainsKey('Rule')) {
            # Wholesale replacement, matching the API - not a merge. See .PARAMETER Rule.
            $targetPolicy.RuleList = @($Rule)
        }

        $inner = ConvertTo-SfosApplicationFilterPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterPolicy '$($Name)' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating ApplicationFilterPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterPolicy' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an ApplicationFilterPolicy object from the Sophos Firewall.

        .DESCRIPTION
        Removes an ApplicationFilterPolicy object using the Sophos Firewall XML API. This
        cmdlet supports ShouldProcess; use -WhatIf to preview the change.

        Removing a policy name that does not exist answers a misleading 503 'Operation
        failed. Entity having same parameter details already exists.' [measured against the
        lab firewall] - not a 'not found'-shaped message at all. This cmdlet therefore reads
        the object first and throws 'was not found' for a name that is not present, rather
        than surfacing that response.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        Remove-SfosApplicationFilterPolicy -Name "BranchOfficeApps"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Never target the 7 factory-default application filter policies with this cmdlet.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/operations/Appfilter%20Policy%20delete.html

        .LINK
        Get-SfosApplicationFilterPolicy
#>
function Remove-SfosApplicationFilterPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
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
        $existing = @(Get-SfosApplicationFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterPolicy object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><ApplicationFilterPolicy><Name>$nameEsc</Name></ApplicationFilterPolicy></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove ApplicationFilterPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterPolicy' -Action 'remove' -Target $Name
    }
}

<#
        .SYNOPSIS
        Builds a rule for use inside an ApplicationFilterPolicy's RuleList.

        .DESCRIPTION
        Creates the object New-SfosApplicationFilterPolicy -Rule, Set-SfosApplicationFilterPolicy
        -Rule and Add-SfosApplicationFilterPolicyRule expect. Performs no API call - the rule
        only becomes part of a policy once handed to one of those cmdlets. SFOS persists rule
        order unchanged, so build rules in the order they must be evaluated.

        A rule works in one of two measured selection modes, controlled by -SelectAllRule:

        - 'Disable' (individual applications): -Application is mandatory and is stored
          exactly as supplied. -Category, -Risk, -Characteristics and -Technology are IGNORED
          - the firewall recomputes them itself from the real signature metadata of the
            applications in -Application, regardless of what is passed here [measured].
          Omitting -Application entirely in this mode causes the whole rule to be silently
          dropped by the firewall on write (200, but the rule disappears) [measured] - this
          cmdlet throws instead of building a rule that would vanish.
        - 'Enable' (broad selection): supply -Category, -Risk, -Characteristics and/or
          -Technology with values the firewall recognizes (there is no client-side
          ValidateSet - the live category/risk/characteristic/technology catalog is large and
          was not enumerated for this build); the firewall computes the matching
          -ApplicationList itself, discarding anything passed there [measured]. An
          unrecognized value in these lists is not rejected - it is silently dropped and
          nothing is computed (200, no error) [measured], so verify with
          Get-SfosApplicationFilterPolicy after using this mode with values you have not
          confirmed against the live category catalog (Get-SfosApplicationFilterCategory in
          another module group of this project, or the web admin).

        .PARAMETER InputObject
        An existing rule to use as the base, as returned in the RuleList of
        Get-SfosApplicationFilterPolicy. Accepts pipeline input. Only the parameters you
        actually supply override it, so a single field can be changed without disturbing the
        rest. Without it, every omitted parameter falls back to its default.

        .PARAMETER SelectAllRule
        'Enable' or 'Disable' - see .DESCRIPTION for the two selection modes this actually
        drives. Default 'Disable'.

        .PARAMETER Category
        Application category names for 'Enable' mode, for example 'Proxy and Tunnel',
        'Gaming'. Ignored in 'Disable' mode - see .DESCRIPTION.

        .PARAMETER Risk
        Risk level names for 'Enable' mode, for example 'Very High'. Ignored in 'Disable'
        mode - see .DESCRIPTION.

        .PARAMETER Characteristics
        Characteristic names for 'Enable' mode, for example 'Tunnels other apps'. Ignored in
        'Disable' mode - see .DESCRIPTION.

        .PARAMETER Technology
        Technology names for 'Enable' mode, for example 'Client Server'. Ignored in 'Disable'
        mode - see .DESCRIPTION.

        .PARAMETER Application
        Application signature names, for example 'Lantern', 'TurboVPN'. Mandatory when
        -SelectAllRule is 'Disable' (see .DESCRIPTION); server-computed and thus ignored when
        -SelectAllRule is 'Enable' with a recognized category/risk/characteristics/technology
        value.

        .PARAMETER SmartFilter
        Free-text search filter, as stored by the web admin's rule builder search box.
        IMPORTANT (measured): a non-empty -SmartFilter causes the firewall to report
        SelectAllRule back as 'Enable' regardless of what was actually sent, and drops the
        computed CategoryList/RiskList/CharacteristicsList/TechnologyList - it behaves as a
        third, separate selection mode. Default '' (empty), matching every factory-default
        rule.

        .PARAMETER Action
        'Allow' or 'Deny' [doc, and validated live with a 501 on any other value]. Default
        'Deny'.

        .PARAMETER Schedule
        Name of an existing Schedule object, for example 'All The Time' (the default on every
        factory-default rule). IMPORTANT (measured): a Schedule name the firewall does not
        recognize is not rejected - it is silently replaced with 'All The Time' (200, no
        error). No client-side ValidateSet is offered, since the schedule catalog is a
        separate, dynamic entity outside the scope of this module group. Default
        'All The Time'.

        .OUTPUTS
        PSCustomObject with SelectAllRule, CategoryList, RiskList, CharacteristicsList,
        TechnologyList, ApplicationList, SmartFilter, Action and Schedule properties - the
        same shape Get-SfosApplicationFilterPolicy returns for each RuleList entry.

        .EXAMPLE
        # Block a single named application
        New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application "Lantern" -Action Deny -Schedule "All The Time"

        .EXAMPLE
        # Block every application in a whole category
        New-SfosApplicationFilterPolicyRule -SelectAllRule Enable -Category "Gaming" -Action Deny

        .EXAMPLE
        # Change one field of an existing rule read back from the firewall
        $policy = Get-SfosApplicationFilterPolicy -NameLike "BranchOfficeApps"
        $edited = $policy.RuleList[0] | New-SfosApplicationFilterPolicyRule -Action "Allow"
        Set-SfosApplicationFilterPolicy -Name "BranchOfficeApps" -Rule $edited

        .NOTES
        Minimum supported PowerShell version: 5.1
        This cmdlet performs no API call; it only builds an in-memory object.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/ApplicationFilterPolicy.html

        .LINK
        New-SfosApplicationFilterPolicy

        .LINK
        Add-SfosApplicationFilterPolicyRule
#>
function New-SfosApplicationFilterPolicyRule {
    # PSUseShouldProcessForStateChangingFunctions is suppressed on purpose. This function
    # builds an in-memory object and never calls the API, so there is no state change for
    # ShouldProcess to confirm. The verb New is still correct - it creates an object that is
    # then handed to New-/Set-SfosApplicationFilterPolicy or Add-SfosApplicationFilterPolicyRule,
    # which do declare ShouldProcess. Same pattern as New-SfosIPSPolicyRule in the sibling
    # IntrusionPrevention module.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [PSCustomObject]$InputObject,

        [ValidateSet('Enable', 'Disable')]
        [string]$SelectAllRule = 'Disable',

        [string[]]$Category,
        [string[]]$Risk,
        [string[]]$Characteristics,
        [string[]]$Technology,
        [string[]]$Application,

        [string]$SmartFilter = '',

        [ValidateSet('Allow', 'Deny')]
        [string]$Action = 'Deny',

        [string]$Schedule = 'All The Time'
    )

    process {
        # Precedence per field: an explicitly bound parameter wins, otherwise the value from
        # -InputObject, otherwise the parameter default. The ContainsKey test is what makes
        # editing safe - without it every default would overwrite the base. Same reasoning as
        # New-SfosIPSPolicyRule in the sibling IntrusionPrevention module.
        $selectAllValue = if ($PSBoundParameters.ContainsKey('SelectAllRule')) { $SelectAllRule }
        elseif ($InputObject -and $InputObject.SelectAllRule) { [string]$InputObject.SelectAllRule }
        else { $SelectAllRule }

        $categoryValue = if ($PSBoundParameters.ContainsKey('Category')) { @($Category) }
        elseif ($InputObject) { @($InputObject.CategoryList) }
        else { @() }

        $riskValue = if ($PSBoundParameters.ContainsKey('Risk')) { @($Risk) }
        elseif ($InputObject) { @($InputObject.RiskList) }
        else { @() }

        $characteristicsValue = if ($PSBoundParameters.ContainsKey('Characteristics')) { @($Characteristics) }
        elseif ($InputObject) { @($InputObject.CharacteristicsList) }
        else { @() }

        $technologyValue = if ($PSBoundParameters.ContainsKey('Technology')) { @($Technology) }
        elseif ($InputObject) { @($InputObject.TechnologyList) }
        else { @() }

        $applicationValue = if ($PSBoundParameters.ContainsKey('Application')) { @($Application) }
        elseif ($InputObject) { @($InputObject.ApplicationList) }
        else { @() }

        $smartFilterValue = if ($PSBoundParameters.ContainsKey('SmartFilter')) { $SmartFilter }
        elseif ($InputObject -and $null -ne $InputObject.SmartFilter) { [string]$InputObject.SmartFilter }
        else { $SmartFilter }

        $actionValue = if ($PSBoundParameters.ContainsKey('Action')) { $Action }
        elseif ($InputObject -and $InputObject.Action) { [string]$InputObject.Action }
        else { $Action }

        $scheduleValue = if ($PSBoundParameters.ContainsKey('Schedule')) { $Schedule }
        elseif ($InputObject -and $InputObject.Schedule) { [string]$InputObject.Schedule }
        else { $Schedule }

        $applicationValue = @($applicationValue | Where-Object -FilterScript { $_ })
        if ($selectAllValue -eq 'Disable' -and $applicationValue.Count -eq 0) {
            throw "New-SfosApplicationFilterPolicyRule: -SelectAllRule 'Disable' requires at least one -Application entry (directly or via -InputObject) - the firewall silently drops a Disable rule with no ApplicationList."
        }

        return [PSCustomObject]@{
            SelectAllRule       = $selectAllValue
            CategoryList        = @($categoryValue | Where-Object -FilterScript { $_ })
            RiskList            = @($riskValue | Where-Object -FilterScript { $_ })
            CharacteristicsList = @($characteristicsValue | Where-Object -FilterScript { $_ })
            TechnologyList      = @($technologyValue | Where-Object -FilterScript { $_ })
            ApplicationList     = $applicationValue
            SmartFilter         = $smartFilterValue
            Action              = $actionValue
            Schedule            = $scheduleValue
        }
    }
}

<#
        .SYNOPSIS
        Appends a rule to the end of an existing ApplicationFilterPolicy's RuleList.

        .DESCRIPTION
        Reads the current ApplicationFilterPolicy, appends the supplied rule after the
        existing ones, and writes the whole entity back - SFOS replaces RuleList wholesale on
        update, so the existing rules and their order are read back first and resent
        unchanged alongside the new one.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Rule
        Rule object to append, built with New-SfosApplicationFilterPolicyRule.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application "TurboVPN" -Action Deny
        Add-SfosApplicationFilterPolicyRule -Name "BranchOfficeApps" -Rule $rule

        .NOTES
        Minimum supported PowerShell version: 5.1
        No write protection for the 7 factory-default application filter policies. Verify
        -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/operations/Appfilterpolicyaddfromapi%26Appfilterpolicyedit.html

        .LINK
        New-SfosApplicationFilterPolicyRule

        .LINK
        Remove-SfosApplicationFilterPolicyRule
#>
function Add-SfosApplicationFilterPolicyRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [PSCustomObject]$Rule,

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
        $existing = @(Get-SfosApplicationFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterPolicy object '$Name' was not found."
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $targetPolicy.RuleList = @($existing[0].RuleList) + $Rule

        $inner = ConvertTo-SfosApplicationFilterPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterPolicy '$($Name)' on $($params.Firewall)", 'Add rule')) {
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
            throw "Error adding a rule to ApplicationFilterPolicy '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterPolicy' -Action 'add rule' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes a single rule from an existing ApplicationFilterPolicy's RuleList by index.

        .DESCRIPTION
        Reads the current ApplicationFilterPolicy, drops the rule at the given zero-based
        index from its RuleList, and writes the whole entity back - SFOS replaces RuleList
        wholesale on update, so the remaining rules and their order are resent unchanged.

        RuleList was measured to NOT be append-only on this entity: shrinking a policy from
        two rules to one took effect correctly and Get-SfosApplicationFilterPolicy read back
        the reduced list. This cmdlet still reads the object back after the update and throws
        if the rule count on the firewall does not match what was sent, rather than trusting
        the 200 status code alone - the defensive pattern used throughout this project for
        writes that could otherwise report success while changing nothing.

        .PARAMETER Name
        Name of the target policy.

        .PARAMETER Index
        Zero-based position of the rule to remove within the policy's RuleList, in the order
        returned by Get-SfosApplicationFilterPolicy. Throws if out of range.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        Remove-SfosApplicationFilterPolicyRule -Name "BranchOfficeApps" -Index 0

        .NOTES
        Minimum supported PowerShell version: 5.1
        No write protection for the 7 factory-default application filter policies. Verify
        -Name before running this against a shared/production policy.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterPolicy/operations/Appfilterpolicyaddfromapi%26Appfilterpolicyedit.html

        .LINK
        Add-SfosApplicationFilterPolicyRule
#>
function Remove-SfosApplicationFilterPolicyRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [int]$Index,

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
        $existing = @(Get-SfosApplicationFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterPolicy object '$Name' was not found."
        }

        $currentRules = @($existing[0].RuleList)
        if ($Index -lt 0 -or $Index -ge $currentRules.Count) {
            throw "ApplicationFilterPolicy '$Name' has $($currentRules.Count) rule(s); index $Index is out of range."
        }

        $targetRules = @()
        for ($i = 0; $i -lt $currentRules.Count; $i++) {
            if ($i -ne $Index) {
                $targetRules += $currentRules[$i]
            }
        }

        $targetPolicy = $existing[0].PSObject.Copy()
        $targetPolicy.RuleList = $targetRules

        $inner = ConvertTo-SfosApplicationFilterPolicyEntityXml -Operation 'update' -Policy $targetPolicy

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterPolicy '$($Name)' on $($params.Firewall)", "Remove rule at index $Index")) {
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
            throw "Error removing rule at index $Index from ApplicationFilterPolicy '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterPolicy' -Action 'remove rule' -Target $Name

        # RuleList is not append-only on this entity (measured, see .DESCRIPTION), but a 200
        # that changes nothing is exactly the failure mode this project has been bitten by
        # before - read back and throw rather than trust the status code alone.
        $after = @(Get-SfosApplicationFilterPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })
        $afterCount = @($after[0].RuleList).Count
        if ($afterCount -ne $targetRules.Count) {
            throw "Removing rule at index $Index from ApplicationFilterPolicy '$Name' reported success, but the firewall now reports $afterCount rule(s) instead of the expected $($targetRules.Count)."
        }
    }
}

#endregion


#region ApplicationObject

function ConvertTo-SfosApplicationObjectEntityXml {
    # Internal helper, not exported. Builds the <Set> inner XML for an ApplicationObject
    # entity, using the shared ConvertTo-SfosAppFilterListXml helper for the same nested
    # selection lists a policy Rule uses. SFOS replaces the whole entity on
    # <Set operation="update">, so New-/Set-SfosApplicationObject merge every field they want
    # preserved into -Application before calling this function.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Application
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Application.Name)
    $selectAllEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Application.SelectAllRule)
    $smartFilterEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Application.SmartFilter)

    $listXml = ConvertTo-SfosAppFilterListXml -Category $Application.CategoryList -Risk $Application.RiskList `
        -Characteristics $Application.CharacteristicsList -Technology $Application.TechnologyList `
        -Application $Application.ApplicationList

    return @"
<Set operation="$Operation">
  <ApplicationObject>
    <Name>$nameEsc</Name>
    <SelectAllRule>$selectAllEsc</SelectAllRule>
    $listXml
    <SmartFilter>$smartFilterEsc</SmartFilter>
  </ApplicationObject>
</Set>
"@
}

<#
        .SYNOPSIS
        Retrieves ApplicationObject objects from the Sophos Firewall.

        .DESCRIPTION
        Queries the Sophos Firewall XML API for ApplicationObject objects (PROTECT >
        Applications > "Application" in the web admin). By default the cmdlet returns
        PowerShell-friendly objects. Use -AsXml to return the raw XML nodes.

        An ApplicationObject groups a set of applications (individually, or via
        category/risk/characteristics/technology criteria) into a single reusable named
        object - the same selection shape used inside an ApplicationFilterPolicy Rule (see
        the internal ConvertTo-SfosAppFilterListXml helper shared by both entities), but
        without the rule-specific Action/Schedule fields. There are no factory-default
        ApplicationObjects - the lab appliance had zero at the start of this build.

        .PARAMETER NameLike
        Optional name filter. In Sophos SFOS, 'like' behaves as a substring match. Sent to
        the firewall as the server-side filter and re-applied client-side, per the project's
        filtering rules.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        PSCustomObject with Name, SelectAllRule, CategoryList, RiskList,
        CharacteristicsList, TechnologyList, ApplicationList and SmartFilter.
        System.Xml.XmlElement when -AsXml is specified.

        .EXAMPLE
        Get-SfosApplicationObject

        .EXAMPLE
        Get-SfosApplicationObject -NameLike "VPN"

        .NOTES
        Minimum supported PowerShell version: 5.1
        Same measured CategoryList/RiskList/CharacteristicsList/TechnologyList computation
        behavior as ApplicationFilterPolicy's Rule - see New-SfosApplicationObject's .NOTES.

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationObject/ApplicationObject.html
#>
function Get-SfosApplicationObject {
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
  <ApplicationObject>
    $filterXml
  </ApplicationObject>
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
        throw "Error retrieving ApplicationObject objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationObject' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ApplicationObject[Name]' | ForEach-Object -Process {
        $_.Node
    }

    $objects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name                = [string]$node.Name
            SelectAllRule       = [string]$node.SelectAllRule
            CategoryList        = [string[]]@($node.CategoryList.Category | Where-Object -FilterScript { $_ })
            RiskList            = [string[]]@($node.RiskList.Risk | Where-Object -FilterScript { $_ })
            CharacteristicsList = [string[]]@($node.CharacteristicsList.Characteristics | Where-Object -FilterScript { $_ })
            TechnologyList      = [string[]]@($node.TechnologyList.Technology | Where-Object -FilterScript { $_ })
            ApplicationList     = [string[]]@($node.ApplicationList.Application | Where-Object -FilterScript { $_ })
            SmartFilter         = [string]$node.SmartFilter
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
        .SYNOPSIS
        Creates a new ApplicationObject on the Sophos Firewall.

        .DESCRIPTION
        Creates an ApplicationObject, a reusable named grouping of applications that can be
        referenced elsewhere (for example from a firewall rule) instead of listing individual
        applications each time.

        Uses the same two measured selection modes as an ApplicationFilterPolicy Rule (see
        New-SfosApplicationFilterPolicyRule's .DESCRIPTION for the full write-up):
        -SelectAllRule 'Disable' stores -Application literally and requires at least one
        entry; -SelectAllRule 'Enable' with a recognized -Category/-Risk/-Characteristics/
        -Technology value computes -Application from that criterion server-side. In both
        modes, whichever of Category/Risk/Characteristics/Technology is NOT the active
        selection mechanism is ignored or dropped by the firewall on write, exactly as
        measured for the policy Rule shape.

        .PARAMETER Name
        Name of the application object (1-80 characters, no commas) [doc].

        .PARAMETER SelectAllRule
        'Enable' or 'Disable' [doc, validated live with a 501 on any other value]. Default
        'Disable'.

        .PARAMETER Category
        Application category names for 'Enable' mode. Ignored in 'Disable' mode - see
        .DESCRIPTION.

        .PARAMETER Risk
        Risk level names for 'Enable' mode. Ignored in 'Disable' mode - see .DESCRIPTION.

        .PARAMETER Characteristics
        Characteristic names for 'Enable' mode. Ignored in 'Disable' mode - see .DESCRIPTION.

        .PARAMETER Technology
        Technology names for 'Enable' mode. Ignored in 'Disable' mode - see .DESCRIPTION.

        .PARAMETER Application
        Application signature names, for example 'Lantern'. Mandatory when -SelectAllRule is
        'Disable'; server-computed and thus ignored when -SelectAllRule is 'Enable' with a
        recognized criterion.

        .PARAMETER SmartFilter
        Free-text search filter. IMPORTANT (measured): a non-empty value causes the firewall
        to report SelectAllRule back as 'Enable' regardless of what was sent, and drops the
        computed lists - same finding as the policy Rule shape. Default '' (empty).

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        # Group a single named application
        New-SfosApplicationObject -Name "KnownProxyApp" -SelectAllRule Disable -Application "Lantern"

        .EXAMPLE
        # Group every application in a category
        New-SfosApplicationObject -Name "AllGamingApps" -SelectAllRule Enable -Category "Gaming"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationObject/operations/Applicationobjectadd%26Applicationobjectedit.html

        .LINK
        Get-SfosApplicationObject
#>
function New-SfosApplicationObject {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 80)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('Enable', 'Disable')]
        [string]$SelectAllRule = 'Disable',

        [string[]]$Category,
        [string[]]$Risk,
        [string[]]$Characteristics,
        [string[]]$Technology,
        [string[]]$Application,

        [string]$SmartFilter = '',

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
        $applicationValue = @($Application | Where-Object -FilterScript { $_ })
        if ($SelectAllRule -eq 'Disable' -and $applicationValue.Count -eq 0) {
            throw "New-SfosApplicationObject: -SelectAllRule 'Disable' requires at least one -Application entry - the firewall silently drops an ApplicationObject with no ApplicationList (measured, same finding as the policy Rule shape)."
        }

        if (-not $PSCmdlet.ShouldProcess("ApplicationObject '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $applicationObj = [PSCustomObject]@{
            Name                = $Name
            SelectAllRule       = $SelectAllRule
            CategoryList        = @($Category)
            RiskList            = @($Risk)
            CharacteristicsList = @($Characteristics)
            TechnologyList      = @($Technology)
            ApplicationList     = $applicationValue
            SmartFilter         = $SmartFilter
        }

        $inner = ConvertTo-SfosApplicationObjectEntityXml -Operation 'add' -Application $applicationObj

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create ApplicationObject '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationObject' -Action 'create' -Target $Name
    }
}

<#
        .SYNOPSIS
        Updates an existing ApplicationObject on the Sophos Firewall.

        .DESCRIPTION
        Updates an ApplicationObject using the Sophos Firewall XML API. You can supply the
        target object name directly or via the pipeline.

        SFOS replaces the whole entity on update - any element not sent in the request is
        cleared on the firewall. This cmdlet reads the current object first and keeps
        whatever the caller does not explicitly pass. operation="update" was measured to
        update the existing object in place (no duplicate created) - unlike some other
        entities in this project's history, "edit" was not needed.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER SelectAllRule
        'Enable' or 'Disable'. If omitted, the existing value is kept. See
        New-SfosApplicationObject's .DESCRIPTION for the two selection modes.

        .PARAMETER Category
        Application category names for 'Enable' mode. If omitted, the existing value is kept
        (though it is recomputed by the firewall regardless in 'Disable' mode - see New-SfosApplicationObject's .DESCRIPTION above).

        .PARAMETER Risk
        Risk level names for 'Enable' mode. If omitted, the existing value is kept.

        .PARAMETER Characteristics
        Characteristic names for 'Enable' mode. If omitted, the existing value is kept.

        .PARAMETER Technology
        Technology names for 'Enable' mode. If omitted, the existing value is kept.

        .PARAMETER Application
        Application signature names. If omitted, the existing value is kept. Mandatory
        (directly or via the preserved existing value) when the resulting -SelectAllRule is
        'Disable'.

        .PARAMETER SmartFilter
        Free-text search filter. If omitted, the existing value is kept.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        # Add a second application to an existing 'Disable'-mode object
        Set-SfosApplicationObject -Name "KnownProxyApp" -Application "Lantern", "TurboVPN"

        .EXAMPLE
        # Update using pipeline input
        Get-SfosApplicationObject -NameLike "KnownProxyApp" | Set-SfosApplicationObject -SmartFilter "proxy"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationObject/operations/Applicationobjectadd%26Applicationobjectedit.html

        .LINK
        Get-SfosApplicationObject
#>
function Set-SfosApplicationObject {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 80)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('Enable', 'Disable')]
        [string]$SelectAllRule,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$Category,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$Risk,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$Characteristics,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$Technology,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$Application,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SmartFilter,

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
        $existing = @(Get-SfosApplicationObject -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationObject '$Name' was not found."
        }

        $target = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('SelectAllRule')) { $target.SelectAllRule = $SelectAllRule }
        if ($PSBoundParameters.ContainsKey('Category')) { $target.CategoryList = @($Category) }
        if ($PSBoundParameters.ContainsKey('Risk')) { $target.RiskList = @($Risk) }
        if ($PSBoundParameters.ContainsKey('Characteristics')) { $target.CharacteristicsList = @($Characteristics) }
        if ($PSBoundParameters.ContainsKey('Technology')) { $target.TechnologyList = @($Technology) }
        if ($PSBoundParameters.ContainsKey('Application')) { $target.ApplicationList = @($Application) }
        if ($PSBoundParameters.ContainsKey('SmartFilter')) { $target.SmartFilter = $SmartFilter }

        if ($target.SelectAllRule -eq 'Disable' -and @($target.ApplicationList | Where-Object { $_ }).Count -eq 0) {
            throw "Set-SfosApplicationObject: '$Name' would end up with -SelectAllRule 'Disable' and no -Application entries - the firewall silently drops such an object on write."
        }

        $inner = ConvertTo-SfosApplicationObjectEntityXml -Operation 'update' -Application $target

        if (-not $PSCmdlet.ShouldProcess("ApplicationObject '$Name' on $($params.Firewall)", 'Edit')) {
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
            throw "Error updating ApplicationObject '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationObject' -Action 'edit' -Target $Name
    }
}

<#
        .SYNOPSIS
        Removes an ApplicationObject from the Sophos Firewall.

        .DESCRIPTION
        Removes an ApplicationObject using the Sophos Firewall XML API. This cmdlet supports
        ShouldProcess; use -WhatIf to preview the change.

        Removing an object name that does not exist answers a misleading 503 'Operation
        failed. Entity having same parameter details already exists.' [measured against the
        lab firewall] - the same wrong-shaped message measured for
        Remove-SfosApplicationFilterPolicy. This cmdlet therefore reads the object first and
        throws 'was not found' for a name that is not present.

        .PARAMETER Name
        Name of the target object.

        .PARAMETER Session
        A session object returned by Connect-SfosFirewall, or the name of a session
        registered with Connect-SfosFirewall -Name. Overrides the stored default
        connection context; any of -Firewall/-Port/-Username/-Password/
        -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
        between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
        Remove-SfosApplicationObject -Name "KnownProxyApp"

        .NOTES
        Minimum supported PowerShell version: 5.1

        .LINK
        https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationObject/operations/Application%20object%20delete.html

        .LINK
        Get-SfosApplicationObject
#>
function Remove-SfosApplicationObject {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 80)]
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
        $existing = @(Get-SfosApplicationObject -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationObject '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ApplicationObject '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><ApplicationObject><Name>$nameEsc</Name></ApplicationObject></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove ApplicationObject '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationObject' -Action 'remove' -Target $Name
    }
}

#endregion

# SophosFirewall.Applications - Group B: ApplicationFilterCategory,
# ApplicationClassificationAssignment (single + batch), ApplicationClassification switch.
#
# Measured live against SFOS 22.0 in the lab. Key cross-cutting findings for
# this fragment - see each function's .NOTES for the specific evidence:
#
# 1. ApplicationFilterCategory has NO documented add or delete operation - only "edit"
#    (doc URL .../ApplicationFilterCategory/operations/ApplicationCategory.html). The 26
#    categories are firmware-fixed. operation="edit" is untrusted without
#    a duplicate check; measured live, "edit" behaves identically to "update" for this
#    entity (200, no duplicate created, same silent-no-op-on-Description behaviour - see
#    Set-SfosApplicationFilterCategory). "update" is used exclusively, since only "add"/
#    "update" are trusted verbs in this API. New-/Remove- are deliberately not built:
#    there is no operation to base them on, and inventing operation="add" against a fixed
#    26-row table would be exactly the kind of unsafe guess.
# 2. Get-SfosApplicationFilterCategory: server-side filtering is a no-op for BOTH "Name"
#    and "Description" keys (measured: a Name-like or Description-like filter for a single
#    category returns all 26 rows unchanged). This project sends only keys
#    "known to work" - since neither measured key works for this entity, no <Filter> is sent
#    at all and -NameLike is client-side only, the same exception already documented for
#    ContentConditionList.
# 3. Set-SfosApplicationFilterCategory -Description is a genuine silent no-op on this
#    firmware [measured]: a <Set operation="update"> that changes ONLY Description answers
#    200, and a subsequent Get shows the original text unchanged - reproduced 3 times,
#    including bundled with a QoSPolicy change that DID persist in the same request. This is
#    the same defect class as Remove-SfosSSLBookmark: a write that reports
#    success and changes nothing. For that class, the cmdlet reads the object
#    back and throws when a caller-requested Description change did not take effect, rather
#    than silently reporting success.
# 4. QoSPolicy on ApplicationFilterCategory only accepts a QoSPolicy object whose own
#    PolicyBasedOn is "Application" [measured]: 'Streaming Video - Limit to SD Quality'
#    (PolicyBasedOn=Application) succeeded and persisted; 'VoIP Guarantee'
#    (PolicyBasedOn=FirewallRule) and 'Low Guarantee User' (PolicyBasedOn=User) both answered
#    501 "Configuration parameters validation failed" with no <InvalidParams> detail. 'None'
#    (the default, clearing any QoS assignment) round-trips as a genuine no-op. This
#    constraint is undocumented on the ApplicationFilterCategory operation page.
# 5. BandwidthUsageType only takes effect together with a real (non-'None') QoSPolicy
#    [measured]: sending BandwidthUsageType alone against QoSPolicy=None is silently ignored
#    (200, unchanged on re-Get), but sending it alongside a valid Application-scoped
#    QoSPolicy in the same request persists correctly.
# 6. The per-application QoS override subtree <ApplicationSettings><Application><Name/
#    QoSPolicy></Application></ApplicationSettings> DOES work and follows the documented
#    full-replace rule: writing it with one <Application> entry persists
#    and is visible on the next Get (measured with Application 'Instagram' and QoSPolicy
#    'Streaming Video - Limit to SD Quality' inside category 'Mobile Applications');
#    omitting the wrapper entirely on a later update clears it back to no per-app overrides.
#    Set-SfosApplicationFilterCategory therefore preserves the existing ApplicationSettings
#    list whenever the caller does not pass -ApplicationSettings, and the dedicated
#    Add-/Remove-SfosApplicationFilterCategoryMember cmdlets exist because every
#    entity that has a member list gets Add-/Remove-...Member cmdlets.
# 7. ApplicationClassificationAssignment: server-side filtering is a no-op for BOTH
#    "Application" and "Classification" keys, exact and like criteria alike [measured against
#    the live 520-row set - every filter tried still returned all 520 rows]. -ApplicationLike
#    and -ClassificationLike are therefore client-side only, no <Filter> is sent.
# 8. Classification value space [measured]: every one of the live 520 assignments currently
#    reads 'New'. Resending 'New' (exact case) succeeds as a no-op (200). Every other
#    candidate tried - 'Reviewed', 'Existing', 'Approved', 'Old', 'Unclassified', 'Known',
#    'Ignore', 'Ignored', 'Acknowledged', 'Seen', 'Discovered', 'None', 'Default', '' (empty),
#    and case variants 'new'/'NEW' - answered 501 "Configuration parameters validation
#    failed" naming /ApplicationClassificationAssignment/Classification in <InvalidParams>.
#    No documented enum exists for this field and the vendor operation page confirms none is
#    published. Only 'New' is confirmed to work on this firmware; the parameter is therefore
#    left as an unrestricted string (no ValidateSet) rather than inventing enum values the
#    API does not document, and the finding is recorded
#    here rather than baked into client-side validation that could reject a value the vendor
#    later documents.
# 9. ApplicationClassificationBatchAssignment: the wire element names are lower-case
#    <app>/<class> (confirmed both by the doc sample AND by re-sending live Get data), unlike
#    the single-assignment operation's <Application>/<Classification>. Sending the
#    upper-case, single-assignment names inside the batch wrapper is rejected: 501 with an
#    EMPTY <InvalidParams/> (no field named) - measured, and the same empty-InvalidParams
#    signature seen for the IsDefault/PerConnectionAuth blockers elsewhere in
#    this project. A batch call with an unknown Application name is rejected the same way
#    (501, empty <InvalidParams/>), so an unresolvable entry in a batch cannot be diagnosed
#    per-item from the response - it is reported as one failure for the whole batch, unlike
#    the single-assignment operation which names the specific field in <InvalidParams>.
#    Multi-entry batches with valid data succeed as a single 200 (measured with 2 entries).
#
# Design choice for pipeline vs. batch (both cmdlets exist, deliberately):
# Set-SfosApplicationClassificationAssignment sends one API request per pipeline item,
# matching this project's usual Set-* semantics: precise per-object error attribution (the
# single-assignment operation names the failing field in <InvalidParams>; the batch
# operation, per finding 9 above, does not), and it is the natural target of
# `Get-SfosApplicationClassificationAssignment | Where-Object {...} | Set-...`.
# Set-SfosApplicationClassificationAssignmentBatch collects every pipeline item in the `end`
# block and issues exactly one API round trip, which is the whole point of the batch
# operation - saving N round trips for a bulk reclassification at the cost of per-item error
# detail. Callers who need per-item confirmation use the single cmdlet; callers who need to
# push hundreds of reclassifications quickly use the batch cmdlet.
#
# ApplicationClassification (undocumented singleton, wire root <ApplicationClassification>,
# single field <ACTION>On/Off</ACTION> - upper-case element name, unlike every other entity
# in this module):
# - No operation page exists for this entity at all (confirmed absent from the Applications
#   doc tree per apps-doku-inventar.md). The write path was probed only after capturing
#   baseline-ApplicationClassification-b.xml, and the ACTUAL toggle (On -> Off -> On) is
#   run as the LAST step of the whole session, not interleaved with the rest of the
#   verification, to keep the window during which application classification is off as
#   short as possible.
# - Status XPath measured the same way as every other entity: an invalid <ACTION>Bogus</ACTION>
#   answered code 501 at /Response/ApplicationClassification/Status[@code], with
#   <InvalidParams><Params>/ApplicationClassification/ACTION</Params></InvalidParams> - same
#   shape as IPSSwitch. A same-value no-op resend of <ACTION>On</ACTION> with
#   operation="update" answered a clean 200 and a following Get still read 'On' - the
#   documented precondition for going ahead with the real toggle test.
# - Get-SfosApplicationClassification uses the identical coded-vs-code-less Status special
#   case as Get-SfosIPSSwitch (a Status DATA FIELD without a code attribute is not
#   an API error) - here the field is <ACTION>, not <Status>, so there is no naming collision
#   at all and no special-casing is actually required; Get-SfosApplicationClassification
#   simply reads /Response/ApplicationClassification/ACTION as data. Documented here because
#   the task explicitly asked the heuristic to be checked, not assumed.

#region ApplicationFilterCategory

<#
.SYNOPSIS
    Retrieves ApplicationFilterCategory objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for ApplicationFilterCategory objects (PROTECT >
    Applications > Application Filter, called "Application Category" in the API operation
    name). These 26 categories are firmware-fixed - there is no add or delete operation, only
    edit - so this module ships Get/Set plus Add-/Remove-SfosApplicationFilterCategoryMember
    for the nested per-application QoS overrides, and no New-/Remove-SfosApplicationFilterCategory.

    Server-side filtering is measured to be a no-op for this entity on both the "Name" and
    "Description" keys - a filtered Get returns all 26 rows regardless. No <Filter> is sent;
    -NameLike is applied entirely client-side.

.PARAMETER NameLike
    Filters by Name, substring match. Client-side only - see .DESCRIPTION.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    # List all 26 application filter categories
    Get-SfosApplicationFilterCategory

.EXAMPLE
    # Find a category by name (client-side substring match)
    Get-SfosApplicationFilterCategory -NameLike 'Mobile'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: server-side filtering by Name or Description both return all 26 rows
    unfiltered - see the fragment header. ApplicationSettings (per-application QoS override
    list) is @() for every category unless Add-SfosApplicationFilterCategoryMember has been
    used on it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterCategory/ApplicationFilterCategory.html

.LINK
    Set-SfosApplicationFilterCategory
#>
function Get-SfosApplicationFilterCategory {
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

    $inner = '<Get><ApplicationFilterCategory></ApplicationFilterCategory></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ApplicationFilterCategory objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterCategory' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ApplicationFilterCategory[Name]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        $appNodes = @($node.SelectNodes('ApplicationSettings/Application'))
        $appList = foreach ($appNode in $appNodes) {
            [PSCustomObject]@{
                Name      = [string]$appNode.Name
                QoSPolicy = [string]$appNode.QoSPolicy
            }
        }

        [PSCustomObject]@{
            Name                = [string]$node.Name
            QoSPolicy           = [string]$node.QoSPolicy
            BandwidthUsageType  = [string]$node.BandwidthUsageType
            Description         = [string]$node.Description
            ApplicationSettings = @($appList)
        }
    }

    $objects = @($objects)
    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $objects
}

<#
.SYNOPSIS
    Updates an ApplicationFilterCategory on the Sophos Firewall.

.DESCRIPTION
    Updates an existing ApplicationFilterCategory (PROTECT > Applications > Application
    Filter) using the Sophos Firewall XML API. There is no create or delete operation for
    this entity - the 26 categories are firmware-fixed - so -Name identifies an existing
    category and cannot itself be changed [doc: "Category Name cannot be changed"].

    Reads the current object first and writes back every field, overriding only what the
    caller passed (read-modify-write) - this entity replaces the whole object on
    update, so an omitted ApplicationSettings list would otherwise silently clear every
    per-application QoS override.

    -Description is measured to be a silent no-op on this firmware: the API answers 200 but
    the value never changes on a following Get, reproduced even bundled with a QoSPolicy
    change that DID persist in the same request. If the caller explicitly asks for a
    Description change, this cmdlet re-reads the object afterwards and throws when the
    change did not take effect, rather than reporting a success that did not happen -
    the same treatment as Remove-SfosSSLBookmark's silent no-op delete.

.PARAMETER Name
    Name of the category to update [doc]. Identifies the object; cannot be changed.

.PARAMETER QoSPolicy
    Name of a QoSPolicy object to apply to the whole category, or 'None' to clear it [doc].
    Measured: only accepted when the referenced QoSPolicy's own PolicyBasedOn is
    'Application' - a QoSPolicy based on 'FirewallRule' or 'User' is rejected with 501
    'Configuration parameters validation failed' (no field-level detail). Not restricted by
    ValidateSet here because the set of eligible QoSPolicy names is data on the firewall
    (Get-SfosQoSPolicy is not part of this module), not a fixed vendor enum.

.PARAMETER BandwidthUsageType
    'Individual', 'Shared', or an empty string to clear it [doc]. Measured: only takes effect
    together with a QoSPolicy other than 'None' in the SAME request - sent alongside
    QoSPolicy='None' it is silently ignored. Empty string is accepted (not a strict
    ValidateSet) because every stock category's baseline value is the empty string.

.PARAMETER Description
    Free-text description [doc]. Measured to be a silent no-op on this firmware - see
    .DESCRIPTION. Included because it is documented and the request shape is otherwise
    correct; do not rely on it changing anything until Sophos fixes the firmware.

.PARAMETER ApplicationSettings
    Complete replacement list of per-application QoS overrides, each a PSCustomObject or
    hashtable with Name (application name) and QoSPolicy properties [doc/measured]. Omit to
    preserve the category's current list; pass an empty array to clear it (measured: an
    update that omits the <ApplicationSettings> wrapper entirely clears any existing
    overrides). Prefer Add-/Remove-SfosApplicationFilterCategoryMember for single-application
    changes - they read the current list for you.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    None. Throws an exception if the update fails or if a requested Description change was
    not confirmed on a following Get.

.EXAMPLE
    # Clear any QoS assignment from a category (round-trips as a no-op if already None)
    Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -QoSPolicy 'None'

.EXAMPLE
    # Assign an Application-scoped QoS policy with a bandwidth usage type
    Set-SfosApplicationFilterCategory -Name 'Mobile Applications' `
        -QoSPolicy 'Streaming Video - Limit to SD Quality' -BandwidthUsageType Individual

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live against SFOS 22.0: QoSPolicy+BandwidthUsageType change on category 'Mobile
    Applications' persisted and was reverted to the exact original baseline afterwards
    (byte-identical full-category-list comparison). See the fragment header for the
    QoSPolicy PolicyBasedOn constraint and the Description no-op finding.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterCategory/operations/ApplicationCategory.html

.LINK
    Get-SfosApplicationFilterCategory
#>
function Set-SfosApplicationFilterCategory {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [string]$QoSPolicy,
        # Not a strict ValidateSet: the baseline value on every stock category is the EMPTY
        # string (measured), which is the value needed to revert a category to 'no per-app
        # bandwidth grouping' after testing - a ValidateSet of just 'Individual'/'Shared'
        # would make that revert impossible through this cmdlet. Validated in the body
        # instead.
        [string]$BandwidthUsageType,
        [string]$Description,
        [PSCustomObject[]]$ApplicationSettings,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
        $bp = $PSBoundParameters

        $existing = @(Get-SfosApplicationFilterCategory -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
            Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterCategory object '$Name' was not found."
        }
        $existing = $existing[0]

        $targetQoSPolicy = if ($bp.ContainsKey('QoSPolicy')) { $QoSPolicy } else { $existing.QoSPolicy }
        $targetBandwidth = if ($bp.ContainsKey('BandwidthUsageType')) { $BandwidthUsageType } else { $existing.BandwidthUsageType }
        if ($targetBandwidth -and $targetBandwidth -ne 'Individual' -and $targetBandwidth -ne 'Shared') {
            throw "ApplicationFilterCategory '$Name': -BandwidthUsageType must be 'Individual', 'Shared' or an empty string, got '$targetBandwidth'."
        }
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { $existing.Description }
        # @() must wrap the whole if/else: on Windows PowerShell 5.1 a one-element array from
        # a branch unrolls to a scalar on assignment, which has no .Count, so the
        # ApplicationSettings block would silently vanish from the request.
        $targetAppSettings = @(if ($bp.ContainsKey('ApplicationSettings')) { $ApplicationSettings } else { $existing.ApplicationSettings })

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterCategory '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $qosEsc = ConvertTo-SfosXmlEscaped -Text $targetQoSPolicy
        $descEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

        $appSettingsXml = ''
        if ($targetAppSettings.Count -gt 0) {
            $appXml = ''
            foreach ($app in $targetAppSettings) {
                $appNameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$app.Name)
                $appQosEsc = ConvertTo-SfosXmlEscaped -Text ([string]$app.QoSPolicy)
                $appXml += "<Application><Name>$appNameEsc</Name><QoSPolicy>$appQosEsc</QoSPolicy></Application>"
            }
            $appSettingsXml = "<ApplicationSettings>$appXml</ApplicationSettings>"
        }

        $inner = @"
<Set operation="update">
  <ApplicationFilterCategory>
    <Name>$nameEsc</Name>
    $appSettingsXml
    <QoSPolicy>$qosEsc</QoSPolicy>
    <BandwidthUsageType>$targetBandwidth</BandwidthUsageType>
    <Description>$descEsc</Description>
  </ApplicationFilterCategory>
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
            throw "Failed to update ApplicationFilterCategory object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationFilterCategory' -Action 'update' -Target $Name

        if ($bp.ContainsKey('Description')) {
            $confirmed = @(Get-SfosApplicationFilterCategory -Firewall $params.Firewall -Port $params.Port `
                    -Username $params.Username -Password $params.Password `
                    -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

            if ($confirmed.Count -eq 0 -or $confirmed[0].Description -ne $Description) {
                throw "ApplicationFilterCategory '$Name' update reported success but the Description change was not confirmed on the firewall - this field is measured to be a silent no-op on this firmware (see module header). Requested '$Description', found '$($confirmed[0].Description)'."
            }
        }
    }
}

<#
.SYNOPSIS
    Adds or updates a per-application QoS override inside an ApplicationFilterCategory.

.DESCRIPTION
    Reads the current ApplicationFilterCategory, upserts one entry in its ApplicationSettings
    list (updates QoSPolicy if -Application already has an override, otherwise adds a new
    one), and writes the complete list back - this entity replaces the whole
    ApplicationSettings subtree on update, so every other override would otherwise be lost.

.PARAMETER Name
    Name of the ApplicationFilterCategory to modify.

.PARAMETER Application
    Name of the application to set a per-application QoS override for.

.PARAMETER QoSPolicy
    Name of the QoSPolicy object to apply to this application. Same PolicyBasedOn='Application'
    constraint as Set-SfosApplicationFilterCategory -QoSPolicy applies here - unconfirmed for
    the per-application field specifically, since the live test used 'Streaming Video - Limit
    to SD Quality' (PolicyBasedOn=Application) throughout.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' `
        -QoSPolicy 'Streaming Video - Limit to SD Quality'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: added Application='Instagram' to category 'Mobile Applications', confirmed
    via a following Get, then removed via Remove-SfosApplicationFilterCategoryMember and
    confirmed the category returned to its exact original baseline (byte-identical
    full-category-list comparison).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterCategory/operations/ApplicationCategory.html

.LINK
    Remove-SfosApplicationFilterCategoryMember
#>
function Add-SfosApplicationFilterCategoryMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Application,

        [Parameter(Mandatory)]
        # 'None' is refused client-side: the firewall answers 200 for a 'None' override but
        # stores nothing (measured), so it would be a silent no-op. To drop an existing
        # override, use Remove-SfosApplicationFilterCategoryMember instead.
        [ValidateScript({
            if ($_ -eq 'None') {
                throw "A per-application QoSPolicy of 'None' is not stored by the firewall (silent no-op). Use Remove-SfosApplicationFilterCategoryMember to remove an override."
            }
            $true
        })]
        [string]$QoSPolicy,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        $existing = @(Get-SfosApplicationFilterCategory -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
            Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterCategory object '$Name' was not found."
        }
        $existing = $existing[0]

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterCategory '$Name' on $($params.Firewall)", "Add/update member '$Application'")) {
            return
        }

        $merged = @($existing.ApplicationSettings | Where-Object -FilterScript { $_.Name -ne $Application })
        $merged += [PSCustomObject]@{ Name = $Application; QoSPolicy = $QoSPolicy }

        Set-SfosApplicationFilterCategory -Name $Name -ApplicationSettings $merged `
            -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false
    }
}

<#
.SYNOPSIS
    Removes a per-application QoS override from an ApplicationFilterCategory.

.DESCRIPTION
    Reads the current ApplicationFilterCategory, removes the entry for -Application from its
    ApplicationSettings list, and writes the remaining list back (or clears the wrapper
    entirely if -Application was the last entry - measured to actually remove the subtree,
    see the fragment header).

.PARAMETER Name
    Name of the ApplicationFilterCategory to modify.

.PARAMETER Application
    Name of the application whose per-application QoS override should be removed.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    None. Throws an exception if the update fails or if -Application had no override.

.EXAMPLE
    Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live - see Add-SfosApplicationFilterCategoryMember.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationFilterCategory/operations/ApplicationCategory.html

.LINK
    Add-SfosApplicationFilterCategoryMember
#>
function Remove-SfosApplicationFilterCategoryMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Application,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    process {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

        $existing = @(Get-SfosApplicationFilterCategory -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
            Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ApplicationFilterCategory object '$Name' was not found."
        }
        $existing = $existing[0]

        if (-not ($existing.ApplicationSettings | Where-Object -FilterScript { $_.Name -eq $Application })) {
            throw "Application '$Application' has no QoS override on ApplicationFilterCategory '$Name'."
        }

        if (-not $PSCmdlet.ShouldProcess("ApplicationFilterCategory '$Name' on $($params.Firewall)", "Remove member '$Application'")) {
            return
        }

        $remaining = @($existing.ApplicationSettings | Where-Object -FilterScript { $_.Name -ne $Application })

        Set-SfosApplicationFilterCategory -Name $Name -ApplicationSettings $remaining `
            -Firewall $params.Firewall -Port $params.Port -Username $params.Username -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck -Confirm:$false

        $confirmed = @(Get-SfosApplicationFilterCategory -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
            Where-Object -FilterScript { $_.Name -eq $Name })

        if ($confirmed.Count -gt 0 -and ($confirmed[0].ApplicationSettings | Where-Object -FilterScript { $_.Name -eq $Application })) {
            throw "Remove-SfosApplicationFilterCategoryMember reported success but '$Application' is still present on '$Name' after re-reading the object."
        }
    }
}

#endregion

#region ApplicationClassificationAssignment

<#
.SYNOPSIS
    Retrieves ApplicationClassificationAssignment objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for ApplicationClassificationAssignment objects
    (PROTECT > Applications > Application Classification Assignment) - the Application ->
    Classification mapping for every known application signature (520 rows on the lab
    firewall). Server-side filtering is measured to be a no-op for both the "Application" and
    "Classification" keys - a filtered Get still returns all rows. No <Filter> is sent;
    -ApplicationLike and -ClassificationLike are applied entirely client-side.

.PARAMETER ApplicationLike
    Filters by Application, substring match. Client-side only - see .DESCRIPTION.

.PARAMETER ClassificationLike
    Filters by Classification, substring match. Client-side only - see .DESCRIPTION.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    # All assignments (520 rows on the lab firewall)
    Get-SfosApplicationClassificationAssignment

.EXAMPLE
    # One application by exact substring
    Get-SfosApplicationClassificationAssignment -ApplicationLike '1Password'

.NOTES
    Minimum supported PowerShell version: 5.1
    Measured live: -ApplicationLike and -ClassificationLike are client-side only - see the
    fragment header for the full server-side filtering measurement (both keys, both
    criteria).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationClassificationAssignment/ApplicationClassificationAssignment.html

.LINK
    Set-SfosApplicationClassificationAssignment
#>
function Get-SfosApplicationClassificationAssignment {
    [CmdletBinding()]
    param(
        [string]$ApplicationLike,
        [string]$ClassificationLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><ApplicationClassificationAssignment></ApplicationClassificationAssignment></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ApplicationClassificationAssignment objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationClassificationAssignment' -Action 'get'

    # This entity has no <Name> child at all - the Core status heuristic's Name-sibling test
    # does not apply here; every returned node carries <Application> and
    # <Classification> and none of them collides with a status container, so a plain
    # selection of every child node is safe.
    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ApplicationClassificationAssignment[Application]' | ForEach-Object -Process { $_.Node }

    $objects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Application    = [string]$node.Application
            Classification = [string]$node.Classification
        }
    }

    $objects = @($objects)
    if ($ApplicationLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Application -like "*$ApplicationLike*" })
    }
    if ($ClassificationLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Classification -like "*$ClassificationLike*" })
    }

    if ($AsXml) {
        $keptKeys = @($objects | ForEach-Object -Process { $_.Application })
        return @($nodes | Where-Object -FilterScript { $keptKeys -contains $_.Application })
    }

    return $objects
}

<#
.SYNOPSIS
    Updates a single application's classification on the Sophos Firewall.

.DESCRIPTION
    Updates one ApplicationClassificationAssignment (PROTECT > Applications > Application
    Classification Assignment) using the Sophos Firewall XML API. Reads the assignment first
    to give a precise "not found" error before calling the API (this entity is Application ->
    Classification only, so there is nothing else to preserve). Pipeline-friendly by design -
    `Get-SfosApplicationClassificationAssignment | Where-Object {...} | Set-...` issues one
    API request per object.

    For pushing many reclassifications at once with a single round trip, see
    Set-SfosApplicationClassificationAssignmentBatch instead - see the fragment header for
    why both cmdlets exist.

.PARAMETER Application
    Name of the application to reclassify [doc]. Mandatory.

.PARAMETER Classification
    New classification value [doc]. Mandatory. Measured: only 'New' (exact case) is confirmed
    accepted on this firmware - every other value tried (see fragment header) is rejected
    with 501. Not restricted by ValidateSet because no vendor enum is documented for this
    field - see the fragment header for why inventing one would be unsafe.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    # No-op resend of the current (only confirmed-valid) classification value
    Set-SfosApplicationClassificationAssignment -Application '10000ft Plans' -Classification 'New'

.EXAMPLE
    # Reclassify every matching application from the pipeline
    Get-SfosApplicationClassificationAssignment -ApplicationLike '10000ft' |
        Set-SfosApplicationClassificationAssignment -Classification 'New'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: round trip on Application='10000ft Plans' (read 'New' -> write 'New' ->
    read 'New' again, raw XML for the row identical before and after) and the not-found error
    path (a made-up application name answers 501 naming
    /ApplicationClassificationAssignment/Application in <InvalidParams> - reproduced here as
    the pre-flight Get/throw so the caller gets a clear message instead of the raw API error).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/ApplicationClassificationAssignment/operations/UpdateApplicationClassificationAssignment.html

.LINK
    Get-SfosApplicationClassificationAssignment

.LINK
    Set-SfosApplicationClassificationAssignmentBatch
#>
function Set-SfosApplicationClassificationAssignment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Application,

        [Parameter(Mandatory)]
        [string]$Classification,

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
        $existing = @(Get-SfosApplicationClassificationAssignment -Firewall $params.Firewall -Port $params.Port `
                -Username $params.Username -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
            Where-Object -FilterScript { $_.Application -eq $Application })

        if ($existing.Count -eq 0) {
            throw "The ApplicationClassificationAssignment object for Application '$Application' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ApplicationClassificationAssignment '$Application' on $($params.Firewall)", "Set classification to '$Classification'")) {
            return
        }

        $appEsc = ConvertTo-SfosXmlEscaped -Text $Application
        $classEsc = ConvertTo-SfosXmlEscaped -Text $Classification

        $inner = @"
<Set operation="update">
  <ApplicationClassificationAssignment>
    <Application>$appEsc</Application>
    <Classification>$classEsc</Classification>
  </ApplicationClassificationAssignment>
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
            throw "Failed to update ApplicationClassificationAssignment '$Application': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationClassificationAssignment' -Action 'update' -Target $Application
    }
}

<#
.SYNOPSIS
    Updates multiple applications' classifications in a single API request.

.DESCRIPTION
    Collects Application/Classification pairs from the pipeline (or -InputObject) and sends
    them as one ApplicationClassificationBatchAssignment request (PROTECT > Applications >
    Application Classification Batch Assignment) when the pipeline completes - one round trip
    for the whole batch, instead of one per item like Set-SfosApplicationClassificationAssignment.

    The wire element names inside the batch are lower-case <app>/<class> - measured to differ
    from the single-assignment operation's <Application>/<Classification> (see the fragment
    header); this cmdlet builds the lower-case form and there is no parameter to override it.

    A rejected batch (bad Classification value, or an application that does not exist) fails
    for the WHOLE batch with a single 501 and an empty <InvalidParams/> - no per-item detail
    is available from the API (measured). This cmdlet therefore cannot tell the caller which
    entry was the problem; use Set-SfosApplicationClassificationAssignment for that.

.PARAMETER InputObject
    One or more objects with Application and Classification properties, typically from
    Get-SfosApplicationClassificationAssignment.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    None. Throws an exception if the batch update fails.

.EXAMPLE
    # No-op resend of two applications' current classification in one request
    Get-SfosApplicationClassificationAssignment -ApplicationLike '10Web' |
        Set-SfosApplicationClassificationAssignmentBatch

.EXAMPLE
    # Explicit pairs
    @(
        [PSCustomObject]@{ Application = '10Web'; Classification = 'New' }
        [PSCustomObject]@{ Application = '1Password'; Classification = 'New' }
    ) | Set-SfosApplicationClassificationAssignmentBatch

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: a 2-entry batch (Applications '10Web' and '1Password', both -> 'New', the
    only confirmed-valid value) answered a single 200; an upper-case
    <Application>/<Classification> batch and a batch containing an unknown application name
    both answered 501 with an empty <InvalidParams/> - see the fragment header.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/AppClassificationBatchAssignment/AppClassificationBatchAssignment.html

.LINK
    Set-SfosApplicationClassificationAssignment
#>
function Set-SfosApplicationClassificationAssignmentBatch {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$InputObject,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    begin {
        $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters
        $collected = New-Object System.Collections.Generic.List[object]
    }

    process {
        foreach ($item in $InputObject) {
            if (-not $item.Application -or -not $item.Classification) {
                throw 'Set-SfosApplicationClassificationAssignmentBatch: every input object needs Application and Classification properties.'
            }
            $collected.Add($item)
        }
    }

    end {
        if ($collected.Count -eq 0) {
            return
        }

        $names = ($collected | ForEach-Object -Process { $_.Application }) -join ', '
        if (-not $PSCmdlet.ShouldProcess("$($collected.Count) ApplicationClassificationAssignment object(s) on $($params.Firewall) ($names)", 'Batch update classification')) {
            return
        }

        $entryXml = ''
        foreach ($item in $collected) {
            $appEsc = ConvertTo-SfosXmlEscaped -Text ([string]$item.Application)
            $classEsc = ConvertTo-SfosXmlEscaped -Text ([string]$item.Classification)
            $entryXml += "<ClassAssignment><app>$appEsc</app><class>$classEsc</class></ClassAssignment>"
        }

        $inner = @"
<Set operation="update">
  <ApplicationClassificationBatchAssignment>
    <ClassAssignmentList>$entryXml</ClassAssignmentList>
  </ApplicationClassificationBatchAssignment>
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
            throw "Failed to batch-update ApplicationClassificationAssignment objects: $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationClassificationBatchAssignment' -Action 'batch update' -Target ($collected.Count.ToString() + ' object(s)')
    }
}

#endregion

#region ApplicationClassification

<#
.SYNOPSIS
    Retrieves the device-wide application classification switch state.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the ApplicationClassification singleton - an
    undocumented entity found only by live probing (no operation page exists for it anywhere
    in the Applications doc tree). Its single field <ACTION>On/Off</ACTION> controls whether
    the firewall classifies newly discovered applications at all.

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    Get-SfosApplicationClassification

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: reads <ACTION>On</ACTION> on the lab firewall. Unlike IPSSwitch/
    IPSFullSignaturePack, the data field here is named <ACTION>, not <Status> - there is no
    naming collision with the API status container at all, so no special-casing of the Core
    status heuristic is needed (checked, not assumed - see fragment header).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/

.LINK
    Set-SfosApplicationClassification
#>
function Get-SfosApplicationClassification {
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

    $inner = '<Get><ApplicationClassification></ApplicationClassification></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ApplicationClassification: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content

    # <ACTION> is a data field, not a status container - there is no <Status> element in this
    # entity's Get response at all, so the generic Assert can run unconditionally (it is a
    # no-op when there is nothing under /Response/ApplicationClassification/Status).
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationClassification' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/ApplicationClassification')
    if (-not $node) {
        throw 'ApplicationClassification could not be retrieved from the firewall.'
    }

    $value = [string]$node.ACTION
    if ($value -ne 'On' -and $value -ne 'Off') {
        throw "Sophos API returned an unrecognised ApplicationClassification ACTION: '$value'"
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        ACTION = $value
    }
}

<#
.SYNOPSIS
    Switches device-wide application classification on or off.

.DESCRIPTION
    Updates the undocumented ApplicationClassification singleton - no operation page exists
    for this entity, so operation="update" is used as the sole trusted verb,
    and the change is confirmed with a following Get before returning.

    This is a device-wide switch for the application classification engine, not an access
    control - see the fragment header for the Baseline-first, last-step-of-the-session
    handling this task applied to the one real toggle performed against the lab.

.PARAMETER ACTION
    'On' or 'Off' [measured - see fragment header; no documentation page exists for this
    entity to confirm the value set against].

.PARAMETER Session
A session object returned by Connect-SfosFirewall, or the name of a session
registered with Connect-SfosFirewall -Name. Overrides the stored default
connection context; any of -Firewall/-Port/-Username/-Password/
-SkipCertificateCheck supplied explicitly still wins over it. Enables piping
between firewalls, e.g. Get-SfosIPHost -Session $fw1 | New-SfosIPHost -Session fw2.

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
    # No-op resend of the current value - safe, does not change device behaviour
    Set-SfosApplicationClassification -ACTION On

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: a same-value resend of ACTION='On' with operation="update" answered a
    clean 200 and a following Get still read 'On' (the documented precondition for this
    task's real toggle test). An invalid ACTION='Bogus' answered 501 at
    /Response/ApplicationClassification/Status[@code] with
    <InvalidParams><Params>/ApplicationClassification/ACTION</Params></InvalidParams> - the
    measured status XPath used by Assert-SfosApiReturnSuccess via -ObjectName
    'ApplicationClassification'. The real Off->On toggle (this switch's only actual state
    change tested) was run once, as the last step of the whole verification session - see the
    task report for its result.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Applications/

.LINK
    Get-SfosApplicationClassification
#>
function Set-SfosApplicationClassification {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('On', 'Off')]
        [string]$ACTION,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("ApplicationClassification on $($params.Firewall)", "Set ACTION $ACTION")) {
        return
    }

    $inner = @"
<Set operation="update">
  <ApplicationClassification>
    <ACTION>$ACTION</ACTION>
  </ApplicationClassification>
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
        throw "Error updating ApplicationClassification: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplicationClassification' -Action 'update'

    $confirmed = Get-SfosApplicationClassification -Firewall $params.Firewall -Port $params.Port `
        -Username $params.Username -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if ($confirmed.ACTION -ne $ACTION) {
        throw "ApplicationClassification update reported success but could not be confirmed on the firewall (expected ACTION '$ACTION', found '$($confirmed.ACTION)')."
    }
}

#endregion

