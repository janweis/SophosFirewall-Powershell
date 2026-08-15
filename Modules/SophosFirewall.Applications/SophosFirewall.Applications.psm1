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

<#
.SYNOPSIS
    Builds the shared selection-list XML used by ApplicationFilterPolicy rules and application
    objects.

.DESCRIPTION
    Builds the CategoryList, RiskList, CharacteristicsList, TechnologyList and ApplicationList
    elements that appear both inside an ApplicationFilterPolicy rule and inside a standalone
    application object. The two entities share this nested list shape.

.PARAMETER Category
    Category names to include in CategoryList.

.PARAMETER Risk
    Risk level names to include in RiskList.

.PARAMETER Characteristics
    Characteristic names to include in CharacteristicsList.

.PARAMETER Technology
    Technology names to include in TechnologyList.

.PARAMETER Application
    Application names to include in ApplicationList.
#>
function ConvertTo-SfosAppFilterListXml {
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

<#
.SYNOPSIS
    Builds one rule element for an application filter policy.

.DESCRIPTION
    Builds a single Rule element for an ApplicationFilterPolicy's RuleList, using
    ConvertTo-SfosAppFilterListXml for the nested selection lists.

.PARAMETER Rule
    The rule object to convert, with the properties SelectAllRule, CategoryList, RiskList,
    CharacteristicsList, TechnologyList, ApplicationList, SmartFilter, Action and Schedule.
#>
function ConvertTo-SfosApplicationFilterPolicyRuleXml {
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

<#
.SYNOPSIS
    Builds the Set request body for an application filter policy.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on an ApplicationFilterPolicy entity, so
    New-, Set-SfosApplicationFilterPolicy, Add-SfosApplicationFilterPolicyRule and
    Remove-SfosApplicationFilterPolicyRule all send the same entity shape. The firewall replaces
    the whole entity on update, so the caller merges every field it wants to keep into -Policy
    before calling this function. The Template field is never sent; the firewall rejects it.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Policy
    The policy object to convert, with the properties Name, Description, DefaultAction,
    MicroAppSupport and RuleList.
#>
function ConvertTo-SfosApplicationFilterPolicyEntityXml {
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
    Retrieves application filter policy objects from a Sophos Firewall.

.DESCRIPTION
    Returns application filter policy objects. An application filter policy is a set of rules
    that allow, deny or warn on application traffic, and is applied to firewall rules. Each
    returned rule has the same shape that New-SfosApplicationFilterPolicyRule builds, so a rule
    read with this cmdlet can be reused directly with Add-SfosApplicationFilterPolicyRule or
    passed to Set-SfosApplicationFilterPolicy.

    The firewall ships 7 built-in policies ('Allow All', 'Deny All' and five 'Block ...'
    policies). Treat them as read-only; Set-SfosApplicationFilterPolicy does not warn before
    overwriting one.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only policies whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern. If omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for application
    filter policies. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per policy, with the properties
    Name, Description, DefaultAction, MicroAppSupport and RuleList. RuleList is an array of rule
    objects with SelectAllRule, CategoryList, RiskList, CharacteristicsList, TechnologyList,
    ApplicationList, SmartFilter, Action and Schedule. A policy with no rules returns RuleList
    as an empty array. Returns System.Xml.XmlElement when -AsXml is used, and an empty array
    when no policy matches.

.EXAMPLE
    Get-SfosApplicationFilterPolicy

    Lists every application filter policy on the firewall of the current connection.

.EXAMPLE
    Get-SfosApplicationFilterPolicy -NameLike 'Block'

    Lists all policies whose name contains 'Block'.

.EXAMPLE
    Get-SfosApplicationFilterPolicy -NameLike 'Allow All' -AsXml

    Returns the raw XML of the matching policy, for example to check a field that the standard
    output does not contain.

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
        # A policy with no rules has no <RuleList> element at all, so $node.RuleList is $null.
        # Without the -FilterScript below, @($null.Rule) is a one-element array containing $null.
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
    Creates an application filter policy on a Sophos Firewall.

.DESCRIPTION
    Creates an application filter policy, which groups application-matching rules into a policy
    that can be assigned to a firewall rule. Rules can be supplied at creation time with -Rule,
    built with New-SfosApplicationFilterPolicyRule, or added afterwards with
    Add-SfosApplicationFilterPolicyRule. A policy with no rules at all is accepted.

    DefaultAction cannot be changed after the policy is created; choose it carefully.
    MicroAppSupport always reads back as 'True', whatever value is sent.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for application filter policies.

.PARAMETER Name
    Required. Name of the policy, 1 to 60 characters, no commas.

.PARAMETER Description
    Optional. Free-text description, up to 1000 characters.

.PARAMETER DefaultAction
    Required. Action for traffic that matches no rule in the policy: Allow or Deny. This value
    cannot be changed after the policy is created.

.PARAMETER MicroAppSupport
    Optional. True or False. Defaults to True. The firewall always reports this field as True.

.PARAMETER Rule
    Optional. Zero or more rule objects, in the order they are evaluated. Build each entry with
    New-SfosApplicationFilterPolicyRule. If omitted, the policy is created with an empty rule
    list.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter policies. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name, Description and DefaultAction by
    property name, for example from Get-SfosApplicationFilterPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -Description 'Empty policy' -DefaultAction Allow -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -Description 'Empty policy' -DefaultAction Allow

    Creates a policy with no rules yet. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'Lantern' -Action Deny -Schedule 'All The Time'
    New-SfosApplicationFilterPolicy -Name 'BranchOfficeBlockLantern' -DefaultAction Allow -Rule $rule

    Creates a policy with one rule that blocks a specific named application.

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
    Updates an application filter policy on a Sophos Firewall.

.DESCRIPTION
    Updates an application filter policy. You can supply the target policy name directly or
    through the pipeline.

    The firewall replaces the whole policy on update; any field not sent is cleared. This
    cmdlet reads the current policy first and keeps whatever the caller does not explicitly
    pass. DefaultAction cannot be changed after the policy was created; the value sent here has
    no effect and the original value is kept. The firewall built-in policies have no write
    protection; this cmdlet overwrites one, including its rule list, without a warning from the
    firewall.

.PARAMETER Name
    Required. Name of the target policy.

.PARAMETER Description
    Optional. Free-text description. If omitted, the existing description is kept.

.PARAMETER DefaultAction
    Optional. Allow or Deny. Has no effect on an existing policy; the value set at creation is
    kept regardless of what is sent here.

.PARAMETER MicroAppSupport
    Optional. True or False. The firewall always reports this field as True after any write.

.PARAMETER Rule
    Optional. Complete replacement rule list, in the order the firewall should evaluate them.
    This replaces the existing rule list; it does not merge with the rules already on the
    firewall. If omitted, the existing rules are kept. To add or remove a single rule without
    touching the rest of the list, use Add-SfosApplicationFilterPolicyRule or
    Remove-SfosApplicationFilterPolicyRule instead.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter policies. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts a policy object by value or by
    property name, for example from Get-SfosApplicationFilterPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -Description 'Updated description' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -Description 'Updated description'

    Changes only the description; the rule list and default action are kept. The cmdlet asks
    for confirmation before it writes.

.EXAMPLE
    Get-SfosApplicationFilterPolicy -NameLike 'BranchOfficeApps' | Set-SfosApplicationFilterPolicy -Description 'Updated'

    Reads the matching policy and applies the same change through the pipeline.

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
    Removes an application filter policy from a Sophos Firewall.

.DESCRIPTION
    Removes an application filter policy. The cmdlet reads the policy first and throws an error
    if the given name does not exist, so the caller gets a clear reason for the failure. Do not
    target the firewall built-in policies with this cmdlet.

.PARAMETER Name
    Required. Name of the policy to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter policies. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts a policy object by value or by
    property name, for example from Get-SfosApplicationFilterPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal,
    or if the named policy does not exist.

.EXAMPLE
    Remove-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosApplicationFilterPolicy -Name 'BranchOfficeApps'

    Removes the named policy. The cmdlet asks for confirmation before it writes.

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
    Builds a rule object for an application filter policy.

.DESCRIPTION
    Builds the object that New-SfosApplicationFilterPolicy -Rule, Set-SfosApplicationFilterPolicy
    -Rule and Add-SfosApplicationFilterPolicyRule expect. This cmdlet makes no API call; the
    rule only becomes part of a policy once handed to one of those cmdlets. The firewall keeps
    the rule order as built, so build rules in the order they must be evaluated.

    A rule works in one of two selection modes, controlled by SelectAllRule. With 'Disable', the
    rule matches the applications named in Application, and the firewall computes Category,
    Risk, Characteristics and Technology itself from those applications; any value sent for
    those four parameters is discarded. With 'Enable', the rule matches by Category, Risk,
    Characteristics and/or Technology, and the firewall computes Application itself from the
    matching applications; any value sent for Application is discarded. With 'Disable' and no
    Application entry at all, this cmdlet throws rather than building a rule the firewall would
    silently drop from the policy.

    There is no fixed list of valid Category, Risk, Characteristics, Technology or Schedule
    values. A name the firewall does not recognize is not rejected; it is silently dropped (for
    Category/Risk/Characteristics/Technology) or replaced with 'All The Time' (for Schedule),
    which results in a rule that matches less than intended. Check the result with
    Get-SfosApplicationFilterPolicy after using an unfamiliar value.

.PARAMETER InputObject
    Optional. An existing rule to use as the base, as returned in the RuleList property of
    Get-SfosApplicationFilterPolicy. Accepts pipeline input. Only the parameters you actually
    supply override it, so a single field can be changed without disturbing the rest.

.PARAMETER SelectAllRule
    Optional. Enable or Disable; selects which of the two matching modes the rule uses. See
    .DESCRIPTION. Defaults to Disable.

.PARAMETER Category
    Optional. Application category names for Enable mode, for example 'Gaming'. Ignored in
    Disable mode. No fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Risk
    Optional. Risk level names for Enable mode, for example 'Very High'. Ignored in Disable
    mode. No fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Characteristics
    Optional. Characteristic names for Enable mode, for example 'Tunnels other apps'. Ignored
    in Disable mode. No fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Technology
    Optional. Technology names for Enable mode, for example 'Client Server'. Ignored in Disable
    mode. No fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Application
    Optional in Enable mode, required in Disable mode. Application signature names, for
    example 'Lantern'. Ignored in Enable mode when the criteria lists match at least one
    recognized value.

.PARAMETER SmartFilter
    Optional. Free-text search filter, as stored by the web admin rule builder search box. A
    non-empty value makes the firewall report SelectAllRule back as Enable, and drops the
    computed Category, Risk, Characteristics and Technology lists, regardless of what
    SelectAllRule was set to. Defaults to an empty string.

.PARAMETER Action
    Optional. Allow or Deny. Defaults to Deny.

.PARAMETER Schedule
    Optional. Name of an existing Schedule object, for example 'All The Time'. No fixed list of
    valid values; a name the firewall does not recognize is silently replaced with
    'All The Time'. Defaults to 'All The Time'.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an existing rule object from the
    pipeline as -InputObject.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with SelectAllRule, CategoryList,
    RiskList, CharacteristicsList, TechnologyList, ApplicationList, SmartFilter, Action and
    Schedule, matching the shape Get-SfosApplicationFilterPolicy returns for each rule.

.EXAMPLE
    New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'Lantern' -Action Deny -Schedule 'All The Time'

    Builds a rule that blocks a single named application.

.EXAMPLE
    New-SfosApplicationFilterPolicyRule -SelectAllRule Enable -Category 'Gaming' -Action Deny

    Builds a rule that blocks every application in a category.

.EXAMPLE
    $policy = Get-SfosApplicationFilterPolicy -NameLike 'BranchOfficeApps'
    $edited = $policy.RuleList[0] | New-SfosApplicationFilterPolicyRule -Action 'Allow'
    Set-SfosApplicationFilterPolicy -Name 'BranchOfficeApps' -Rule $edited

    Changes one field of an existing rule and writes the updated rule list back.

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
    Appends a rule to the end of an application filter policy.

.DESCRIPTION
    Reads the current policy, appends the supplied rule after the existing ones, and writes the
    whole policy back. The firewall built-in policies have no write protection; verify the
    policy name before running this against a shared or production policy.

.PARAMETER Name
    Required. Name of the target policy.

.PARAMETER Rule
    Required. Rule object to append, built with New-SfosApplicationFilterPolicyRule.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter policies. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the policy name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'TurboVPN' -Action Deny
    Add-SfosApplicationFilterPolicyRule -Name 'BranchOfficeApps' -Rule $rule -WhatIf

    Shows what the call would add without sending it to the firewall.

.EXAMPLE
    $rule = New-SfosApplicationFilterPolicyRule -SelectAllRule Disable -Application 'TurboVPN' -Action Deny
    Add-SfosApplicationFilterPolicyRule -Name 'BranchOfficeApps' -Rule $rule

    Appends the rule to the named policy. The cmdlet asks for confirmation before it writes.

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
    Removes a single rule from an application filter policy by index.

.DESCRIPTION
    Reads the current policy, drops the rule at the given zero-based index from the rule list,
    and writes the whole policy back. The cmdlet reads the policy back afterwards and throws if
    the rule count on the firewall does not match what was sent, rather than trusting a success
    status alone. The firewall built-in policies have no write protection; verify the policy
    name before running this against a shared or production policy.

.PARAMETER Name
    Required. Name of the target policy.

.PARAMETER Index
    Required. Zero-based position of the rule to remove, in the order returned by
    Get-SfosApplicationFilterPolicy. The cmdlet throws if the index is out of range.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter policies. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the policy name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update, or
    if the rule was not actually removed.

.EXAMPLE
    Remove-SfosApplicationFilterPolicyRule -Name 'BranchOfficeApps' -Index 0 -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosApplicationFilterPolicyRule -Name 'BranchOfficeApps' -Index 0

    Removes the first rule of the policy. The cmdlet asks for confirmation before it writes.

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

        # RuleList is not append-only on this entity, but a 200 that changes nothing is a
        # known failure mode of this API - read back and throw rather than trust the status
        # code alone.
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

<#
.SYNOPSIS
    Builds the Set request body for an application object.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on an ApplicationObject entity, using
    ConvertTo-SfosAppFilterListXml for the nested selection lists. The firewall replaces the
    whole entity on update, so New- and Set-SfosApplicationObject merge every field they want to
    keep into -Application before calling this function.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Application
    The application object to convert, with the properties Name, SelectAllRule, CategoryList,
    RiskList, CharacteristicsList, TechnologyList, ApplicationList and SmartFilter.
#>
function ConvertTo-SfosApplicationObjectEntityXml {
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
        Retrieves application objects from a Sophos Firewall.

        .DESCRIPTION
        Returns application objects (PROTECT > Applications > "Application").

        An application object groups a set of applications, either individually or by
        category/risk/characteristics/technology criteria, into a single reusable named object.
        It uses the same selection shape as a rule inside an application filter policy, but has
        no Action or Schedule field. The cmdlet only reads; nothing on the firewall is changed.
        It needs an open connection from Connect-SfosFirewall, or the connection parameters
        supplied directly.

        .PARAMETER NameLike
        Optional. Returns only objects whose name contains the given text anywhere. This is a
        substring match, not a wildcard pattern. If omitted, the name is not used to filter.

        .PARAMETER Firewall
        Optional. Host name or IP address of the firewall. If omitted, the value from the
        current connection is used.

        .PARAMETER Port
        Optional. TCP port of the management API, usually 4444. If omitted, the value from the
        current connection is used.

        .PARAMETER Username
        Optional. User name for the API login. The account needs read permission for
        application objects. If omitted, the value from the current connection is used.

        .PARAMETER Password
        Optional. Password for the API login, as a SecureString. If omitted, the value from the
        current connection is used.

        .PARAMETER SkipCertificateCheck
        Optional. Accepts the firewall certificate without validating it. Use this only for
        appliances that still present a self-signed certificate. If omitted, the certificate is
        validated.

        .PARAMETER Session
        Optional. A session object from Connect-SfosFirewall, or the name of a session that was
        registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when
        you work with more than one at a time. Any connection parameter you pass explicitly
        still takes precedence. If omitted, the stored default connection is used.

        .PARAMETER AsXml
        Optional. Returns the raw XML elements sent by the firewall instead of PowerShell
        objects. Useful when you need a field that the standard output does not show.

        .INPUTS
        None. This cmdlet does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. One object per application object, with
        the properties Name, SelectAllRule, CategoryList, RiskList, CharacteristicsList,
        TechnologyList, ApplicationList and SmartFilter. Returns System.Xml.XmlElement when
        -AsXml is used, and an empty array when no object matches.

        .EXAMPLE
        Get-SfosApplicationObject

        Lists every application object on the firewall of the current connection.

        .EXAMPLE
        Get-SfosApplicationObject -NameLike 'VPN'

        Lists all application objects whose name contains 'VPN'.

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
    Creates an application object on a Sophos Firewall.

.DESCRIPTION
    Creates an application object, a reusable named grouping of applications that can be
    referenced elsewhere, for example from a firewall rule, instead of listing individual
    applications each time.

    It uses the same two selection modes as a rule inside an application filter policy: with
    SelectAllRule 'Disable', Application is stored as given and at least one entry is required;
    with SelectAllRule 'Enable' and a recognized Category, Risk, Characteristics or Technology
    value, the firewall computes Application from that criterion itself. In both modes,
    whichever of Category, Risk, Characteristics and Technology is not the active selection
    criterion is ignored or dropped on write.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for application objects.

.PARAMETER Name
    Required. Name of the application object, 1 to 80 characters, no commas.

.PARAMETER SelectAllRule
    Optional. Enable or Disable; selects which of the two matching modes the object uses.
    Defaults to Disable.

.PARAMETER Category
    Optional. Application category names for Enable mode. Ignored in Disable mode. No fixed
    list of valid values; an unrecognized name is silently dropped.

.PARAMETER Risk
    Optional. Risk level names for Enable mode. Ignored in Disable mode. No fixed list of valid
    values; an unrecognized name is silently dropped.

.PARAMETER Characteristics
    Optional. Characteristic names for Enable mode. Ignored in Disable mode. No fixed list of
    valid values; an unrecognized name is silently dropped.

.PARAMETER Technology
    Optional. Technology names for Enable mode. Ignored in Disable mode. No fixed list of valid
    values; an unrecognized name is silently dropped.

.PARAMETER Application
    Optional in Enable mode, required in Disable mode. Application signature names, for example
    'Lantern'. Ignored in Enable mode when the criteria lists match at least one recognized
    value.

.PARAMETER SmartFilter
    Optional. Free-text search filter. A non-empty value makes the firewall report
    SelectAllRule back as Enable, and drops the computed lists, regardless of what SelectAllRule
    was set to. Defaults to an empty string.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    objects. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosApplicationObject -Name 'KnownProxyApp' -SelectAllRule Disable -Application 'Lantern' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosApplicationObject -Name 'KnownProxyApp' -SelectAllRule Disable -Application 'Lantern'

    Groups a single named application. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    New-SfosApplicationObject -Name 'AllGamingApps' -SelectAllRule Enable -Category 'Gaming'

    Groups every application in a category.

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
            throw "New-SfosApplicationObject: -SelectAllRule 'Disable' requires at least one -Application entry - the firewall silently drops an ApplicationObject with no ApplicationList."
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
    Updates an application object on a Sophos Firewall.

.DESCRIPTION
    Updates an application object. You can supply the target object name directly or through
    the pipeline.

    The firewall replaces the whole object on update; any field not sent is cleared. This
    cmdlet reads the current object first and keeps whatever the caller does not explicitly
    pass.

.PARAMETER Name
    Required. Name of the target object.

.PARAMETER SelectAllRule
    Optional. Enable or Disable. If omitted, the existing value is kept. See
    New-SfosApplicationObject for the two selection modes.

.PARAMETER Category
    Optional. Application category names for Enable mode. If omitted, the existing value is
    kept. No fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Risk
    Optional. Risk level names for Enable mode. If omitted, the existing value is kept. No
    fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Characteristics
    Optional. Characteristic names for Enable mode. If omitted, the existing value is kept. No
    fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Technology
    Optional. Technology names for Enable mode. If omitted, the existing value is kept. No
    fixed list of valid values; an unrecognized name is silently dropped.

.PARAMETER Application
    Optional. Application signature names. If omitted, the existing value is kept. Required,
    directly or through the existing value, when the resulting SelectAllRule is Disable.

.PARAMETER SmartFilter
    Optional. Free-text search filter. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    objects. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an application object by value or by
    property name, for example from Get-SfosApplicationObject.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosApplicationObject -Name 'KnownProxyApp' -Application 'Lantern', 'TurboVPN' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosApplicationObject -Name 'KnownProxyApp' -Application 'Lantern', 'TurboVPN'

    Replaces the application list of an existing Disable-mode object. The cmdlet asks for
    confirmation before it writes.

.EXAMPLE
    Get-SfosApplicationObject -NameLike 'KnownProxyApp' | Set-SfosApplicationObject -SmartFilter 'proxy'

    Reads the matching object and applies the same change through the pipeline.

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
    Removes an application object from a Sophos Firewall.

.DESCRIPTION
    Removes an application object. The cmdlet reads the object first and throws an error if the
    given name does not exist, so the caller gets a clear reason for the failure.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    objects. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts an application object by value or by
    property name, for example from Get-SfosApplicationObject.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal,
    or if the named object does not exist.

.EXAMPLE
    Remove-SfosApplicationObject -Name 'KnownProxyApp' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosApplicationObject -Name 'KnownProxyApp'

    Removes the named object. The cmdlet asks for confirmation before it writes.

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

# ApplicationFilterCategory, ApplicationClassificationAssignment (single and batch) and the
# ApplicationClassification switch.
#
# ApplicationFilterCategory has no add or delete operation, only edit; the 26 categories are
# fixed. operation="edit" and operation="update" behave identically for this entity; the
# module uses "update" exclusively, since only "add"/"update" are trusted verbs in this API.
# There is no New-/Remove-SfosApplicationFilterCategory, because there is no operation to
# build them on. Server-side filtering on the Name and Description keys has no effect; no
# <Filter> is sent and NameLike is applied on the client. Description cannot be changed
# through this entity's update operation; the field is accepted and sent but the firewall
# discards the change, so Set-SfosApplicationFilterCategory reads the object back and throws
# if a requested Description change did not take effect. QoSPolicy only accepts a policy
# whose own PolicyBasedOn is Application; a policy based on FirewallRule or User is rejected.
# BandwidthUsageType only takes effect together with a QoSPolicy value other than None in the
# same request. The per-application QoS override list (ApplicationSettings) follows the
# general full-replace rule: Set-SfosApplicationFilterCategory preserves the existing list
# whenever the caller does not pass -ApplicationSettings, and
# Add-/Remove-SfosApplicationFilterCategoryMember read the current list before changing it.
#
# ApplicationClassificationAssignment: server-side filtering on the Application and
# Classification keys has no effect; both filters are applied on the client. Only the
# classification value 'New' is confirmed to work; there is no documented value set, so the
# parameter is left as an unrestricted string rather than an invented ValidateSet.
#
# ApplicationClassificationBatchAssignment sends the same pairs as one request instead of one
# request per item. A rejected batch fails as a whole, with no way to tell from the response
# which entry caused it. Set-SfosApplicationClassificationAssignment exists for callers who
# need per-item error detail; Set-SfosApplicationClassificationAssignmentBatch exists for
# bulk reclassification in a single round trip.
#
# ApplicationClassification is an undocumented singleton with a single field, ACTION (On or
# Off), controlling whether the firewall classifies newly discovered applications at all.
# Unlike most entities in this module, the field is named ACTION rather than a mixed-case
# name, and there is no <Status> element to collide with it.

#region ApplicationFilterCategory

<#
.SYNOPSIS
    Retrieves application filter category objects from a Sophos Firewall.

.DESCRIPTION
    Returns application filter category objects (PROTECT > Applications > Application Filter,
    called "Application Category" in the API). The firewall ships 26 fixed categories; there is
    no create or delete operation, only update, so this module offers Get and Set plus
    Add-/Remove-SfosApplicationFilterCategoryMember for the nested per-application QoS
    overrides.

    Server-side filtering on Name or Description has no effect for this entity; a filtered
    request still returns all 26 categories, so NameLike is applied on the client. The cmdlet
    only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only categories whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern, and is applied on the client. If omitted, the name
    is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for application
    filter categories. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per category. A category with no
    per-application QoS override returns an empty array for that list until
    Add-SfosApplicationFilterCategoryMember has been used on it. Returns System.Xml.XmlElement
    when -AsXml is used, and an empty array when no category matches.

.EXAMPLE
    Get-SfosApplicationFilterCategory

    Lists all 26 application filter categories.

.EXAMPLE
    Get-SfosApplicationFilterCategory -NameLike 'Mobile'

    Lists all categories whose name contains 'Mobile'.

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
    Updates an application filter category on a Sophos Firewall.

.DESCRIPTION
    Updates an existing application filter category (PROTECT > Applications > Application
    Filter). There is no create or delete operation for this entity; the 26 categories are
    fixed, so Name identifies an existing category and cannot itself be changed.

    The cmdlet reads the current category first and writes back every field, overriding only
    what the caller passed, because the firewall replaces the whole object on update.

    Description cannot be changed on this firmware. The firewall answers success but the value
    never changes; the cmdlet reads the object back afterwards and throws when a requested
    Description change did not take effect. A category only accepts a QoS policy whose own
    PolicyBasedOn is 'Application'; a policy based on 'FirewallRule' or 'User' is rejected.

.PARAMETER Name
    Required. Name of the category to update. Identifies the object; cannot be changed.

.PARAMETER QoSPolicy
    Optional. Name of a QoS policy to apply to the whole category, or 'None' to clear it. Only
    accepted when the referenced policy is based on Application.

.PARAMETER BandwidthUsageType
    Optional. Individual, Shared, or an empty string to clear it. Only takes effect together
    with a QoSPolicy value other than 'None' in the same request; sent alongside QoSPolicy
    'None' it is ignored.

.PARAMETER Description
    Optional. Free-text description. Sending a change has no effect on this firmware; the
    cmdlet reads the object back and throws if the change did not take effect.

.PARAMETER ApplicationSettings
    Optional. Complete replacement list of per-application QoS overrides, each an object with
    Name and QoSPolicy properties. If omitted, the existing list is kept; passing an empty
    array clears it. Prefer Add-/Remove-SfosApplicationFilterCategoryMember for single-
    application changes; they read the current list for you.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter categories. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the category name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if a requested Description change was not confirmed on a following read.

.EXAMPLE
    Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -QoSPolicy 'None' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -QoSPolicy 'None'

    Clears the QoS assignment of a category. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    Set-SfosApplicationFilterCategory -Name 'Mobile Applications' -QoSPolicy 'Streaming Video - Limit to SD Quality' -BandwidthUsageType Individual

    Assigns an Application-scoped QoS policy with a bandwidth usage type.

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
        # Not a strict ValidateSet: the baseline value on every stock category is the empty
        # string, which is also the value needed to clear a bandwidth grouping - a ValidateSet
        # of just 'Individual'/'Shared' would make that impossible through this cmdlet.
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
                throw "ApplicationFilterCategory '$Name' update reported success but the Description change was not confirmed on the firewall. Requested '$Description', found '$($confirmed[0].Description)'."
            }
        }
    }
}

<#
.SYNOPSIS
    Adds or updates a per-application QoS override inside an application filter category.

.DESCRIPTION
    Reads the current category, adds or updates one entry in its per-application QoS override
    list (updates the QoS policy if the application already has an override, otherwise adds a
    new entry), and writes the complete list back. The firewall replaces the whole override
    list on update, so every other override would otherwise be lost.

.PARAMETER Name
    Required. Name of the category to modify.

.PARAMETER Application
    Required. Name of the application to set a per-application QoS override for.

.PARAMETER QoSPolicy
    Required. Name of the QoS policy to apply to this application. The policy must be based on
    Application. The value 'None' is rejected; use Remove-SfosApplicationFilterCategoryMember
    to remove an override instead.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter categories. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the category name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -QoSPolicy 'Streaming Video - Limit to SD Quality' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Add-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -QoSPolicy 'Streaming Video - Limit to SD Quality'

    Adds a per-application QoS override. The cmdlet asks for confirmation before it writes.

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
        # 'None' is refused client-side: the firewall answers success for a 'None' override
        # but stores nothing, so it would be a silent no-op. To drop an existing override,
        # use Remove-SfosApplicationFilterCategoryMember instead.
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
    Removes a per-application QoS override from an application filter category.

.DESCRIPTION
    Reads the current category, removes the entry for the given application from its
    per-application QoS override list, and writes the remaining list back.

.PARAMETER Name
    Required. Name of the category to modify.

.PARAMETER Application
    Required. Name of the application whose QoS override should be removed.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    filter categories. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the category name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update, or
    if the application had no override.

.EXAMPLE
    Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosApplicationFilterCategoryMember -Name 'Mobile Applications' -Application 'Instagram'

    Removes the per-application QoS override. The cmdlet asks for confirmation before it
    writes.

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
    Retrieves application classification assignments from a Sophos Firewall.

.DESCRIPTION
    Returns the application-to-classification mapping for every known application signature
    (PROTECT > Applications > Application Classification Assignment). Server-side filtering has
    no effect for this entity; a filtered request still returns every row, so ApplicationLike
    and ClassificationLike are applied on the client. The cmdlet only reads; nothing on the
    firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

.PARAMETER ApplicationLike
    Optional. Returns only rows whose application name contains the given text anywhere. This
    is a substring match, not a wildcard pattern, and is applied on the client. If omitted, the
    application name is not used to filter.

.PARAMETER ClassificationLike
    Optional. Returns only rows whose classification contains the given text anywhere. Applied
    on the client. If omitted, the classification is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for application
    classification assignments. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.
    Useful when you need a field that the standard output does not show.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per application, with the
    properties Application and Classification. Returns System.Xml.XmlElement when -AsXml is
    used, and an empty array when no row matches.

.EXAMPLE
    Get-SfosApplicationClassificationAssignment

    Lists every application classification assignment on the firewall of the current
    connection.

.EXAMPLE
    Get-SfosApplicationClassificationAssignment -ApplicationLike '1Password'

    Lists all rows whose application name contains '1Password'.

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
    Updates a single application's classification on a Sophos Firewall.

.DESCRIPTION
    Updates one application classification assignment. The cmdlet reads the assignment first
    and throws a clear "not found" error if the application does not exist. It is
    pipeline-friendly: Get-SfosApplicationClassificationAssignment | Where-Object {...} |
    Set-SfosApplicationClassificationAssignment issues one request per object. To push many
    reclassifications at once with a single request, use
    Set-SfosApplicationClassificationAssignmentBatch instead.

    Only the classification value 'New' is confirmed to work on this firmware; there is no
    fixed list of valid values.

.PARAMETER Application
    Required. Name of the application to reclassify.

.PARAMETER Classification
    Required. New classification value. Only 'New' is confirmed to work on this firmware.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    classification assignments. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the application name by value or by
    property name, for example from Get-SfosApplicationClassificationAssignment.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosApplicationClassificationAssignment -Application '10000ft Plans' -Classification 'New' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosApplicationClassificationAssignment -Application '10000ft Plans' -Classification 'New'

    Sets the classification of a single application. The cmdlet asks for confirmation before
    it writes.

.EXAMPLE
    Get-SfosApplicationClassificationAssignment -ApplicationLike '10000ft' | Set-SfosApplicationClassificationAssignment -Classification 'New'

    Reclassifies every matching application through the pipeline.

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
    Collects Application/Classification pairs from the pipeline or -InputObject and sends them
    as one batch request (PROTECT > Applications > Application Classification Batch
    Assignment) when the pipeline completes, instead of one request per item like
    Set-SfosApplicationClassificationAssignment.

    A rejected batch, for example because of an invalid classification value or an application
    that does not exist, fails for the whole batch with a single error and no detail about
    which entry caused it. Use Set-SfosApplicationClassificationAssignment if you need to know
    which entry failed. Only the classification value 'New' is confirmed to work on this
    firmware.

.PARAMETER InputObject
    Required. One or more objects with Application and Classification properties, typically
    from Get-SfosApplicationClassificationAssignment.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    classification assignments. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts one or more objects with Application
    and Classification properties from the pipeline.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the batch.

.EXAMPLE
    Get-SfosApplicationClassificationAssignment -ApplicationLike '10Web' | Set-SfosApplicationClassificationAssignmentBatch -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Get-SfosApplicationClassificationAssignment -ApplicationLike '10Web' | Set-SfosApplicationClassificationAssignmentBatch

    Resends the current classification of the matching applications in one request. The
    cmdlet asks for confirmation before it writes.

.EXAMPLE
    @([PSCustomObject]@{ Application = '10Web'; Classification = 'New' }, [PSCustomObject]@{ Application = '1Password'; Classification = 'New' }) | Set-SfosApplicationClassificationAssignmentBatch

    Sets the classification of two named applications in one request.

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
    Returns the state of the application classification switch, which controls whether the
    firewall classifies newly discovered applications at all. The cmdlet only reads; nothing on
    the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for application
    settings. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with the property ACTION, either On
    or Off. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosApplicationClassification

    Shows whether application classification is on or off.

.EXAMPLE
    Get-SfosApplicationClassification -AsXml

    Returns the raw XML of the switch state, for example to check a field that the standard
    output does not contain.

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
    Updates the application classification switch, which controls whether the firewall
    classifies newly discovered applications at all. The cmdlet confirms the change with a
    following read before returning.

.PARAMETER ACTION
    Required. On or Off.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for application
    settings. If omitted, the value from the current connection is used.

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
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if the change cannot be confirmed on a following read.

.EXAMPLE
    Set-SfosApplicationClassification -ACTION On -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosApplicationClassification -ACTION On

    Switches application classification on. The cmdlet asks for confirmation before it writes.

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

