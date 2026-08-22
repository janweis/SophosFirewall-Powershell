#requires -Version 5.1
#requires -Modules @{ ModuleName = 'SophosFirewall.Core'; ModuleVersion = '1.4.0' }

<#
.SYNOPSIS
    Manages email protection on a Sophos Firewall: scanning policies, address groups,
    exceptions, data control, SPX and the SMTP settings.

.DESCRIPTION
    Functions for the PROTECT > Email area of the Sophos Firewall XML API (SFOS 22.0).

    The area exists in two shapes, and the appliance runs in one of them at a time. In MTA
    mode the firewall accepts and delivers mail itself, so SMTP policies, exception policies,
    address groups and the MTA data control lists are the objects that matter. In legacy mode
    the firewall scans mail in passing, and the anti-spam rules and the SMTP malware scanning
    policies take that role instead. A handful of objects are shared by both shapes - the mail
    configuration, malware protection, POP/IMAP scanning policies and trusted domains - and
    behave the same either way.

    Writing to an entity that belongs to the shape the appliance is not currently in is
    refused with status 545. The cmdlets pass that answer through with its meaning rather
    than dressing it up, so a failure says which mode would be needed.

    Total Functions: 80 (70 exported, 10 internal helpers) - see README.md for the full
    cmdlet table.

    Connect once with Connect-SfosFirewall, then call the cmdlets in this module without
    repeating the connection parameters.

    Several fields take the NAME of an object that must already exist rather than a literal
    value - the source hosts of an exception policy, and the domains of an SMTP policy, which
    expect an MTA address group. Their help says so, and the cmdlets name the expected object
    type when the firewall refuses a value.

.EXAMPLE
    Connect-SfosFirewall -Firewall '192.0.2.1' -Credential (Get-Credential) -SkipCertificateCheck
    Get-SfosEmailConfiguration

    Connects to the firewall and reads the mail configuration.

.EXAMPLE
    New-SfosMTAAddressGroup -Name 'Partner domains' -GroupType EmailAddressOrDomain -EmailAddressDomain 'partner.example.com'
    Get-SfosMailExceptionPolicy -NameLike 'Partner'

    Creates an address group and looks for exception policies that mention it.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Connect-SfosFirewall
#>

#region AntiSpamRule

<#
.SYNOPSIS
    Builds the Set request body for an AntiSpamRules entity.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on an AntiSpamRules entity, so New-
    and Set-SfosAntiSpamRule send the same entity shape. The firewall replaces the whole
    entity on update, so the caller merges every field it wants to keep into -Rule first.

    Measured against a live firewall: RecipientList and SenderEmailList are each one
    sibling block per entry (<RecipientList><Action/><RecipientEmail/></RecipientList>
    repeated), not multiple Action/RecipientEmail pairs inside a single block - the latter
    shape was tried first and rejected by the firewall's field validation.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Rule
    The object to convert, with the properties Name, After, RecipientList, SenderEmailList,
    Condition, OtherHeader, ConditionOperator, MatchIs, SPXTemplateName, SMTPResponseAction,
    SMTPActionParameter, Quarantine, POPIMAPResponseAction and POPIMAPActionParameter.
#>
function ConvertTo-SfosAntiSpamRuleEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Rule
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Name)

    $afterXml = ''
    if ($Rule.After) {
        $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.After))</Name></After>"
    }

    $recipientXml = ''
    foreach ($item in @($Rule.RecipientList)) {
        if (-not $item) { continue }
        $actionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$item.Action)
        $emailEsc = ConvertTo-SfosXmlEscaped -Text ([string]$item.RecipientEmail)
        $recipientXml += "<RecipientList><Action>$actionEsc</Action><RecipientEmail>$emailEsc</RecipientEmail></RecipientList>"
    }

    $senderXml = ''
    foreach ($item in @($Rule.SenderEmailList)) {
        if (-not $item) { continue }
        $actionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$item.Action)
        $emailEsc = ConvertTo-SfosXmlEscaped -Text ([string]$item.SenderEmail)
        $senderXml += "<SenderEmailList><Action>$actionEsc</Action><SenderEmail>$emailEsc</SenderEmail></SenderEmailList>"
    }

    $conditionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Condition)
    $matchIsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.MatchIs)
    $otherHeaderXml = ''
    if ($Rule.OtherHeader) {
        $otherHeaderXml = "<OtherHeader>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.OtherHeader))</OtherHeader>"
    }
    $operatorXml = ''
    if ($Rule.ConditionOperator) {
        $operatorXml = "<Operator>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.ConditionOperator))</Operator>"
    }

    $smtpActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SMTPResponseAction)
    $smtpParamEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SMTPActionParameter)
    $quarantineEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.Quarantine)

    $popImapXml = ''
    if ($Rule.POPIMAPResponseAction) {
        $popActionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.POPIMAPResponseAction)
        $popParamEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Rule.POPIMAPActionParameter)
        $popImapXml = "<POPIMAPAction><Action>$popActionEsc</Action><ActionParameter>$popParamEsc</ActionParameter></POPIMAPAction>"
    }

    $spxXml = ''
    if ($Rule.SPXTemplateName) {
        $spxXml = "<SPXTemplates>$(ConvertTo-SfosXmlEscaped -Text ([string]$Rule.SPXTemplateName))</SPXTemplates>"
    }

    return @"
<Set operation="$Operation">
  <AntiSpamRules>
    <Name>$nameEsc</Name>
    $afterXml
    $recipientXml
    $senderXml
    <MarkSpamIf>
      <Condition>$conditionEsc</Condition>
      $otherHeaderXml
      $operatorXml
      <MatchIs>$matchIsEsc</MatchIs>
    </MarkSpamIf>
    <SMTPAction>
      <Action>$smtpActionEsc</Action>
      <ActionParameter>$smtpParamEsc</ActionParameter>
      <Quarantine>$quarantineEsc</Quarantine>
    </SMTPAction>
    $popImapXml
    $spxXml
  </AntiSpamRules>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves Anti Spam Rule objects from a Sophos Firewall.

.DESCRIPTION
    Returns Anti Spam Rule objects (PROTECT > Email > Anti Spam Rules, legacy scanning
    engine). Each rule matches SMTP or POP/IMAP mail against a recipient/sender pattern and
    a spam-detection condition, then applies an SMTP and a POP/IMAP action.

    On an appliance running MTA mode, creating a new rule (Add) is refused with status 545,
    the generic "MTA mode" gate documented for the legacy Email entities. Switching the
    appliance to legacy mode (SMTPDeploymentMode/MTAMode = OFF) lifts the gate; New-, Set- and
    Remove-SfosAntiSpamRule are all confirmed working against a live appliance in that mode.
    Get- is unaffected by the mode either way, and returns the four rules shipped with every
    appliance plus any rule created through the web admin console.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER NameLike
    Optional. Returns only rules whose name contains the given text anywhere. Sent to the
    firewall as a server-side pre-filter (measured to work for this entity) and re-applied
    client-side. Measured with more than one filter key present in the same request: unlike
    most entities in this suite, AntiSpamRules combines multiple keys with AND rather than
    evaluating only the first one - not relied upon here, since this cmdlet only ever sends
    one key, but noted because it contradicts the general filter rule for this product. If
    omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per rule, with the properties
    Name, After, RecipientList, SenderEmailList (each an array of objects with Action plus
    RecipientEmail/SenderEmail), Condition, OtherHeader, ConditionOperator, MatchIs,
    SPXTemplateName, SMTPResponseAction, SMTPActionParameter, Quarantine,
    POPIMAPResponseAction and POPIMAPActionParameter. Returns System.Xml.XmlElement when
    -AsXml is used, and an empty array when no rule matches.

.EXAMPLE
    Get-SfosAntiSpamRule

    Lists every Anti Spam Rule on the firewall of the current connection.

.EXAMPLE
    Get-SfosAntiSpamRule -NameLike 'rule1'

    Lists all rules whose name contains 'rule1'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/AntiSpamRules/AntiSpamRules.html

.LINK
    New-SfosAntiSpamRule
#>
function Get-SfosAntiSpamRule {
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
  <AntiSpamRules>
    $filterXml
  </AntiSpamRules>
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
        throw "Error retrieving AntiSpamRules objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamRules' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AntiSpamRules[Name]' | ForEach-Object -Process { $_.Node }

    $ruleObjects = foreach ($node in @($nodes)) {
        $recipientList = @($node.RecipientList | ForEach-Object -Process {
                [PSCustomObject]@{ Action = [string]$_.Action; RecipientEmail = [string]$_.RecipientEmail }
            })
        $senderList = @($node.SenderEmailList | ForEach-Object -Process {
                [PSCustomObject]@{ Action = [string]$_.Action; SenderEmail = [string]$_.SenderEmail }
            })

        [PSCustomObject]@{
            Name                   = [string]$node.Name
            After                  = [string]$node.After.Name
            RecipientList          = $recipientList
            SenderEmailList        = $senderList
            Condition               = [string]$node.MarkSpamIf.Condition
            OtherHeader             = [string]$node.MarkSpamIf.OtherHeader
            ConditionOperator       = [string]$node.MarkSpamIf.Operator
            MatchIs                 = [string]$node.MarkSpamIf.MatchIs
            SPXTemplateName         = [string]$node.SPXTemplates
            SMTPResponseAction      = [string]$node.SMTPAction.Action
            SMTPActionParameter     = [string]$node.SMTPAction.ActionParameter
            Quarantine              = [string]$node.SMTPAction.Quarantine
            POPIMAPResponseAction   = [string]$node.POPIMAPAction.Action
            POPIMAPActionParameter  = [string]$node.POPIMAPAction.ActionParameter
        }
    }

    $ruleObjects = @($ruleObjects)
    if ($NameLike) {
        $ruleObjects = @($ruleObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($ruleObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $ruleObjects
}

<#
.SYNOPSIS
    Creates an Anti Spam Rule object on a Sophos Firewall.

.DESCRIPTION
    Creates an Anti Spam Rule (PROTECT > Email > Anti Spam Rules, legacy scanning engine).

    Measured against a live appliance: on an appliance running MTA mode, this operation
    answers status 545 ("Operation failed", the generic message the vendor uses for the
    MTA-mode gate on legacy Email entities) for every field combination tried, and nothing is
    created - verified with a follow-up Get. Confirmed against the same appliance switched to
    legacy mode (SMTPDeploymentMode/MTAMode = OFF): the create succeeds and the object reads
    back with the fields sent.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

.PARAMETER Name
    Required. Name of the rule, 1 to 50 characters, no commas.

.PARAMETER After
    Optional. Name of the rule this one should be positioned after. If omitted, the
    firewall applies its own default position.

.PARAMETER RecipientList
    Required. One or more objects with the properties Action ('Contains' or 'Equals') and
    RecipientEmail. Only the literal value 'Any' is confirmed to be accepted for
    RecipientEmail on this appliance; other values were rejected with a field validation
    error when this was the only entry - see the module report.

.PARAMETER SenderEmailList
    Required. One or more objects with the properties Action ('Contains' or 'Equals') and
    SenderEmail. Same 'Any'-only observation as -RecipientList.

.PARAMETER Condition
    Required. The condition to test the mail against, for example
    'CyberoamAntiSpamIdentifiesMailAs' or 'SenderIPAddressBlacklistedByRBL'.

.PARAMETER OtherHeader
    Optional. Free-text header name, only meaningful when -Condition selects a header
    check.

.PARAMETER ConditionOperator
    Optional. Contains, Equals, GreaterThan or LessThan. Only meaningful for conditions
    that compare a value, such as message size.

.PARAMETER MatchIs
    Required. The value to compare -Condition against, for example 'Spam' or 'Virus
    Outbreak'.

.PARAMETER SPXTemplateName
    Optional. Name of an SPX template, only meaningful when -SMTPResponseAction is 'Accept
    With SPX'.

.PARAMETER SMTPResponseAction
    Required. Action for SMTP traffic: Reject, Accept, 'Change Recipient', 'Prefix
    Subject', Drop or 'Accept With SPX'.

.PARAMETER SMTPActionParameter
    Optional. Free text used when -SMTPResponseAction is 'Change Recipient' or 'Prefix
    Subject'.

.PARAMETER Quarantine
    Optional. Enable or Disable. If omitted, the firewall applies its own default.

.PARAMETER POPIMAPResponseAction
    Optional. Accept or 'Prefix Subject'. If omitted, the firewall applies its own default.

.PARAMETER POPIMAPActionParameter
    Optional. Free text used when -POPIMAPResponseAction is 'Prefix Subject'.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosAntiSpamRule -Name 'FlagLargeMail' -RecipientList @([PSCustomObject]@{Action='Contains';RecipientEmail='Any'}) -SenderEmailList @([PSCustomObject]@{Action='Contains';SenderEmail='Any'}) -Condition MessageSizeIs -ConditionOperator GreaterThan -MatchIs 10000 -SMTPResponseAction 'Prefix Subject' -SMTPActionParameter 'Large mail:' -WhatIf

    Shows what the call would create without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/AntiSpamRules/operations/AddSMTPScanningPolicy%26OrderSMTPScanningPolicy%26EditSMTPScanningPolicy.html

.LINK
    Get-SfosAntiSpamRule
#>
function New-SfosAntiSpamRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$After,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$RecipientList,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$SenderEmailList,

        [Parameter(Mandatory)]
        [string]$Condition,

        [string]$OtherHeader,

        [ValidateSet('Contains', 'Equals', 'GreaterThan', 'LessThan')]
        [string]$ConditionOperator,

        [Parameter(Mandatory)]
        [string]$MatchIs,

        [string]$SPXTemplateName,

        [Parameter(Mandatory)]
        [ValidateSet('Reject', 'Accept', 'Change Recipient', 'Prefix Subject', 'Drop', 'Accept With SPX')]
        [string]$SMTPResponseAction,

        [string]$SMTPActionParameter,

        [ValidateSet('Enable', 'Disable')]
        [string]$Quarantine,

        [ValidateSet('Accept', 'Prefix Subject')]
        [string]$POPIMAPResponseAction,

        [string]$POPIMAPActionParameter,

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
        if (-not $PSCmdlet.ShouldProcess("AntiSpamRules '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $rule = [PSCustomObject]@{
            Name                   = $Name
            After                  = $After
            RecipientList          = $RecipientList
            SenderEmailList        = $SenderEmailList
            Condition              = $Condition
            OtherHeader            = $OtherHeader
            ConditionOperator      = $ConditionOperator
            MatchIs                = $MatchIs
            SPXTemplateName        = $SPXTemplateName
            SMTPResponseAction     = $SMTPResponseAction
            SMTPActionParameter    = $SMTPActionParameter
            Quarantine             = $Quarantine
            POPIMAPResponseAction  = $POPIMAPResponseAction
            POPIMAPActionParameter = $POPIMAPActionParameter
        }

        $inner = ConvertTo-SfosAntiSpamRuleEntityXml -Operation 'add' -Rule $rule

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create AntiSpamRules object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamRules' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an Anti Spam Rule object on a Sophos Firewall.

.DESCRIPTION
    Updates an Anti Spam Rule. The firewall replaces the whole object on update; this
    cmdlet reads the current object first and keeps whatever the caller does not
    explicitly pass.

    Verified end to end against a live appliance in legacy mode (SMTPDeploymentMode/MTAMode =
    OFF): a field changed through this cmdlet is applied, and an unchanged round trip -
    read, write back, read again - produces byte-identical XML. On an appliance running MTA
    mode, expect the same 545 gate documented on New-SfosAntiSpamRule.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the target rule.

.PARAMETER After
    Optional. If omitted, the existing position is kept.

.PARAMETER RecipientList
    Optional. If omitted, the existing recipient list is kept.

.PARAMETER SenderEmailList
    Optional. If omitted, the existing sender list is kept.

.PARAMETER Condition
    Optional. If omitted, the existing condition is kept.

.PARAMETER OtherHeader
    Optional. If omitted, the existing value is kept.

.PARAMETER ConditionOperator
    Optional. If omitted, the existing value is kept.

.PARAMETER MatchIs
    Optional. If omitted, the existing value is kept.

.PARAMETER SPXTemplateName
    Optional. If omitted, the existing value is kept.

.PARAMETER SMTPResponseAction
    Optional. If omitted, the existing value is kept.

.PARAMETER SMTPActionParameter
    Optional. If omitted, the existing value is kept.

.PARAMETER Quarantine
    Optional. If omitted, the existing value is kept.

.PARAMETER POPIMAPResponseAction
    Optional. If omitted, the existing value is kept.

.PARAMETER POPIMAPActionParameter
    Optional. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts an object by value or by property
    name, for example from Get-SfosAntiSpamRule.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if the named rule does not exist.

.EXAMPLE
    Set-SfosAntiSpamRule -Name 'FlagLargeMail' -Quarantine Enable -WhatIf

    Shows what the call would change without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/AntiSpamRules/operations/AddSMTPScanningPolicy%26OrderSMTPScanningPolicy%26EditSMTPScanningPolicy.html

.LINK
    Get-SfosAntiSpamRule
#>
function Set-SfosAntiSpamRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$After,
        [PSCustomObject[]]$RecipientList,
        [PSCustomObject[]]$SenderEmailList,
        [string]$Condition,
        [string]$OtherHeader,

        [ValidateSet('Contains', 'Equals', 'GreaterThan', 'LessThan')]
        [string]$ConditionOperator,

        [string]$MatchIs,
        [string]$SPXTemplateName,

        [ValidateSet('Reject', 'Accept', 'Change Recipient', 'Prefix Subject', 'Drop', 'Accept With SPX')]
        [string]$SMTPResponseAction,

        [string]$SMTPActionParameter,

        [ValidateSet('Enable', 'Disable')]
        [string]$Quarantine,

        [ValidateSet('Accept', 'Prefix Subject')]
        [string]$POPIMAPResponseAction,

        [string]$POPIMAPActionParameter,

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
        $existing = @(Get-SfosAntiSpamRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AntiSpamRules object '$Name' was not found."
        }

        $target = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('After')) { $target.After = $After }
        if ($PSBoundParameters.ContainsKey('RecipientList')) { $target.RecipientList = $RecipientList }
        if ($PSBoundParameters.ContainsKey('SenderEmailList')) { $target.SenderEmailList = $SenderEmailList }
        if ($PSBoundParameters.ContainsKey('Condition')) { $target.Condition = $Condition }
        if ($PSBoundParameters.ContainsKey('OtherHeader')) { $target.OtherHeader = $OtherHeader }
        if ($PSBoundParameters.ContainsKey('ConditionOperator')) { $target.ConditionOperator = $ConditionOperator }
        if ($PSBoundParameters.ContainsKey('MatchIs')) { $target.MatchIs = $MatchIs }
        if ($PSBoundParameters.ContainsKey('SPXTemplateName')) { $target.SPXTemplateName = $SPXTemplateName }
        if ($PSBoundParameters.ContainsKey('SMTPResponseAction')) { $target.SMTPResponseAction = $SMTPResponseAction }
        if ($PSBoundParameters.ContainsKey('SMTPActionParameter')) { $target.SMTPActionParameter = $SMTPActionParameter }
        if ($PSBoundParameters.ContainsKey('Quarantine')) { $target.Quarantine = $Quarantine }
        if ($PSBoundParameters.ContainsKey('POPIMAPResponseAction')) { $target.POPIMAPResponseAction = $POPIMAPResponseAction }
        if ($PSBoundParameters.ContainsKey('POPIMAPActionParameter')) { $target.POPIMAPActionParameter = $POPIMAPActionParameter }

        $inner = ConvertTo-SfosAntiSpamRuleEntityXml -Operation 'update' -Rule $target

        if (-not $PSCmdlet.ShouldProcess("AntiSpamRules '$Name' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating AntiSpamRules object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamRules' -Action 'edit' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an Anti Spam Rule object from a Sophos Firewall.

.DESCRIPTION
    Removes an Anti Spam Rule. The cmdlet reads the object first and throws a clear error if
    the given name does not exist, rather than trusting the firewall's own removal response.

    Measured directly for this entity, not just by analogy to its siblings
    (AntiSpamEmailArchiver, AntiSpamTrustedDomain): a raw Remove of a non-existent
    AntiSpamRules name answers 200 ("Configuration applied successfully") on this appliance,
    with nothing to remove. Without this guard that false success would pass through
    silently.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the rule to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts the rule name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal, or if the named rule does not exist.

.EXAMPLE
    Remove-SfosAntiSpamRule -Name 'FlagLargeMail' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/AntiSpamRules/operations/Delete_SMTP_Scanning_Policy.html

.LINK
    Get-SfosAntiSpamRule
#>
function Remove-SfosAntiSpamRule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        $existing = @(Get-SfosAntiSpamRule -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AntiSpamRules object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("AntiSpamRules '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><AntiSpamRules><Name>$nameEsc</Name></AntiSpamRules></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove AntiSpamRules object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamRules' -Action 'remove' -Target $Name
    }
}

#endregion


#region AntiSpamTrustedDomain

<#
.SYNOPSIS
    Retrieves Anti Spam Trusted Domain objects from a Sophos Firewall.

.DESCRIPTION
    Returns Anti Spam Trusted Domain objects (PROTECT > Email > Trusted Domains). Mail from
    a trusted domain bypasses spam scanning. Measured against a live appliance: the entity
    is structurally one instance per domain (each <Get> response element carries exactly one
    DomainList/DomainName pair), not a single instance holding an array - the same shape
    already documented for other single-field list entities in this product.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per trusted domain, with the
    property DomainName. Returns System.Xml.XmlElement when -AsXml is used, and an empty
    array when no domain is configured.

.EXAMPLE
    Get-SfosAntiSpamTrustedDomain

    Lists every trusted domain on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/TrustedDomain/TrustedDomain.html

.LINK
    New-SfosAntiSpamTrustedDomain
#>
function Get-SfosAntiSpamTrustedDomain {
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

    # No server-side filter key is sent: the identifying field is DomainList/DomainName,
    # not Name, and a filter on it was not measured. Sending an unmeasured key risks a
    # fail-closed entity (see the module report for AntiSpamRules/Description on this same
    # product); this entity's list is normally short, so client-side filtering alone is safe.
    $inner = '<Get><AntiSpamTrustedDomain></AntiSpamTrustedDomain></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AntiSpamTrustedDomain objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamTrustedDomain' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AntiSpamTrustedDomain[DomainList]' | ForEach-Object -Process { $_.Node }

    $domainObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            DomainName = [string]$node.DomainList.DomainName
        }
    }

    $domainObjects = @($domainObjects)

    if ($AsXml) {
        return @($nodes)
    }

    return $domainObjects
}

<#
.SYNOPSIS
    Adds a trusted domain to a Sophos Firewall.

.DESCRIPTION
    Adds an Anti Spam Trusted Domain. There is no Set-SfosAntiSpamTrustedDomain: the entity
    carries only DomainName - once a domain exists there is nothing left to update, and
    changing the value would just be a different domain, which New-/Remove- already cover.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER DomainName
    Required. The domain name to trust, for example 'example.com'.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts DomainName by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosAntiSpamTrustedDomain -DomainName 'example.com' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosAntiSpamTrustedDomain -DomainName 'example.com'

    Trusts the given domain. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/TrustedDomain/operations/AddDomainName.html

.LINK
    Get-SfosAntiSpamTrustedDomain
#>
function New-SfosAntiSpamTrustedDomain {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

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
        if (-not $PSCmdlet.ShouldProcess("AntiSpamTrustedDomain '$DomainName' on $($params.Firewall)", 'Create')) {
            return
        }

        $domainEsc = ConvertTo-SfosXmlEscaped -Text $DomainName
        $inner = "<Set operation=`"add`"><AntiSpamTrustedDomain><DomainList><DomainName>$domainEsc</DomainName></DomainList></AntiSpamTrustedDomain></Set>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create AntiSpamTrustedDomain object '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamTrustedDomain' -Action 'create' -Target $DomainName
    }
}

<#
.SYNOPSIS
    Removes a trusted domain from a Sophos Firewall.

.DESCRIPTION
    Removes an Anti Spam Trusted Domain. The cmdlet reads the current list first and throws
    a clear error if the given domain is not present.

    This is not a cosmetic convenience on this entity: a Remove for a domain that was
    already removed was measured to still answer 200 ("Configuration applied
    successfully") on a live appliance - a false success, exactly like the pattern already
    documented elsewhere in this product for a removal of a non-existent object. Without the
    read-first check, a typo in -DomainName would silently do nothing and report success.

    The Remove request itself has to nest the domain inside a DomainList wrapper, the same
    shape the Add operation and Get both use - a flat
    <Remove><AntiSpamTrustedDomain><DomainName>...</DomainName></...></Remove> was measured
    to fail with status 533 "API request failed", not the "not found" error one might expect.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER DomainName
    Required. The domain name to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts DomainName by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal, or if the named domain does not exist.

.EXAMPLE
    Remove-SfosAntiSpamTrustedDomain -DomainName 'example.com' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/TrustedDomain/operations/Delete_Trusted_Domain.html

.LINK
    Get-SfosAntiSpamTrustedDomain
#>
function Remove-SfosAntiSpamTrustedDomain {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$DomainName,

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
        $existing = @(Get-SfosAntiSpamTrustedDomain -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.DomainName -eq $DomainName })

        if ($existing.Count -eq 0) {
            throw "The AntiSpamTrustedDomain object '$DomainName' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("AntiSpamTrustedDomain '$DomainName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $domainEsc = ConvertTo-SfosXmlEscaped -Text $DomainName
        $inner = "<Remove><AntiSpamTrustedDomain><DomainList><DomainName>$domainEsc</DomainName></DomainList></AntiSpamTrustedDomain></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove AntiSpamTrustedDomain object '$DomainName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamTrustedDomain' -Action 'remove' -Target $DomainName
    }
}

#endregion


#region AntiSpamEmailArchiver

<#
.SYNOPSIS
    Builds the Set request body for an AntiSpamEmailArchiver entity.

.DESCRIPTION
    Builds the complete inner XML for a Set operation on an AntiSpamEmailArchiver entity, so
    New- and Set-SfosAntiSpamEmailArchiver send the same entity shape.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Archiver
    The object to convert, with the properties Name, Recipient (an array) and
    SendCopyOfEmailTo.
#>
function ConvertTo-SfosAntiSpamEmailArchiverEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [PSCustomObject]$Archiver
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Archiver.Name)
    $sendCopyEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Archiver.SendCopyOfEmailTo)

    $recipientXml = ''
    foreach ($recipient in @($Archiver.Recipient)) {
        if (-not $recipient) { continue }
        $recipientXml += "<Recipient>$(ConvertTo-SfosXmlEscaped -Text ([string]$recipient))</Recipient>"
    }

    return @"
<Set operation="$Operation">
  <AntiSpamEmailArchiver>
    <Name>$nameEsc</Name>
    <RecipientList>$recipientXml</RecipientList>
    <SendCopyOfEmailTo>$sendCopyEsc</SendCopyOfEmailTo>
  </AntiSpamEmailArchiver>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves Anti Spam Email Archiver objects from a Sophos Firewall.

.DESCRIPTION
    Returns Anti Spam Email Archiver objects (PROTECT > Email > Email Archiver, legacy
    scanning engine). Each archiver forwards a copy of matching mail to an address.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

    This object belongs to legacy mail scanning. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

.PARAMETER NameLike
    Optional. Returns only archivers whose name contains the given text anywhere. Not sent
    as a server-side filter - untested for this entity - and applied client-side only. If
    omitted, the name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements sent by the firewall instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per archiver, with the
    properties Name, Recipient (an array) and SendCopyOfEmailTo. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no archiver is
    configured.

.EXAMPLE
    Get-SfosAntiSpamEmailArchiver

    Lists every Email Archiver on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/EmailArchiver/EmailArchiver.html

.LINK
    New-SfosAntiSpamEmailArchiver
#>
function Get-SfosAntiSpamEmailArchiver {
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

    $inner = '<Get><AntiSpamEmailArchiver></AntiSpamEmailArchiver></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AntiSpamEmailArchiver objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamEmailArchiver' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AntiSpamEmailArchiver[Name]' | ForEach-Object -Process { $_.Node }

    $archiverObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name              = [string]$node.Name
            Recipient         = [string[]]@($node.RecipientList.Recipient | Where-Object -FilterScript { $_ })
            SendCopyOfEmailTo = [string]$node.SendCopyOfEmailTo
        }
    }

    $archiverObjects = @($archiverObjects)
    if ($NameLike) {
        $archiverObjects = @($archiverObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($archiverObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $archiverObjects
}

<#
.SYNOPSIS
    Creates an Anti Spam Email Archiver object on a Sophos Firewall.

.DESCRIPTION
    Creates an Anti Spam Email Archiver (PROTECT > Email > Email Archiver, legacy scanning
    engine).

    Measured against a live appliance: -Recipient accepts the literal value 'Any' ("any
    recipient"). A raw email address given as the only entry is rejected outright with a
    field validation error. A raw email address given alongside 'Any' is not rejected -
    the request answers 200 - but is silently dropped: reading the object back afterwards
    shows only 'Any', the other address is gone. Whether any other named object (a user,
    an address group) is accepted was not tested. Passing anything other than 'Any' is
    therefore unreliable on this appliance; the parameter still accepts arbitrary text
    because the documented contract does, and stopping short of what the firewall accepts
    would be guessing in the other direction.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the archiver, 1 to 50 characters.

.PARAMETER Recipient
    Required. One or more recipient values to archive mail for. Read the description of this
    cmdlet before using anything other than 'Any' - other values are dropped silently.

.PARAMETER SendCopyOfEmailTo
    Required. Email address the archived copy is sent to, up to 50 characters.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts Name and SendCopyOfEmailTo by
    property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the create.

.EXAMPLE
    New-SfosAntiSpamEmailArchiver -Name 'ArchiveAll' -Recipient 'Any' -SendCopyOfEmailTo 'archive@example.com' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosAntiSpamEmailArchiver -Name 'ArchiveAll' -Recipient 'Any' -SendCopyOfEmailTo 'archive@example.com'

    Creates an archiver copying every mail to the given address. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/EmailArchiver/operations/AddEmailArchiver%26EditEmailArchiver.html

.LINK
    Get-SfosAntiSpamEmailArchiver
#>
function New-SfosAntiSpamEmailArchiver {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$Recipient,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$SendCopyOfEmailTo,

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
        if (-not $PSCmdlet.ShouldProcess("AntiSpamEmailArchiver '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $archiver = [PSCustomObject]@{
            Name              = $Name
            Recipient         = $Recipient
            SendCopyOfEmailTo = $SendCopyOfEmailTo
        }

        $inner = ConvertTo-SfosAntiSpamEmailArchiverEntityXml -Operation 'add' -Archiver $archiver

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create AntiSpamEmailArchiver object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamEmailArchiver' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an Anti Spam Email Archiver object on a Sophos Firewall.

.DESCRIPTION
    Updates an Anti Spam Email Archiver. The firewall replaces the whole object on update;
    this cmdlet reads the current object first and keeps whatever the caller does not
    explicitly pass. See New-SfosAntiSpamEmailArchiver for the -Recipient defect measured on
    this appliance.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the target archiver.

.PARAMETER Recipient
    Optional. If omitted, the existing recipient list is kept.

.PARAMETER SendCopyOfEmailTo
    Optional. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts an object by value or by property
    name, for example from Get-SfosAntiSpamEmailArchiver.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update,
    or if the named archiver does not exist.

.EXAMPLE
    Set-SfosAntiSpamEmailArchiver -Name 'ArchiveAll' -SendCopyOfEmailTo 'archive2@example.com' -WhatIf

    Shows what the call would change without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/EmailArchiver/operations/AddEmailArchiver%26EditEmailArchiver.html

.LINK
    Get-SfosAntiSpamEmailArchiver
#>
function Set-SfosAntiSpamEmailArchiver {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [string]$Name,

        [string[]]$Recipient,

        [ValidateLength(1, 50)]
        [string]$SendCopyOfEmailTo,

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
        $existing = @(Get-SfosAntiSpamEmailArchiver -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AntiSpamEmailArchiver object '$Name' was not found."
        }

        $target = $existing[0].PSObject.Copy()

        if ($PSBoundParameters.ContainsKey('Recipient')) { $target.Recipient = $Recipient }
        if ($PSBoundParameters.ContainsKey('SendCopyOfEmailTo')) { $target.SendCopyOfEmailTo = $SendCopyOfEmailTo }

        $inner = ConvertTo-SfosAntiSpamEmailArchiverEntityXml -Operation 'update' -Archiver $target

        if (-not $PSCmdlet.ShouldProcess("AntiSpamEmailArchiver '$Name' on $($params.Firewall)", 'Update')) {
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
            throw "Error updating AntiSpamEmailArchiver object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamEmailArchiver' -Action 'edit' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an Anti Spam Email Archiver object from a Sophos Firewall.

.DESCRIPTION
    Removes an Anti Spam Email Archiver. The cmdlet reads the object first and throws a
    clear error if the given name does not exist.

    Measured against a live appliance: a Remove for an archiver name that does not exist
    still answers 200 ("Configuration applied successfully") - a false success. Without the
    read-first check here, a typo in -Name would silently do nothing and report success.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the archiver to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts the archiver name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal, or if the named archiver does not exist.

.EXAMPLE
    Remove-SfosAntiSpamEmailArchiver -Name 'ArchiveAll' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/EmailArchiver/operations/Delete_Email_Archiver.html

.LINK
    Get-SfosAntiSpamEmailArchiver
#>
function Remove-SfosAntiSpamEmailArchiver {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        $existing = @(Get-SfosAntiSpamEmailArchiver -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AntiSpamEmailArchiver object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("AntiSpamEmailArchiver '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><AntiSpamEmailArchiver><Name>$nameEsc</Name></AntiSpamEmailArchiver></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove AntiSpamEmailArchiver object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamEmailArchiver' -Action 'remove' -Target $Name
    }
}

#endregion


#region AntiSpamQuarantineDigestSettings

<#
.SYNOPSIS
    Retrieves the Anti Spam Quarantine Digest settings from a Sophos Firewall.

.DESCRIPTION
    Returns the single Anti Spam Quarantine Digest Settings object (PROTECT > Email >
    Quarantine Digest Settings, legacy scanning engine). Controls whether and how often a
    digest mail listing quarantined spam is sent to each user, and which users are
    excluded from it.

    Two undocumented findings from a live read on this appliance, not present in the
    vendor's attribute table or sample XML: ReferenceMyAccountIP, an empty element with no
    documented purpose (returned here for completeness, unmodified by Set-* unless you pass
    it back yourself); and the absence of ReleaseLinkSettings/ReleaseLinkInterface/
    ReleaseLinkHost and QuarantineArea/DiskSize entirely from the response while the digest
    is disabled, even though the vendor table marks several of those as mandatory - they
    only appear once actually configured.

    -DisableUsers and -EnableUsers can contain real account names; treat the output of this
    cmdlet as being at the same sensitivity level as a user list.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

    This object belongs to legacy mail scanning. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. A single object with the properties
    SpamQuarantineDigest, EmailFrequency, Hour, Minute, Days (an array, only populated for
    weekly digests), FromEmailAddress, DisplayName, AllowUserToOverride,
    ReleaseLinkSettings, ReleaseLinkInterface, ReleaseLinkHost, DiskSize,
    ReferenceMyAccountIP, EnableUsers and DisableUsers (both arrays). Returns
    System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosAntiSpamQuarantineDigestSettings

    Reads the current digest settings from the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/DigestSettings/DigestSettings.html

.LINK
    Set-SfosAntiSpamQuarantineDigestSettings
#>
function Get-SfosAntiSpamQuarantineDigestSettings {
    # AntiSpamQuarantineDigestSettings is a single configuration object, not a container
    # holding many named entities - Get-...QuarantineDigestSetting would wrongly suggest one
    # of several settings. The Sophos spelling wins per the module's noun rule for singletons.
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

    $inner = '<Get><AntiSpamQuarantineDigestSettings></AntiSpamQuarantineDigestSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AntiSpamQuarantineDigestSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiSpamQuarantineDigestSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/AntiSpamQuarantineDigestSettings')

    if ($AsXml) {
        return $node
    }

    if (-not $node) {
        return $null
    }

    $settings = $node.SpamDigestSettings
    $days = @()
    if ($settings.SendEmailAt) {
        $days = [string[]]@($settings.SendEmailAt.Days | Where-Object -FilterScript { $_ })
    }

    [PSCustomObject]@{
        SpamQuarantineDigest  = [string]$settings.SpamQuarantineDigest
        EmailFrequency        = [string]$settings.EmailFrequency
        Hour                  = if ($settings.SendEmailAt.Hour) { [int]$settings.SendEmailAt.Hour } else { $null }
        Minute                = if ($settings.SendEmailAt.Minute) { [int]$settings.SendEmailAt.Minute } else { $null }
        Days                  = $days
        FromEmailAddress      = [string]$settings.FromEmailAddress
        DisplayName           = [string]$settings.DisplayName
        AllowUserToOverride   = [string]$settings.AllowUserToOverride
        ReleaseLinkSettings   = [string]$settings.ReleaseLinkSettings
        ReleaseLinkInterface  = [string]$settings.ReleaseLinkInterface
        ReleaseLinkHost       = [string]$settings.ReleaseLinkHost
        DiskSize              = [string]$settings.QuarantineArea.DiskSize
        ReferenceMyAccountIP  = [string]$settings.ReferenceMyAccountIP
        EnableUsers           = [string[]]@($node.SpamDigestUsers.EnableUsers.EnableUser | Where-Object -FilterScript { $_ })
        DisableUsers          = [string[]]@($node.SpamDigestUsers.DisableUsers.DisableUser | Where-Object -FilterScript { $_ })
    }
}

<#
.SYNOPSIS
    Updates the Anti Spam Quarantine Digest settings on a Sophos Firewall.

.DESCRIPTION
    Updates the single Anti Spam Quarantine Digest Settings object. The firewall replaces
    the settings on update; this cmdlet reads the current object first and keeps whatever
    the caller does not explicitly pass, including EnableUsers, DisableUsers and the
    undocumented ReferenceMyAccountIP field - none of those are exposed as parameters here,
    on purpose, so this cmdlet can never touch the user override lists.

    Measured against a live appliance, and not resolved: an update that reproduced every
    field of the SpamDigestSettings block exactly as read back (including the empty
    FromEmailAddress and the undocumented ReferenceMyAccountIP) still answered status 501
    "Configuration parameters validation failed" with an empty InvalidParams list - no
    field was named as the cause, and the digest settings were confirmed unchanged
    afterwards. The SpamDigestUsers block, sent as part of the same request, answered 200
    and left the user lists provably unchanged.

    Not a mode-gate: retested after switching the appliance to legacy mode
    (SMTPDeploymentMode/MTAMode = OFF), where every other legacy Email write in this module
    started working. This one still answers 501, including for a raw request that echoed
    the appliance's own last Get response for this entity byte for byte back as an update -
    proof the 501 is not caused by anything this cmdlet builds. Setting
    -SpamQuarantineDigest Enable instead names a field, ReferenceMyAccountIP, but every
    value tried for it - empty, an IP literal, omitted entirely - was rejected the same way,
    so that name does not point at a fixable request shape either. This looks like a
    firmware-side validation defect on this entity, not a defect in this cmdlet. Anything
    that reaches Set-SfosAntiSpamQuarantineDigestSettings and changes a field under
    -SpamQuarantineDigest/-EmailFrequency/etc. should be expected to hit the same 501 until
    Sophos support can attribute it; the cmdlet is implemented to the documented contract
    and raises the firewall's own error rather than a made-up one.

    The response carries two independent statuses at two different, unexpected XPaths -
    measured, not guessed: /Response/SpamDigestSettings/Status and
    /Response/SpamDigestUsers/Status, both direct children of /Response, neither nested
    under /Response/AntiSpamQuarantineDigestSettings. This cmdlet checks both explicitly so
    a failure in one block is never masked by success in the other.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER SpamQuarantineDigest
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER EmailFrequency
    Optional. Hourly, Day or Week. If omitted, the existing value is kept.

.PARAMETER Hour
    Optional. Hour of the day, 0-23. If omitted, the existing value is kept.

.PARAMETER Minute
    Optional. Minute of the hour, 0-59. If omitted, the existing value is kept.

.PARAMETER Days
    Optional. Days of the week the digest is sent, only meaningful when -EmailFrequency is
    Week. If omitted, the existing value is kept.

.PARAMETER FromEmailAddress
    Optional. Sender address of the digest mail. If omitted, the existing value is kept.

.PARAMETER DisplayName
    Optional. Sender display name of the digest mail. If omitted, the existing value is
    kept.

.PARAMETER AllowUserToOverride
    Optional. Enable or Disable. If omitted, the existing value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosAntiSpamQuarantineDigestSettings -EmailFrequency Hourly -WhatIf

    Shows what the call would change without sending it to the firewall.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/PROTECT/Email/DigestSettings/operations/SpamDigestSettings.html

.LINK
    Get-SfosAntiSpamQuarantineDigestSettings
#>
function Set-SfosAntiSpamQuarantineDigestSettings {
    # Same singleton-noun exception as Get-SfosAntiSpamQuarantineDigestSettings.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$SpamQuarantineDigest,

        [ValidateSet('Hourly', 'Day', 'Week')]
        [string]$EmailFrequency,

        [ValidateRange(0, 23)]
        [int]$Hour,

        [ValidateRange(0, 59)]
        [int]$Minute,

        [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
        [string[]]$Days,

        [string]$FromEmailAddress,

        [string]$DisplayName,

        [ValidateSet('Enable', 'Disable')]
        [string]$AllowUserToOverride,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAntiSpamQuarantineDigestSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    if (-not $existing) {
        throw 'Failed to read the current AntiSpamQuarantineDigestSettings before updating.'
    }

    $target = $existing.PSObject.Copy()

    if ($PSBoundParameters.ContainsKey('SpamQuarantineDigest')) { $target.SpamQuarantineDigest = $SpamQuarantineDigest }
    if ($PSBoundParameters.ContainsKey('EmailFrequency')) { $target.EmailFrequency = $EmailFrequency }
    if ($PSBoundParameters.ContainsKey('Hour')) { $target.Hour = $Hour }
    if ($PSBoundParameters.ContainsKey('Minute')) { $target.Minute = $Minute }
    if ($PSBoundParameters.ContainsKey('Days')) { $target.Days = $Days }
    if ($PSBoundParameters.ContainsKey('FromEmailAddress')) { $target.FromEmailAddress = $FromEmailAddress }
    if ($PSBoundParameters.ContainsKey('DisplayName')) { $target.DisplayName = $DisplayName }
    if ($PSBoundParameters.ContainsKey('AllowUserToOverride')) { $target.AllowUserToOverride = $AllowUserToOverride }

    if (-not $PSCmdlet.ShouldProcess("AntiSpamQuarantineDigestSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $sqEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.SpamQuarantineDigest)
    $efEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.EmailFrequency)
    $feEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.FromEmailAddress)
    $dnEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.DisplayName)
    $auEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.AllowUserToOverride)
    $refEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.ReferenceMyAccountIP)

    $daysXml = ''
    foreach ($day in @($target.Days)) {
        if (-not $day) { continue }
        $daysXml += "<Days>$(ConvertTo-SfosXmlEscaped -Text $day)</Days>"
    }

    $releaseXml = ''
    if ($target.ReleaseLinkSettings) {
        $rlsEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.ReleaseLinkSettings)
        $rliEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.ReleaseLinkInterface)
        $rlhEsc = ConvertTo-SfosXmlEscaped -Text ([string]$target.ReleaseLinkHost)
        $releaseXml = "<ReleaseLinkSettings>$rlsEsc</ReleaseLinkSettings><ReleaseLinkInterface>$rliEsc</ReleaseLinkInterface><ReleaseLinkHost>$rlhEsc</ReleaseLinkHost>"
    }

    $quarantineAreaXml = ''
    if ($target.DiskSize) {
        $quarantineAreaXml = "<QuarantineArea><DiskSize>$(ConvertTo-SfosXmlEscaped -Text ([string]$target.DiskSize))</DiskSize></QuarantineArea>"
    }

    $enableUsersXml = ''
    foreach ($u in @($target.EnableUsers)) {
        if (-not $u) { continue }
        $enableUsersXml += "<EnableUser>$(ConvertTo-SfosXmlEscaped -Text $u)</EnableUser>"
    }
    $disableUsersXml = ''
    foreach ($u in @($target.DisableUsers)) {
        if (-not $u) { continue }
        $disableUsersXml += "<DisableUser>$(ConvertTo-SfosXmlEscaped -Text $u)</DisableUser>"
    }

    $inner = @"
<Set operation="update">
  <AntiSpamQuarantineDigestSettings>
    <SpamDigestSettings>
      <SpamQuarantineDigest>$sqEsc</SpamQuarantineDigest>
      <EmailFrequency>$efEsc</EmailFrequency>
      <SendEmailAt>
        <Hour>$([int]$target.Hour)</Hour>
        <Minute>$([int]$target.Minute)</Minute>
        $daysXml
      </SendEmailAt>
      <FromEmailAddress>$feEsc</FromEmailAddress>
      <DisplayName>$dnEsc</DisplayName>
      <ReferenceMyAccountIP>$refEsc</ReferenceMyAccountIP>
      <AllowUserToOverride>$auEsc</AllowUserToOverride>
      $releaseXml
      $quarantineAreaXml
    </SpamDigestSettings>
    <SpamDigestUsers>
      <EnableUsers>$enableUsersXml</EnableUsers>
      <DisableUsers>$disableUsersXml</DisableUsers>
    </SpamDigestUsers>
  </AntiSpamQuarantineDigestSettings>
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
        throw "Error updating AntiSpamQuarantineDigestSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured: the two sub-blocks report status at two separate flat roots, neither nested
    # under AntiSpamQuarantineDigestSettings - checked individually so one block's failure
    # is never hidden by the other block's success.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SpamDigestSettings' -Action 'update digest settings'
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SpamDigestUsers' -Action 'update digest user overrides'
}

#endregion

#region SMTPMalwareScanningPolicy

<#
.SYNOPSIS
    Builds the Set request body for an AntiVirusMailSMTPScanningRules entity. Internal
    helper, not exported.

.DESCRIPTION
    Shared by New-SfosSMTPMalwareScanningPolicy and Set-SfosSMTPMalwareScanningPolicy so both send
    the same entity shape. Every value is escaped through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the rule.

.PARAMETER After
    Optional. Name of the rule this one is ordered after.

.PARAMETER SenderAddress
    One or more sender email addresses (or 'Any').

.PARAMETER Receiver
    One or more receiver email addresses (or 'Any').

.PARAMETER Scanning
    Scanning mode.

.PARAMETER Quarantine
    Enable/Disable.

.PARAMETER NotifySender
    Enable/Disable.

.PARAMETER FileType
    One or more block-listed attachment file type names (or 'None').

.PARAMETER ReceiverActionInfected
    Action for infected attachments.

.PARAMETER NotifyAdministratorInfected
    Administrator notification action for infected attachments.

.PARAMETER ReceiverActionSuspicious
    Action for suspicious attachments.

.PARAMETER NotifyAdministratorSuspicious
    Administrator notification action for suspicious attachments.

.PARAMETER ReceiverActionProtectedAttachment
    Action for password-protected attachments.

.PARAMETER NotifyAdministratorProtectedAttachment
    Administrator notification action for password-protected attachments.
#>
function ConvertTo-SfosSMTPMalwareScanningPolicyEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$After,

        [Parameter(Mandatory)]
        [string[]]$SenderAddress,

        [Parameter(Mandatory)]
        [string[]]$Receiver,

        [string]$Scanning,
        [string]$Quarantine,
        [string]$NotifySender,

        [Parameter(Mandatory)]
        [string[]]$FileType,

        [string]$ReceiverActionInfected,
        [string]$NotifyAdministratorInfected,
        [string]$ReceiverActionSuspicious,
        [string]$NotifyAdministratorSuspicious,
        [string]$ReceiverActionProtectedAttachment,
        [string]$NotifyAdministratorProtectedAttachment
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $afterXml = ''
    if ($After) {
        $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text $After)</Name></After>"
    }

    $senderXml = ($SenderAddress | Where-Object { $_ } | ForEach-Object { "<Sender>$(ConvertTo-SfosXmlEscaped -Text $_)</Sender>" }) -join ''
    $receiverXml = ($Receiver | Where-Object { $_ } | ForEach-Object { "<Receiver>$(ConvertTo-SfosXmlEscaped -Text $_)</Receiver>" }) -join ''
    $fileTypeXml = ($FileType | Where-Object { $_ } | ForEach-Object { "<FileType>$(ConvertTo-SfosXmlEscaped -Text $_)</FileType>" }) -join ''

    return @"
<Set operation="$Operation">
  <AntiVirusMailSMTPScanningRules>
    <Name>$nameEsc</Name>
    $afterXml
    <SenderList>$senderXml</SenderList>
    <ReceiverList>$receiverXml</ReceiverList>
    <Scanning>$(ConvertTo-SfosXmlEscaped -Text $Scanning)</Scanning>
    <Quarantine>$(ConvertTo-SfosXmlEscaped -Text $Quarantine)</Quarantine>
    <NotifySender>$(ConvertTo-SfosXmlEscaped -Text $NotifySender)</NotifySender>
    <BlockFileTypes>$fileTypeXml</BlockFileTypes>
    <ReceiverActionInfected>$(ConvertTo-SfosXmlEscaped -Text $ReceiverActionInfected)</ReceiverActionInfected>
    <NotifyAdministratorInfected>$(ConvertTo-SfosXmlEscaped -Text $NotifyAdministratorInfected)</NotifyAdministratorInfected>
    <ReceiverActionSuspicious>$(ConvertTo-SfosXmlEscaped -Text $ReceiverActionSuspicious)</ReceiverActionSuspicious>
    <NotifyAdministratorSuspicious>$(ConvertTo-SfosXmlEscaped -Text $NotifyAdministratorSuspicious)</NotifyAdministratorSuspicious>
    <ReceiverActionProtectedAttachment>$(ConvertTo-SfosXmlEscaped -Text $ReceiverActionProtectedAttachment)</ReceiverActionProtectedAttachment>
    <NotifyAdministratorProtectedAttachment>$(ConvertTo-SfosXmlEscaped -Text $NotifyAdministratorProtectedAttachment)</NotifyAdministratorProtectedAttachment>
  </AntiVirusMailSMTPScanningRules>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves SMTP anti-malware scanning rules from a Sophos Firewall.

.DESCRIPTION
    Returns AntiVirusMailSMTPScanningRules objects (PROTECT > Email > Protection, SMTP
    scanning rules). This root is shared between the legacy Email area and the MTA-based
    Email(MTA) area on firmware where both are visible through the API; a write here can
    therefore affect whichever mode is active, not only the legacy one. Confirmed against a
    live appliance switched to legacy mode (SMTPDeploymentMode/MTAMode = OFF): create,
    update and remove on this entity all succeed there - see the write cmdlets for the
    exact responses. Whether the same writes succeed while the appliance runs MTA mode is
    still unmeasured.

    Every firewall observed so far carries exactly one built-in rule, 'default-smtp-av'.
    Do not modify or remove that rule; it is the appliance's own SMTP virus scanning
    policy.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

.PARAMETER NameLike
    Optional. Returns only rules whose name contains the given text anywhere. Sent to the
    firewall as a server-side pre-filter (Name/like) and re-applied client-side. If
    omitted, every rule is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per rule, with the properties
    Name, After, Sender, Receiver (both string arrays), Scanning, Quarantine,
    NotifySender, FileType (string array), ReceiverActionInfected,
    NotifyAdministratorInfected, ReceiverActionSuspicious, NotifyAdministratorSuspicious,
    ReceiverActionProtectedAttachment and NotifyAdministratorProtectedAttachment. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no rule matches.

.EXAMPLE
    Get-SfosSMTPMalwareScanningPolicy

    Lists every SMTP malware scanning policy, including the built-in default-smtp-av.

.EXAMPLE
    Get-SfosSMTPMalwareScanningPolicy -NameLike 'default'

    Lists rules whose name contains 'default'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/SMTPScanningRules/SMTPScanningRules.html

.LINK
    New-SfosSMTPMalwareScanningPolicy
#>
function Get-SfosSMTPMalwareScanningPolicy {
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

    $inner = "<Get><AntiVirusMailSMTPScanningRules>$filterXml</AntiVirusMailSMTPScanningRules></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AntiVirusMailSMTPScanningRules objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiVirusMailSMTPScanningRules' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/AntiVirusMailSMTPScanningRules[Name]' | ForEach-Object -Process { $_.Node }

    $ruleObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name                                   = [string]$node.Name
            After                                  = [string]$node.After.Name
            Sender                                 = @($node.SenderList.Sender | Where-Object -FilterScript { $null -ne $_ })
            Receiver                               = @($node.ReceiverList.Receiver | Where-Object -FilterScript { $null -ne $_ })
            Scanning                               = [string]$node.Scanning
            Quarantine                             = [string]$node.Quarantine
            NotifySender                           = [string]$node.NotifySender
            FileType                               = @($node.BlockFileTypes.FileType | Where-Object -FilterScript { $null -ne $_ })
            ReceiverActionInfected                 = [string]$node.ReceiverActionInfected
            NotifyAdministratorInfected             = [string]$node.NotifyAdministratorInfected
            ReceiverActionSuspicious               = [string]$node.ReceiverActionSuspicious
            NotifyAdministratorSuspicious          = [string]$node.NotifyAdministratorSuspicious
            ReceiverActionProtectedAttachment      = [string]$node.ReceiverActionProtectedAttachment
            NotifyAdministratorProtectedAttachment = [string]$node.NotifyAdministratorProtectedAttachment
        }
    }

    $ruleObjects = @($ruleObjects)
    if ($NameLike) {
        $ruleObjects = @($ruleObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($ruleObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $ruleObjects
}

<#
.SYNOPSIS
    Creates an SMTP anti-malware scanning rule on a Sophos Firewall.

.DESCRIPTION
    Creates an AntiVirusMailSMTPScanningRules object. AntiVirusMailSMTPScanningRules is
    documented only under the legacy Email area (PROTECT > Email > Protection); on a
    firewall running in MTA mode, adding a rule here was measured to fail with status
    545 ("MTAModeDisableCheck" in the vendor status table), regardless of the field
    values sent - confirmed by first provoking an unrelated 501 field-validation error
    with the same payload shape, which proves the request itself parses correctly and
    the 545 is a mode gate, not a malformed request. Confirmed against the same appliance
    switched to legacy mode (SMTPDeploymentMode/MTAMode = OFF): the create succeeds and the
    object reads back with the fields sent. This module has no way to detect the
    appliance's current mode (see the module header).

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

.PARAMETER Name
    Required. Name of the rule. Maximum 50 characters, no comma.

.PARAMETER After
    Optional. Name of the existing rule this one is ordered after.

.PARAMETER SenderAddress
    Required. One or more sender email addresses to match, or 'Any'.

.PARAMETER Receiver
    Required. One or more receiver email addresses to match, or 'Any'.

.PARAMETER Scanning
    Optional. Scanning mode. If omitted, 'Disable' is used.

.PARAMETER Quarantine
    Optional. Whether infected mail is quarantined (Enable/Disable). If omitted,
    'Disable' is used.

.PARAMETER NotifySender
    Optional. Whether the sender is notified of infected mail (Enable/Disable). If
    omitted, 'Disable' is used.

.PARAMETER FileType
    Required. One or more attachment file type names to block, or 'None' to block
    nothing by type.

.PARAMETER ReceiverActionInfected
    Optional. Action taken for the receiver when an attachment is infected. If omitted,
    "Don'tDeliver" is used.

.PARAMETER NotifyAdministratorInfected
    Optional. Administrator notification action for infected attachments. If omitted,
    "Don'tDeliver" is used.

.PARAMETER ReceiverActionSuspicious
    Optional. Action taken for the receiver when an attachment is suspicious. If
    omitted, "Don'tDeliver" is used.

.PARAMETER NotifyAdministratorSuspicious
    Optional. Administrator notification action for suspicious attachments. If omitted,
    "Don'tDeliver" is used.

.PARAMETER ReceiverActionProtectedAttachment
    Optional. Action taken for the receiver when an attachment is password-protected. If
    omitted, "Don'tDeliver" is used.

.PARAMETER NotifyAdministratorProtectedAttachment
    Optional. Administrator notification action for password-protected attachments. If
    omitted, "Don'tDeliver" is used.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create - including a 545 mode gate on a firewall running in MTA mode.

.EXAMPLE
    New-SfosSMTPMalwareScanningPolicy -Name 'AttachmentPolicy' -Sender 'Any' -Receiver 'Any' -FileType 'None' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosSMTPMalwareScanningPolicy -Name 'AttachmentPolicy' -Sender 'Any' -Receiver 'Any' -FileType 'None' -Quarantine Enable

    Creates a rule that quarantines infected mail for any sender and receiver, with no
    file type block list. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/SMTPScanningRules/operations/AddSMTPMalwareScanningPolicy%26EditSMTPMalwareScanningPolicy.html

.LINK
    Get-SfosSMTPMalwareScanningPolicy
#>
function New-SfosSMTPMalwareScanningPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$After,

        [Parameter(Mandatory)]
        [string[]]$SenderAddress,

        [Parameter(Mandatory)]
        [string[]]$Receiver,

        [string]$Scanning = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$Quarantine = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$NotifySender = 'Disable',

        [Parameter(Mandatory)]
        [string[]]$FileType,

        [ValidateSet("Don'tDeliver", 'DeliverOriginal', 'RemoveAndDeliver')]
        [string]$ReceiverActionInfected = "Don'tDeliver",
        [ValidateSet("Don'tDeliver", 'SendOriginal', 'RemoveAttachment')]
        [string]$NotifyAdministratorInfected = "Don'tDeliver",
        [ValidateSet("Don'tDeliver", 'DeliverOriginal', 'RemoveAndDeliver')]
        [string]$ReceiverActionSuspicious = "Don'tDeliver",
        [ValidateSet("Don'tDeliver", 'SendOriginal', 'RemoveAttachment')]
        [string]$NotifyAdministratorSuspicious = "Don'tDeliver",
        [ValidateSet("Don'tDeliver", 'DeliverOriginal', 'RemoveAndDeliver')]
        [string]$ReceiverActionProtectedAttachment = "Don'tDeliver",
        [ValidateSet("Don'tDeliver", 'SendOriginal', 'RemoveAttachment')]
        [string]$NotifyAdministratorProtectedAttachment = "Don'tDeliver",

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
        if (-not $PSCmdlet.ShouldProcess("AntiVirusMailSMTPScanningRules '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosSMTPMalwareScanningPolicyEntityXml -Operation 'add' -Name $Name -After $After `
            -SenderAddress $SenderAddress -Receiver $Receiver -Scanning $Scanning -Quarantine $Quarantine `
            -NotifySender $NotifySender -FileType $FileType `
            -ReceiverActionInfected $ReceiverActionInfected -NotifyAdministratorInfected $NotifyAdministratorInfected `
            -ReceiverActionSuspicious $ReceiverActionSuspicious -NotifyAdministratorSuspicious $NotifyAdministratorSuspicious `
            -ReceiverActionProtectedAttachment $ReceiverActionProtectedAttachment `
            -NotifyAdministratorProtectedAttachment $NotifyAdministratorProtectedAttachment

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create AntiVirusMailSMTPScanningRules object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiVirusMailSMTPScanningRules' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an SMTP anti-malware scanning rule on a Sophos Firewall.

.DESCRIPTION
    Reads the named AntiVirusMailSMTPScanningRules object first and writes back a
    complete entity, overriding only the fields you pass - this is a full-replace
    entity, so anything not read back and resent would be cleared. See
    New-SfosSMTPMalwareScanningPolicy for the 545 mode-gate note; the same applies here.
    Verified against a live appliance in legacy mode: a field changed through this cmdlet is
    applied, and an unchanged round trip - read, write back, read again - produces
    byte-identical XML.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'default-smtp-av' rule with this cmdlet.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing rule to update.

.PARAMETER After
    Optional. Name of the existing rule this one is ordered after, replacing the current
    value. If omitted, the current value is kept.

.PARAMETER SenderAddress
    Optional. Sender email addresses to match, replacing the current list. If omitted,
    the current list is kept.

.PARAMETER Receiver
    Optional. Receiver email addresses to match, replacing the current list. If omitted,
    the current list is kept.

.PARAMETER Scanning
    Optional. Scanning mode, replacing the current value. If omitted, the current value
    is kept.

.PARAMETER Quarantine
    Optional. Whether infected mail is quarantined, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER NotifySender
    Optional. Whether the sender is notified of infected mail, replacing the current
    value. If omitted, the current value is kept.

.PARAMETER FileType
    Optional. Attachment file type names to block, replacing the current list. If
    omitted, the current list is kept.

.PARAMETER ReceiverActionInfected
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER NotifyAdministratorInfected
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER ReceiverActionSuspicious
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER NotifyAdministratorSuspicious
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER ReceiverActionProtectedAttachment
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER NotifyAdministratorProtectedAttachment
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosSMTPMalwareScanningPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update or if the named rule does not exist.

.EXAMPLE
    Set-SfosSMTPMalwareScanningPolicy -Name 'AttachmentPolicy' -Quarantine Enable -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSMTPMalwareScanningPolicy -Name 'AttachmentPolicy' -Quarantine Enable

    Turns on quarantine for infected mail on the named rule. Every other field, including
    the sender and receiver lists, is kept unchanged. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/SMTPScanningRules/operations/AddSMTPMalwareScanningPolicy%26EditSMTPMalwareScanningPolicy.html

.LINK
    Get-SfosSMTPMalwareScanningPolicy
#>
function Set-SfosSMTPMalwareScanningPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$After,
        [string[]]$SenderAddress,
        [string[]]$Receiver,
        [string]$Scanning,
        [ValidateSet('Enable', 'Disable')]
        [string]$Quarantine,
        [ValidateSet('Enable', 'Disable')]
        [string]$NotifySender,
        [string[]]$FileType,
        [ValidateSet("Don'tDeliver", 'DeliverOriginal', 'RemoveAndDeliver')]
        [string]$ReceiverActionInfected,
        [ValidateSet("Don'tDeliver", 'SendOriginal', 'RemoveAttachment')]
        [string]$NotifyAdministratorInfected,
        [ValidateSet("Don'tDeliver", 'DeliverOriginal', 'RemoveAndDeliver')]
        [string]$ReceiverActionSuspicious,
        [ValidateSet("Don'tDeliver", 'SendOriginal', 'RemoveAttachment')]
        [string]$NotifyAdministratorSuspicious,
        [ValidateSet("Don'tDeliver", 'DeliverOriginal', 'RemoveAndDeliver')]
        [string]$ReceiverActionProtectedAttachment,
        [ValidateSet("Don'tDeliver", 'SendOriginal', 'RemoveAttachment')]
        [string]$NotifyAdministratorProtectedAttachment,

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
        $existing = @(Get-SfosSMTPMalwareScanningPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AntiVirusMailSMTPScanningRules object '$Name' was not found."
        }
        $current = $existing[0]

        if (-not $PSCmdlet.ShouldProcess("AntiVirusMailSMTPScanningRules '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $bp = $PSBoundParameters
        $targetAfter = if ($bp.ContainsKey('After')) { $After } else { $current.After }
        $targetSender = @(if ($bp.ContainsKey('SenderAddress')) { $SenderAddress } else { $current.Sender })
        $targetReceiver = @(if ($bp.ContainsKey('Receiver')) { $Receiver } else { $current.Receiver })
        $targetScanning = if ($bp.ContainsKey('Scanning')) { $Scanning } else { $current.Scanning }
        $targetQuarantine = if ($bp.ContainsKey('Quarantine')) { $Quarantine } else { $current.Quarantine }
        $targetNotifySender = if ($bp.ContainsKey('NotifySender')) { $NotifySender } else { $current.NotifySender }
        $targetFileType = @(if ($bp.ContainsKey('FileType')) { $FileType } else { $current.FileType })
        $targetRAI = if ($bp.ContainsKey('ReceiverActionInfected')) { $ReceiverActionInfected } else { $current.ReceiverActionInfected }
        $targetNAI = if ($bp.ContainsKey('NotifyAdministratorInfected')) { $NotifyAdministratorInfected } else { $current.NotifyAdministratorInfected }
        $targetRAS = if ($bp.ContainsKey('ReceiverActionSuspicious')) { $ReceiverActionSuspicious } else { $current.ReceiverActionSuspicious }
        $targetNAS = if ($bp.ContainsKey('NotifyAdministratorSuspicious')) { $NotifyAdministratorSuspicious } else { $current.NotifyAdministratorSuspicious }
        $targetRAP = if ($bp.ContainsKey('ReceiverActionProtectedAttachment')) { $ReceiverActionProtectedAttachment } else { $current.ReceiverActionProtectedAttachment }
        $targetNAP = if ($bp.ContainsKey('NotifyAdministratorProtectedAttachment')) { $NotifyAdministratorProtectedAttachment } else { $current.NotifyAdministratorProtectedAttachment }

        $inner = ConvertTo-SfosSMTPMalwareScanningPolicyEntityXml -Operation 'update' -Name $Name -After $targetAfter `
            -Sender $targetSender -Receiver $targetReceiver -Scanning $targetScanning -Quarantine $targetQuarantine `
            -NotifySender $targetNotifySender -FileType $targetFileType `
            -ReceiverActionInfected $targetRAI -NotifyAdministratorInfected $targetNAI `
            -ReceiverActionSuspicious $targetRAS -NotifyAdministratorSuspicious $targetNAS `
            -ReceiverActionProtectedAttachment $targetRAP -NotifyAdministratorProtectedAttachment $targetNAP

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update AntiVirusMailSMTPScanningRules object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiVirusMailSMTPScanningRules' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SMTP anti-malware scanning rule from a Sophos Firewall.

.DESCRIPTION
    Removes an AntiVirusMailSMTPScanningRules object. Measured against a live firewall:
    removing a name that does not exist answers HTTP 200 with a success status,
    identical to a real removal - the firewall reports success without having done
    anything. This cmdlet reads the object first and throws "was not found" itself
    rather than passing that misleading success through.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'default-smtp-av' rule with this cmdlet.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the rule to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosSMTPMalwareScanningPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named rule does not exist.

.EXAMPLE
    Remove-SfosSMTPMalwareScanningPolicy -Name 'AttachmentPolicy' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosSMTPMalwareScanningPolicy -Name 'AttachmentPolicy'

    Removes the named rule. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/SMTPScanningRules/operations/Delete%20SMTP%20Malware%20Scanning%20Policy..html

.LINK
    Get-SfosSMTPMalwareScanningPolicy
#>
function Remove-SfosSMTPMalwareScanningPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        $existing = @(Get-SfosSMTPMalwareScanningPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AntiVirusMailSMTPScanningRules object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("AntiVirusMailSMTPScanningRules '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><AntiVirusMailSMTPScanningRules><Name>$nameEsc</Name></AntiVirusMailSMTPScanningRules></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove AntiVirusMailSMTPScanningRules object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AntiVirusMailSMTPScanningRules' -Action 'remove' -Target $Name
    }
}

#endregion

#region POPIMAPScanningPolicy

<#
.SYNOPSIS
    Builds the Set request body for a POPIMAPScanningPolicy entity. Internal helper, not
    exported.

.DESCRIPTION
    Shared by New-SfosPOPIMAPScanningPolicy and Set-SfosPOPIMAPScanningPolicy so both
    send the same entity shape. Every value is escaped through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the policy rule.

.PARAMETER After
    Optional. Name of the rule this one is ordered after.

.PARAMETER SenderEmail
    Sender email address to match, or 'Any'.

.PARAMETER SenderAction
    Whether SenderEmail is matched as a substring (Contains) or exactly (Equals).

.PARAMETER RecipientEmail
    Recipient email address to match, or 'Any'.

.PARAMETER RecipientAction
    Whether RecipientEmail is matched as a substring (Contains) or exactly (Equals).

.PARAMETER FilterCriteria
    What the rule filters on. Only 'InboundEmailIs' was confirmed against a live
    firewall; other documented values are passed through unvalidated.

.PARAMETER Address
    Optional. Source IP/network addresses, used when FilterCriteria selects that mode.

.PARAMETER MessageSizeOperator
    Optional. GreaterThan or LessThan, used when FilterCriteria selects message size.

.PARAMETER MessageSize
    Optional. Message size threshold, used when FilterCriteria selects message size.

.PARAMETER Action
    Action taken for matching mail: Accept or 'Prefix Subject'.

.PARAMETER To
    Optional. Text prefixed to the subject when Action is 'Prefix Subject'.

.PARAMETER MessageHeaderString
    Optional. Message header name, used when FilterCriteria selects message header.

.PARAMETER MessageHeaderOperator
    Optional. Contains or Equals, used when FilterCriteria selects message header.

.PARAMETER MatchIs
    Optional. The value matched for the selected FilterCriteria.
#>
function ConvertTo-SfosPOPIMAPScanningPolicyEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [string]$After,

        [Parameter(Mandatory)]
        [string]$SenderEmail,
        [Parameter(Mandatory)]
        [string]$SenderAction,
        [Parameter(Mandatory)]
        [string]$RecipientEmail,
        [Parameter(Mandatory)]
        [string]$RecipientAction,

        [Parameter(Mandatory)]
        [string]$FilterCriteria,

        [string[]]$Address,
        [string]$MessageSizeOperator,
        [Nullable[int]]$MessageSize,

        [Parameter(Mandatory)]
        [string]$Action,

        [string]$To,
        [string]$MessageHeaderString,
        [string]$MessageHeaderOperator,
        [string]$MatchIs
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $afterXml = ''
    if ($After) {
        $afterXml = "<After><Name>$(ConvertTo-SfosXmlEscaped -Text $After)</Name></After>"
    }

    $addressXml = ''
    if ($Address) {
        $addressXml = ($Address | Where-Object { $_ } | ForEach-Object { "<Address>$(ConvertTo-SfosXmlEscaped -Text $_)</Address>" }) -join ''
    }

    $messageSizeOperatorXml = ''
    if ($MessageSizeOperator) {
        $messageSizeOperatorXml = "<MessageSizeOperator>$(ConvertTo-SfosXmlEscaped -Text $MessageSizeOperator)</MessageSizeOperator>"
    }
    $messageSizeXml = ''
    if ($null -ne $MessageSize) {
        $messageSizeXml = "<MessageSize>$MessageSize</MessageSize>"
    }
    $toXml = ''
    if ($To) {
        $toXml = "<To>$(ConvertTo-SfosXmlEscaped -Text $To)</To>"
    }
    $headerStringXml = ''
    if ($MessageHeaderString) {
        $headerStringXml = "<MessageHeaderString>$(ConvertTo-SfosXmlEscaped -Text $MessageHeaderString)</MessageHeaderString>"
    }
    $headerOperatorXml = ''
    if ($MessageHeaderOperator) {
        $headerOperatorXml = "<MessageHeaderOperator>$(ConvertTo-SfosXmlEscaped -Text $MessageHeaderOperator)</MessageHeaderOperator>"
    }
    $matchIsXml = ''
    if ($MatchIs) {
        $matchIsXml = "<MatchIs>$(ConvertTo-SfosXmlEscaped -Text $MatchIs)</MatchIs>"
    }

    return @"
<Set operation="$Operation">
  <POPIMAPScanningPolicy>
    <Name>$nameEsc</Name>
    $afterXml
    <EmailAddress>
      <SenderEmail>$(ConvertTo-SfosXmlEscaped -Text $SenderEmail)</SenderEmail>
      <SenderAction>$(ConvertTo-SfosXmlEscaped -Text $SenderAction)</SenderAction>
      <RecipientEmail>$(ConvertTo-SfosXmlEscaped -Text $RecipientEmail)</RecipientEmail>
      <RecipientAction>$(ConvertTo-SfosXmlEscaped -Text $RecipientAction)</RecipientAction>
    </EmailAddress>
    <FilterCriteria>$(ConvertTo-SfosXmlEscaped -Text $FilterCriteria)</FilterCriteria>
    $addressXml
    $messageSizeOperatorXml
    $messageSizeXml
    <Action>$(ConvertTo-SfosXmlEscaped -Text $Action)</Action>
    $toXml
    $headerStringXml
    $headerOperatorXml
    $matchIsXml
  </POPIMAPScanningPolicy>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves POP/IMAP scanning policy rules from a Sophos Firewall.

.DESCRIPTION
    Returns POPIMAPScanningPolicy objects (PROTECT > Email > Protection, POP/IMAP
    scanning rules). This root is shared between the legacy Email area and the MTA-based
    Email(MTA) area - measured identical on both, same storage, same call - so a write
    here can affect whichever mode is active.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER NameLike
    Optional. Returns only rules whose name contains the given text anywhere. Sent to the
    firewall as a server-side pre-filter (Name/like) and re-applied client-side. If
    omitted, every rule is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per rule, with the properties
    Name, After, SenderEmail, SenderAction, RecipientEmail, RecipientAction,
    FilterCriteria, Address (string array), MessageSizeOperator, MessageSize, Action, To,
    MessageHeaderString, MessageHeaderOperator and MatchIs. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no rule matches.

.EXAMPLE
    Get-SfosPOPIMAPScanningPolicy

    Lists every POP/IMAP scanning rule.

.EXAMPLE
    Get-SfosPOPIMAPScanningPolicy -NameLike 'Outbreak'

    Lists rules whose name contains 'Outbreak'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/popimaprule/popimaprule.html

.LINK
    New-SfosPOPIMAPScanningPolicy
#>
function Get-SfosPOPIMAPScanningPolicy {
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

    $inner = "<Get><POPIMAPScanningPolicy>$filterXml</POPIMAPScanningPolicy></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving POPIMAPScanningPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'POPIMAPScanningPolicy' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/POPIMAPScanningPolicy[Name]' | ForEach-Object -Process { $_.Node }

    $ruleObjects = foreach ($node in @($nodes)) {
        $messageSize = $null
        if ([string]$node.MessageSize) {
            $messageSize = [int]$node.MessageSize
        }
        [PSCustomObject]@{
            Name                  = [string]$node.Name
            After                 = [string]$node.After.Name
            SenderEmail           = [string]$node.EmailAddress.SenderEmail
            SenderAction          = [string]$node.EmailAddress.SenderAction
            RecipientEmail        = [string]$node.EmailAddress.RecipientEmail
            RecipientAction       = [string]$node.EmailAddress.RecipientAction
            FilterCriteria        = [string]$node.FilterCriteria
            Address               = @($node.Address | Where-Object -FilterScript { $null -ne $_ })
            MessageSizeOperator   = [string]$node.MessageSizeOperator
            MessageSize           = $messageSize
            Action                = [string]$node.Action
            To                    = [string]$node.To
            MessageHeaderString   = [string]$node.MessageHeaderString
            MessageHeaderOperator = [string]$node.MessageHeaderOperator
            MatchIs               = [string]$node.MatchIs
        }
    }

    $ruleObjects = @($ruleObjects)
    if ($NameLike) {
        $ruleObjects = @($ruleObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($ruleObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $ruleObjects
}

<#
.SYNOPSIS
    Creates a POP/IMAP scanning policy rule on a Sophos Firewall.

.DESCRIPTION
    Creates a POPIMAPScanningPolicy object (PROTECT > Email > Protection, POP/IMAP
    scanning rules). Confirmed against a live firewall: the create, a no-op update round
    trip (read, write back unchanged, read again, compare raw XML - identical), and
    removal all work.

    This root is shared with the MTA-based Email(MTA) area (same storage, same call), so
    a rule created here is also visible and effective there.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER Name
    Required. Name of the rule. Maximum 255 characters.

.PARAMETER After
    Optional. Name of the existing rule this one is ordered after.

.PARAMETER SenderEmail
    Optional. Sender email address to match, or 'Any'. If omitted, 'Any' is used.

.PARAMETER SenderAction
    Optional. Contains or Equals. If omitted, 'Contains' is used.

.PARAMETER RecipientEmail
    Optional. Recipient email address to match, or 'Any'. If omitted, 'Any' is used.

.PARAMETER RecipientAction
    Optional. Contains or Equals. If omitted, 'Contains' is used.

.PARAMETER FilterCriteria
    Required. What the rule filters on. Only 'InboundEmailIs' was confirmed against a
    live firewall; the documented alternatives (source IP/network, message size, message
    header, none) are passed through unvalidated.

.PARAMETER Address
    Optional. Source IP/network addresses, used when -FilterCriteria selects that mode.

.PARAMETER MessageSizeOperator
    Optional. GreaterThan or LessThan, used when -FilterCriteria selects message size.

.PARAMETER MessageSize
    Optional. Message size threshold, used when -FilterCriteria selects message size.

.PARAMETER Action
    Required. Action taken for matching mail: Accept or 'Prefix Subject'.

.PARAMETER To
    Optional. Text prefixed to the subject when -Action is 'Prefix Subject'. Maximum 300
    characters.

.PARAMETER MessageHeaderString
    Optional. Message header name, used when -FilterCriteria selects message header.
    Maximum 765 characters.

.PARAMETER MessageHeaderOperator
    Optional. Contains or Equals, used when -FilterCriteria selects message header.

.PARAMETER MatchIs
    Optional. The value matched for the selected -FilterCriteria. Maximum 750
    characters.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosPOPIMAPScanningPolicy -Name 'OutbreakSubject' -FilterCriteria InboundEmailIs -Action 'Prefix Subject' -To 'Virus Outbreak:' -MatchIs 'Virus Outbreak' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosPOPIMAPScanningPolicy -Name 'OutbreakSubject' -FilterCriteria InboundEmailIs -Action 'Prefix Subject' -To 'Virus Outbreak:' -MatchIs 'Virus Outbreak'

    Creates a rule that prefixes the subject of inbound mail flagged as a virus outbreak.
    The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/popimaprule/operations/AddPOP-IMAPScanningPolicy%26EditPOP-IMAPScanningPolicy.html

.LINK
    Get-SfosPOPIMAPScanningPolicy
#>
function New-SfosPOPIMAPScanningPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$Name,

        [string]$After,

        [string]$SenderEmail = 'Any',
        [ValidateSet('Contains', 'Equals')]
        [string]$SenderAction = 'Contains',
        [string]$RecipientEmail = 'Any',
        [ValidateSet('Contains', 'Equals')]
        [string]$RecipientAction = 'Contains',

        [Parameter(Mandatory)]
        [string]$FilterCriteria,

        [string[]]$Address,
        [ValidateSet('GreaterThan', 'LessThan')]
        [string]$MessageSizeOperator,
        [Nullable[int]]$MessageSize,

        [Parameter(Mandatory)]
        [ValidateSet('Accept', 'Prefix Subject')]
        [string]$Action,

        [ValidateLength(0, 300)]
        [string]$To,
        [ValidateLength(0, 765)]
        [string]$MessageHeaderString,
        [ValidateSet('Contains', 'Equals')]
        [string]$MessageHeaderOperator,
        [ValidateLength(0, 750)]
        [string]$MatchIs,

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
        if (-not $PSCmdlet.ShouldProcess("POPIMAPScanningPolicy '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosPOPIMAPScanningPolicyEntityXml -Operation 'add' -Name $Name -After $After `
            -SenderEmail $SenderEmail -SenderAction $SenderAction -RecipientEmail $RecipientEmail -RecipientAction $RecipientAction `
            -FilterCriteria $FilterCriteria -Address $Address -MessageSizeOperator $MessageSizeOperator -MessageSize $MessageSize `
            -Action $Action -To $To -MessageHeaderString $MessageHeaderString -MessageHeaderOperator $MessageHeaderOperator -MatchIs $MatchIs

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create POPIMAPScanningPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'POPIMAPScanningPolicy' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a POP/IMAP scanning policy rule on a Sophos Firewall.

.DESCRIPTION
    Reads the named POPIMAPScanningPolicy object first and writes back a complete
    entity, overriding only the fields you pass - this is a full-replace entity, so
    anything not read back and resent would be cleared. Confirmed against a live
    firewall with an unchanged round trip (read, write back, read again, compare raw
    XML - identical).

    -FilterCriteria is always required on this cmdlet, even when you only change an
    unrelated field, because it is the discriminator for which of the type-specific
    fields (Address, MessageSizeOperator/MessageSize, MessageHeaderString/
    MessageHeaderOperator) apply; requiring it on every call keeps this cmdlet safe to
    use from a pipeline.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER Name
    Required. Name of the existing rule to update.

.PARAMETER After
    Optional. Name of the existing rule this one is ordered after, replacing the current
    value. If omitted, the current value is kept.

.PARAMETER SenderEmail
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER SenderAction
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER RecipientEmail
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER RecipientAction
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER FilterCriteria
    Required. What the rule filters on - see the description.

.PARAMETER Address
    Optional. Replacing the current list. If omitted, the current list is kept.

.PARAMETER MessageSizeOperator
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER MessageSize
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER Action
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER To
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER MessageHeaderString
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER MessageHeaderOperator
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER MatchIs
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosPOPIMAPScanningPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update or if the named rule does not exist.

.EXAMPLE
    Set-SfosPOPIMAPScanningPolicy -Name 'OutbreakSubject' -FilterCriteria InboundEmailIs -To 'Outbreak detected:' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosPOPIMAPScanningPolicy -Name 'OutbreakSubject' -FilterCriteria InboundEmailIs -To 'Outbreak detected:'

    Changes the subject prefix text. Every other field is kept unchanged. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/popimaprule/operations/AddPOP-IMAPScanningPolicy%26EditPOP-IMAPScanningPolicy.html

.LINK
    Get-SfosPOPIMAPScanningPolicy
#>
function Set-SfosPOPIMAPScanningPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [string]$Name,

        [string]$After,
        [string]$SenderEmail,
        [ValidateSet('Contains', 'Equals')]
        [string]$SenderAction,
        [string]$RecipientEmail,
        [ValidateSet('Contains', 'Equals')]
        [string]$RecipientAction,

        [Parameter(Mandatory)]
        [string]$FilterCriteria,

        [string[]]$Address,
        [ValidateSet('GreaterThan', 'LessThan')]
        [string]$MessageSizeOperator,
        [Nullable[int]]$MessageSize,

        [ValidateSet('Accept', 'Prefix Subject')]
        [string]$Action,

        [ValidateLength(0, 300)]
        [string]$To,
        [ValidateLength(0, 765)]
        [string]$MessageHeaderString,
        [ValidateSet('Contains', 'Equals')]
        [string]$MessageHeaderOperator,
        [ValidateLength(0, 750)]
        [string]$MatchIs,

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
        $existing = @(Get-SfosPOPIMAPScanningPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The POPIMAPScanningPolicy object '$Name' was not found."
        }
        $current = $existing[0]

        if (-not $PSCmdlet.ShouldProcess("POPIMAPScanningPolicy '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $bp = $PSBoundParameters
        $targetAfter = if ($bp.ContainsKey('After')) { $After } else { $current.After }
        $targetSenderEmail = if ($bp.ContainsKey('SenderEmail')) { $SenderEmail } else { $current.SenderEmail }
        $targetSenderAction = if ($bp.ContainsKey('SenderAction')) { $SenderAction } else { $current.SenderAction }
        $targetRecipientEmail = if ($bp.ContainsKey('RecipientEmail')) { $RecipientEmail } else { $current.RecipientEmail }
        $targetRecipientAction = if ($bp.ContainsKey('RecipientAction')) { $RecipientAction } else { $current.RecipientAction }
        $targetAddress = @(if ($bp.ContainsKey('Address')) { $Address } else { $current.Address })
        $targetMsgSizeOp = if ($bp.ContainsKey('MessageSizeOperator')) { $MessageSizeOperator } else { $current.MessageSizeOperator }
        $targetMsgSize = if ($bp.ContainsKey('MessageSize')) { $MessageSize } else { $current.MessageSize }
        $targetAction = if ($bp.ContainsKey('Action')) { $Action } else { $current.Action }
        $targetTo = if ($bp.ContainsKey('To')) { $To } else { $current.To }
        $targetHeaderString = if ($bp.ContainsKey('MessageHeaderString')) { $MessageHeaderString } else { $current.MessageHeaderString }
        $targetHeaderOperator = if ($bp.ContainsKey('MessageHeaderOperator')) { $MessageHeaderOperator } else { $current.MessageHeaderOperator }
        $targetMatchIs = if ($bp.ContainsKey('MatchIs')) { $MatchIs } else { $current.MatchIs }

        $inner = ConvertTo-SfosPOPIMAPScanningPolicyEntityXml -Operation 'update' -Name $Name -After $targetAfter `
            -SenderEmail $targetSenderEmail -SenderAction $targetSenderAction -RecipientEmail $targetRecipientEmail -RecipientAction $targetRecipientAction `
            -FilterCriteria $FilterCriteria -Address $targetAddress -MessageSizeOperator $targetMsgSizeOp -MessageSize $targetMsgSize `
            -Action $targetAction -To $targetTo -MessageHeaderString $targetHeaderString -MessageHeaderOperator $targetHeaderOperator -MatchIs $targetMatchIs

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update POPIMAPScanningPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'POPIMAPScanningPolicy' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a POP/IMAP scanning policy rule from a Sophos Firewall.

.DESCRIPTION
    Removes a POPIMAPScanningPolicy object. Measured against a live firewall: removing a
    name that does not exist is correctly reported as a failure (a status without a
    'code' attribute and a non-"No. of records Zero." message, which
    Assert-SfosApiReturnSuccess already treats as an error) - unlike some other entities
    in this module family, this one does not falsely report success. This cmdlet still
    reads the object first, so the error names the object clearly before any request is
    sent.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER Name
    Required. Name of the rule to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosPOPIMAPScanningPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named rule does not exist.

.EXAMPLE
    Remove-SfosPOPIMAPScanningPolicy -Name 'OutbreakSubject' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosPOPIMAPScanningPolicy -Name 'OutbreakSubject'

    Removes the named rule. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/popimaprule/operations/Delete%20POP-IMAP%20Scanning%20Policy.html

.LINK
    Get-SfosPOPIMAPScanningPolicy
#>
function Remove-SfosPOPIMAPScanningPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
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
        $existing = @(Get-SfosPOPIMAPScanningPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The POPIMAPScanningPolicy object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("POPIMAPScanningPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><POPIMAPScanningPolicy><Name>$nameEsc</Name></POPIMAPScanningPolicy></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove POPIMAPScanningPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'POPIMAPScanningPolicy' -Action 'remove' -Target $Name
    }
}

#endregion

#region MailMalwareProtection

<#
.SYNOPSIS
    Retrieves the mail malware protection engine setting of a Sophos Firewall.

.DESCRIPTION
    Returns the MalwareProtection singleton (PROTECT > Email > Protection). It holds a
    single field, the primary anti-virus engine. This root is shared between the legacy
    Email area and the MTA-based Email(MTA) area - measured identical on both, same
    storage, same call - so a write here affects whichever mode is active.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the single property
    PrimaryAntiVirusEngine. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosMailMalwareProtection

    Shows the current primary anti-virus engine.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/malwareprotection/malwareprotection.html

.LINK
    Set-SfosMailMalwareProtection
#>
function Get-SfosMailMalwareProtection {
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

    $inner = '<Get><MalwareProtection></MalwareProtection></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MalwareProtection: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MalwareProtection' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/MalwareProtection')
    if (-not $node) {
        throw 'MalwareProtection could not be retrieved from the firewall.'
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
    Sets the mail malware protection engine of a Sophos Firewall.

.DESCRIPTION
    Updates the MalwareProtection singleton. Confirmed against a live firewall with a
    no-op update (current value re-sent unchanged, status 200, value re-read
    identical). This root is shared between the legacy Email area and the MTA-based
    Email(MTA) area, so this write affects whichever mode is active.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER PrimaryAntiVirusEngine
    Optional. Sophos or Avira. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosMailMalwareProtection -PrimaryAntiVirusEngine Sophos -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMailMalwareProtection -PrimaryAntiVirusEngine Sophos

    Sets the primary anti-virus engine to Sophos. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/malwareprotection/operations/UpdateMalwareProtection.html

.LINK
    Get-SfosMailMalwareProtection
#>
function Set-SfosMailMalwareProtection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Sophos', 'Avira')]
        [string]$PrimaryAntiVirusEngine,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosMailMalwareProtection -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $target = if ($PSBoundParameters.ContainsKey('PrimaryAntiVirusEngine')) { $PrimaryAntiVirusEngine } else { $existing.PrimaryAntiVirusEngine }

    if (-not $PSCmdlet.ShouldProcess("MalwareProtection on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = "<Set operation=`"update`"><MalwareProtection><PrimaryAntiVirusEngine>$(ConvertTo-SfosXmlEscaped -Text $target)</PrimaryAntiVirusEngine></MalwareProtection></Set>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to update MalwareProtection: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MalwareProtection' -Action 'update'
}

#endregion

#region EmailConfiguration

<#
.SYNOPSIS
    Retrieves the email scanning configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the EmailConfiguration singleton (PROTECT > Email > Protection > General
    Configuration). This root is shared between the legacy Email area and the MTA-based
    Email(MTA) area - measured identical on both, same storage, same call - so a write
    here affects whichever mode is active.

    Only the fields actually observed on a live firewall are exposed. The vendor sample
    for this operation also lists EmailBannerMode (banner insertion mode) and, inside
    SMTPSSettings, ConfirmSpamAction, ProbableSpamAction, MaximumConnections,
    MaximumConnectionsHost, MaximumEmailsConnection, MaximumRecepientsEmail, EmailsRate
    and ConnectionsRate, and inside SMTPTLSConfiguration RequireTLSWithHost,
    RequireTLSWithSenderDomain and SkipTLSHosts - none of these appeared in a live Get on
    this appliance, so none of them is read, written or preserved here; a Set-* that
    silently dropped a field it never saw would violate the read-modify-write contract
    this module relies on everywhere else.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML element instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the properties EmailSignature,
    SMTPHostName, SMTPDontScanEmailsGreaterThan, ActionForOversizeEmails,
    BypassSpamCheck, VerifySendersIPReputation, SMTPSDosSettings,
    POPIMAPDontScanEmailsGreaterThan, RecipientHeaders (string array),
    SMTPTLSCertificate, SMTPAllowInvalidCertificate, SMTPDisableTLS1,
    POPIMAPTLSCertificate, POPIMAPAllowInvalidCertificate and POPIMAPDisableTLS1.
    Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosEmailConfiguration

    Shows the current email scanning configuration.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/AntiVirusConfiguration/AntiVirusConfiguration.html

.LINK
    Set-SfosEmailConfiguration
#>
function Get-SfosEmailConfiguration {
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

    $inner = '<Get><EmailConfiguration></EmailConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving EmailConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EmailConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/EmailConfiguration')
    if (-not $node) {
        throw 'EmailConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $recipientHeaders = @()
    if ($node.POPIMAPSettings.RecipientHeaders) {
        $recipientHeaders = @($node.POPIMAPSettings.RecipientHeaders.Header)
    }

    return [PSCustomObject]@{
        EmailSignature                   = [string]$node.GeneralSettings.EmailSignature
        SMTPHostName                     = [string]$node.SMTPSSettings.smtphostname
        SMTPDontScanEmailsGreaterThan     = [string]$node.SMTPSSettings.DontScanEmailsGreaterThan
        ActionForOversizeEmails          = [string]$node.SMTPSSettings.ActionForOversizeEmails
        BypassSpamCheck                  = [string]$node.SMTPSSettings.BypassSpamCheck
        VerifySendersIPReputation        = [string]$node.SMTPSSettings.VerifySendersIPReputation
        SMTPSDosSettings                 = [string]$node.SMTPSSettings.SMTPSDosSettings
        POPIMAPDontScanEmailsGreaterThan = [string]$node.POPIMAPSettings.DontScanEmailsGreaterThan
        RecipientHeaders                 = [string[]]$recipientHeaders
        SMTPTLSCertificate                = [string]$node.SMTPTLSConfiguration.TLSCertificate
        SMTPAllowInvalidCertificate       = [string]$node.SMTPTLSConfiguration.AllowInvalidCertificate
        SMTPDisableTLS1                   = [string]$node.SMTPTLSConfiguration.DisableTLS1
        POPIMAPTLSCertificate             = [string]$node.POPSIMAPTLSConfiguration.TLSCertificate
        POPIMAPAllowInvalidCertificate    = [string]$node.POPSIMAPTLSConfiguration.AllowInvalidCertificate
        POPIMAPDisableTLS1                = [string]$node.POPSIMAPTLSConfiguration.DisableTLS1
    }
}

<#
.SYNOPSIS
    Updates the email scanning configuration of a Sophos Firewall.

.DESCRIPTION
    Reads the current EmailConfiguration first and writes back a complete entity down
    into every sub-tree (GeneralSettings, SMTPSSettings, POPIMAPSettings/
    RecipientHeaders, SMTPTLSConfiguration, POPSIMAPTLSConfiguration), overriding only
    the fields you pass - this is a full-replace singleton, so anything not read back
    and resent would be cleared. Confirmed against a live firewall with a full
    unchanged round trip (every current value re-sent unchanged, status 200, re-read
    identical to the pre-change baseline, byte for byte after normalising whitespace).

    See Get-SfosEmailConfiguration for the fields the vendor sample documents but this
    appliance never returned; those are not covered by this cmdlet and are therefore
    left untouched by every call.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. This
    root is shared between the legacy Email area and the MTA-based Email(MTA) area, so
    a write here affects whichever mode is active.

    This object is shared by both shapes of the email area: the same storage answers in
    MTA mode and in legacy mail scanning, so it behaves the same either way.

.PARAMETER EmailSignature
    Optional. Signature text appended to outgoing mail, replacing the current value. If
    omitted, the current value is kept. Maximum 2000 characters.

.PARAMETER SMTPHostName
    Optional. SMTP host name, replacing the current value. If omitted, the current
    value is kept. Maximum 255 characters.

.PARAMETER SMTPDontScanEmailsGreaterThan
    Optional. Maximum SMTP message size in KB to scan, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER ActionForOversizeEmails
    Optional. Accept, Reject or Drop, replacing the current value. If omitted, the
    current value is kept.

.PARAMETER BypassSpamCheck
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER VerifySendersIPReputation
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER SMTPSDosSettings
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER POPIMAPDontScanEmailsGreaterThan
    Optional. Maximum POP3/IMAP message size in KB to scan, replacing the current
    value. If omitted, the current value is kept.

.PARAMETER RecipientHeaders
    Optional. Header names used to detect the recipient for POP3/IMAP, replacing the
    current list. If omitted, the current list is kept.

.PARAMETER SMTPTLSCertificate
    Optional. Certificate used for SMTP TLS, replacing the current value. If omitted,
    the current value is kept.

.PARAMETER SMTPAllowInvalidCertificate
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER SMTPDisableTLS1
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER POPIMAPTLSCertificate
    Optional. Certificate used for POP/IMAP TLS, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER POPIMAPAllowInvalidCertificate
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER POPIMAPDisableTLS1
    Optional. Enable or Disable, replacing the current value. If omitted, the current
    value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosEmailConfiguration -EmailSignature 'Sent from example.com' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosEmailConfiguration -EmailSignature 'Sent from example.com'

    Sets the outgoing mail signature. Every other field, in every sub-tree, is kept
    unchanged. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/AntiVirusConfiguration/operations/EmailConfiguration.html

.LINK
    Get-SfosEmailConfiguration
#>
function Set-SfosEmailConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateLength(0, 2000)]
        [string]$EmailSignature,
        [ValidateLength(0, 255)]
        [string]$SMTPHostName,
        [string]$SMTPDontScanEmailsGreaterThan,
        [ValidateSet('Accept', 'Reject', 'Drop')]
        [string]$ActionForOversizeEmails,
        [ValidateSet('Enable', 'Disable')]
        [string]$BypassSpamCheck,
        [ValidateSet('Enable', 'Disable')]
        [string]$VerifySendersIPReputation,
        [ValidateSet('Enable', 'Disable')]
        [string]$SMTPSDosSettings,

        [string]$POPIMAPDontScanEmailsGreaterThan,
        [string[]]$RecipientHeaders,

        [string]$SMTPTLSCertificate,
        [ValidateSet('Enable', 'Disable')]
        [string]$SMTPAllowInvalidCertificate,
        [ValidateSet('Enable', 'Disable')]
        [string]$SMTPDisableTLS1,

        [string]$POPIMAPTLSCertificate,
        [ValidateSet('Enable', 'Disable')]
        [string]$POPIMAPAllowInvalidCertificate,
        [ValidateSet('Enable', 'Disable')]
        [string]$POPIMAPDisableTLS1,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosEmailConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetSignature = if ($bp.ContainsKey('EmailSignature')) { $EmailSignature } else { $existing.EmailSignature }
    $targetHostName = if ($bp.ContainsKey('SMTPHostName')) { $SMTPHostName } else { $existing.SMTPHostName }
    $targetSmtpDontScan = if ($bp.ContainsKey('SMTPDontScanEmailsGreaterThan')) { $SMTPDontScanEmailsGreaterThan } else { $existing.SMTPDontScanEmailsGreaterThan }
    $targetOversize = if ($bp.ContainsKey('ActionForOversizeEmails')) { $ActionForOversizeEmails } else { $existing.ActionForOversizeEmails }
    $targetBypassSpam = if ($bp.ContainsKey('BypassSpamCheck')) { $BypassSpamCheck } else { $existing.BypassSpamCheck }
    $targetVerifyRep = if ($bp.ContainsKey('VerifySendersIPReputation')) { $VerifySendersIPReputation } else { $existing.VerifySendersIPReputation }
    $targetDos = if ($bp.ContainsKey('SMTPSDosSettings')) { $SMTPSDosSettings } else { $existing.SMTPSDosSettings }
    $targetPopDontScan = if ($bp.ContainsKey('POPIMAPDontScanEmailsGreaterThan')) { $POPIMAPDontScanEmailsGreaterThan } else { $existing.POPIMAPDontScanEmailsGreaterThan }
    $targetHeaders = @(if ($bp.ContainsKey('RecipientHeaders')) { $RecipientHeaders } else { $existing.RecipientHeaders })
    $targetSmtpTlsCert = if ($bp.ContainsKey('SMTPTLSCertificate')) { $SMTPTLSCertificate } else { $existing.SMTPTLSCertificate }
    $targetSmtpAllowInvalid = if ($bp.ContainsKey('SMTPAllowInvalidCertificate')) { $SMTPAllowInvalidCertificate } else { $existing.SMTPAllowInvalidCertificate }
    $targetSmtpDisableTls1 = if ($bp.ContainsKey('SMTPDisableTLS1')) { $SMTPDisableTLS1 } else { $existing.SMTPDisableTLS1 }
    $targetPopTlsCert = if ($bp.ContainsKey('POPIMAPTLSCertificate')) { $POPIMAPTLSCertificate } else { $existing.POPIMAPTLSCertificate }
    $targetPopAllowInvalid = if ($bp.ContainsKey('POPIMAPAllowInvalidCertificate')) { $POPIMAPAllowInvalidCertificate } else { $existing.POPIMAPAllowInvalidCertificate }
    $targetPopDisableTls1 = if ($bp.ContainsKey('POPIMAPDisableTLS1')) { $POPIMAPDisableTLS1 } else { $existing.POPIMAPDisableTLS1 }

    if (-not $PSCmdlet.ShouldProcess("EmailConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    $headersXml = ''
    foreach ($header in $targetHeaders) {
        if (-not $header) { continue }
        $headersXml += "<Header>$(ConvertTo-SfosXmlEscaped -Text $header)</Header>"
    }

    $inner = @"
<Set operation="update">
  <EmailConfiguration>
    <GeneralSettings>
      <EmailSignature>$(ConvertTo-SfosXmlEscaped -Text $targetSignature)</EmailSignature>
    </GeneralSettings>
    <SMTPSSettings>
      <smtphostname>$(ConvertTo-SfosXmlEscaped -Text $targetHostName)</smtphostname>
      <DontScanEmailsGreaterThan>$(ConvertTo-SfosXmlEscaped -Text $targetSmtpDontScan)</DontScanEmailsGreaterThan>
      <ActionForOversizeEmails>$(ConvertTo-SfosXmlEscaped -Text $targetOversize)</ActionForOversizeEmails>
      <BypassSpamCheck>$(ConvertTo-SfosXmlEscaped -Text $targetBypassSpam)</BypassSpamCheck>
      <VerifySendersIPReputation>$(ConvertTo-SfosXmlEscaped -Text $targetVerifyRep)</VerifySendersIPReputation>
      <SMTPSDosSettings>$(ConvertTo-SfosXmlEscaped -Text $targetDos)</SMTPSDosSettings>
    </SMTPSSettings>
    <POPIMAPSettings>
      <DontScanEmailsGreaterThan>$(ConvertTo-SfosXmlEscaped -Text $targetPopDontScan)</DontScanEmailsGreaterThan>
      <RecipientHeaders>$headersXml</RecipientHeaders>
    </POPIMAPSettings>
    <SMTPTLSConfiguration>
      <TLSCertificate>$(ConvertTo-SfosXmlEscaped -Text $targetSmtpTlsCert)</TLSCertificate>
      <AllowInvalidCertificate>$(ConvertTo-SfosXmlEscaped -Text $targetSmtpAllowInvalid)</AllowInvalidCertificate>
      <DisableTLS1>$(ConvertTo-SfosXmlEscaped -Text $targetSmtpDisableTls1)</DisableTLS1>
    </SMTPTLSConfiguration>
    <POPSIMAPTLSConfiguration>
      <TLSCertificate>$(ConvertTo-SfosXmlEscaped -Text $targetPopTlsCert)</TLSCertificate>
      <AllowInvalidCertificate>$(ConvertTo-SfosXmlEscaped -Text $targetPopAllowInvalid)</AllowInvalidCertificate>
      <DisableTLS1>$(ConvertTo-SfosXmlEscaped -Text $targetPopDisableTls1)</DisableTLS1>
    </POPSIMAPTLSConfiguration>
  </EmailConfiguration>
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
        throw "Failed to update EmailConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'EmailConfiguration' -Action 'update'
}

#endregion

#region MTAAddressGroup

<#
.SYNOPSIS
    Builds the Set request body for an MTAAddressGroup entity. Internal helper, not
    exported.

.DESCRIPTION
    Shared by New-SfosMTAAddressGroup and Set-SfosMTAAddressGroup so both send the same
    entity shape. Measured against a live firewall: exactly one of RBLList/RBLName,
    IPAddressList/IPAddressNetwork or EmailAddressList/EmailAddressDomain is sent,
    selected by -GroupType. EmailImportType is only meaningful, and only emitted, when
    -GroupType is EmailAddressOrDomain. Every value is escaped through
    ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the address group.

.PARAMETER GroupType
    RBLIPv4, RBLIPv6, IPAddress or EmailAddressOrDomain. Selects which member list is
    built.

.PARAMETER Member
    The RBL names, IP addresses/networks or email addresses/domains for -GroupType,
    depending on which one was selected.

.PARAMETER Description
    Optional. Free-text description.

.PARAMETER EmailImportType
    Optional. Import or Manual. Only sent when -GroupType is EmailAddressOrDomain.
#>
function ConvertTo-SfosMTAAddressGroupEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RBLIPv4', 'RBLIPv6', 'IPAddress', 'EmailAddressOrDomain')]
        [string]$GroupType,

        [string[]]$Member,

        [string]$Description,

        [string]$EmailImportType
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $groupTypeEsc = ConvertTo-SfosXmlEscaped -Text $GroupType

    $descriptionXml = ''
    if ($Description) {
        $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $memberValues = @($Member | Where-Object -FilterScript { $_ })

    $importTypeXml = ''
    $memberXml = ''
    if ($GroupType -eq 'RBLIPv4' -or $GroupType -eq 'RBLIPv6') {
        $items = ($memberValues | ForEach-Object -Process { "<RBLName>$(ConvertTo-SfosXmlEscaped -Text $_)</RBLName>" }) -join ''
        $memberXml = "<RBLList>$items</RBLList>"
    }
    elseif ($GroupType -eq 'IPAddress') {
        $items = ($memberValues | ForEach-Object -Process { "<IPAddressNetwork>$(ConvertTo-SfosXmlEscaped -Text $_)</IPAddressNetwork>" }) -join ''
        $memberXml = "<IPAddressList>$items</IPAddressList>"
    }
    else {
        $items = ($memberValues | ForEach-Object -Process { "<EmailAddressDomain>$(ConvertTo-SfosXmlEscaped -Text $_)</EmailAddressDomain>" }) -join ''
        $memberXml = "<EmailAddressList>$items</EmailAddressList>"
        if ($EmailImportType) {
            $importTypeXml = "<EmailImportType>$(ConvertTo-SfosXmlEscaped -Text $EmailImportType)</EmailImportType>"
        }
    }

    return @"
<Set operation="$Operation">
  <MTAAddressGroup>
    <Name>$nameEsc</Name>
    <GroupType>$groupTypeEsc</GroupType>
    $descriptionXml
    $importTypeXml
    $memberXml
  </MTAAddressGroup>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves MTA Address Group objects from a Sophos Firewall.

.DESCRIPTION
    Returns MTAAddressGroup objects (PROTECT > Email (MTA) > MTA Address Group). An
    address group bundles RBL server names, IP addresses/networks or email
    addresses/domains for use in Anti Spam scanning rules while MTA mode is enabled.

    Measured against a live firewall: this root has its own storage, separate from the
    legacy AVASAddressGroup root, even though both currently ship the same two default
    RBL groups ("Premium RBL Services", "Standard RBL Services") - a group created
    through one root is not visible through the other. GroupType was measured to accept
    RBLIPv4 (the two built-in groups) and, in a create/read round trip, IPAddress and
    EmailAddressOrDomain; RBLIPv6 is documented but was not exercised against a live
    firewall.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

.PARAMETER NameLike
    Optional. Returns only groups whose name contains the given text anywhere. Sent to
    the firewall as a server-side pre-filter (Name/like, measured to work for this
    entity) and re-applied client-side. If omitted, every group is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per group, with the
    properties Name, GroupType, Description, EmailImportType and Member - a single
    string array holding whichever of RBLName, IPAddressNetwork or EmailAddressDomain
    applies to GroupType. Returns System.Xml.XmlElement when -AsXml is used, and an
    empty array when no group matches.

.EXAMPLE
    Get-SfosMTAAddressGroup

    Lists every MTA address group, including the two built-in RBL groups.

.EXAMPLE
    Get-SfosMTAAddressGroup -NameLike 'RBL'

    Lists all groups whose name contains 'RBL'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaaddressgroup/mtaaddressgroup.html

.LINK
    New-SfosMTAAddressGroup
#>
function Get-SfosMTAAddressGroup {
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

    $inner = "<Get><MTAAddressGroup>$filterXml</MTAAddressGroup></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MTAAddressGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTAAddressGroup' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/MTAAddressGroup[Name]' | ForEach-Object -Process { $_.Node }

    $groupObjects = foreach ($node in @($nodes)) {
        $groupType = [string]$node.GroupType
        $member = @()
        if ($groupType -eq 'RBLIPv4' -or $groupType -eq 'RBLIPv6') {
            $member = @($node.RBLList.RBLName | Where-Object -FilterScript { $null -ne $_ })
        }
        elseif ($groupType -eq 'IPAddress') {
            $member = @($node.IPAddressList.IPAddressNetwork | Where-Object -FilterScript { $null -ne $_ })
        }
        elseif ($groupType -eq 'EmailAddressOrDomain') {
            $member = @($node.EmailAddressList.EmailAddressDomain | Where-Object -FilterScript { $null -ne $_ })
        }

        [PSCustomObject]@{
            Name            = [string]$node.Name
            GroupType       = $groupType
            Description     = [string]$node.Description
            EmailImportType = [string]$node.EmailImportType
            Member          = $member
        }
    }

    $groupObjects = @($groupObjects)
    if ($NameLike) {
        $groupObjects = @($groupObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($groupObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $groupObjects
}

<#
.SYNOPSIS
    Creates an MTA Address Group on a Sophos Firewall.

.DESCRIPTION
    Creates an MTAAddressGroup object (PROTECT > Email (MTA) > MTA Address Group).
    Measured against a live firewall for all three GroupType values exercised
    (RBLIPv4, IPAddress, EmailAddressOrDomain): create, a no-op update round trip
    (read, write back unchanged, read again, compare raw XML - identical) and removal
    all work.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the group. Maximum 50 characters.

.PARAMETER GroupType
    Required. RBLIPv4, RBLIPv6, IPAddress or EmailAddressOrDomain. Selects which kind
    of -Member values are expected. RBLIPv6 is documented but was not exercised against
    a live firewall.

.PARAMETER Member
    Required. One or more RBL server names (RBLIPv4/RBLIPv6), IP addresses/networks
    (IPAddress) or email addresses/domains (EmailAddressOrDomain), matching -GroupType.

.PARAMETER Description
    Optional. Free-text description. Maximum 255 characters.

.PARAMETER EmailImportType
    Optional. Import or Manual. Only meaningful when -GroupType is
    EmailAddressOrDomain. If omitted while -GroupType is EmailAddressOrDomain,
    'Manual' is used. File-based import (EmailAddressFile) is documented but not
    implemented by this cmdlet.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosMTAAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Member 'example.com' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosMTAAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Member 'example.com'

    Creates an address group matching one email domain. The cmdlet asks for
    confirmation before it writes.

.EXAMPLE
    New-SfosMTAAddressGroup -Name 'TrustedNetworks' -GroupType IPAddress -Member '192.0.2.0/24'

    Creates an address group matching one IP network.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaaddressgroup/operations/AddAddressGroup%26EditAddressGroup.html

.LINK
    Get-SfosMTAAddressGroup
#>
function New-SfosMTAAddressGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RBLIPv4', 'RBLIPv6', 'IPAddress', 'EmailAddressOrDomain')]
        [string]$GroupType,

        [Parameter(Mandatory)]
        [string[]]$Member,

        [string]$Description,

        [ValidateSet('Import', 'Manual')]
        [string]$EmailImportType = 'Manual',

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
        if (-not @($Member | Where-Object -FilterScript { $_ }).Count) {
            throw "MTAAddressGroup object '$Name' needs at least one -Member value."
        }

        if (-not $PSCmdlet.ShouldProcess("MTAAddressGroup '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosMTAAddressGroupEntityXml -Operation 'add' -Name $Name -GroupType $GroupType `
            -Member $Member -Description $Description -EmailImportType $EmailImportType

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create MTAAddressGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTAAddressGroup' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an MTA Address Group on a Sophos Firewall.

.DESCRIPTION
    Reads the named MTAAddressGroup object first and writes back a complete entity,
    overriding only the fields you pass - this is a full-replace entity, so anything not
    read back and resent would be cleared. Confirmed against a live firewall with an
    unchanged round trip (read, write back unchanged, read again, compare raw XML -
    identical).

    -GroupType is mandatory even on an update, per the project rule against mixing
    parameter sets with pipeline input. If it matches the object's current GroupType,
    -Member may be omitted and the current member list is kept. If it differs (changing
    the kind of group), -Member is required, because a member list built for one
    GroupType (an RBL name, say) is not a valid value for another (an IP network).

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'Premium RBL Services' or 'Standard RBL Services' groups with
    this cmdlet.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing group to update.

.PARAMETER GroupType
    Required. RBLIPv4, RBLIPv6, IPAddress or EmailAddressOrDomain - the group's current
    type, or the new type if you are changing it.

.PARAMETER Member
    Optional. New member values, replacing the current list. Required if -GroupType
    differs from the object's current GroupType. If omitted and -GroupType matches the
    current value, the current member list is kept.

.PARAMETER Description
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER EmailImportType
    Optional. Replacing the current value. Only meaningful when -GroupType is
    EmailAddressOrDomain. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name and GroupType
    by property name, for example from Get-SfosMTAAddressGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update, if the named group does not exist, or if -GroupType changes without
    -Member.

.EXAMPLE
    Set-SfosMTAAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Description 'Trusted partner domains' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMTAAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Member 'example.com','example.net'

    Replaces the member list on the named group, keeping its description unchanged. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaaddressgroup/operations/AddAddressGroup%26EditAddressGroup.html

.LINK
    Get-SfosMTAAddressGroup
#>
function Set-SfosMTAAddressGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RBLIPv4', 'RBLIPv6', 'IPAddress', 'EmailAddressOrDomain')]
        [string]$GroupType,

        [string[]]$Member,
        [string]$Description,

        [ValidateSet('Import', 'Manual')]
        [string]$EmailImportType,

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
        $existing = @(Get-SfosMTAAddressGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The MTAAddressGroup object '$Name' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        if ($bp.ContainsKey('Member')) {
            $targetMember = $Member
        }
        elseif ($GroupType -eq $current.GroupType) {
            $targetMember = $current.Member
        }
        else {
            throw "The MTAAddressGroup object '$Name' is currently GroupType '$($current.GroupType)'. Pass -Member when changing -GroupType to '$GroupType'."
        }

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }
        $targetImportType = if ($bp.ContainsKey('EmailImportType')) { $EmailImportType } else { $current.EmailImportType }

        if (-not $PSCmdlet.ShouldProcess("MTAAddressGroup '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosMTAAddressGroupEntityXml -Operation 'update' -Name $Name -GroupType $GroupType `
            -Member $targetMember -Description $targetDescription -EmailImportType $targetImportType

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update MTAAddressGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTAAddressGroup' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an MTA Address Group from a Sophos Firewall.

.DESCRIPTION
    Removes an MTAAddressGroup object. Measured against a live firewall: removing a
    name that does not exist answers HTTP 200 with a success status, identical to a
    real removal - the firewall reports success without having done anything. This
    cmdlet reads the object first and throws "was not found" itself rather than passing
    that misleading success through.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'Premium RBL Services' or 'Standard RBL Services' groups with
    this cmdlet.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the group to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosMTAAddressGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named group does not exist.

.EXAMPLE
    Remove-SfosMTAAddressGroup -Name 'PartnerDomains' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosMTAAddressGroup -Name 'PartnerDomains'

    Removes the named group. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaaddressgroup/operations/Delete%20Address%20Group.html

.LINK
    Get-SfosMTAAddressGroup
#>
function Remove-SfosMTAAddressGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        $existing = @(Get-SfosMTAAddressGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The MTAAddressGroup object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("MTAAddressGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><MTAAddressGroup><Name>$nameEsc</Name></MTAAddressGroup></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove MTAAddressGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTAAddressGroup' -Action 'remove' -Target $Name
    }
}

#endregion

#region MTADataControlList

<#
.SYNOPSIS
    Builds the Set request body for an MTADataControlList entity. Internal helper, not
    exported.

.DESCRIPTION
    Shared by New-SfosMTADataControlList and Set-SfosMTADataControlList so both send the
    same entity shape. Measured against a live firewall: Signatures is a full replace on
    update, not append-only - sending fewer signatures genuinely removes the others.
    Every value is escaped through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the data control list.

.PARAMETER Signature
    One or more catalog signature names, for example 'Postal addresses [Germany]'.
#>
function ConvertTo-SfosMTADataControlListEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [string[]]$Signature
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $sigItems = (@($Signature | Where-Object -FilterScript { $_ }) | ForEach-Object -Process {
            "<Signature>$(ConvertTo-SfosXmlEscaped -Text $_)</Signature>"
        }) -join ''

    return @"
<Set operation="$Operation">
  <MTADataControlList>
    <Name>$nameEsc</Name>
    <Signatures>$sigItems</Signatures>
  </MTADataControlList>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves MTA Data Control List objects from a Sophos Firewall.

.DESCRIPTION
    Returns MTADataControlList objects (PROTECT > Email (MTA) > Data Control List). Each
    list bundles data-loss-prevention signatures (a fixed catalog, for example 'Postal
    addresses [Germany]') for use in Exception Policies and SMTP policies.

    Every appliance ships three predefined lists ('Postal addresses', 'Financial
    information', 'Confidential information'); do not modify or remove those. Measured
    against a live firewall: this root has its own storage, separate from the legacy
    DataControlList root - the legacy root answers status 545 (MTAModeDisableCheck) for
    every write on an appliance running in MTA mode, while this MTA-side root is fully
    writable there. To read the full catalog of valid signature names for -Signature on
    New-/Set-SfosMTADataControlList, read one of the predefined lists.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

.PARAMETER NameLike
    Optional. Returns only lists whose name contains the given text anywhere. Sent to
    the firewall as a server-side pre-filter (Name/like, measured to work for this
    entity) and re-applied client-side. If omitted, every list is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per list, with the
    properties Name and Signature (a string array). Returns System.Xml.XmlElement when
    -AsXml is used, and an empty array when no list matches.

.EXAMPLE
    Get-SfosMTADataControlList

    Lists every MTA data control list, including the three predefined ones.

.EXAMPLE
    (Get-SfosMTADataControlList -NameLike 'Postal').Signature

    Reads the full catalog of signature names in the predefined 'Postal addresses' list -
    useful as a source of valid values for -Signature on New-/Set-SfosMTADataControlList.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtadataprotectionpolicy/mtadataprotectionpolicy.html

.LINK
    New-SfosMTADataControlList
#>
function Get-SfosMTADataControlList {
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

    $inner = "<Get><MTADataControlList>$filterXml</MTADataControlList></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MTADataControlList objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTADataControlList' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/MTADataControlList[Name]' | ForEach-Object -Process { $_.Node }

    $listObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name      = [string]$node.Name
            Signature = @($node.Signatures.Signature | Where-Object -FilterScript { $null -ne $_ })
        }
    }

    $listObjects = @($listObjects)
    if ($NameLike) {
        $listObjects = @($listObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($listObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $listObjects
}

<#
.SYNOPSIS
    Creates an MTA Data Control List on a Sophos Firewall.

.DESCRIPTION
    Creates an MTADataControlList object (PROTECT > Email (MTA) > Data Control List).
    Measured against a live firewall: create, a no-op update round trip (read, write
    back unchanged, read again, compare raw XML - identical) and removal all work.

    -Signature values come from a fixed catalog; read one of the three predefined lists
    with Get-SfosMTADataControlList to see valid names such as 'Postal addresses
    [Germany]'. This cmdlet requires at least one signature - the attribute table marks
    the field optional, but a data control list with no signature has no matching
    effect, so an empty list is refused here rather than silently created.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the list. Maximum 255 characters.

.PARAMETER Signature
    Required. One or more catalog signature names.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosMTADataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosMTADataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]','Postal addresses [France]'

    Creates a data control list matching two catalog signatures. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtadataprotectionpolicy/operations/AddDataControlList%26UpdateDataControlList.html

.LINK
    Get-SfosMTADataControlList
#>
function New-SfosMTADataControlList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$Signature,

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
        if (-not @($Signature | Where-Object -FilterScript { $_ }).Count) {
            throw "MTADataControlList object '$Name' needs at least one -Signature value."
        }

        if (-not $PSCmdlet.ShouldProcess("MTADataControlList '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosMTADataControlListEntityXml -Operation 'add' -Name $Name -Signature $Signature

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create MTADataControlList object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTADataControlList' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an MTA Data Control List on a Sophos Firewall.

.DESCRIPTION
    Reads the named MTADataControlList object first and writes back a complete entity,
    overriding only -Signature when you pass it - this is a full-replace entity (measured:
    sending fewer signatures genuinely removes the others, it is not append-only), so
    omitting -Signature keeps the current list unchanged rather than clearing it.
    Confirmed against a live firewall with an unchanged round trip (read, write back
    unchanged, read again, compare raw XML - identical).

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the three predefined lists ('Postal addresses', 'Financial information',
    'Confidential information') with this cmdlet.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing list to update.

.PARAMETER Signature
    Optional. New signature list, replacing the current one. If omitted, the current
    list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosMTADataControlList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update or if the named list does not exist.

.EXAMPLE
    Set-SfosMTADataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMTADataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]'

    Replaces the signature list on the named object with a single entry. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtadataprotectionpolicy/operations/AddDataControlList%26UpdateDataControlList.html

.LINK
    Get-SfosMTADataControlList
#>
function Set-SfosMTADataControlList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$Signature,

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
        $existing = @(Get-SfosMTADataControlList -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The MTADataControlList object '$Name' was not found."
        }
        $current = $existing[0]

        $targetSignature = if ($PSBoundParameters.ContainsKey('Signature')) { $Signature } else { $current.Signature }

        if (-not $PSCmdlet.ShouldProcess("MTADataControlList '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosMTADataControlListEntityXml -Operation 'update' -Name $Name -Signature $targetSignature

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update MTADataControlList object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTADataControlList' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an MTA Data Control List from a Sophos Firewall.

.DESCRIPTION
    Removes an MTADataControlList object. Measured against a live firewall: removing a
    name that does not exist answers with a code-less status ("Operation could not be
    performed on Entity.") rather than a false success - unlike some sibling entities
    in this area, the firewall's own response is already trustworthy here. This cmdlet
    still reads the object first, so the error it raises names the object clearly
    ("was not found") instead of surfacing the firewall's generic message.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the three predefined lists ('Postal addresses', 'Financial information',
    'Confidential information') with this cmdlet.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the list to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosMTADataControlList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named list does not exist.

.EXAMPLE
    Remove-SfosMTADataControlList -Name 'AddressCheck' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosMTADataControlList -Name 'AddressCheck'

    Removes the named list. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtadataprotectionpolicy/operations/Delete%20Data%20Control%20List.html

.LINK
    Get-SfosMTADataControlList
#>
function Remove-SfosMTADataControlList {
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
        $existing = @(Get-SfosMTADataControlList -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The MTADataControlList object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("MTADataControlList '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><MTADataControlList><Name>$nameEsc</Name></MTADataControlList></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove MTADataControlList object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTADataControlList' -Action 'remove' -Target $Name
    }
}

#endregion

#region MailExceptionPolicy

<#
.SYNOPSIS
    Builds the Set request body for an ExceptionPolicy entity. Internal helper, not
    exported.

.DESCRIPTION
    Shared by New-SfosMailExceptionPolicy and Set-SfosMailExceptionPolicy so both send
    the same entity shape. The wire shape was measured against a live firewall and
    differs from both documentation sources for one field: the sample XML shows
    <CheckForSPF> nested under <Other>, and the attribute table names it 'CheckforSPF'
    with no location - live testing found neither is right on its own. The field that is
    actually honored is <CheckforSPF> (lowercase 'f') nested under <SpamProtection>; a
    value sent as <CheckForSPF> under <Other>, matching the sample exactly, is silently
    ignored on both add and update. This helper builds the measured, working shape.
    Every value is escaped through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Policy
    The object to convert, with the properties Name, Malware, ZeroDayProtection,
    Antispam, Greylisting, IPReputation, RecipientVerification, BATV, RBL,
    RDNSAndHelo, CheckforSPF, Encryption, DataProtection, FileProtection,
    BanerAddition, DKIMSigning, DKIMVerification, ForTheseSourceHost,
    ORTheseSenderAddresses, ORTheseRecipientAddresses, SourceHost, SenderAddress and
    RecipientAddress.
#>
function ConvertTo-SfosMailExceptionPolicyEntityXml {
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

    $sourceHostXml = (@($Policy.SourceHost | Where-Object -FilterScript { $_ }) | ForEach-Object -Process {
            "<SourceHost>$(ConvertTo-SfosXmlEscaped -Text $_)</SourceHost>"
        }) -join ''
    $senderXml = (@($Policy.SenderAddress | Where-Object -FilterScript { $_ }) | ForEach-Object -Process {
            "<Address>$(ConvertTo-SfosXmlEscaped -Text $_)</Address>"
        }) -join ''
    $recipientXml = (@($Policy.RecipientAddress | Where-Object -FilterScript { $_ }) | ForEach-Object -Process {
            "<Address>$(ConvertTo-SfosXmlEscaped -Text $_)</Address>"
        }) -join ''

    $malwareEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Malware)
    $zeroDayEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.ZeroDayProtection)
    $antispamEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Antispam)
    $greylistingEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Greylisting)
    $ipReputationEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.IPReputation)
    $recipientVerificationEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.RecipientVerification)
    $batvEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.BATV)
    $rblEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.RBL)
    $rdnsAndHeloEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.RDNSAndHelo)
    $checkforSpfEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.CheckforSPF)
    $encryptionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.Encryption)
    $dataProtectionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DataProtection)
    $fileProtectionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.FileProtection)
    $banerAdditionEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.BanerAddition)
    $dkimSigningEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DKIMSigning)
    $dkimVerificationEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.DKIMVerification)
    $forTheseSourceHostEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.ForTheseSourceHost)
    $orTheseSenderEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.ORTheseSenderAddresses)
    $orTheseRecipientEsc = ConvertTo-SfosXmlEscaped -Text ([string]$Policy.ORTheseRecipientAddresses)

    return @"
<Set operation="$Operation">
  <ExceptionPolicy>
    <Name>$nameEsc</Name>
    <MalwareProtection>
      <Malware>$malwareEsc</Malware>
      <ZeroDayProtection>$zeroDayEsc</ZeroDayProtection>
    </MalwareProtection>
    <SpamProtection>
      <Antispam>$antispamEsc</Antispam>
      <Greylisting>$greylistingEsc</Greylisting>
      <IPReputation>$ipReputationEsc</IPReputation>
      <RecipientVerification>$recipientVerificationEsc</RecipientVerification>
      <BATV>$batvEsc</BATV>
      <RBL>$rblEsc</RBL>
      <RDNSAndHelo>$rdnsAndHeloEsc</RDNSAndHelo>
      <CheckforSPF>$checkforSpfEsc</CheckforSPF>
    </SpamProtection>
    <Other>
      <Encryption>$encryptionEsc</Encryption>
      <DataProtection>$dataProtectionEsc</DataProtection>
      <FileProtection>$fileProtectionEsc</FileProtection>
      <BanerAddition>$banerAdditionEsc</BanerAddition>
      <DKIMSigning>$dkimSigningEsc</DKIMSigning>
      <DKIMVerification>$dkimVerificationEsc</DKIMVerification>
    </Other>
    <ForTheseSourceHost>$forTheseSourceHostEsc</ForTheseSourceHost>
    <ORTheseSenderAddresses>$orTheseSenderEsc</ORTheseSenderAddresses>
    <ORTheseRecipientAddresses>$orTheseRecipientEsc</ORTheseRecipientAddresses>
    <SourceHostList>$sourceHostXml</SourceHostList>
    <SenderAddressesList>$senderXml</SenderAddressesList>
    <RecipientAddresses>$recipientXml</RecipientAddresses>
  </ExceptionPolicy>
</Set>
"@
}

<#
.SYNOPSIS
    Retrieves Exception Policy objects from a Sophos Firewall.

.DESCRIPTION
    Returns ExceptionPolicy objects (PROTECT > Email (MTA) > Exception Policy). An
    exception policy switches off selected protection modules (malware, spam, data
    protection, ...) for mail that matches a source host, sender address or recipient
    address. The Mail prefix on this cmdlet's name (Get-SfosMailExceptionPolicy rather
    than Get-SfosExceptionPolicy) avoids ambiguity with unrelated exception-policy
    entities elsewhere in this module family, the same reasoning used for
    Get-SfosMailMalwareProtection.

    Measured against a live firewall: the CheckforSPF field is returned nested under
    SpamProtection, not under Other as the vendor sample shows, and spelled with a
    lowercase 'f', not 'CheckForSPF' as the sample spells it - see
    Set-SfosMailExceptionPolicy for the create/update side of this discrepancy. RBL and
    RDNSAndHelo, both documented but absent from the sample, were also confirmed
    present and settable.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

    This object belongs to MTA mode. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

.PARAMETER NameLike
    Optional. Returns only policies whose name contains the given text anywhere. Sent
    to the firewall as a server-side pre-filter (Name/like, following the pattern
    measured for sibling entities in this area; not separately re-measured for
    ExceptionPolicy) and re-applied client-side. If omitted, every policy is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per policy, with the
    properties Name, Malware, ZeroDayProtection, Antispam, Greylisting, IPReputation,
    RecipientVerification, BATV, RBL, RDNSAndHelo, CheckforSPF, Encryption,
    DataProtection, FileProtection, BanerAddition, DKIMSigning, DKIMVerification,
    ForTheseSourceHost, ORTheseSenderAddresses, ORTheseRecipientAddresses, SourceHost,
    SenderAddress and RecipientAddress (the last three are string arrays). Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no policy
    matches.

.EXAMPLE
    Get-SfosMailExceptionPolicy

    Lists every exception policy.

.EXAMPLE
    Get-SfosMailExceptionPolicy -NameLike 'Marketing'

    Lists all policies whose name contains 'Marketing'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/exceptionpolicy/exceptionpolicy.html

.LINK
    New-SfosMailExceptionPolicy
#>
function Get-SfosMailExceptionPolicy {
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

    $inner = "<Get><ExceptionPolicy>$filterXml</ExceptionPolicy></Get>"

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ExceptionPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    try {
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ExceptionPolicy' -Action 'get'
    }
    catch {
        # -SourceHost takes the name of a host object, and the firewall only says the
        # field is invalid. Say which kind of value it wants.
        if ($PSBoundParameters.ContainsKey('SourceHost') -and $_.Exception.Message -match '501') {
            throw ($_.Exception.Message + " -SourceHost expects the name of an existing IPHost or FQDN host object, not an address or a domain typed out.")
        }
        throw
    }

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/ExceptionPolicy[Name]' | ForEach-Object -Process { $_.Node }

    $policyObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name                       = [string]$node.Name
            Malware                    = [string]$node.MalwareProtection.Malware
            ZeroDayProtection          = [string]$node.MalwareProtection.ZeroDayProtection
            Antispam                   = [string]$node.SpamProtection.Antispam
            Greylisting                = [string]$node.SpamProtection.Greylisting
            IPReputation               = [string]$node.SpamProtection.IPReputation
            RecipientVerification      = [string]$node.SpamProtection.RecipientVerification
            BATV                       = [string]$node.SpamProtection.BATV
            RBL                        = [string]$node.SpamProtection.RBL
            RDNSAndHelo                = [string]$node.SpamProtection.RDNSAndHelo
            CheckforSPF                = [string]$node.SpamProtection.CheckforSPF
            Encryption                 = [string]$node.Other.Encryption
            DataProtection             = [string]$node.Other.DataProtection
            FileProtection             = [string]$node.Other.FileProtection
            BanerAddition              = [string]$node.Other.BanerAddition
            DKIMSigning                = [string]$node.Other.DKIMSigning
            DKIMVerification           = [string]$node.Other.DKIMVerification
            ForTheseSourceHost         = [string]$node.ForTheseSourceHost
            ORTheseSenderAddresses     = [string]$node.ORTheseSenderAddresses
            ORTheseRecipientAddresses  = [string]$node.ORTheseRecipientAddresses
            SourceHost                 = @($node.SourceHostList.SourceHost | Where-Object -FilterScript { $null -ne $_ })
            SenderAddress              = @($node.SenderAddressesList.Address | Where-Object -FilterScript { $null -ne $_ })
            RecipientAddress           = @($node.RecipientAddresses.Address | Where-Object -FilterScript { $null -ne $_ })
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
    Creates an Exception Policy on a Sophos Firewall.

.DESCRIPTION
    Creates an ExceptionPolicy object (PROTECT > Email (MTA) > Exception Policy).
    Measured against a live firewall: create, a no-op update round trip (read, write
    back unchanged, read again, compare raw XML - identical) and removal all work when
    the mail-matching criteria below are satisfied.

    The firewall requires at least one active, populated matching criterion (status
    545/EmailExceptionIPSenderRcptChk otherwise) - either -ORTheseSenderAddresses
    'Enable' with -SenderAddress, -ORTheseRecipientAddresses 'Enable' with
    -RecipientAddress, or -ForTheseSourceHost 'Enable' with -SourceHost. The last
    combination needs a host object: -SourceHost takes the NAME of an IPHost or FQDN
    host that already exists on the firewall, not an address or a domain typed out.
    A literal value is refused with status 501 naming
    /ExceptionPolicy/SourceHostList/SourceHost - create the host first, for example
    with New-SfosIPHost, then pass its name here.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the policy. Maximum 100 characters.

.PARAMETER Malware
    Optional. Enable or Disable malware protection for matching mail. If omitted,
    'Disable' is used.

.PARAMETER ZeroDayProtection
    Optional. Enable or Disable zero-day protection. If omitted, 'Disable' is used.

.PARAMETER Antispam
    Optional. Enable or Disable anti-spam scanning. If omitted, 'Disable' is used.

.PARAMETER Greylisting
    Optional. Enable or Disable greylisting. If omitted, 'Disable' is used.

.PARAMETER IPReputation
    Optional. Enable or Disable IP reputation checking. If omitted, 'Disable' is used.

.PARAMETER RecipientVerification
    Optional. Enable or Disable recipient verification. If omitted, 'Disable' is used.

.PARAMETER BATV
    Optional. Enable or Disable Bounce Address Tag Validation. If omitted, 'Disable' is
    used.

.PARAMETER RBL
    Optional. Enable or Disable RBL (real-time blackhole list) checking. If omitted,
    'Disable' is used.

.PARAMETER RDNSAndHelo
    Optional. Enable or Disable reverse-DNS and HELO checking. If omitted, 'Disable' is
    used.

.PARAMETER CheckforSPF
    Optional. Enable or Disable SPF (Sender Policy Framework) checking. If omitted,
    'Disable' is used.

.PARAMETER Encryption
    Optional. Enable or Disable encryption handling. If omitted, 'Disable' is used.

.PARAMETER DataProtection
    Optional. Enable or Disable data protection (data control list) scanning. If
    omitted, 'Disable' is used.

.PARAMETER FileProtection
    Optional. Enable or Disable file-type protection. If omitted, 'Disable' is used.

.PARAMETER BanerAddition
    Optional. Enable or Disable banner addition to outgoing mail. Spelled 'Baner' to
    match the field name on the wire. If omitted, 'Disable' is used.

.PARAMETER DKIMSigning
    Optional. Enable or Disable DKIM signing. If omitted, 'Disable' is used.

.PARAMETER DKIMVerification
    Optional. Enable or Disable DKIM verification. If omitted, 'Disable' is used.

.PARAMETER ForTheseSourceHost
    Optional. Enable or Disable matching by source host - see -SourceHost. If omitted,
    'Disable' is used.

.PARAMETER SourceHost
    Optional. One or more source hosts (IP address or FQDN) to match when
    -ForTheseSourceHost is 'Enable'. See the description for the currently blocked
    status of this field.

.PARAMETER ORTheseSenderAddresses
    Optional. Enable or Disable matching by sender address - see -SenderAddress. If
    omitted, 'Disable' is used.

.PARAMETER SenderAddress
    Optional. One or more sender email addresses to match when
    -ORTheseSenderAddresses is 'Enable'.

.PARAMETER ORTheseRecipientAddresses
    Optional. Enable or Disable matching by recipient address - see -RecipientAddress.
    If omitted, 'Disable' is used.

.PARAMETER RecipientAddress
    Optional. One or more recipient email addresses to match when
    -ORTheseRecipientAddresses is 'Enable'.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosMailExceptionPolicy -Name 'PartnerMail' -ORTheseSenderAddresses Enable -SenderAddress 'billing@example.com' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosMailExceptionPolicy -Name 'PartnerMail' -ORTheseSenderAddresses Enable -SenderAddress 'billing@example.com' -Antispam Disable

    Creates a policy that switches off anti-spam scanning for mail from one sender
    address. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/exceptionpolicy/operations/ExceptionPolicyAdd%26ExceptionPolicyDelete%26ExceptionPolicyUpdate.html

.LINK
    Get-SfosMailExceptionPolicy
#>
function New-SfosMailExceptionPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('Enable', 'Disable')]
        [string]$Malware = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$ZeroDayProtection = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$Antispam = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$Greylisting = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$IPReputation = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$RecipientVerification = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$BATV = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$RBL = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$RDNSAndHelo = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$CheckforSPF = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$Encryption = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$DataProtection = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$FileProtection = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$BanerAddition = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$DKIMSigning = 'Disable',
        [ValidateSet('Enable', 'Disable')]
        [string]$DKIMVerification = 'Disable',

        [ValidateSet('Enable', 'Disable')]
        [string]$ForTheseSourceHost = 'Disable',
        [string[]]$SourceHost,

        [ValidateSet('Enable', 'Disable')]
        [string]$ORTheseSenderAddresses = 'Disable',
        [string[]]$SenderAddress,

        [ValidateSet('Enable', 'Disable')]
        [string]$ORTheseRecipientAddresses = 'Disable',
        [string[]]$RecipientAddress,

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
        if (-not $PSCmdlet.ShouldProcess("ExceptionPolicy '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $policy = [PSCustomObject]@{
            Name                       = $Name
            Malware                    = $Malware
            ZeroDayProtection          = $ZeroDayProtection
            Antispam                   = $Antispam
            Greylisting                = $Greylisting
            IPReputation               = $IPReputation
            RecipientVerification      = $RecipientVerification
            BATV                       = $BATV
            RBL                        = $RBL
            RDNSAndHelo                = $RDNSAndHelo
            CheckforSPF                = $CheckforSPF
            Encryption                 = $Encryption
            DataProtection             = $DataProtection
            FileProtection             = $FileProtection
            BanerAddition              = $BanerAddition
            DKIMSigning                = $DKIMSigning
            DKIMVerification           = $DKIMVerification
            ForTheseSourceHost         = $ForTheseSourceHost
            ORTheseSenderAddresses     = $ORTheseSenderAddresses
            ORTheseRecipientAddresses  = $ORTheseRecipientAddresses
            SourceHost                 = $SourceHost
            SenderAddress              = $SenderAddress
            RecipientAddress           = $RecipientAddress
        }

        $inner = ConvertTo-SfosMailExceptionPolicyEntityXml -Operation 'add' -Policy $policy

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create ExceptionPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        try {
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ExceptionPolicy' -Action 'create' -Target $Name
        }
        catch {
            # -SourceHost takes the name of a host object, and the firewall only says the
            # field is invalid. Say which kind of value it wants.
            if ($PSBoundParameters.ContainsKey('SourceHost') -and $_.Exception.Message -match '501') {
                throw ($_.Exception.Message + " -SourceHost expects the name of an existing IPHost or FQDN host object, not an address or a domain typed out.")
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Updates an Exception Policy on a Sophos Firewall.

.DESCRIPTION
    Reads the named ExceptionPolicy object first and writes back a complete entity,
    overriding only the fields you pass - this is a full-replace entity, so anything not
    read back and resent would be cleared. Confirmed against a live firewall with an
    unchanged round trip (read, write back unchanged, read again, compare raw XML -
    identical) across every nested block (MalwareProtection, SpamProtection, Other, the
    three address/host lists).

    See New-SfosMailExceptionPolicy for the CheckforSPF wire-shape discrepancy and the
    current live-firewall limitation on -SourceHost.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing policy to update.

.PARAMETER Malware
    Optional. If omitted, the current value is kept.

.PARAMETER ZeroDayProtection
    Optional. If omitted, the current value is kept.

.PARAMETER Antispam
    Optional. If omitted, the current value is kept.

.PARAMETER Greylisting
    Optional. If omitted, the current value is kept.

.PARAMETER IPReputation
    Optional. If omitted, the current value is kept.

.PARAMETER RecipientVerification
    Optional. If omitted, the current value is kept.

.PARAMETER BATV
    Optional. If omitted, the current value is kept.

.PARAMETER RBL
    Optional. If omitted, the current value is kept.

.PARAMETER RDNSAndHelo
    Optional. If omitted, the current value is kept.

.PARAMETER CheckforSPF
    Optional. If omitted, the current value is kept.

.PARAMETER Encryption
    Optional. If omitted, the current value is kept.

.PARAMETER DataProtection
    Optional. If omitted, the current value is kept.

.PARAMETER FileProtection
    Optional. If omitted, the current value is kept.

.PARAMETER BanerAddition
    Optional. If omitted, the current value is kept.

.PARAMETER DKIMSigning
    Optional. If omitted, the current value is kept.

.PARAMETER DKIMVerification
    Optional. If omitted, the current value is kept.

.PARAMETER ForTheseSourceHost
    Optional. If omitted, the current value is kept.

.PARAMETER SourceHost
    Optional. Replaces the current source host list. If omitted, the current list is
    kept. See New-SfosMailExceptionPolicy for the current live-firewall limitation on
    this field.

.PARAMETER ORTheseSenderAddresses
    Optional. If omitted, the current value is kept.

.PARAMETER SenderAddress
    Optional. Replaces the current sender address list. If omitted, the current list is
    kept.

.PARAMETER ORTheseRecipientAddresses
    Optional. If omitted, the current value is kept.

.PARAMETER RecipientAddress
    Optional. Replaces the current recipient address list. If omitted, the current list
    is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosMailExceptionPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update or if the named policy does not exist.

.EXAMPLE
    Set-SfosMailExceptionPolicy -Name 'PartnerMail' -Antispam Enable -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMailExceptionPolicy -Name 'PartnerMail' -Antispam Enable

    Turns anti-spam scanning back on for the named policy. Every other field, including
    the sender/recipient address lists, is kept unchanged. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/exceptionpolicy/operations/ExceptionPolicyAdd%26ExceptionPolicyDelete%26ExceptionPolicyUpdate.html

.LINK
    Get-SfosMailExceptionPolicy
#>
function Set-SfosMailExceptionPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [ValidateSet('Enable', 'Disable')]
        [string]$Malware,
        [ValidateSet('Enable', 'Disable')]
        [string]$ZeroDayProtection,
        [ValidateSet('Enable', 'Disable')]
        [string]$Antispam,
        [ValidateSet('Enable', 'Disable')]
        [string]$Greylisting,
        [ValidateSet('Enable', 'Disable')]
        [string]$IPReputation,
        [ValidateSet('Enable', 'Disable')]
        [string]$RecipientVerification,
        [ValidateSet('Enable', 'Disable')]
        [string]$BATV,
        [ValidateSet('Enable', 'Disable')]
        [string]$RBL,
        [ValidateSet('Enable', 'Disable')]
        [string]$RDNSAndHelo,
        [ValidateSet('Enable', 'Disable')]
        [string]$CheckforSPF,
        [ValidateSet('Enable', 'Disable')]
        [string]$Encryption,
        [ValidateSet('Enable', 'Disable')]
        [string]$DataProtection,
        [ValidateSet('Enable', 'Disable')]
        [string]$FileProtection,
        [ValidateSet('Enable', 'Disable')]
        [string]$BanerAddition,
        [ValidateSet('Enable', 'Disable')]
        [string]$DKIMSigning,
        [ValidateSet('Enable', 'Disable')]
        [string]$DKIMVerification,

        [ValidateSet('Enable', 'Disable')]
        [string]$ForTheseSourceHost,
        [string[]]$SourceHost,

        [ValidateSet('Enable', 'Disable')]
        [string]$ORTheseSenderAddresses,
        [string[]]$SenderAddress,

        [ValidateSet('Enable', 'Disable')]
        [string]$ORTheseRecipientAddresses,
        [string[]]$RecipientAddress,

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
        $existing = @(Get-SfosMailExceptionPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ExceptionPolicy object '$Name' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $policy = [PSCustomObject]@{
            Name                       = $Name
            Malware                    = if ($bp.ContainsKey('Malware')) { $Malware } else { $current.Malware }
            ZeroDayProtection          = if ($bp.ContainsKey('ZeroDayProtection')) { $ZeroDayProtection } else { $current.ZeroDayProtection }
            Antispam                   = if ($bp.ContainsKey('Antispam')) { $Antispam } else { $current.Antispam }
            Greylisting                = if ($bp.ContainsKey('Greylisting')) { $Greylisting } else { $current.Greylisting }
            IPReputation               = if ($bp.ContainsKey('IPReputation')) { $IPReputation } else { $current.IPReputation }
            RecipientVerification      = if ($bp.ContainsKey('RecipientVerification')) { $RecipientVerification } else { $current.RecipientVerification }
            BATV                       = if ($bp.ContainsKey('BATV')) { $BATV } else { $current.BATV }
            RBL                        = if ($bp.ContainsKey('RBL')) { $RBL } else { $current.RBL }
            RDNSAndHelo                = if ($bp.ContainsKey('RDNSAndHelo')) { $RDNSAndHelo } else { $current.RDNSAndHelo }
            CheckforSPF                = if ($bp.ContainsKey('CheckforSPF')) { $CheckforSPF } else { $current.CheckforSPF }
            Encryption                 = if ($bp.ContainsKey('Encryption')) { $Encryption } else { $current.Encryption }
            DataProtection             = if ($bp.ContainsKey('DataProtection')) { $DataProtection } else { $current.DataProtection }
            FileProtection             = if ($bp.ContainsKey('FileProtection')) { $FileProtection } else { $current.FileProtection }
            BanerAddition              = if ($bp.ContainsKey('BanerAddition')) { $BanerAddition } else { $current.BanerAddition }
            DKIMSigning                = if ($bp.ContainsKey('DKIMSigning')) { $DKIMSigning } else { $current.DKIMSigning }
            DKIMVerification           = if ($bp.ContainsKey('DKIMVerification')) { $DKIMVerification } else { $current.DKIMVerification }
            ForTheseSourceHost         = if ($bp.ContainsKey('ForTheseSourceHost')) { $ForTheseSourceHost } else { $current.ForTheseSourceHost }
            ORTheseSenderAddresses     = if ($bp.ContainsKey('ORTheseSenderAddresses')) { $ORTheseSenderAddresses } else { $current.ORTheseSenderAddresses }
            ORTheseRecipientAddresses  = if ($bp.ContainsKey('ORTheseRecipientAddresses')) { $ORTheseRecipientAddresses } else { $current.ORTheseRecipientAddresses }
            SourceHost                 = @(if ($bp.ContainsKey('SourceHost')) { $SourceHost } else { $current.SourceHost })
            SenderAddress              = @(if ($bp.ContainsKey('SenderAddress')) { $SenderAddress } else { $current.SenderAddress })
            RecipientAddress           = @(if ($bp.ContainsKey('RecipientAddress')) { $RecipientAddress } else { $current.RecipientAddress })
        }

        if (-not $PSCmdlet.ShouldProcess("ExceptionPolicy '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosMailExceptionPolicyEntityXml -Operation 'update' -Policy $policy

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update ExceptionPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        try {
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ExceptionPolicy' -Action 'update' -Target $Name
        }
        catch {
            # -SourceHost takes the name of a host object, and the firewall only says the
            # field is invalid. Say which kind of value it wants.
            if ($PSBoundParameters.ContainsKey('SourceHost') -and $_.Exception.Message -match '501') {
                throw ($_.Exception.Message + " -SourceHost expects the name of an existing IPHost or FQDN host object, not an address or a domain typed out.")
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Removes an Exception Policy from a Sophos Firewall.

.DESCRIPTION
    Removes an ExceptionPolicy object. Measured against a live firewall: removing a
    name that does not exist answers with a code-less status ("Operation could not be
    performed on Entity.") rather than a false success - the firewall's own response is
    already trustworthy here. This cmdlet still reads the object first, so the error it
    raises names the object clearly ("was not found") instead of surfacing the
    firewall's generic message.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the policy to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosMailExceptionPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named policy does not exist.

.EXAMPLE
    Remove-SfosMailExceptionPolicy -Name 'PartnerMail' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosMailExceptionPolicy -Name 'PartnerMail'

    Removes the named policy. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/exceptionpolicy/operations/Exception%20Policy%20Delete.html

.LINK
    Get-SfosMailExceptionPolicy
#>
function Remove-SfosMailExceptionPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
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
        $existing = @(Get-SfosMailExceptionPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The ExceptionPolicy object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("ExceptionPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><ExceptionPolicy><Name>$nameEsc</Name></ExceptionPolicy></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove ExceptionPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        try {
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ExceptionPolicy' -Action 'remove' -Target $Name
        }
        catch {
            # -SourceHost takes the name of a host object, and the firewall only says the
            # field is invalid. Say which kind of value it wants.
            if ($PSBoundParameters.ContainsKey('SourceHost') -and $_.Exception.Message -match '501') {
                throw ($_.Exception.Message + " -SourceHost expects the name of an existing IPHost or FQDN host object, not an address or a domain typed out.")
            }
            throw
        }
    }
}

#endregion

#region MTASPXConfiguration

<#
.SYNOPSIS
    Retrieves the MTA SPX configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the MTASPXConfiguration singleton (PROTECT > Email (MTA) > SPX >
    Configuration): the global SPX template, the password-registration portal settings and
    the notification-on-error behaviour. There is exactly one instance of this object per
    firewall. The cmdlet only reads; nothing on the firewall is changed. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly.

    This entity has a same-named counterpart on the Legacy Email side, SPXConfiguration, and
    both started out holding identical values on this appliance. They are separate stored
    objects, not one object seen through two roots - see Set-SfosMTASPXConfiguration for the
    write test that established this.

    This object belongs to MTA mode. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with the properties
    DefaultSPXTemplate, HostName, AllowedNetwork, PortalPort, AllowSecureReplyfor,
    KeepUnusedPassFor, AllowPassRegistrationFor and SendNotifcationErrorTo (the API's own
    spelling - "Notifcation" is not a typo introduced here). HostName is a single string on
    the wire even though the vendor's attribute table marks it as an array; AllowedNetwork is
    the field that is actually a list. PortalPort is named to avoid a collision with the
    -Port connection parameter shared by every cmdlet in this suite - the wire element is
    Port. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosMTASPXConfiguration

    Returns the current MTA SPX configuration.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaspxconfiguration/mtaspxconfiguration.html

.LINK
    Set-SfosMTASPXConfiguration
#>
function Get-SfosMTASPXConfiguration {
    # PSUseSingularNouns is suppressed on purpose. 'Configuration' is not a plural container
    # here but the name of the entity itself - the API element is <MTASPXConfiguration>, a
    # singleton holding one configuration, with no <MTASPXConfiguration...s> child to fall back
    # to. The Sophos spelling goes above PowerShell habit here, as it does for every other
    # settings singleton in this module family.
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

    $inner = '<Get><MTASPXConfiguration></MTASPXConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MTASPXConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTASPXConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/MTASPXConfiguration')
    if (-not $node) {
        throw 'MTASPXConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $allowedNetworks = @(if ($node.AllowedNetworks) { @($node.AllowedNetworks.Network) } else { @() })

    return [PSCustomObject]@{
        DefaultSPXTemplate       = [string]$node.SPXGlobalTemplate.DefaultSPXTemplate
        HostName                 = [string]$node.HostName
        AllowedNetwork           = [string[]]$allowedNetworks
        # Named PortalPort, not Port: the wire element is <Port>, but this cmdlet family
        # reserves -Port for the management API's own TCP port on every function (see the
        # connection parameter block), so the entity's own port field cannot reuse that name
        # without colliding in Set-SfosMTASPXConfiguration's parameter set - the same reason
        # RADIUS/TACACS Server's own Port is exposed as ServerPort elsewhere in this suite.
        PortalPort               = [int]$node.Port
        AllowSecureReplyfor      = [int]$node.AllowSecureReplyfor
        KeepUnusedPassFor        = [int]$node.KeepUnusedPassFor
        AllowPassRegistrationFor = [int]$node.AllowPassRegistrationFor
        SendNotifcationErrorTo   = [string]$node.SendNotifcationErrorTo
    }
}

<#
.SYNOPSIS
    Updates the MTA SPX configuration of a Sophos Firewall.

.DESCRIPTION
    Changes the global SPX template, the password-registration portal settings or the
    notification-on-error behaviour of MTASPXConfiguration. This is a full-replace singleton:
    the cmdlet reads the current settings first and sends them back complete, so a field you do
    not pass keeps its current value. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with write permission.

    MTASPXConfiguration has a same-named counterpart on the Legacy Email side,
    SPXConfiguration - both start out holding identical values on a fresh appliance, which
    could be mistaken for shared storage. It is not: raising -AllowPassRegistrationFor by one
    day here and reading SPXConfiguration back afterwards left SPXConfiguration at its old
    value. The two are independent objects that merely start out equal; a write to one is
    confirmed NOT to reach the other.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER DefaultSPXTemplate
    Optional. Name of the SPXTemplate/MTASPXTemplate object used as the global default. If
    omitted, the current value is kept.

.PARAMETER HostName
    Optional. IP address or domain name on which the password-registration portal is hosted,
    replacing the current value. If omitted, the current value is kept.

.PARAMETER AllowedNetwork
    Optional. Networks from which password-registration requests are accepted, replacing the
    current list. If omitted, the current list is kept. Pass an empty array to clear it.
    Clearing it (the only outcome measured to work) is safe; no value shape for a non-empty
    list was found to be accepted on this firmware - a plain address, a CIDR address and a
    space-separated address/netmask pair were all rejected with the same "Configuration
    parameters validation failed" error naming this exact field, so passing a non-empty list
    here is unconfirmed and may throw.

.PARAMETER PortalPort
    Optional. TCP port the SPX password-registration portal listens on (1025-65535), replacing
    the current value. If omitted, the current value is kept. Named PortalPort, not Port, to
    avoid a collision with the -Port connection parameter below - the wire element is Port.

.PARAMETER AllowSecureReplyfor
    Optional. Maximum number of days in which a recipient can securely reply to an
    SPX-encrypted email through the SPX Reply Portal, replacing the current value. If omitted,
    the current value is kept.

.PARAMETER KeepUnusedPassFor
    Optional. Expiry time, in days, of an unused password, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER AllowPassRegistrationFor
    Optional. Number of days after which the link to the password-registration portal expires,
    replacing the current value. If omitted, the current value is kept.

.PARAMETER SendNotifcationErrorTo
    Optional. Who is notified when an SPX error occurs, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosMTASPXConfiguration -AllowPassRegistrationFor 14 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMTASPXConfiguration -SendNotifcationErrorTo Nobody

    Stops sending SPX error notifications. Every other field keeps its current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaspxconfiguration/operations/UpdateSPXConfiguration.html

.LINK
    Get-SfosMTASPXConfiguration
#>
function Set-SfosMTASPXConfiguration {
    # PSUseSingularNouns is suppressed on purpose. 'Configuration' is not a plural container
    # here but the name of the entity itself - the API element is <MTASPXConfiguration>, a
    # singleton holding one configuration, with no <MTASPXConfiguration...s> child to fall back
    # to. The Sophos spelling goes above PowerShell habit here, as it does for every other
    # settings singleton in this module family.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$DefaultSPXTemplate,
        [string]$HostName,
        [string[]]$AllowedNetwork,
        [ValidateRange(1025, 65535)]
        [int]$PortalPort,
        [int]$AllowSecureReplyfor,
        [int]$KeepUnusedPassFor,
        [int]$AllowPassRegistrationFor,
        [ValidateSet('SenderOnly', 'Nobody')]
        [string]$SendNotifcationErrorTo,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosMTASPXConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetDefaultSPXTemplate = if ($bp.ContainsKey('DefaultSPXTemplate')) { $DefaultSPXTemplate } else { $existing.DefaultSPXTemplate }
    $targetHostName = if ($bp.ContainsKey('HostName')) { $HostName } else { $existing.HostName }
    $targetAllowedNetworks = @(if ($bp.ContainsKey('AllowedNetwork')) { $AllowedNetwork } else { $existing.AllowedNetwork })
    $targetPortalPort = if ($bp.ContainsKey('PortalPort')) { $PortalPort } else { $existing.PortalPort }
    $targetAllowSecureReplyfor = if ($bp.ContainsKey('AllowSecureReplyfor')) { $AllowSecureReplyfor } else { $existing.AllowSecureReplyfor }
    $targetKeepUnusedPassFor = if ($bp.ContainsKey('KeepUnusedPassFor')) { $KeepUnusedPassFor } else { $existing.KeepUnusedPassFor }
    $targetAllowPassRegistrationFor = if ($bp.ContainsKey('AllowPassRegistrationFor')) { $AllowPassRegistrationFor } else { $existing.AllowPassRegistrationFor }
    $targetSendNotifcationErrorTo = if ($bp.ContainsKey('SendNotifcationErrorTo')) { $SendNotifcationErrorTo } else { $existing.SendNotifcationErrorTo }

    if (-not $PSCmdlet.ShouldProcess("MTASPXConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    # Loop variable deliberately not named $allowedNetwork: PowerShell variable names are
    # case-insensitive, and that would collide with the [string[]]$AllowedNetwork parameter.
    $networksXml = ''
    foreach ($networkValue in $targetAllowedNetworks) {
        if (-not $networkValue) {
            continue
        }
        $networkEsc = ConvertTo-SfosXmlEscaped -Text $networkValue
        $networksXml += "<Network>$networkEsc</Network>"
    }

    $inner = @"
<Set operation="update">
  <MTASPXConfiguration>
    <SPXGlobalTemplate>
      <DefaultSPXTemplate>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDefaultSPXTemplate))</DefaultSPXTemplate>
    </SPXGlobalTemplate>
    <HostName>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetHostName))</HostName>
    <AllowedNetworks>$networksXml</AllowedNetworks>
    <Port>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetPortalPort))</Port>
    <AllowSecureReplyfor>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetAllowSecureReplyfor))</AllowSecureReplyfor>
    <KeepUnusedPassFor>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetKeepUnusedPassFor))</KeepUnusedPassFor>
    <AllowPassRegistrationFor>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetAllowPassRegistrationFor))</AllowPassRegistrationFor>
    <SendNotifcationErrorTo>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetSendNotifcationErrorTo))</SendNotifcationErrorTo>
  </MTASPXConfiguration>
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
        throw "Error updating MTASPXConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTASPXConfiguration' -Action 'update'
}

#endregion

#region MTASPXTemplate

<#
.SYNOPSIS
    Retrieves MTA SPX templates from a Sophos Firewall.

.DESCRIPTION
    Returns MTASPXTemplates objects (PROTECT > Email (MTA) > SPX > Templates): the
    branding, encryption and notification text used when an email is SPX-encrypted. At least
    one object, "Default Template", always exists.

    This entity has a same-named counterpart on the Legacy Email side, SPXTemplates, and both
    start out holding the one factory object "Default Template" with identical content. They
    are separate stored lists, not one list seen through two roots: a template created through
    this cmdlet does not appear on the Legacy side, and vice versa - see New-SfosMTASPXTemplate
    for the write test that established this.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

    This object belongs to MTA mode. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. This is a
    substring match, not a wildcard pattern, sent to the firewall as a server-side pre-filter
    and re-applied client-side. If omitted, every object is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per template, with the properties
    Name, Description, OrganizationName, PDFEncryption, PageSize, PasswordType,
    NotificationSubject, NotificationBody, InstructionsForRecipient, SPXReplyPortal and
    IncludeOriginalBodyIntoReply. NotificationSubject/NotificationBody come back empty on a
    template whose PasswordType does not use them - the firewall omits the fields rather than
    returning them blank. Returns System.Xml.XmlElement when -AsXml is used, and an empty array
    when no object matches.

.EXAMPLE
    Get-SfosMTASPXTemplate

    Lists every MTA SPX template on the firewall of the current connection.

.EXAMPLE
    Get-SfosMTASPXTemplate -NameLike 'Default'

    Lists every MTA SPX template whose name contains 'Default'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaspxtemplates/mtaspxtemplates.html

.LINK
    New-SfosMTASPXTemplate
#>
function Get-SfosMTASPXTemplate {
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
  <MTASPXTemplates>
    $filterXml
  </MTASPXTemplates>
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
        throw "Error retrieving MTASPXTemplates objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTASPXTemplates' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/MTASPXTemplates[Name]' | ForEach-Object -Process { $_.Node }

    $templateObjects = foreach ($node in @($nodes)) {
        [PSCustomObject]@{
            Name                         = [string]$node.Name
            Description                  = [string]$node.Description
            OrganizationName             = [string]$node.OrganizationName
            PDFEncryption                = [string]$node.PDFEncryption
            PageSize                     = [string]$node.PageSize
            PasswordType                 = [string]$node.PasswordType
            NotificationSubject          = [string]$node.NotificationSubject
            NotificationBody             = [string]$node.NotificationBody
            InstructionsForRecipient     = [string]$node.InstructionsForRecipient
            SPXReplyPortal               = [string]$node.SPXReplyPortal
            IncludeOriginalBodyIntoReply = [string]$node.IncludeOriginalBodyIntoReply
        }
    }

    $templateObjects = @($templateObjects)
    if ($NameLike) {
        $templateObjects = @($templateObjects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }

    if ($AsXml) {
        $keptNames = @($templateObjects | ForEach-Object -Process { $_.Name })
        return @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    return $templateObjects
}

<#
.SYNOPSIS
    Creates an MTA SPX template on a Sophos Firewall.

.DESCRIPTION
    Creates a new MTASPXTemplates object (PROTECT > Email (MTA) > SPX > Templates). It
    needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with write permission for the Email (MTA) area.

    This entity has a same-named counterpart on the Legacy Email side, SPXTemplates. They are
    separate stored lists: a template created through this cmdlet was confirmed absent from a
    same-name filter on the Legacy side afterwards. The reverse direction could not be
    established the same way - every Add attempted directly against the Legacy SPXTemplates
    root during this measurement failed with a generic error unrelated to this question
    (nothing was created, confirmed by reading it back), so there is no Legacy-side template to
    check for on this root. Nothing suggests the two share storage; the one-direction result is
    reported as what it is.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name to uniquely identify the template.

.PARAMETER Description
    Optional. Free-text description of the template.

.PARAMETER OrganizationName
    Optional. Organization name shown in the email notification.

.PARAMETER PDFEncryption
    Optional. Encryption standard of the generated PDF. If omitted, the firewall applies its
    own default.

.PARAMETER PageSize
    Optional. Page size of the generated PDF. If omitted, the firewall applies its own default.

.PARAMETER PasswordType
    Optional. How the password for the encrypted message is generated. If omitted, the
    firewall applies its own default.

.PARAMETER NotificationSubject
    Optional. Subject of the notification email. Only applied when -PasswordType is
    'GeneratedOneTimePasswordForEveryEmail', 'GeneratedAndStoredForRecipient' or
    'SpecifiedByRecipient'.

.PARAMETER NotificationBody
    Optional. HTML body of the notification email. Same -PasswordType restriction as
    -NotificationSubject. Write the markup entity-encoded if you need angle brackets in a
    literal PowerShell example; this parameter itself accepts plain HTML text.

.PARAMETER InstructionsForRecipient
    Optional. HTML instructions shown to the recipient of the SPX-encrypted email.

.PARAMETER SPXReplyPortal
    Optional. Whether the recipient can reply through the SPX Reply Portal. If omitted, the
    firewall applies its own default ('Disabled').

.PARAMETER IncludeOriginalBodyIntoReply
    Optional. Whether the original message body is included in a portal reply. If omitted, the
    firewall applies its own default ('Disabled').

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    New-SfosMTASPXTemplate -Name 'PartnerTemplate' -PDFEncryption 'AES/256' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosMTASPXTemplate -Name 'PartnerTemplate' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender'

    Creates a template for a partner organization. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaspxtemplates/operations/AddSPXTemplate%26UpdateSPXTemplate.html

.LINK
    Get-SfosMTASPXTemplate
#>
function New-SfosMTASPXTemplate {
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives here: Username/Password are the fixed connection parameters every write
    # cmdlet in this suite takes, and PasswordType is the wire field naming how the SPX
    # message password is generated (an enum, not a credential).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordType')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Description,
        [string]$OrganizationName,

        [ValidateSet('AES/128', 'AES/256')]
        [string]$PDFEncryption,

        [ValidateSet('A/4', 'Letter', 'Legal')]
        [string]$PageSize,

        [ValidateSet('SpecifiedBySender', 'GeneratedOneTimePasswordForEveryEmail', 'GeneratedAndStoredForRecipient', 'SpecifiedByRecipient')]
        [string]$PasswordType,

        [string]$NotificationSubject,
        [string]$NotificationBody,
        [string]$InstructionsForRecipient,

        [ValidateSet('Disabled', 'Enable')]
        [string]$SPXReplyPortal,

        [ValidateSet('Disabled', 'Enable')]
        [string]$IncludeOriginalBodyIntoReply,

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
        if (-not $PSCmdlet.ShouldProcess("MTASPXTemplate '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $bp = $PSBoundParameters

        $fieldsXml = ''
        if ($bp.ContainsKey('Description')) { $fieldsXml += "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>" }
        if ($bp.ContainsKey('OrganizationName')) { $fieldsXml += "<OrganizationName>$(ConvertTo-SfosXmlEscaped -Text $OrganizationName)</OrganizationName>" }
        if ($bp.ContainsKey('PDFEncryption')) { $fieldsXml += "<PDFEncryption>$(ConvertTo-SfosXmlEscaped -Text $PDFEncryption)</PDFEncryption>" }
        if ($bp.ContainsKey('PageSize')) { $fieldsXml += "<PageSize>$(ConvertTo-SfosXmlEscaped -Text $PageSize)</PageSize>" }
        if ($bp.ContainsKey('PasswordType')) { $fieldsXml += "<PasswordType>$(ConvertTo-SfosXmlEscaped -Text $PasswordType)</PasswordType>" }
        if ($bp.ContainsKey('NotificationSubject')) { $fieldsXml += "<NotificationSubject>$(ConvertTo-SfosXmlEscaped -Text $NotificationSubject)</NotificationSubject>" }
        if ($bp.ContainsKey('NotificationBody')) { $fieldsXml += "<NotificationBody>$(ConvertTo-SfosXmlEscaped -Text $NotificationBody)</NotificationBody>" }
        if ($bp.ContainsKey('InstructionsForRecipient')) { $fieldsXml += "<InstructionsForRecipient>$(ConvertTo-SfosXmlEscaped -Text $InstructionsForRecipient)</InstructionsForRecipient>" }
        if ($bp.ContainsKey('SPXReplyPortal')) { $fieldsXml += "<SPXReplyPortal>$(ConvertTo-SfosXmlEscaped -Text $SPXReplyPortal)</SPXReplyPortal>" }
        if ($bp.ContainsKey('IncludeOriginalBodyIntoReply')) { $fieldsXml += "<IncludeOriginalBodyIntoReply>$(ConvertTo-SfosXmlEscaped -Text $IncludeOriginalBodyIntoReply)</IncludeOriginalBodyIntoReply>" }

        $inner = @"
<Set operation="add">
  <MTASPXTemplates>
    <Name>$nameEsc</Name>
    $fieldsXml
  </MTASPXTemplates>
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
            throw "Failed to create MTASPXTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTASPXTemplates' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an existing MTA SPX template on a Sophos Firewall.

.DESCRIPTION
    Changes fields of an existing MTASPXTemplates object. This is a full-replace entity: the
    cmdlet reads the current object first and sends it back complete, so a field you do not
    pass keeps its current value. It first confirms the named object exists and throws a clear
    "was not found" error if it does not.

    This entity has a same-named counterpart on the Legacy Email side, SPXTemplates, both
    starting out with the factory object "Default Template" holding identical content. They are
    separate stored lists, not one list seen through two roots - see New-SfosMTASPXTemplate for
    the write test that established this. That test used a new object, not "Default Template"
    itself, which this module never writes to or removes.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email (MTA) area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing MTASPXTemplates object to update.

.PARAMETER Description
    Optional. Free-text description of the template, replacing the current value. If omitted,
    the current value is kept.

.PARAMETER OrganizationName
    Optional. Organization name shown in the email notification, replacing the current value.
    If omitted, the current value is kept.

.PARAMETER PDFEncryption
    Optional. Encryption standard of the generated PDF, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER PageSize
    Optional. Page size of the generated PDF, replacing the current value. If omitted, the
    current value is kept.

.PARAMETER PasswordType
    Optional. How the password for the encrypted message is generated, replacing the current
    value. If omitted, the current value is kept.

.PARAMETER NotificationSubject
    Optional. Subject of the notification email, replacing the current value. If omitted, the
    current value is kept.

.PARAMETER NotificationBody
    Optional. HTML body of the notification email, replacing the current value. If omitted,
    the current value is kept.

.PARAMETER InstructionsForRecipient
    Optional. HTML instructions shown to the recipient, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER SPXReplyPortal
    Optional. Whether the recipient can reply through the SPX Reply Portal, replacing the
    current value. If omitted, the current value is kept.

.PARAMETER IncludeOriginalBodyIntoReply
    Optional. Whether the original message body is included in a portal reply, replacing the
    current value. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts the object name by property name, for
    example from Get-SfosMTASPXTemplate.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update or
    if the named object does not exist.

.EXAMPLE
    Set-SfosMTASPXTemplate -Name 'PartnerTemplate' -OrganizationName 'Renamed Org' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMTASPXTemplate -Name 'PartnerTemplate' -PageSize 'A/4'

    Changes the page size of an existing template. Every other field keeps its current value.
    The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaspxtemplates/operations/AddSPXTemplate%26UpdateSPXTemplate.html

.LINK
    Get-SfosMTASPXTemplate
#>
function Set-SfosMTASPXTemplate {
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives here: Username/Password are the fixed connection parameters every write
    # cmdlet in this suite takes, and PasswordType is the wire field naming how the SPX
    # message password is generated (an enum, not a credential).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordType')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Description,
        [string]$OrganizationName,

        [ValidateSet('AES/128', 'AES/256')]
        [string]$PDFEncryption,

        [ValidateSet('A/4', 'Letter', 'Legal')]
        [string]$PageSize,

        [ValidateSet('SpecifiedBySender', 'GeneratedOneTimePasswordForEveryEmail', 'GeneratedAndStoredForRecipient', 'SpecifiedByRecipient')]
        [string]$PasswordType,

        [string]$NotificationSubject,
        [string]$NotificationBody,
        [string]$InstructionsForRecipient,

        [ValidateSet('Disabled', 'Enable')]
        [string]$SPXReplyPortal,

        [ValidateSet('Disabled', 'Enable')]
        [string]$IncludeOriginalBodyIntoReply,

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
        $existing = @(Get-SfosMTASPXTemplate -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The MTASPXTemplate object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("MTASPXTemplate '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $bp = $PSBoundParameters
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetOrganizationName = if ($bp.ContainsKey('OrganizationName')) { $OrganizationName } else { [string]$existing[0].OrganizationName }
        $targetPDFEncryption = if ($bp.ContainsKey('PDFEncryption')) { $PDFEncryption } else { [string]$existing[0].PDFEncryption }
        $targetPageSize = if ($bp.ContainsKey('PageSize')) { $PageSize } else { [string]$existing[0].PageSize }
        $targetPasswordType = if ($bp.ContainsKey('PasswordType')) { $PasswordType } else { [string]$existing[0].PasswordType }
        $targetNotificationSubject = if ($bp.ContainsKey('NotificationSubject')) { $NotificationSubject } else { [string]$existing[0].NotificationSubject }
        $targetNotificationBody = if ($bp.ContainsKey('NotificationBody')) { $NotificationBody } else { [string]$existing[0].NotificationBody }
        $targetInstructionsForRecipient = if ($bp.ContainsKey('InstructionsForRecipient')) { $InstructionsForRecipient } else { [string]$existing[0].InstructionsForRecipient }
        $targetSPXReplyPortal = if ($bp.ContainsKey('SPXReplyPortal')) { $SPXReplyPortal } else { [string]$existing[0].SPXReplyPortal }
        $targetIncludeOriginalBodyIntoReply = if ($bp.ContainsKey('IncludeOriginalBodyIntoReply')) { $IncludeOriginalBodyIntoReply } else { [string]$existing[0].IncludeOriginalBodyIntoReply }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Set operation="update">
  <MTASPXTemplates>
    <Name>$nameEsc</Name>
    <Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>
    <OrganizationName>$(ConvertTo-SfosXmlEscaped -Text $targetOrganizationName)</OrganizationName>
    <PDFEncryption>$(ConvertTo-SfosXmlEscaped -Text $targetPDFEncryption)</PDFEncryption>
    <PageSize>$(ConvertTo-SfosXmlEscaped -Text $targetPageSize)</PageSize>
    <PasswordType>$(ConvertTo-SfosXmlEscaped -Text $targetPasswordType)</PasswordType>
    <NotificationSubject>$(ConvertTo-SfosXmlEscaped -Text $targetNotificationSubject)</NotificationSubject>
    <NotificationBody>$(ConvertTo-SfosXmlEscaped -Text $targetNotificationBody)</NotificationBody>
    <InstructionsForRecipient>$(ConvertTo-SfosXmlEscaped -Text $targetInstructionsForRecipient)</InstructionsForRecipient>
    <SPXReplyPortal>$(ConvertTo-SfosXmlEscaped -Text $targetSPXReplyPortal)</SPXReplyPortal>
    <IncludeOriginalBodyIntoReply>$(ConvertTo-SfosXmlEscaped -Text $targetIncludeOriginalBodyIntoReply)</IncludeOriginalBodyIntoReply>
  </MTASPXTemplates>
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
            throw "Failed to update MTASPXTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTASPXTemplates' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an MTA SPX template from a Sophos Firewall.

.DESCRIPTION
    Removes an MTASPXTemplates object. The cmdlet reads the object first and throws a clear
    "was not found" error for a name that does not exist, rather than forwarding the firewall's
    own answer for that case - this area of the API is measured to report a false success (code
    200) for a Remove on a non-existent name of a related entity, and the same shape of request
    is used here.

    Never remove a template that is still referenced as the global default
    (Get-SfosMTASPXConfiguration -> DefaultSPXTemplate) or by an active SPX policy; the firewall
    documents a dedicated failure code for exactly that case.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email (MTA) area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    System.Management.Automation.PSCustomObject. Accepts the object name by property name, for
    example from Get-SfosMTASPXTemplate.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal
    or if the named object does not exist.

.EXAMPLE
    Remove-SfosMTASPXTemplate -Name 'PartnerTemplate' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosMTASPXTemplate -Name 'PartnerTemplate'

    Removes the named object. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/mtaspxtemplates/operations/Delete%20SPX%20Template.html

.LINK
    Get-SfosMTASPXTemplate
#>
function Remove-SfosMTASPXTemplate {
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
        $existing = @(Get-SfosMTASPXTemplate -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The MTASPXTemplate object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("MTASPXTemplate '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><MTASPXTemplates><Name>$nameEsc</Name></MTASPXTemplates></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove MTASPXTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MTASPXTemplates' -Action 'remove' -Target $Name
    }
}

#endregion

#region AdvancedSMTPSetting

<#
.SYNOPSIS
    Retrieves the advanced SMTP settings of a Sophos Firewall.

.DESCRIPTION
    Returns the AdvancedSMTPSetting singleton (PROTECT > Email (MTA) > Advanced >
    MTA/SMTP): HELO/RDNS validation, outbound scanning, the firewall-rule relation for inbound
    mail, and the BATV secret. There is exactly one instance of this object per firewall. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

    The BATV secret itself is never returned in clear text - the firewall answers it hashed,
    freshly salted on every read, so hash equality cannot be used to detect "unchanged". This
    cmdlet exposes it as BATVSecretHash/BATVSecretHashForm, not as BATVSecret, to make clear
    neither is the plaintext; Set-SfosAdvancedSMTPSetting resends this hash to preserve the
    secret when -BATVSecret is not passed.

    This object belongs to MTA mode. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. An object with the properties
    RejectInvalidHELOorMissingRDNS, ScanOutboundEmails, DoStrictRDNSchecks,
    FirewallRelateInboundMails, BATVSecretHash and BATVSecretHashForm.
    FirewallRelateInboundMails carries the values 'Turn on'/'Turn off' on this firmware, not
    'Enable'/'Disable' as the vendor's own attribute table states for one operation page and
    not another - the two disagree, and the value observed on the wire is what this cmdlet
    validates against. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosAdvancedSMTPSetting

    Returns the current advanced SMTP settings.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/advancedsmtpsetting/advancedsmtpsetting.html

.LINK
    Set-SfosAdvancedSMTPSetting
#>
function Get-SfosAdvancedSMTPSetting {
    # PSUseSingularNouns is suppressed on purpose. 'Setting' is already singular, but this
    # function shares the region's naming rationale with Get-SfosMTASPXConfiguration: the API
    # element <AdvancedSMTPSetting> is the entity's own name, a singleton with no plural
    # container, and the Sophos spelling goes above PowerShell habit here as it does for every
    # other settings singleton in this module family.
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

    $inner = '<Get><AdvancedSMTPSetting></AdvancedSMTPSetting></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AdvancedSMTPSetting: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdvancedSMTPSetting' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/AdvancedSMTPSetting')
    if (-not $node) {
        throw 'AdvancedSMTPSetting could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $secretNode = $node.SelectSingleNode('BATVsecret')

    return [PSCustomObject]@{
        RejectInvalidHELOorMissingRDNS = [string]$node.RejectInvalidHELOorMissingRDNS
        ScanOutboundEmails             = [string]$node.ScanOutboundEmails
        DoStrictRDNSchecks             = [string]$node.DoStrictRDNSchecks
        FirewallRelateInboundMails     = [string]$node.FirewallRelateInboundMails
        BATVSecretHash                 = if ($secretNode) { $secretNode.InnerText } else { '' }
        BATVSecretHashForm             = if ($secretNode) { $secretNode.GetAttribute('hashform') } else { '' }
    }
}

<#
.SYNOPSIS
    Updates the advanced SMTP settings of a Sophos Firewall.

.DESCRIPTION
    Changes HELO/RDNS validation, outbound scanning, the firewall-rule relation for inbound
    mail, or the BATV secret. This is a full-replace singleton: the cmdlet reads the current
    settings first and sends them back complete, so a field you do not pass keeps its current
    value.

    The BATV secret cannot be read back in clear text (see Get-SfosAdvancedSMTPSetting), so when
    -BATVSecret is not passed this cmdlet resends the hashed value together with its hashform
    attribute - confirmed live to be accepted by the firewall as "leave the secret unchanged".

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email (MTA) area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER RejectInvalidHELOorMissingRDNS
    Optional. Rejects hosts that send invalid HELO/EHLO arguments or lack RDNS entries,
    replacing the current value. If omitted, the current value is kept.

.PARAMETER ScanOutboundEmails
    Optional. Scans all outgoing email traffic, replacing the current value. If omitted, the
    current value is kept.

.PARAMETER DoStrictRDNSchecks
    Optional. Additionally rejects emails from hosts with invalid RDNS records, replacing the
    current value. If omitted, the current value is kept.

.PARAMETER FirewallRelateInboundMails
    Optional. Relates firewall rules on inbound mail, replacing the current value. If omitted,
    the current value is kept. The values are 'Turn on'/'Turn off' on this firmware - see
    Get-SfosAdvancedSMTPSetting.

.PARAMETER BATVSecret
    Optional. New BATV secret, as a SecureString. If omitted, the current secret is preserved
    by resending its hash.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    (MTA) area. If omitted, the value from the current connection is used.

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
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosAdvancedSMTPSetting -ScanOutboundEmails Enable -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosAdvancedSMTPSetting -DoStrictRDNSchecks Enable

    Turns on strict RDNS checks. The BATV secret and every other field keep their current
    value. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/advancedsmtpsetting/operations/UpdateAdvancedSMTPSetting.html

.LINK
    Get-SfosAdvancedSMTPSetting
#>
function Set-SfosAdvancedSMTPSetting {
    # PSUseSingularNouns is suppressed on purpose - see the matching comment in
    # Get-SfosAdvancedSMTPSetting.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$RejectInvalidHELOorMissingRDNS,

        [ValidateSet('Enable', 'Disable')]
        [string]$ScanOutboundEmails,

        [ValidateSet('Enable', 'Disable')]
        [string]$DoStrictRDNSchecks,

        [ValidateSet('Turn on', 'Turn off')]
        [string]$FirewallRelateInboundMails,

        [SecureString]$BATVSecret,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdvancedSMTPSetting -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetReject = if ($bp.ContainsKey('RejectInvalidHELOorMissingRDNS')) { $RejectInvalidHELOorMissingRDNS } else { $existing.RejectInvalidHELOorMissingRDNS }
    $targetScan = if ($bp.ContainsKey('ScanOutboundEmails')) { $ScanOutboundEmails } else { $existing.ScanOutboundEmails }
    $targetStrictRDNS = if ($bp.ContainsKey('DoStrictRDNSchecks')) { $DoStrictRDNSchecks } else { $existing.DoStrictRDNSchecks }
    $targetFirewallRelate = if ($bp.ContainsKey('FirewallRelateInboundMails')) { $FirewallRelateInboundMails } else { $existing.FirewallRelateInboundMails }

    if (-not $PSCmdlet.ShouldProcess("AdvancedSMTPSetting on $($params.Firewall)", 'Update')) {
        return
    }

    if ($bp.ContainsKey('BATVSecret')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($BATVSecret)
        try {
            $plainSecret = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
        $secretXml = "<BATVsecret>$(ConvertTo-SfosXmlEscaped -Text $plainSecret)</BATVsecret>"
    }
    elseif ($existing.BATVSecretHash) {
        # Preserve the existing secret by resending its hashed form with its hashform
        # attribute - accepted by the firewall as "unchanged" (see the region header).
        $hashEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.BATVSecretHash)
        $hashFormEsc = ConvertTo-SfosXmlEscaped -Text ([string]$existing.BATVSecretHashForm)
        $secretXml = "<BATVsecret hashform=`"$hashFormEsc`">$hashEsc</BATVsecret>"
    }
    else {
        throw 'Set-SfosAdvancedSMTPSetting cannot preserve the BATV secret: Get-SfosAdvancedSMTPSetting returned no existing hash to resend. Pass -BATVSecret explicitly.'
    }

    $inner = @"
<Set operation="update">
  <AdvancedSMTPSetting>
    <RejectInvalidHELOorMissingRDNS>$(ConvertTo-SfosXmlEscaped -Text $targetReject)</RejectInvalidHELOorMissingRDNS>
    <ScanOutboundEmails>$(ConvertTo-SfosXmlEscaped -Text $targetScan)</ScanOutboundEmails>
    <DoStrictRDNSchecks>$(ConvertTo-SfosXmlEscaped -Text $targetStrictRDNS)</DoStrictRDNSchecks>
    <FirewallRelateInboundMails>$(ConvertTo-SfosXmlEscaped -Text $targetFirewallRelate)</FirewallRelateInboundMails>
    $secretXml
  </AdvancedSMTPSetting>
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
        throw "Error updating AdvancedSMTPSetting: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdvancedSMTPSetting' -Action 'update'
}

#endregion

# SophosFirewall.Email - Baugruppe E: read-only cmdlets for entities that either
# intervene directly in mail flow (Relay, Smarthost, blocklist, DKIM) or answer every
# write with 545/MTAModeDisableCheck on this appliance's active MTA mode (AVASAddressGroup,
# SPXConfiguration, SPXTemplates, DataControlList), plus SMTPPolicy, whose Add path could
# not be brought to a success in nine measured variants. Requires SophosFirewall.Core to be
# imported and a connection from Connect-SfosFirewall (or explicit connection parameters).

#region RelaySettings

<#
.SYNOPSIS
    Retrieves the SMTP relay settings of a Sophos Firewall.

.DESCRIPTION
    Returns the RelaySettings singleton (PROTECT > Email (MTA) > Relay settings): which
    hosts and networks are allowed or blocked from relaying mail through the appliance, and
    whether authenticated relay is enabled.

    Relay settings govern which traffic the appliance forwards as mail, so a write here can
    open or close the relay for the whole environment. Only reading is implemented; there is
    no Set-SfosMailRelaySettings in this module.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties HostBased,
    UpstreamHost (each a nested object with AllowRelay and BlockRelay host/network lists) and
    AuthenticatedRelaySettings (AuthenticatedRelay plus a UsersOrGroups list). Missing lists
    come back as an empty array, never $null. Returns System.Xml.XmlElement when -AsXml is
    used.

.EXAMPLE
    Get-SfosMailRelaySettings

    Shows the current relay configuration of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/relaysettings/relaysettings.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosMailRelaySettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is the entity's own name -
    # the API element is <RelaySettings>, a singleton with no <RelaySetting> child - not a
    # plural container.
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

    $inner = '<Get><RelaySettings></RelaySettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving RelaySettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'RelaySettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/RelaySettings')
    if (-not $node) {
        throw 'RelaySettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $hostBasedNode = $node.SelectSingleNode('HostBased')
    $upstreamNode = $node.SelectSingleNode('UpstreamHost')
    $authNode = $node.SelectSingleNode('AuthenticatedRelaySettings')

    $hostBasedAllow = @()
    $hostBasedBlock = @()
    if ($hostBasedNode) {
        $hostBasedAllow = @($hostBasedNode.SelectNodes('AllowRelay/HostsOrNetworks/HostsOrNetwork') | ForEach-Object -Process { $_.InnerText })
        $hostBasedBlock = @($hostBasedNode.SelectNodes('BlockRelay/HostsOrNetworks/HostsOrNetwork') | ForEach-Object -Process { $_.InnerText })
    }

    $upstreamAllow = @()
    $upstreamBlock = @()
    if ($upstreamNode) {
        $upstreamAllow = @($upstreamNode.SelectNodes('AllowRelay/HostsOrNetworks/HostsOrNetwork') | ForEach-Object -Process { $_.InnerText })
        $upstreamBlock = @($upstreamNode.SelectNodes('BlockRelay/HostsOrNetworks/HostsOrNetwork') | ForEach-Object -Process { $_.InnerText })
    }

    $usersOrGroups = @()
    if ($authNode) {
        $usersOrGroups = @($authNode.SelectNodes('UsersOrGroups/*') | ForEach-Object -Process { $_.InnerText })
    }

    return [PSCustomObject]@{
        HostBased    = [PSCustomObject]@{
            AllowRelay = $hostBasedAllow
            BlockRelay = $hostBasedBlock
        }
        UpstreamHost = [PSCustomObject]@{
            AllowRelay = $upstreamAllow
            BlockRelay = $upstreamBlock
        }
        AuthenticatedRelaySettings = [PSCustomObject]@{
            AuthenticatedRelay = [string]$authNode.AuthenticatedRelay
            UsersOrGroups      = $usersOrGroups
        }
    }
}

#endregion

#region SmarthostSettings

<#
.SYNOPSIS
    Retrieves the smarthost settings of a Sophos Firewall.

.DESCRIPTION
    Returns the SmarthostSettings singleton (PROTECT > Email (MTA) > Smarthost): whether
    outbound mail is routed through an upstream smarthost, its port, and whether the
    appliance authenticates to it.

    Smarthost routing changes how the appliance delivers every outbound message, so a write
    here can silently break mail delivery. Only reading is implemented; there is no
    Set-SfosSmarthostSettings in this module.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties UseSmarthost,
    Port, AuthenticateDevicewithSmarthost, Username and Password (the value the firewall
    reports for this field - it may be an encrypted representation rather than plain text
    once a smarthost account is configured; unconfigured, both come back empty). Returns
    System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosSmarthostSettings

    Shows the current smarthost configuration of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/smarthostsetting/smarthostsetting.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosSmarthostSettings {
    # PSUseSingularNouns is suppressed on purpose. 'Settings' is the entity's own name -
    # the API element is <SmarthostSettings>, a singleton - not a plural container.
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

    $inner = '<Get><SmarthostSettings></SmarthostSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SmarthostSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SmarthostSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SmarthostSettings')
    if (-not $node) {
        throw 'SmarthostSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        UseSmarthost                     = [string]$node.UseSmarthost
        Port                             = [int]$node.Port
        AuthenticateDevicewithSmarthost  = [string]$node.AuthenticateDevicewithSmarthost
        Username                         = [string]$node.Username
        Password                         = [string]$node.Password
    }
}

#endregion

#region MtaBlockedSenders

<#
.SYNOPSIS
    Retrieves the MTA SMTP blocked-sender list of a Sophos Firewall.

.DESCRIPTION
    Returns the individual entries of the MTA blocked-sender list (PROTECT > Email (MTA) >
    Block list). Measured against a live appliance: with no addresses configured, the
    firewall answers the Get with no MtaBlockedSenders element at all and no status of any
    kind - not even a code-less one - so this cmdlet treats that shape as "no blocked
    senders" and returns an empty array rather than throwing.

    The blocked-sender list controls which senders are rejected outright, so a write here can
    silently drop mail. Only reading is implemented; there is no Set/New/Remove for this
    entity in this module.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per blocked sender, with the
    property EmailAddress. Returns an empty array when the list is empty (including the
    measured case where the firewall omits the entity entirely). Returns
    System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosMTABlockedSender

    Lists every entry of the MTA blocked-sender list. Returns an empty array if none are
    configured.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/smtpblockedemailaddresses/smtpblockedemailaddresses.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosMTABlockedSender {
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

    $inner = '<Get><MtaBlockedSenders></MtaBlockedSenders></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving MtaBlockedSenders: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'MtaBlockedSenders' -Action 'get'

    # No MtaBlockedSenders element at all is the measured "empty" shape on this entity - not
    # an error. The XPath below simply yields nothing in that case, same as when the element
    # exists but the wrapped list is empty.
    $addressNodes = @($XmlResponse.SelectNodes('/Response/MtaBlockedSenders/BlockedEmailAddresses/EmailAddress'))

    if ($AsXml) {
        return $addressNodes
    }

    return @($addressNodes | ForEach-Object -Process {
            [PSCustomObject]@{ EmailAddress = $_.InnerText }
        })
}

#endregion

#region DKIMSigning

<#
.SYNOPSIS
    Retrieves DKIM signing configurations of a Sophos Firewall.

.DESCRIPTION
    Returns DKIMSigning objects (PROTECT > Email (MTA) > DKIM > Signing): the per-domain DKIM
    selector and private signing key the appliance uses to sign outbound mail.

    A DKIMSigning object carries the domain's private signing key, so a write here changes
    what the appliance signs mail with. Only reading is implemented; there is no
    New-/Set-/Remove-SfosDKIMSigning in this module.

    Filtering by -DomainLike is applied client-side only. A server-side pre-filter on Domain
    was not sent because it could not be measured as effective - the entity holds no records
    on the appliance this module was built against, so a filtered and an unfiltered Get both
    answer "No. of records Zero." and a working filter cannot be told apart from an ignored
    one. Measure and add a server-side key once a populated appliance is available.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER DomainLike
    Optional. Returns only objects whose Domain contains the given text anywhere. This is a
    substring match, not a wildcard pattern, applied client-side. If omitted, every
    DKIMSigning object is returned.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per DKIMSigning entry, with the
    properties Domain, KeySelector and PrivateRSAKey. Returns System.Xml.XmlElement when
    -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosDKIMSigning

    Lists every DKIM signing configuration on the firewall of the current connection.

.EXAMPLE
    Get-SfosDKIMSigning -DomainLike 'example'

    Lists DKIM signing configurations whose domain contains 'example'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/dkimsigning/dkimsigning.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosDKIMSigning {
    [CmdletBinding()]
    param(
        [string]$DomainLike,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $inner = '<Get><DKIMSigning></DKIMSigning></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DKIMSigning objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DKIMSigning' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/DKIMSigning[Domain]'))

    $objects = @($nodes | ForEach-Object -Process {
            [PSCustomObject]@{
                Domain        = [string]$_.Domain
                KeySelector   = [string]$_.KeySelector
                PrivateRSAKey = [string]$_.PrivateRSAKey
            }
        })

    if ($DomainLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Domain -like "*$DomainLike*" })
        $keptDomains = @($objects | ForEach-Object -Process { $_.Domain })
        $nodes = @($nodes | Where-Object -FilterScript { $keptDomains -contains $_.Domain })
    }

    if ($AsXml) {
        return $nodes
    }

    return $objects
}

#endregion

#region DKIMVerification

<#
.SYNOPSIS
    Retrieves the DKIM verification settings of a Sophos Firewall.

.DESCRIPTION
    Returns the DKIMVerification singleton (PROTECT > Email (MTA) > DKIM > Verification):
    whether inbound DKIM verification is enabled and what action is taken for each failure
    case. Its property VerifactionStatus keeps the spelling the firewall uses on the wire
    (a typo in the API itself, not in this module).

    DKIM verification is part of the appliance's inbound spam/spoofing defence, so a write
    here changes what mail is accepted. Only reading is implemented; there is no
    Set-SfosDKIMVerification in this module.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties
    VerifactionStatus, ActionForVerifactionFail, ActionForSignatureInvalid and
    ActionForSignatureNotFound. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosDKIMVerification

    Shows the current DKIM verification configuration of the firewall of the current
    connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/dkimverification/dkimverification.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosDKIMVerification {
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

    $inner = '<Get><DKIMVerification></DKIMVerification></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving DKIMVerification: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DKIMVerification' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/DKIMVerification')
    if (-not $node) {
        throw 'DKIMVerification could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        VerifactionStatus          = [string]$node.VerifactionStatus
        ActionForVerifactionFail   = [string]$node.ActionForVerifactionFail
        ActionForSignatureInvalid  = [string]$node.ActionForSignatureInvalid
        ActionForSignatureNotFound = [string]$node.ActionForSignatureNotFound
    }
}

#endregion

#region SMTPPolicy

<#
.SYNOPSIS
    Retrieves SMTP policy profiles of a Sophos Firewall.

.DESCRIPTION
    Returns SMTPPolicy objects (PROTECT > Email (MTA) > Policies > SMTP), the per-domain
    profile that decides spam, malware, file-type and data-protection handling for mail
    addressed to a domain.

    Only Get-SfosSMTPPolicy is implemented. Nine measured variants of an Add request all
    failed validation on DomainList/DomainName - different domain values, with and without
    the wrapper element, single and dual entries, an unrelated element casing, and a
    domain already present in AntiSpamTrustedDomain - every one of them was rejected with
    the same field marked invalid, and the underlying cause was not found. New-SfosSMTPPolicy
    is deliberately not implemented until that is resolved.

    The nested field shapes below (SpamProtection/SpamProtectionStatus and so on) come from
    the validation error paths of that same failed Add request, not from a populated object -
    the entity holds no records on the appliance this module was built against. Filtering by
    -NameLike is sent to the firewall as a server-side pre-filter by analogy with the other
    Name-keyed entities in this module (measured to work there), then re-applied client-side
    regardless, so an unsupported or ignored server-side key cannot produce a wrong result.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

    This object belongs to MTA mode. Reading it works whichever mode the appliance runs;
    Get-SfosSMTPDeploymentMode says which one that is.

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
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per SMTPPolicy, with the
    properties Name, DomainName (array), SpamProtectionStatus, MalwareProtectionStatus,
    MalwareScanning, FiletypeFilterStatus, DataProtectionStatus, DropMessageGreaterThan,
    Action and SPXEncryption. Returns System.Xml.XmlElement when -AsXml is used, and an empty
    array when no object matches.

.EXAMPLE
    Get-SfosSMTPPolicy

    Lists every SMTP policy profile on the firewall of the current connection. Returns an
    empty array on an appliance where none is configured.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/smtpprofile/smtpprofile.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosSMTPPolicy {
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
  <SMTPPolicy>
    $filterXml
  </SMTPPolicy>
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
        throw "Error retrieving SMTPPolicy objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMTPPolicy' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/SMTPPolicy[Name]'))

    $objects = @($nodes | ForEach-Object -Process {
            $domainNames = @($_.SelectNodes('DomainList/DomainName') | ForEach-Object -Process { $_.InnerText })
            [PSCustomObject]@{
                Name                    = [string]$_.Name
                DomainName              = $domainNames
                SpamProtectionStatus    = [string]$_.SelectSingleNode('SpamProtection/SpamProtectionStatus').InnerText
                MalwareProtectionStatus = [string]$_.SelectSingleNode('MalwareProtection/MalwareProtectionStatus').InnerText
                MalwareScanning         = [string]$_.SelectSingleNode('MalwareProtection/MalwareScanning').InnerText
                FiletypeFilterStatus    = [string]$_.SelectSingleNode('FiletypeFilter/FiletypeFilterStatus').InnerText
                DataProtectionStatus    = [string]$_.SelectSingleNode('DataProtection/DataProtectionStatus').InnerText
                DropMessageGreaterThan  = [string]$_.DropMessageGreaterThan
                Action                  = [string]$_.Action
                SPXEncryption           = [string]$_.SPXEncryption
            }
        })

    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        $nodes = @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    if ($AsXml) {
        return $nodes
    }

    return $objects
}

#endregion

#region AVASAddressGroup

<#
.SYNOPSIS
    Retrieves address group objects of a Sophos Firewall.

.DESCRIPTION
    Returns AVASAddressGroup objects (PROTECT > Email > Address group), used by the legacy
    anti-spam engine as RBL, IP address or email address/domain lists.

    This is a legacy entity. Its MTA-mode counterpart is a separate object with its own
    storage, served by the MTAAddressGroup cmdlets in this module.

    Filtering by -NameLike is sent to the firewall as a server-side pre-filter and
    re-applied client-side; measured against a live appliance to actually narrow the result
    (a filter with no match answers "No. of records Zero.", not the full list).

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
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per AVASAddressGroup, with the
    properties Name, GroupType, Description, RBLName, IPAddressNetwork, EmailAddressDomain
    (each a list, populated only for the matching GroupType) and EmailImportType. Missing
    lists come back as an empty array, never $null. Returns System.Xml.XmlElement when
    -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosAVASAddressGroup

    Lists every address group on the firewall of the current connection.

.EXAMPLE
    Get-SfosAVASAddressGroup -NameLike 'RBL'

    Lists address groups whose name contains 'RBL'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/AddressGroup/AddressGroup.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosAVASAddressGroup {
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
  <AVASAddressGroup>
    $filterXml
  </AVASAddressGroup>
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
        throw "Error retrieving AVASAddressGroup objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AVASAddressGroup' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/AVASAddressGroup[Name]'))

    $objects = @($nodes | ForEach-Object -Process {
            [PSCustomObject]@{
                Name               = [string]$_.Name
                GroupType          = [string]$_.GroupType
                Description        = [string]$_.Description
                RBLName            = @($_.SelectNodes('RBLList/RBLName') | ForEach-Object -Process { $_.InnerText })
                IPAddressNetwork   = @($_.SelectNodes('IPAddressList/IPAddressNetwork') | ForEach-Object -Process { $_.InnerText })
                EmailAddressDomain = @($_.SelectNodes('EmailAddressList/EmailAddressDomain') | ForEach-Object -Process { $_.InnerText })
                EmailImportType    = [string]$_.EmailImportType
            }
        })

    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        $nodes = @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    if ($AsXml) {
        return $nodes
    }

    return $objects
}

#endregion

#region SPXConfiguration

<#
.SYNOPSIS
    Retrieves the SPX (Secure PDF Exchange) configuration of a Sophos Firewall.

.DESCRIPTION
    Returns the SPXConfiguration singleton (PROTECT > Email > SPX > Configuration): the
    default template, portal host name and port, and the pass-registration/notification
    behaviour of the legacy SPX engine.

    This is a legacy entity. Its MTA-mode counterpart is a separate object with its own
    storage, served by the MTASPXConfiguration cmdlets in this module.

    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element instead of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object with the properties
    DefaultSPXTemplate, HostName, Port, KeepUnusedPassFor, AllowPassRegistrationFor,
    SendNotifcationErrorTo (spelling as reported by the firewall) and AllowedNetworks (a
    list, empty when the firewall omits it). Returns System.Xml.XmlElement when -AsXml is
    used.

.EXAMPLE
    Get-SfosSPXConfiguration

    Shows the current SPX configuration of the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/spxconfiguration/spxconfiguration.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosSPXConfiguration {
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

    $inner = '<Get><SPXConfiguration></SPXConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SPXConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SPXConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SPXConfiguration')
    if (-not $node) {
        throw 'SPXConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $allowedNetworks = @($node.SelectNodes('AllowedNetworks/Network') | ForEach-Object -Process { $_.InnerText })

    return [PSCustomObject]@{
        DefaultSPXTemplate       = [string]$node.SelectSingleNode('SPXGlobalTemplate/DefaultSPXTemplate').InnerText
        HostName                 = [string]$node.HostName
        Port                     = [int]$node.Port
        KeepUnusedPassFor        = [string]$node.KeepUnusedPassFor
        AllowPassRegistrationFor = [string]$node.AllowPassRegistrationFor
        SendNotifcationErrorTo   = [string]$node.SendNotifcationErrorTo
        AllowedNetworks          = $allowedNetworks
    }
}

#endregion

#region SPXTemplates

<#
.SYNOPSIS
    Retrieves SPX (Secure PDF Exchange) templates of a Sophos Firewall.

.DESCRIPTION
    Returns SPXTemplates objects (PROTECT > Email > SPX > Templates), the notification and
    encryption templates used to deliver encrypted PDF messages via the legacy SPX engine.

    This is a legacy entity. Its MTA-mode counterpart is a separate object with its own
    storage, served by the MTASPXTemplates cmdlets in this module.

    Filtering by -NameLike is sent to the firewall as a server-side pre-filter and
    re-applied client-side; measured against a live appliance to actually narrow the result.

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
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per SPXTemplates entry, with the
    properties Name, Description, OrganizationName, PDFEncryption, PageSize, PasswordType,
    NotificationSubject, NotificationBody and InstructionsForRecipient (the latter two hold
    HTML; NotificationSubject/NotificationBody come back empty when the firewall omits them).
    Returns System.Xml.XmlElement when -AsXml is used, and an empty array when no object
    matches.

.EXAMPLE
    Get-SfosSPXTemplate

    Lists every SPX template on the firewall of the current connection.

.EXAMPLE
    Get-SfosSPXTemplate -NameLike 'Default'

    Lists SPX templates whose name contains 'Default'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/spxtemplates/spxtemplates.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosSPXTemplate {
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
  <SPXTemplates>
    $filterXml
  </SPXTemplates>
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
        throw "Error retrieving SPXTemplates objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SPXTemplates' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/SPXTemplates[Name]'))

    $objects = @($nodes | ForEach-Object -Process {
            [PSCustomObject]@{
                Name                      = [string]$_.Name
                Description               = [string]$_.Description
                OrganizationName          = [string]$_.OrganizationName
                PDFEncryption             = [string]$_.PDFEncryption
                PageSize                  = [string]$_.PageSize
                PasswordType              = [string]$_.PasswordType
                NotificationSubject       = [string]$_.NotificationSubject
                NotificationBody          = [string]$_.NotificationBody
                InstructionsForRecipient  = [string]$_.InstructionsForRecipient
            }
        })

    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        $nodes = @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    if ($AsXml) {
        return $nodes
    }

    return $objects
}

#endregion

#region DataControlList

<#
.SYNOPSIS
    Retrieves data control lists of a Sophos Firewall.

.DESCRIPTION
    Returns DataControlList objects (PROTECT > Email > Data control list), the legacy
    data-protection signature lists (postal addresses, financial information, and similar
    catalog categories).

    This is a legacy entity. Its MTA-mode counterpart is a separate object with its own
    storage, served by the MTADataControlList cmdlets in this module.

    Filtering by -NameLike is sent to the firewall as a server-side pre-filter by analogy
    with the other Name-keyed entities in this module (measured to work there), then
    re-applied client-side regardless, so an unsupported or ignored server-side key cannot
    produce a wrong result - it could not be independently confirmed here because the entity
    is empty on this appliance.

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
    Optional. User name for the API login. The account needs read permission for the Email
    area. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements instead of PowerShell objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per DataControlList entry, with
    the properties Name and Signature (a list of catalog signature names). Missing lists come
    back as an empty array, never $null. Returns System.Xml.XmlElement when -AsXml is used,
    and an empty array when no object matches.

.EXAMPLE
    Get-SfosDataControlList

    Lists every data control list on the firewall of the current connection. Returns an
    empty array on an appliance running in MTA mode, where this legacy entity holds no
    records.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/dataprotectionpolicy/dataprotectionpolicy.html

.LINK
    Connect-SfosFirewall
#>
function Get-SfosDataControlList {
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
  <DataControlList>
    $filterXml
  </DataControlList>
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
        throw "Error retrieving DataControlList objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataControlList' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/DataControlList[Name]'))

    $objects = @($nodes | ForEach-Object -Process {
            [PSCustomObject]@{
                Name      = [string]$_.Name
                Signature = @($_.SelectNodes('Signatures/Signature') | ForEach-Object -Process { $_.InnerText })
            }
        })

    if ($NameLike) {
        $objects = @($objects | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
        $keptNames = @($objects | ForEach-Object -Process { $_.Name })
        $nodes = @($nodes | Where-Object -FilterScript { $keptNames -contains $_.Name })
    }

    if ($AsXml) {
        return $nodes
    }

    return $objects
}

#endregion

#region SMTPPolicy

<#
.SYNOPSIS
    Builds the Set request body for an SMTPPolicy entity. Internal helper, not exported.

.DESCRIPTION
    Shared by New-SfosSMTPPolicy and Set-SfosSMTPPolicy so both send the same entity shape.
    Measured against a live firewall: the *Status fields must be nested in their own blocks
    (SpamProtection/SpamProtectionStatus, MalwareProtection/MalwareProtectionStatus and so
    on) - the flat layout the attribute table shows is rejected with status 501 naming every
    one of those paths as invalid. DomainList/DomainName does not take a domain literal; it
    takes the name of an existing MTAAddressGroup object (GroupType EmailAddressOrDomain).
    RouteBy is never sent - a measured attempt to set it explicitly (Static Host/DNS Host)
    was itself rejected as invalid, and the firewall assigns it on its own once a domain
    group is referenced. Every value is escaped through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the SMTP policy profile.

.PARAMETER DomainName
    One or more names of existing MTAAddressGroup objects (GroupType EmailAddressOrDomain)
    that this profile routes for.

.PARAMETER SpamProtectionStatus
    ON or OFF.

.PARAMETER MalwareProtectionStatus
    ON or OFF.

.PARAMETER MalwareScanning
    The malware scanning engine mode, for example 'Dual Anti-Virus'.

.PARAMETER FiletypeFilterStatus
    ON or OFF.

.PARAMETER DataProtectionStatus
    ON or OFF.

.PARAMETER DropMessageGreaterThan
    Message size threshold in KB above which a message is dropped. 0 means no threshold.

.PARAMETER Action
    The action taken for this profile, for example 'Accept'.

.PARAMETER SPXEncryption
    The SPX encryption mode, for example 'None'.
#>
function ConvertTo-SfosSMTPPolicyEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$DomainName,

        [Parameter(Mandatory)]
        [string]$SpamProtectionStatus,

        [Parameter(Mandatory)]
        [string]$MalwareProtectionStatus,

        [Parameter(Mandatory)]
        [string]$MalwareScanning,

        [Parameter(Mandatory)]
        [string]$FiletypeFilterStatus,

        [Parameter(Mandatory)]
        [string]$DataProtectionStatus,

        [Parameter(Mandatory)]
        [int]$DropMessageGreaterThan,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$SPXEncryption
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $domainItems = (@($DomainName | Where-Object -FilterScript { $_ }) | ForEach-Object -Process {
            "<DomainName>$(ConvertTo-SfosXmlEscaped -Text $_)</DomainName>"
        }) -join ''

    $spamStatusEsc = ConvertTo-SfosXmlEscaped -Text $SpamProtectionStatus
    $malwareStatusEsc = ConvertTo-SfosXmlEscaped -Text $MalwareProtectionStatus
    $malwareScanningEsc = ConvertTo-SfosXmlEscaped -Text $MalwareScanning
    $filetypeStatusEsc = ConvertTo-SfosXmlEscaped -Text $FiletypeFilterStatus
    $dataProtectionStatusEsc = ConvertTo-SfosXmlEscaped -Text $DataProtectionStatus
    $actionEsc = ConvertTo-SfosXmlEscaped -Text $Action
    $spxEncryptionEsc = ConvertTo-SfosXmlEscaped -Text $SPXEncryption

    return @"
<Set operation="$Operation">
  <SMTPPolicy>
    <Name>$nameEsc</Name>
    <DomainList>$domainItems</DomainList>
    <SpamProtection>
      <SpamProtectionStatus>$spamStatusEsc</SpamProtectionStatus>
    </SpamProtection>
    <MalwareProtection>
      <MalwareProtectionStatus>$malwareStatusEsc</MalwareProtectionStatus>
      <MalwareScanning>$malwareScanningEsc</MalwareScanning>
    </MalwareProtection>
    <FiletypeFilter>
      <FiletypeFilterStatus>$filetypeStatusEsc</FiletypeFilterStatus>
    </FiletypeFilter>
    <DataProtection>
      <DataProtectionStatus>$dataProtectionStatusEsc</DataProtectionStatus>
    </DataProtection>
    <DropMessageGreaterThan>$DropMessageGreaterThan</DropMessageGreaterThan>
    <Action>$actionEsc</Action>
    <SPXEncryption>$spxEncryptionEsc</SPXEncryption>
  </SMTPPolicy>
</Set>
"@
}

<#
.SYNOPSIS
    Creates an SMTP policy profile on a Sophos Firewall.

.DESCRIPTION
    Creates an SMTPPolicy object (PROTECT > Email (MTA) > Policies > SMTP), the per-domain
    profile that decides spam, malware, file-type and data-protection handling for mail
    addressed to a domain.

    -DomainName does not take a domain as text. It takes the name of an existing
    MTAAddressGroup object whose GroupType is EmailAddressOrDomain and whose members are the
    domains this profile applies to - build that group first with New-SfosMTAAddressGroup.
    A domain literal (even a real, resolvable one) is rejected by the firewall with status
    501 naming DomainList/DomainName as invalid; this was measured across nine variants of
    the value before the actual requirement (an object name) was found. Neither the
    attribute table nor the sample XML on the operation page documents this - both suggest a
    free-text domain.

    -MalwareScanning and -DropMessageGreaterThan default to the only values measured to work
    ('Dual Anti-Virus' and 0). The firewall's Get response for this entity never returns
    either field back (measured, independent of what was sent), so there is no way to read a
    different value off an existing object to use as a better-informed default - the values
    below are simply what a successful create used.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the policy profile. Maximum 50 characters.

.PARAMETER DomainName
    Required. One or more names of existing MTAAddressGroup objects (GroupType
    EmailAddressOrDomain) that this profile routes and scans for - not domain text itself.

.PARAMETER SpamProtectionStatus
    Required. ON or OFF.

.PARAMETER MalwareProtectionStatus
    Required. ON or OFF.

.PARAMETER MalwareScanning
    Optional. The malware scanning engine mode. Defaults to 'Dual Anti-Virus', the only value
    measured against a live firewall.

.PARAMETER FiletypeFilterStatus
    Required. ON or OFF.

.PARAMETER DataProtectionStatus
    Required. ON or OFF.

.PARAMETER DropMessageGreaterThan
    Optional. Message size threshold in KB above which a message is dropped. Defaults to 0
    (no threshold), the only value measured against a live firewall.

.PARAMETER Action
    Required. The action taken by this profile, for example 'Accept'. Only 'Accept' was
    exercised against a live firewall; other values from the vendor documentation were not
    tested.

.PARAMETER SPXEncryption
    Required. The SPX encryption mode for this profile, for example 'None'. Only 'None' was
    exercised against a live firewall; other values from the vendor documentation were not
    tested.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    New-SfosSMTPPolicy -Name 'PartnerDomainsPolicy' -DomainName 'PartnerDomainsGroup' -SpamProtectionStatus ON -MalwareProtectionStatus ON -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None -WhatIf

    Shows what the call would create without sending it to the firewall. PartnerDomainsGroup
    must already exist as an MTAAddressGroup with GroupType EmailAddressOrDomain, for example
    created with: New-SfosMTAAddressGroup -Name PartnerDomainsGroup -GroupType EmailAddressOrDomain -Member example.com

.EXAMPLE
    New-SfosSMTPPolicy -Name 'PartnerDomainsPolicy' -DomainName 'PartnerDomainsGroup' -SpamProtectionStatus ON -MalwareProtectionStatus ON -FiletypeFilterStatus OFF -DataProtectionStatus OFF -Action Accept -SPXEncryption None

    Creates a policy profile for the domains in the PartnerDomainsGroup address group, with
    spam and malware protection enabled. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/smtpprofile/operations/AddSMTPPolicy%26EditSMTPPolicy.html

.LINK
    Get-SfosSMTPPolicy
#>
function New-SfosSMTPPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$DomainName,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$SpamProtectionStatus,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$MalwareProtectionStatus,

        [string]$MalwareScanning = 'Dual Anti-Virus',

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$FiletypeFilterStatus,

        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$DataProtectionStatus,

        [int]$DropMessageGreaterThan = 0,

        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$SPXEncryption,

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
        if (-not @($DomainName | Where-Object -FilterScript { $_ }).Count) {
            throw "SMTPPolicy object '$Name' needs at least one -DomainName value naming an existing MTAAddressGroup object."
        }

        if (-not $PSCmdlet.ShouldProcess("SMTPPolicy '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosSMTPPolicyEntityXml -Operation 'add' -Name $Name -DomainName $DomainName `
            -SpamProtectionStatus $SpamProtectionStatus -MalwareProtectionStatus $MalwareProtectionStatus `
            -MalwareScanning $MalwareScanning -FiletypeFilterStatus $FiletypeFilterStatus `
            -DataProtectionStatus $DataProtectionStatus -DropMessageGreaterThan $DropMessageGreaterThan `
            -Action $Action -SPXEncryption $SPXEncryption

        # Deviation from the usual two-step try/catch: Assert-SfosApiReturnSuccess is folded
        # into the same try so a rejected DomainName (status 501) also gets the object-name
        # hint below, not just a transport failure from Invoke-SfosApi.
        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop

            $XmlResponse = [xml]$response.Content
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMTPPolicy' -Action 'create' -Target $Name
        }
        catch {
            throw "Failed to create SMTPPolicy object '$Name': $($_.Exception.Message) DomainName must name an existing MTAAddressGroup object (GroupType EmailAddressOrDomain), not a literal domain."
        }
    }
}

<#
.SYNOPSIS
    Updates an SMTP policy profile on a Sophos Firewall.

.DESCRIPTION
    Reads the named SMTPPolicy object first and writes back a complete entity, overriding
    only the fields you pass - this is a full-replace entity, so anything not read back and
    resent would be cleared. Confirmed against a live firewall with an unchanged round trip
    (read, write back unchanged, read again, compare raw XML - identical, including the
    RouteBy value the firewall assigns on its own).

    -MalwareScanning and -DropMessageGreaterThan are mandatory here, unlike every other field.
    The firewall's Get response for this entity never returns either value (measured), so
    there is nothing to read back and preserve - accepting them as optional would risk
    silently sending an unrelated value on every update of this entity, the same class of
    defect already found and fixed for WebFilterProtectionSettings/PharmingProtection. Making
    them mandatory forces you to state the value you want on every call instead.

    -DomainName is a name, not domain text - see New-SfosSMTPPolicy for the reasoning.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing policy profile to update.

.PARAMETER DomainName
    Optional. New list of MTAAddressGroup object names, replacing the current list. If
    omitted, the current list is kept.

.PARAMETER SpamProtectionStatus
    Optional. ON or OFF. If omitted, the current value is kept.

.PARAMETER MalwareProtectionStatus
    Optional. ON or OFF. If omitted, the current value is kept.

.PARAMETER MalwareScanning
    Required. The malware scanning engine mode. The firewall never returns the current value
    for this field, so it cannot be preserved automatically - state it on every update.

.PARAMETER FiletypeFilterStatus
    Optional. ON or OFF. If omitted, the current value is kept.

.PARAMETER DataProtectionStatus
    Optional. ON or OFF. If omitted, the current value is kept.

.PARAMETER DropMessageGreaterThan
    Required. Message size threshold in KB above which a message is dropped. The firewall
    never returns the current value for this field, so it cannot be preserved automatically -
    state it on every update.

.PARAMETER Action
    Optional. The action taken by this profile. If omitted, the current value is kept.

.PARAMETER SPXEncryption
    Optional. The SPX encryption mode for this profile. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    for example from Get-SfosSMTPPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update
    or if the named profile does not exist.

.EXAMPLE
    Set-SfosSMTPPolicy -Name 'PartnerDomainsPolicy' -MalwareScanning 'Dual Anti-Virus' -DropMessageGreaterThan 0 -SpamProtectionStatus OFF -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSMTPPolicy -Name 'PartnerDomainsPolicy' -MalwareScanning 'Dual Anti-Virus' -DropMessageGreaterThan 0 -SpamProtectionStatus OFF

    Turns spam protection off on the named profile, keeping every other field unchanged. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/smtpprofile/operations/AddSMTPPolicy%26EditSMTPPolicy.html

.LINK
    Get-SfosSMTPPolicy
#>
function Set-SfosSMTPPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$DomainName,

        [ValidateSet('ON', 'OFF')]
        [string]$SpamProtectionStatus,

        [ValidateSet('ON', 'OFF')]
        [string]$MalwareProtectionStatus,

        [Parameter(Mandatory)]
        [string]$MalwareScanning,

        [ValidateSet('ON', 'OFF')]
        [string]$FiletypeFilterStatus,

        [ValidateSet('ON', 'OFF')]
        [string]$DataProtectionStatus,

        [Parameter(Mandatory)]
        [int]$DropMessageGreaterThan,

        [string]$Action,
        [string]$SPXEncryption,

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
        $existing = @(Get-SfosSMTPPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SMTPPolicy object '$Name' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        $targetDomainName = if ($bp.ContainsKey('DomainName')) { $DomainName } else { $current.DomainName }
        if (-not @($targetDomainName | Where-Object -FilterScript { $_ }).Count) {
            throw "SMTPPolicy object '$Name' needs at least one -DomainName value naming an existing MTAAddressGroup object."
        }

        $targetSpamProtectionStatus = if ($bp.ContainsKey('SpamProtectionStatus')) { $SpamProtectionStatus } else { $current.SpamProtectionStatus }
        $targetMalwareProtectionStatus = if ($bp.ContainsKey('MalwareProtectionStatus')) { $MalwareProtectionStatus } else { $current.MalwareProtectionStatus }
        $targetFiletypeFilterStatus = if ($bp.ContainsKey('FiletypeFilterStatus')) { $FiletypeFilterStatus } else { $current.FiletypeFilterStatus }
        $targetDataProtectionStatus = if ($bp.ContainsKey('DataProtectionStatus')) { $DataProtectionStatus } else { $current.DataProtectionStatus }
        $targetAction = if ($bp.ContainsKey('Action')) { $Action } else { $current.Action }
        $targetSPXEncryption = if ($bp.ContainsKey('SPXEncryption')) { $SPXEncryption } else { $current.SPXEncryption }

        if (-not $PSCmdlet.ShouldProcess("SMTPPolicy '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosSMTPPolicyEntityXml -Operation 'update' -Name $Name -DomainName $targetDomainName `
            -SpamProtectionStatus $targetSpamProtectionStatus -MalwareProtectionStatus $targetMalwareProtectionStatus `
            -MalwareScanning $MalwareScanning -FiletypeFilterStatus $targetFiletypeFilterStatus `
            -DataProtectionStatus $targetDataProtectionStatus -DropMessageGreaterThan $DropMessageGreaterThan `
            -Action $targetAction -SPXEncryption $targetSPXEncryption

        # Deviation from the usual two-step try/catch: Assert-SfosApiReturnSuccess is folded
        # into the same try so a rejected DomainName (status 501) also gets the object-name
        # hint below, not just a transport failure from Invoke-SfosApi.
        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop

            $XmlResponse = [xml]$response.Content
            Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMTPPolicy' -Action 'update' -Target $Name
        }
        catch {
            throw "Failed to update SMTPPolicy object '$Name': $($_.Exception.Message) DomainName must name an existing MTAAddressGroup object (GroupType EmailAddressOrDomain), not a literal domain."
        }
    }
}

<#
.SYNOPSIS
    Removes an SMTP policy profile from a Sophos Firewall.

.DESCRIPTION
    Removes an SMTPPolicy object. This cmdlet reads the object first and throws "was not
    found" itself for a name that does not exist, rather than trusting the firewall's raw
    answer - several sibling entities in this area were measured to answer a removal of a
    non-existent object with a false success (status 200, nothing removed because nothing
    existed), and this cmdlet does not assume SMTPPolicy behaves differently without having
    measured it.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to MTA mode. Writing to it can be refused with status 545 while the
    appliance runs legacy mail scanning - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the policy profile to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

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
    for example from Get-SfosSMTPPolicy.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the removal
    or if the named profile does not exist.

.EXAMPLE
    Remove-SfosSMTPPolicy -Name 'PartnerDomainsPolicy' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosSMTPPolicy -Name 'PartnerDomainsPolicy'

    Removes the named policy profile. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email(MTA)/smtpprofile/operations/Delete%20SMTP%20Policy.html

.LINK
    Get-SfosSMTPPolicy
#>
function Remove-SfosSMTPPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        $existing = @(Get-SfosSMTPPolicy -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SMTPPolicy object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SMTPPolicy '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SMTPPolicy><Name>$nameEsc</Name></SMTPPolicy></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove SMTPPolicy object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMTPPolicy' -Action 'remove' -Target $Name
    }
}

#endregion

#region AVASAddressGroup

<#
.SYNOPSIS
    Builds the Set request body for an AVASAddressGroup entity. Internal helper, not
    exported.

.DESCRIPTION
    Shared by New-SfosAVASAddressGroup and Set-SfosAVASAddressGroup so both send the same
    entity shape. Measured against a live firewall in legacy mode: the wire shape matches
    the MTA-side counterpart (MTAAddressGroup) field for field, including EmailImportType
    as a sibling of EmailAddressList, not nested inside it - confirmed by writing an
    EmailAddressOrDomain group and reading the raw response back. Every value is escaped
    through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the address group.

.PARAMETER GroupType
    RBLIPv4, RBLIPv6, IPAddress or EmailAddressOrDomain.

.PARAMETER Member
    One or more RBL names, IP addresses/networks or email addresses/domains, matching
    -GroupType.

.PARAMETER Description
    Free-text description.

.PARAMETER EmailImportType
    Import or Manual. Only sent when -GroupType is EmailAddressOrDomain.
#>
function ConvertTo-SfosAVASAddressGroupEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RBLIPv4', 'RBLIPv6', 'IPAddress', 'EmailAddressOrDomain')]
        [string]$GroupType,

        [string[]]$Member,

        [string]$Description,

        [string]$EmailImportType
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $groupTypeEsc = ConvertTo-SfosXmlEscaped -Text $GroupType

    $descriptionXml = ''
    if ($Description) {
        $descriptionXml = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $memberValues = @($Member | Where-Object -FilterScript { $_ })

    $importTypeXml = ''
    $memberXml = ''
    if ($GroupType -eq 'RBLIPv4' -or $GroupType -eq 'RBLIPv6') {
        $items = ($memberValues | ForEach-Object -Process { "<RBLName>$(ConvertTo-SfosXmlEscaped -Text $_)</RBLName>" }) -join ''
        $memberXml = "<RBLList>$items</RBLList>"
    }
    elseif ($GroupType -eq 'IPAddress') {
        $items = ($memberValues | ForEach-Object -Process { "<IPAddressNetwork>$(ConvertTo-SfosXmlEscaped -Text $_)</IPAddressNetwork>" }) -join ''
        $memberXml = "<IPAddressList>$items</IPAddressList>"
    }
    else {
        $items = ($memberValues | ForEach-Object -Process { "<EmailAddressDomain>$(ConvertTo-SfosXmlEscaped -Text $_)</EmailAddressDomain>" }) -join ''
        $memberXml = "<EmailAddressList>$items</EmailAddressList>"
        if ($EmailImportType) {
            $importTypeXml = "<EmailImportType>$(ConvertTo-SfosXmlEscaped -Text $EmailImportType)</EmailImportType>"
        }
    }

    return @"
<Set operation="$Operation">
  <AVASAddressGroup>
    <Name>$nameEsc</Name>
    <GroupType>$groupTypeEsc</GroupType>
    $descriptionXml
    $importTypeXml
    $memberXml
  </AVASAddressGroup>
</Set>
"@
}

<#
.SYNOPSIS
    Creates a legacy address group on a Sophos Firewall.

.DESCRIPTION
    Creates an AVASAddressGroup object (PROTECT > Email > Address group). This is the
    legacy counterpart of MTAAddressGroup; use this cmdlet only on an appliance running in
    legacy (non-MTA) mail deployment mode, where AVASAddressGroup is the writable root - on
    an appliance running in MTA mode this call answers 545/MTAModeDisableCheck.

    Measured against a live firewall running in legacy mode for RBLIPv4 and
    EmailAddressOrDomain: create, a no-op update round trip (read, write back unchanged,
    read again, compare raw XML - identical) and removal all work. RBLIPv6 is documented
    but was not exercised. GroupType IPAddress was not separately measured on the legacy
    root but uses the identical wire shape confirmed on the MTA-side counterpart.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'Premium RBL Services' or 'Standard RBL Services' groups with
    this cmdlet.

.PARAMETER Name
    Required. Name of the group. Maximum 50 characters.

.PARAMETER GroupType
    Required. RBLIPv4, RBLIPv6, IPAddress or EmailAddressOrDomain. Selects which kind
    of -Member values are expected.

.PARAMETER Member
    Required. One or more RBL server names (RBLIPv4/RBLIPv6), IP addresses/networks
    (IPAddress) or email addresses/domains (EmailAddressOrDomain), matching -GroupType.

.PARAMETER Description
    Optional. Free-text description. Maximum 255 characters.

.PARAMETER EmailImportType
    Optional. Import or Manual. Only meaningful when -GroupType is EmailAddressOrDomain.
    If omitted while -GroupType is EmailAddressOrDomain, 'Manual' is used. File-based
    import (EmailAddressFile) is documented but not implemented by this cmdlet.
    Get-SfosAVASAddressGroup always reads this field back empty on this firmware - its
    lookup path does not match where the firewall actually stores the value - so a value
    set here cannot be confirmed by reading it back; it is still applied on the wire.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosAVASAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Member 'example.com' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosAVASAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Member 'example.com'

    Creates an address group matching one email domain. The cmdlet asks for confirmation
    before it writes.

.EXAMPLE
    New-SfosAVASAddressGroup -Name 'TrustedNetworks' -GroupType IPAddress -Member '192.0.2.0/24'

    Creates an address group matching one IP network.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/AddressGroup/operations/AddAddressGroup%26AddAddressGroup%26EditAddressGroup%26EditAddressGroup.html

.LINK
    Get-SfosAVASAddressGroup
#>
function New-SfosAVASAddressGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RBLIPv4', 'RBLIPv6', 'IPAddress', 'EmailAddressOrDomain')]
        [string]$GroupType,

        [Parameter(Mandatory)]
        [string[]]$Member,

        [string]$Description,

        [ValidateSet('Import', 'Manual')]
        [string]$EmailImportType = 'Manual',

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
        if (-not @($Member | Where-Object -FilterScript { $_ }).Count) {
            throw "AVASAddressGroup object '$Name' needs at least one -Member value."
        }

        if (-not $PSCmdlet.ShouldProcess("AVASAddressGroup '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosAVASAddressGroupEntityXml -Operation 'add' -Name $Name -GroupType $GroupType `
            -Member $Member -Description $Description -EmailImportType $EmailImportType

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create AVASAddressGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AVASAddressGroup' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a legacy address group on a Sophos Firewall.

.DESCRIPTION
    Reads the named AVASAddressGroup object first and writes back a complete entity,
    overriding only the fields you pass - this is a full-replace entity, so anything not
    read back and resent would be cleared. Confirmed against a live firewall running in
    legacy mode with an unchanged round trip (read, write back unchanged, read again,
    compare raw XML - identical).

    -GroupType is mandatory even on an update, per the project rule against mixing
    parameter sets with pipeline input. If it matches the object's current GroupType,
    -Member may be omitted and the current member list is kept. If it differs (changing
    the kind of group), -Member is required, because a member list built for one
    GroupType is not a valid value for another.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'Premium RBL Services' or 'Standard RBL Services' groups with
    this cmdlet.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing group to update.

.PARAMETER GroupType
    Required. RBLIPv4, RBLIPv6, IPAddress or EmailAddressOrDomain - the group's current
    type, or the new type if you are changing it.

.PARAMETER Member
    Optional. New member values, replacing the current list. Required if -GroupType
    differs from the object's current GroupType. If omitted and -GroupType matches the
    current value, the current member list is kept.

.PARAMETER Description
    Optional. Replacing the current value. If omitted, the current value is kept.

.PARAMETER EmailImportType
    Optional. Replacing the current value. Only meaningful when -GroupType is
    EmailAddressOrDomain. If omitted, 'Manual' is sent - Get-SfosAVASAddressGroup cannot
    report the object's current value back (see New-SfosAVASAddressGroup), so there is
    nothing to preserve here.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name and GroupType
    by property name, for example from Get-SfosAVASAddressGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update, if the named group does not exist, or if -GroupType changes without
    -Member.

.EXAMPLE
    Set-SfosAVASAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Description 'Trusted partner domains' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosAVASAddressGroup -Name 'PartnerDomains' -GroupType EmailAddressOrDomain -Member 'example.com','example.net'

    Replaces the member list on the named group, keeping its description unchanged. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/AddressGroup/operations/AddAddressGroup%26AddAddressGroup%26EditAddressGroup%26EditAddressGroup.html

.LINK
    Get-SfosAVASAddressGroup
#>
function Set-SfosAVASAddressGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('RBLIPv4', 'RBLIPv6', 'IPAddress', 'EmailAddressOrDomain')]
        [string]$GroupType,

        [string[]]$Member,
        [string]$Description,

        [ValidateSet('Import', 'Manual')]
        [string]$EmailImportType = 'Manual',

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
        $existing = @(Get-SfosAVASAddressGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AVASAddressGroup object '$Name' was not found."
        }
        $current = $existing[0]

        $bp = $PSBoundParameters
        if ($bp.ContainsKey('Member')) {
            $targetMember = $Member
        }
        elseif ($GroupType -eq $current.GroupType) {
            if ($GroupType -eq 'RBLIPv4' -or $GroupType -eq 'RBLIPv6') { $targetMember = $current.RBLName }
            elseif ($GroupType -eq 'IPAddress') { $targetMember = $current.IPAddressNetwork }
            else { $targetMember = $current.EmailAddressDomain }
        }
        else {
            throw "The AVASAddressGroup object '$Name' is currently GroupType '$($current.GroupType)'. Pass -Member when changing -GroupType to '$GroupType'."
        }

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { $current.Description }

        if (-not $PSCmdlet.ShouldProcess("AVASAddressGroup '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosAVASAddressGroupEntityXml -Operation 'update' -Name $Name -GroupType $GroupType `
            -Member $targetMember -Description $targetDescription -EmailImportType $EmailImportType

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update AVASAddressGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AVASAddressGroup' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a legacy address group from a Sophos Firewall.

.DESCRIPTION
    Removes an AVASAddressGroup object. Measured against a live firewall running in
    legacy mode: removing a name that does not exist answers HTTP 200 with a success
    status, identical to a real removal - the same false-success shape already measured
    on the MTA-side counterpart. This cmdlet reads the object first and throws "was not
    found" itself rather than passing that misleading success through.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'Premium RBL Services' or 'Standard RBL Services' groups with
    this cmdlet.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the group to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosAVASAddressGroup.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named group does not exist.

.EXAMPLE
    Remove-SfosAVASAddressGroup -Name 'PartnerDomains' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosAVASAddressGroup -Name 'PartnerDomains'

    Removes the named group. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/AddressGroup/operations/Delete%20Address%20Group.html

.LINK
    Get-SfosAVASAddressGroup
#>
function Remove-SfosAVASAddressGroup {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 50)]
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
        $existing = @(Get-SfosAVASAddressGroup -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The AVASAddressGroup object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("AVASAddressGroup '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><AVASAddressGroup><Name>$nameEsc</Name></AVASAddressGroup></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove AVASAddressGroup object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AVASAddressGroup' -Action 'remove' -Target $Name
    }
}

#endregion

#region DataControlList

<#
.SYNOPSIS
    Builds the Set request body for a DataControlList entity. Internal helper, not
    exported.

.DESCRIPTION
    Shared by New-SfosDataControlList and Set-SfosDataControlList so both send the same
    entity shape. Measured against a live firewall in legacy mode: identical shape to the
    MTA-side counterpart (MTADataControlList) - Signatures is a full replace on update,
    not append-only. Every value is escaped through ConvertTo-SfosXmlEscaped.

.PARAMETER Operation
    The Set operation attribute, either 'add' or 'update'.

.PARAMETER Name
    Name of the data control list.

.PARAMETER Signature
    One or more catalog signature names, for example 'Postal addresses [Germany]'.
#>
function ConvertTo-SfosDataControlListEntityXml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('add', 'update')]
        [string]$Operation,

        [Parameter(Mandatory)]
        [string]$Name,

        [string[]]$Signature
    )

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $sigItems = (@($Signature | Where-Object -FilterScript { $_ }) | ForEach-Object -Process {
            "<Signature>$(ConvertTo-SfosXmlEscaped -Text $_)</Signature>"
        }) -join ''

    return @"
<Set operation="$Operation">
  <DataControlList>
    <Name>$nameEsc</Name>
    <Signatures>$sigItems</Signatures>
  </DataControlList>
</Set>
"@
}

<#
.SYNOPSIS
    Creates a legacy data control list on a Sophos Firewall.

.DESCRIPTION
    Creates a DataControlList object (PROTECT > Email > Data control list). This is the
    legacy counterpart of MTADataControlList; use this cmdlet only on an appliance
    running in legacy (non-MTA) mail deployment mode, where DataControlList is the
    writable root - on an appliance running in MTA mode this call answers
    545/MTAModeDisableCheck and the entity holds no records.

    Measured against a live firewall running in legacy mode: create, a no-op update
    round trip (read, write back unchanged, read again, compare raw XML - identical) and
    removal all work. A create with an empty -Signature list has no useful effect, so an
    empty list is refused here rather than silently created.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

.PARAMETER Name
    Required. Name of the list. Maximum 255 characters.

.PARAMETER Signature
    Required. One or more catalog signature names.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosDataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosDataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]','Postal addresses [France]'

    Creates a data control list matching two catalog signatures. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/dataprotectionpolicy/operations/AddDataControlList%26UpdateDataControlList.html

.LINK
    Get-SfosDataControlList
#>
function New-SfosDataControlList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string[]]$Signature,

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
        if (-not @($Signature | Where-Object -FilterScript { $_ }).Count) {
            throw "DataControlList object '$Name' needs at least one -Signature value."
        }

        if (-not $PSCmdlet.ShouldProcess("DataControlList '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $inner = ConvertTo-SfosDataControlListEntityXml -Operation 'add' -Name $Name -Signature $Signature

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to create DataControlList object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataControlList' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates a legacy data control list on a Sophos Firewall.

.DESCRIPTION
    Reads the named DataControlList object first and writes back a complete entity,
    overriding only -Signature when you pass it - this is a full-replace entity, so
    omitting -Signature keeps the current list unchanged rather than clearing it.
    Confirmed against a live firewall running in legacy mode with an unchanged round
    trip (read, write back unchanged, read again, compare raw XML - identical).

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing list to update.

.PARAMETER Signature
    Optional. New signature list, replacing the current one. If omitted, the current
    list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosDataControlList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update or if the named list does not exist.

.EXAMPLE
    Set-SfosDataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosDataControlList -Name 'AddressCheck' -Signature 'Postal addresses [Germany]'

    Replaces the signature list on the named object with a single entry. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/dataprotectionpolicy/operations/AddDataControlList%26UpdateDataControlList.html

.LINK
    Get-SfosDataControlList
#>
function Set-SfosDataControlList {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string[]]$Signature,

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
        $existing = @(Get-SfosDataControlList -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The DataControlList object '$Name' was not found."
        }
        $current = $existing[0]

        $targetSignature = if ($PSBoundParameters.ContainsKey('Signature')) { $Signature } else { $current.Signature }

        if (-not $PSCmdlet.ShouldProcess("DataControlList '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = ConvertTo-SfosDataControlListEntityXml -Operation 'update' -Name $Name -Signature $targetSignature

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to update DataControlList object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataControlList' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a legacy data control list from a Sophos Firewall.

.DESCRIPTION
    Removes a DataControlList object. Measured against a live firewall running in legacy
    mode: removing a name that does not exist answers with a code-less status
    ("Operation could not be performed on Entity.") rather than a false success - the
    same trustworthy shape already measured on the MTA-side counterpart. This cmdlet
    still reads the object first, so the error it raises names the object clearly
    ("was not found") instead of surfacing the firewall's generic message.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the list to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosDataControlList.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named list does not exist.

.EXAMPLE
    Remove-SfosDataControlList -Name 'AddressCheck' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosDataControlList -Name 'AddressCheck'

    Removes the named list. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/dataprotectionpolicy/operations/Delete%20Data%20Control%20List.html

.LINK
    Get-SfosDataControlList
#>
function Remove-SfosDataControlList {
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
        $existing = @(Get-SfosDataControlList -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The DataControlList object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("DataControlList '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><DataControlList><Name>$nameEsc</Name></DataControlList></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove DataControlList object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DataControlList' -Action 'remove' -Target $Name
    }
}

#endregion

#region SPXConfiguration

<#
.SYNOPSIS
    Updates the legacy SPX configuration of a Sophos Firewall.

.DESCRIPTION
    Changes the global SPX template, the password-registration portal settings or the
    notification-on-error behaviour of SPXConfiguration. This is the legacy counterpart
    of MTASPXConfiguration; use this cmdlet only on an appliance running in legacy
    (non-MTA) mail deployment mode. This is a full-replace singleton: the cmdlet reads
    the current settings first and sends them back complete, so a field you do not pass
    keeps its current value.

    The vendor sample XML for this operation wraps the entity in itself
    (<SPXConfiguration><SPXConfiguration>...) - measured against a live firewall to be
    wrong; the working shape is a single <SPXConfiguration> root, matching what
    Get-SfosSPXConfiguration reads back and matching the MTA-side counterpart. Round
    trip confirmed against a live firewall: a probe change to -AllowPassRegistrationFor
    was written, read back, then restored to its original value and re-confirmed
    unchanged. Unlike MTASPXConfiguration, this entity has no AllowSecureReplyfor field -
    absent from both the vendor documentation and every live read.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER DefaultSPXTemplate
    Optional. Name of the SPXTemplates/MTASPXTemplates object used as the global default.
    If omitted, the current value is kept.

.PARAMETER HostName
    Optional. IP address or domain name on which the password-registration portal is
    hosted, replacing the current value. If omitted, the current value is kept.

.PARAMETER AllowedNetwork
    Optional. Networks from which password-registration requests are accepted, replacing
    the current list. If omitted, the current list is kept.

.PARAMETER PortalPort
    Optional. TCP port the SPX password-registration portal listens on (1025-65535),
    replacing the current value. If omitted, the current value is kept. Named
    PortalPort, not Port, to avoid a collision with the -Port connection parameter below
    - the wire element, and the property on Get-SfosSPXConfiguration, is Port.

.PARAMETER KeepUnusedPassFor
    Optional. Expiry time, in days, of an unused password, replacing the current value.
    If omitted, the current value is kept.

.PARAMETER AllowPassRegistrationFor
    Optional. Number of days after which the link to the password-registration portal
    expires, replacing the current value. If omitted, the current value is kept.

.PARAMETER SendNotifcationErrorTo
    Optional. Who is notified when an SPX error occurs, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosSPXConfiguration -AllowPassRegistrationFor 14 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSPXConfiguration -SendNotifcationErrorTo Nobody

    Stops sending SPX error notifications. Every other field keeps its current value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/spxconfiguration/operations/UpdateSPXConfiguration.html

.LINK
    Get-SfosSPXConfiguration
#>
function Set-SfosSPXConfiguration {
    # PSUseSingularNouns is suppressed on purpose. 'Configuration' is not a plural container
    # here but the name of the entity itself - the API element is <SPXConfiguration>, a
    # singleton holding one configuration, with no plural child to fall back to. The Sophos
    # spelling goes above PowerShell habit here, as it does for every other settings
    # singleton in this module family.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$DefaultSPXTemplate,
        [string]$HostName,
        [string[]]$AllowedNetwork,
        [ValidateRange(1025, 65535)]
        [int]$PortalPort,
        [int]$KeepUnusedPassFor,
        [int]$AllowPassRegistrationFor,
        [ValidateSet('SenderOnly', 'Nobody')]
        [string]$SendNotifcationErrorTo,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSPXConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetDefaultSPXTemplate = if ($bp.ContainsKey('DefaultSPXTemplate')) { $DefaultSPXTemplate } else { $existing.DefaultSPXTemplate }
    $targetHostName = if ($bp.ContainsKey('HostName')) { $HostName } else { $existing.HostName }
    $targetAllowedNetworks = @(if ($bp.ContainsKey('AllowedNetwork')) { $AllowedNetwork } else { $existing.AllowedNetworks })
    $targetPortalPort = if ($bp.ContainsKey('PortalPort')) { $PortalPort } else { $existing.Port }
    $targetKeepUnusedPassFor = if ($bp.ContainsKey('KeepUnusedPassFor')) { $KeepUnusedPassFor } else { $existing.KeepUnusedPassFor }
    $targetAllowPassRegistrationFor = if ($bp.ContainsKey('AllowPassRegistrationFor')) { $AllowPassRegistrationFor } else { $existing.AllowPassRegistrationFor }
    $targetSendNotifcationErrorTo = if ($bp.ContainsKey('SendNotifcationErrorTo')) { $SendNotifcationErrorTo } else { $existing.SendNotifcationErrorTo }

    if (-not $PSCmdlet.ShouldProcess("SPXConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    # Loop variable deliberately not named $allowedNetwork: PowerShell variable names are
    # case-insensitive, and that would collide with the [string[]]$AllowedNetwork parameter.
    $networksXml = ''
    foreach ($networkValue in $targetAllowedNetworks) {
        if (-not $networkValue) {
            continue
        }
        $networkEsc = ConvertTo-SfosXmlEscaped -Text $networkValue
        $networksXml += "<Network>$networkEsc</Network>"
    }

    $inner = @"
<Set operation="update">
  <SPXConfiguration>
    <SPXGlobalTemplate>
      <DefaultSPXTemplate>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetDefaultSPXTemplate))</DefaultSPXTemplate>
    </SPXGlobalTemplate>
    <HostName>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetHostName))</HostName>
    <AllowedNetworks>$networksXml</AllowedNetworks>
    <Port>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetPortalPort))</Port>
    <KeepUnusedPassFor>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetKeepUnusedPassFor))</KeepUnusedPassFor>
    <AllowPassRegistrationFor>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetAllowPassRegistrationFor))</AllowPassRegistrationFor>
    <SendNotifcationErrorTo>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetSendNotifcationErrorTo))</SendNotifcationErrorTo>
  </SPXConfiguration>
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
        throw "Error updating SPXConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SPXConfiguration' -Action 'update'
}

#endregion

#region SPXTemplates

<#
.SYNOPSIS
    Creates a legacy SPX template on a Sophos Firewall.

.DESCRIPTION
    Creates a new SPXTemplates object (PROTECT > Email > SPX > Templates). This is the
    legacy counterpart of MTASPXTemplates; use this cmdlet only on an appliance running
    in legacy (non-MTA) mail deployment mode.

    Measured against a live firewall running in legacy mode: create, a no-op update
    round trip (read, write back unchanged, read again, compare raw XML - identical),
    a second round trip that changes -PasswordType to one that uses
    -NotificationSubject/-NotificationBody, and removal all work. Unlike
    MTASPXTemplates, this entity has no SPXReplyPortal or IncludeOriginalBodyIntoReply
    field - both are absent from the vendor documentation for this operation and from
    every live read, so this cmdlet does not expose them.

    The vendor documentation marks -PDFEncryption, -PageSize and -PasswordType
    optional with a firewall-side default - measured against a live firewall to be
    wrong for create: a name-only request, and a request naming only -Description,
    both answered 501/"Configuration parameters validation failed" until all three
    were supplied. Treat them as required in practice, even though this cmdlet does
    not enforce that with a [Parameter(Mandatory)] attribute (the underlying object
    does have a firewall-assigned value for each once created, so the attribute
    would be wrong for Set-SfosSPXTemplate, which shares this parameter block by
    contract but must leave them optional to keep the current value).

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name to uniquely identify the template.

.PARAMETER Description
    Optional. Free-text description of the template.

.PARAMETER OrganizationName
    Optional. Organization name shown in the email notification.

.PARAMETER PDFEncryption
    Required in practice despite the vendor documentation marking it optional - see the
    description. Encryption standard of the generated PDF.

.PARAMETER PageSize
    Required in practice despite the vendor documentation marking it optional - see the
    description. Page size of the generated PDF.

.PARAMETER PasswordType
    Required in practice despite the vendor documentation marking it optional - see the
    description. How the password for the encrypted message is generated.

.PARAMETER NotificationSubject
    Optional. Subject of the notification email. Only applied when -PasswordType is
    'GeneratedOneTimePasswordForEveryEmail', 'GeneratedAndStoredForRecipient' or
    'SpecifiedByRecipient'.

.PARAMETER NotificationBody
    Optional. HTML body of the notification email. Same -PasswordType restriction as
    -NotificationSubject. Write the markup entity-encoded if you need angle brackets in
    a literal PowerShell example; this parameter itself accepts plain HTML text.

.PARAMETER InstructionsForRecipient
    Optional. HTML instructions shown to the recipient of the SPX-encrypted email.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts Name by property name.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosSPXTemplate -Name 'PartnerTemplate' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosSPXTemplate -Name 'PartnerTemplate' -PDFEncryption 'AES/256' -PageSize 'Letter' -PasswordType 'SpecifiedBySender'

    Creates a template for a partner organization. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/spxtemplates/operations/AddSPXTemplate%26UpdateSPXTemplate.html

.LINK
    Get-SfosSPXTemplate
#>
function New-SfosSPXTemplate {
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives here: Username/Password are the fixed connection parameters every write
    # cmdlet in this suite takes, and PasswordType is the wire field naming how the SPX
    # message password is generated (an enum, not a credential).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordType')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Description,
        [string]$OrganizationName,

        [ValidateSet('AES/128', 'AES/256')]
        [string]$PDFEncryption,

        [ValidateSet('A/4', 'Letter', 'Legal')]
        [string]$PageSize,

        [ValidateSet('SpecifiedBySender', 'GeneratedOneTimePasswordForEveryEmail', 'GeneratedAndStoredForRecipient', 'SpecifiedByRecipient')]
        [string]$PasswordType,

        [string]$NotificationSubject,
        [string]$NotificationBody,
        [string]$InstructionsForRecipient,

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
        if (-not $PSCmdlet.ShouldProcess("SPXTemplate '$Name' on $($params.Firewall)", 'Create')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $bp = $PSBoundParameters

        $fieldsXml = ''
        if ($bp.ContainsKey('Description')) { $fieldsXml += "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>" }
        if ($bp.ContainsKey('OrganizationName')) { $fieldsXml += "<OrganizationName>$(ConvertTo-SfosXmlEscaped -Text $OrganizationName)</OrganizationName>" }
        if ($bp.ContainsKey('PDFEncryption')) { $fieldsXml += "<PDFEncryption>$(ConvertTo-SfosXmlEscaped -Text $PDFEncryption)</PDFEncryption>" }
        if ($bp.ContainsKey('PageSize')) { $fieldsXml += "<PageSize>$(ConvertTo-SfosXmlEscaped -Text $PageSize)</PageSize>" }
        if ($bp.ContainsKey('PasswordType')) { $fieldsXml += "<PasswordType>$(ConvertTo-SfosXmlEscaped -Text $PasswordType)</PasswordType>" }
        if ($bp.ContainsKey('NotificationSubject')) { $fieldsXml += "<NotificationSubject>$(ConvertTo-SfosXmlEscaped -Text $NotificationSubject)</NotificationSubject>" }
        if ($bp.ContainsKey('NotificationBody')) { $fieldsXml += "<NotificationBody>$(ConvertTo-SfosXmlEscaped -Text $NotificationBody)</NotificationBody>" }
        if ($bp.ContainsKey('InstructionsForRecipient')) { $fieldsXml += "<InstructionsForRecipient>$(ConvertTo-SfosXmlEscaped -Text $InstructionsForRecipient)</InstructionsForRecipient>" }

        $inner = @"
<Set operation="add">
  <SPXTemplates>
    <Name>$nameEsc</Name>
    $fieldsXml
  </SPXTemplates>
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
            throw "Failed to create SPXTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SPXTemplates' -Action 'create' -Target $Name
    }
}

<#
.SYNOPSIS
    Updates an existing legacy SPX template on a Sophos Firewall.

.DESCRIPTION
    Changes fields of an existing SPXTemplates object. This is a full-replace entity:
    the cmdlet reads the current object first and sends it back complete, so a field you
    do not pass keeps its current value. It first confirms the named object exists and
    throws a clear "was not found" error if it does not.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area. Never
    target the built-in 'Default Template' object with this cmdlet.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the existing SPXTemplates object to update.

.PARAMETER Description
    Optional. Free-text description of the template, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER OrganizationName
    Optional. Organization name shown in the email notification, replacing the current
    value. If omitted, the current value is kept.

.PARAMETER PDFEncryption
    Optional. Encryption standard of the generated PDF, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER PageSize
    Optional. Page size of the generated PDF, replacing the current value. If omitted,
    the current value is kept.

.PARAMETER PasswordType
    Optional. How the password for the encrypted message is generated, replacing the
    current value. If omitted, the current value is kept.

.PARAMETER NotificationSubject
    Optional. Subject of the notification email, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER NotificationBody
    Optional. HTML body of the notification email, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER InstructionsForRecipient
    Optional. HTML instructions shown to the recipient, replacing the current value. If
    omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosSPXTemplate.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update or if the named object does not exist.

.EXAMPLE
    Set-SfosSPXTemplate -Name 'PartnerTemplate' -OrganizationName 'Renamed Org' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSPXTemplate -Name 'PartnerTemplate' -PageSize 'A/4'

    Changes the page size of an existing template. Every other field keeps its current
    value. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/spxtemplates/operations/AddSPXTemplate%26UpdateSPXTemplate.html

.LINK
    Get-SfosSPXTemplate
#>
function Set-SfosSPXTemplate {
    # PSAvoidUsingUsernameAndPasswordParams/PSAvoidUsingPlainTextForPassword are false
    # positives here: Username/Password are the fixed connection parameters every write
    # cmdlet in this suite takes, and PasswordType is the wire field naming how the SPX
    # message password is generated (an enum, not a credential).
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordType')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 255)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [string]$Description,
        [string]$OrganizationName,

        [ValidateSet('AES/128', 'AES/256')]
        [string]$PDFEncryption,

        [ValidateSet('A/4', 'Letter', 'Legal')]
        [string]$PageSize,

        [ValidateSet('SpecifiedBySender', 'GeneratedOneTimePasswordForEveryEmail', 'GeneratedAndStoredForRecipient', 'SpecifiedByRecipient')]
        [string]$PasswordType,

        [string]$NotificationSubject,
        [string]$NotificationBody,
        [string]$InstructionsForRecipient,

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
        $existing = @(Get-SfosSPXTemplate -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SPXTemplate object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SPXTemplate '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $bp = $PSBoundParameters
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetOrganizationName = if ($bp.ContainsKey('OrganizationName')) { $OrganizationName } else { [string]$existing[0].OrganizationName }
        $targetPDFEncryption = if ($bp.ContainsKey('PDFEncryption')) { $PDFEncryption } else { [string]$existing[0].PDFEncryption }
        $targetPageSize = if ($bp.ContainsKey('PageSize')) { $PageSize } else { [string]$existing[0].PageSize }
        $targetPasswordType = if ($bp.ContainsKey('PasswordType')) { $PasswordType } else { [string]$existing[0].PasswordType }
        $targetNotificationSubject = if ($bp.ContainsKey('NotificationSubject')) { $NotificationSubject } else { [string]$existing[0].NotificationSubject }
        $targetNotificationBody = if ($bp.ContainsKey('NotificationBody')) { $NotificationBody } else { [string]$existing[0].NotificationBody }
        $targetInstructionsForRecipient = if ($bp.ContainsKey('InstructionsForRecipient')) { $InstructionsForRecipient } else { [string]$existing[0].InstructionsForRecipient }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Set operation="update">
  <SPXTemplates>
    <Name>$nameEsc</Name>
    <Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>
    <OrganizationName>$(ConvertTo-SfosXmlEscaped -Text $targetOrganizationName)</OrganizationName>
    <PDFEncryption>$(ConvertTo-SfosXmlEscaped -Text $targetPDFEncryption)</PDFEncryption>
    <PageSize>$(ConvertTo-SfosXmlEscaped -Text $targetPageSize)</PageSize>
    <PasswordType>$(ConvertTo-SfosXmlEscaped -Text $targetPasswordType)</PasswordType>
    <NotificationSubject>$(ConvertTo-SfosXmlEscaped -Text $targetNotificationSubject)</NotificationSubject>
    <NotificationBody>$(ConvertTo-SfosXmlEscaped -Text $targetNotificationBody)</NotificationBody>
    <InstructionsForRecipient>$(ConvertTo-SfosXmlEscaped -Text $targetInstructionsForRecipient)</InstructionsForRecipient>
  </SPXTemplates>
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
            throw "Failed to update SPXTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SPXTemplates' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes a legacy SPX template from a Sophos Firewall.

.DESCRIPTION
    Removes an SPXTemplates object. Measured against a live firewall running in legacy
    mode: removing a name that does not exist answers with a code-less status
    ("Operation could not be performed on Entity.") rather than a false success. This
    cmdlet still reads the object first, so the error it raises names the object clearly
    ("was not found") instead of surfacing the firewall's generic message.

    Never remove a template that is still referenced as the global default
    (Get-SfosSPXConfiguration -> DefaultSPXTemplate) or by an active SPX policy, and
    never remove the built-in 'Default Template' object.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with write permission for the Email area.

    This object belongs to legacy mail scanning. Writing to it can be refused with status 545 while the
    appliance runs MTA mode - the refusal is decided per object, not per shape.
    Get-SfosSMTPDeploymentMode says which mode is active.

.PARAMETER Name
    Required. Name of the object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from
    the current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the
    Email area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from
    the current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate. If omitted, the certificate
    is validated.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that
    was registered with Connect-SfosFirewall -Name. Use it to address a specific firewall
    when you work with more than one at a time. Any connection parameter you pass
    explicitly still takes precedence. If omitted, the stored default connection is used.

.INPUTS
    System.Management.Automation.PSCustomObject. Accepts the object name by property
    name, for example from Get-SfosSPXTemplate.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal or if the named object does not exist.

.EXAMPLE
    Remove-SfosSPXTemplate -Name 'PartnerTemplate' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosSPXTemplate -Name 'PartnerTemplate'

    Removes the named object. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/PROTECT/Email/spxtemplates/operations/Delete%20SPX%20Template.html

.LINK
    Get-SfosSPXTemplate
#>
function Remove-SfosSPXTemplate {
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
        $existing = @(Get-SfosSPXTemplate -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SPXTemplate object '$Name' was not found."
        }

        if (-not $PSCmdlet.ShouldProcess("SPXTemplate '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
        $inner = "<Remove><SPXTemplates><Name>$nameEsc</Name></SPXTemplates></Remove>"

        try {
            $response = Invoke-SfosApi -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
        }
        catch {
            throw "Failed to remove SPXTemplate object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SPXTemplates' -Action 'remove' -Target $Name
    }
}

#endregion

#region SMTPDeploymentMode

<#
.SYNOPSIS
    Reads which of the two email shapes a Sophos Firewall is running.

.DESCRIPTION
    Returns the mail deployment mode. MTAMode 'ON' means the firewall accepts and delivers mail
    itself and the SMTP policy, exception policy, MTA address group and MTA data control list
    cmdlets are the ones that can write. 'OFF' means legacy mode, where the anti-spam rules, the
    SMTP malware scanning policies and the legacy address group, data control and SPX objects
    take that role.

    Reading this object is the only reliable way to tell the modes apart: the objects of the
    inactive shape stay readable, so finding populated rules or policies says nothing about
    which mode is running.

    It needs an open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly. The cmdlet only reads; nothing on the firewall is changed.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. If omitted, the value from the current connection is
    used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.PARAMETER AsXml
    Optional. Returns the raw XmlElement instead of a PSCustomObject.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with the property MTAMode.

.EXAMPLE
    Get-SfosSMTPDeploymentMode

    Returns ON for MTA mode or OFF for legacy mode.

.EXAMPLE
    if ((Get-SfosSMTPDeploymentMode).MTAMode -eq 'ON') { Get-SfosSMTPPolicy } else { Get-SfosAntiSpamRule }

    Reads the objects that are in charge in the current mode.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosSMTPDeploymentMode
#>
function Get-SfosSMTPDeploymentMode {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml '<Get><SMTPDeploymentMode></SMTPDeploymentMode></Get>' `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SMTPDeploymentMode: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMTPDeploymentMode' -Action 'get'

    $node = Select-Xml -Xml $XmlResponse -XPath '/Response/SMTPDeploymentMode' | ForEach-Object -Process { $_.Node }
    if (-not $node) { return }

    if ($AsXml) { return $node }

    return [PSCustomObject]@{
        MTAMode = [string]$node.MTAMode
    }
}

<#
.SYNOPSIS
    Switches a Sophos Firewall between MTA mode and legacy mail scanning.

.DESCRIPTION
    Sets the mail deployment mode. 'ON' puts the firewall into MTA mode, where it accepts and
    delivers mail itself; 'OFF' puts it into legacy mode, where it scans mail in passing.

    This decides which half of the email area accepts writes. Measured against a live appliance:
    the change takes effect immediately and without a reboot - a write that was refused with
    status 545 before the switch goes through afterwards, and the objects of the other shape
    start refusing in its place. Objects of the inactive shape stay readable either way, so
    nothing is lost by switching, but everything configured for one shape stops taking effect
    while the other is active.

    This is a device-wide change to how the appliance handles mail for everyone behind it, which
    is why it asks for confirmation before writing. Read both shapes before switching and compare
    afterwards.

.PARAMETER MTAMode
    Required. ON for MTA mode, OFF for legacy mail scanning.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs write permission for the Email
    area. If omitted, the value from the current connection is used.

.PARAMETER Password
    Optional. Password for the API login, as a SecureString. If omitted, the value from the
    current connection is used.

.PARAMETER SkipCertificateCheck
    Optional. Accepts the firewall certificate without validating it. Use this only for
    appliances that still present a self-signed certificate.

.PARAMETER Session
    Optional. A session object from Connect-SfosFirewall, or the name of a session that was
    registered with Connect-SfosFirewall -Name. Use it to address a specific firewall when you
    work with more than one at a time. Any connection parameter you pass explicitly still takes
    precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the change.

.EXAMPLE
    Set-SfosSMTPDeploymentMode -MTAMode OFF -WhatIf

    Shows the switch to legacy mode without sending it.

.EXAMPLE
    Set-SfosSMTPDeploymentMode -MTAMode ON -Confirm:$false

    Switches the appliance to MTA mode without asking. Automation needs the explicit
    -Confirm:$false because this cmdlet is marked as high impact.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSMTPDeploymentMode
#>
function Set-SfosSMTPDeploymentMode {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ON', 'OFF')]
        [string]$MTAMode,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $target = if ($MTAMode -eq 'ON') { 'MTA mode' } else { 'legacy mail scanning' }
    if (-not $PSCmdlet.ShouldProcess("Mail deployment mode on $($params.Firewall)", "Switch to $target")) {
        return
    }

    $modeEsc = ConvertTo-SfosXmlEscaped -Text $MTAMode

    $inner = @"
<Set operation="update">
  <SMTPDeploymentMode>
    <MTAMode>$modeEsc</MTAMode>
  </SMTPDeploymentMode>
</Set>
"@

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner `
            -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to switch the mail deployment mode to '$MTAMode': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SMTPDeploymentMode' -Action 'update' -Target $MTAMode
}

#endregion
