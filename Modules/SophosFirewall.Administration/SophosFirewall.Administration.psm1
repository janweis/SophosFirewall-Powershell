#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.Administration
    ==============================
    PowerShell module for the Sophos Firewall (SFOS) System > Administration area via the
    XML API: mail server notification settings, SNMP agent configuration, system date/time,
    SNMP communities, SNMPv3 users, customizable end-user messages, appliance service access
    (zones per management service), the admin settings singleton (hostname, web admin ports,
    login security, password complexity, login disclaimer, default language), and the
    Local Service ACL rule list (management access control by zone/source host).

    Total Functions: 29 - see README.md for the full cmdlet table.

    Requires SophosFirewall.Core (>= 1.3.0) for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S) happens
    in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/
#>


#region Notification
# Notification (SYSTEM > Administration > Notification Settings) is the device-wide mail
# server used to send system notifications. Wire root is <Notification>, a singleton with
# no <Name> child.
#
# Measured against the lab appliance (Get, live baseline):
# - The live shape is narrower than the doc sample: MailServer, Port, NotificationServer,
#   AuthenticationRequired, ConnectionSecurity, Password, Recepient (Sophos's own spelling,
#   kept as-is), Username, ManagementInterface, IPFamily, SenderAddress. The doc sample's
#   Subject/MailBody/Certificate/Oauth2Provider/IPSecTunnelStatusChangeNotification belong to
#   the "Test Notification Mail" half of this same operation page, not to the stored
#   singleton, and are not part of this cmdlet.
# - AuthenticationRequired reads back 'Disable' on this firmware, not the doc table's '0' -
#   the ValidateSet on Set-SfosNotification follows the live value, not the table.
# - <Password/> always reads back empty, unconditionally - not a hash like ThirdPartyFeed,
#   just blank. Set-SfosNotification therefore has no read-back value to preserve and sends
#   <Password> only when the caller passes -SmtpPassword explicitly; see that function's
#   .NOTES for what was and was not possible to measure about omission.
# - Port is a silent no-op on update [measured]: sending any value answers 200
#   "Configuration applied successfully" and the stored value is unchanged, reproduced twice
#   (through the cmdlet and via a raw request bypassing it). No working value was found.
# - Changing NotificationServer or ManagementInterface away from their lab baseline answers
#   501 blaming /Notification/MailServer, even though MailServer itself was resent unchanged
#   [measured]. The lab's MailServer is 127.0.0.1, which the doc table's own IP-class rule
#   excludes ('LOCALHOST' is not an allowed class) - plausible reading: NotificationServer=1
#   (external server) and a non-empty ManagementInterface both imply the doc's stricter
#   MailServer validation, which the lab's loopback placeholder then fails, and the error
#   names the field that failed validation rather than the field the caller changed. Not
#   pursued further since fixing the diagnosis would mean writing a real MailServer address
#   into the lab - out of scope here. Both parameters are implemented documentation-faithful;
#   a caller with a real external mail server should not hit this.
# - -SmtpPort/-SmtpUsername/-SmtpPassword on Set-SfosNotification are the entity's own
#   Port/Username/Password fields, renamed to avoid colliding with the connection parameters
#   of the same names (same reasoning as -HostAddress on Set-SfosGreRoute and -FeedPassword
#   on Set-SfosThirdPartyFeed) - Get-SfosNotification's output keeps the API's own names.

<#
.SYNOPSIS
    Retrieves the mail server notification settings from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the Notification singleton (System >
    Administration > Notification Settings): the mail server used for system-generated
    notification emails. Use -AsXml to return the raw XML node instead of a
    PowerShell-friendly object.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosNotification -Session $fw1 | Set-SfosNotification -Session fw2.

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
    PSCustomObject (default) with MailServer, Port, NotificationServer,
    AuthenticationRequired, Username, Password, ConnectionSecurity, SenderAddress,
    Recepient, ManagementInterface, IPFamily. System.Xml.XmlElement when -AsXml is
    specified.

.EXAMPLE
    # Read the current mail server settings
    Get-SfosNotification | Select-Object MailServer, SenderAddress, Recepient

.NOTES
    Minimum supported PowerShell version: 5.1
    Password always reads back empty regardless of whether one is stored - see the region
    header.
    Verified live: executed against the lab firewall; all fields matched the saved baseline
    XML.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/Notification/operations/TestNotificationMail%26UpdateMailServerSettings.html

.LINK
    Set-SfosNotification
#>
function Get-SfosNotification {
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

    $inner = '<Get><Notification></Notification></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving Notification: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Notification' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/Notification')
    if (-not $node) {
        throw 'Notification could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        MailServer             = [string]$node.MailServer
        Port                   = [string]$node.Port
        NotificationServer     = [string]$node.NotificationServer
        AuthenticationRequired = [string]$node.AuthenticationRequired
        Username                = [string]$node.Username
        Password                = [string]$node.Password
        ConnectionSecurity     = [string]$node.ConnectionSecurity
        SenderAddress          = [string]$node.SenderAddress
        Recepient              = [string]$node.Recepient
        ManagementInterface    = [string]$node.ManagementInterface
        IPFamily               = [string]$node.IPFamily
    }
}

<#
.SYNOPSIS
    Updates the mail server notification settings on the Sophos Firewall.

.DESCRIPTION
    Updates the Notification singleton (System > Administration > Notification Settings)
    using the Sophos Firewall XML API. Reads the current settings first and resends every
    field, overriding only what the caller explicitly passed (read-modify-write) - omitting
    a field on this API clears it. Supports ShouldProcess; use -WhatIf to preview.

    -SmtpPassword is the exception: the firewall always reads <Password> back empty (see the
    region header), so there is no stored value to re-merge. The element is included in the
    request only when -SmtpPassword is bound; when it is not, no <Password> element is sent
    at all.

.PARAMETER MailServer
    Mail server IPv4/IPv6 address or FQDN. If omitted, the current value is kept.

.PARAMETER SmtpPort
    Mail server port number. Named -SmtpPort rather than -Port to avoid colliding with the
    connection parameter of the same name. If omitted, the current value is kept.

.PARAMETER NotificationServer
    '1' to send notifications through the external mail server, '0' through the firewall
    device itself. If omitted, the current value is kept.

.PARAMETER AuthenticationRequired
    Whether the mail server requires authentication. The doc table lists '0'/'Enable'/
    'Oauth2'; the lab appliance reads back 'Disable' instead of '0' [measured], so both
    'Disable' and '0' are accepted. If omitted, the current value is kept.

.PARAMETER SmtpUsername
    Username for mail server authentication. Named -SmtpUsername rather than -Username to
    avoid colliding with the connection parameter of the same name. If omitted, the current
    value is kept.

.PARAMETER SmtpPassword
    Password for mail server authentication. Named -SmtpPassword rather than -Password to
    avoid colliding with the connection parameter of the same name. Sent only when supplied
    - see .DESCRIPTION.

.PARAMETER ConnectionSecurity
    'None', 'STARTTLS' or 'SSLTLS'. If omitted, the current value is kept.

.PARAMETER SenderAddress
    Email address notifications are sent from. If omitted, the current value is kept.

.PARAMETER Recepient
    Email address notifications are sent to (Sophos's own spelling). If omitted, the current
    value is kept.

.PARAMETER ManagementInterface
    Management interface whose IP address is included in notification emails. If omitted,
    the current value is kept.

.PARAMETER IPFamily
    'IPv4' or 'IPv6', the IP family of -ManagementInterface. If omitted, the current value
    is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosNotification -Session $fw1 | Set-SfosNotification -Session fw2.

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
    # Change only the sender address, every other field is preserved
    Set-SfosNotification -SenderAddress 'firewall-alerts@example.test'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the example above was executed against the lab firewall (changing
    SenderAddress from its baseline), confirmed via Get-SfosNotification, then reverted to
    the baseline value and reconfirmed.
    -SmtpPassword omission was probed by first setting AuthenticationRequired='Enable' with a
    username and password, then sending a second update that changed only SenderAddress and
    did not touch -SmtpPassword: the request succeeded (code 200). But AuthenticationRequired
    itself turned out not to persist on this firmware (read back as 'Disable' both times,
    with and without ConnectionSecurity set alongside it - see the region header), so the
    probe never actually reached "Enable" mode and the question of whether omitting
    -SmtpPassword preserves or clears a stored password stays open. Because
    Get-SfosNotification never reads the real password back either (always blank, not a
    hash), the API gives no positive signal at all here, unlike ThirdPartyFeed's read-back
    hash. Not resolvable further without a live SMTP server or a firmware where
    AuthenticationRequired actually takes 'Enable'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/Notification/operations/TestNotificationMail%26UpdateMailServerSettings.html

.LINK
    Get-SfosNotification
#>
function Set-SfosNotification {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$MailServer,

        [ValidateRange(1, 65535)]
        [int]$SmtpPort,

        [ValidateSet('0', '1')]
        [string]$NotificationServer,

        [ValidateSet('Disable', 'Enable', 'Oauth2', '0')]
        [string]$AuthenticationRequired,

        [string]$SmtpUsername,

        [SecureString]$SmtpPassword,

        [ValidateSet('None', 'STARTTLS', 'SSLTLS')]
        [string]$ConnectionSecurity,

        [string]$SenderAddress,

        [string]$Recepient,

        [string]$ManagementInterface,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosNotification -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetMailServer = if ($bp.ContainsKey('MailServer')) { $MailServer } else { $existing.MailServer }
    $targetPort = if ($bp.ContainsKey('SmtpPort')) { $SmtpPort } else { $existing.Port }
    $targetNotificationServer = if ($bp.ContainsKey('NotificationServer')) { $NotificationServer } else { $existing.NotificationServer }
    $targetAuthRequired = if ($bp.ContainsKey('AuthenticationRequired')) { $AuthenticationRequired } else { $existing.AuthenticationRequired }
    $targetUsername = if ($bp.ContainsKey('SmtpUsername')) { $SmtpUsername } else { $existing.Username }
    $targetConnectionSecurity = if ($bp.ContainsKey('ConnectionSecurity')) { $ConnectionSecurity } else { $existing.ConnectionSecurity }
    $targetSenderAddress = if ($bp.ContainsKey('SenderAddress')) { $SenderAddress } else { $existing.SenderAddress }
    $targetRecepient = if ($bp.ContainsKey('Recepient')) { $Recepient } else { $existing.Recepient }
    $targetManagementInterface = if ($bp.ContainsKey('ManagementInterface')) { $ManagementInterface } else { $existing.ManagementInterface }
    $targetIPFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { $existing.IPFamily }

    if (-not $PSCmdlet.ShouldProcess("Notification on $($params.Firewall)", 'Update')) {
        return
    }

    $passwordXml = ''
    if ($bp.ContainsKey('SmtpPassword')) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SmtpPassword)
        try {
            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
        }
        $passwordEsc = ConvertTo-SfosXmlEscaped -Text $plainPassword
        $passwordXml = "<Password>$passwordEsc</Password>"
    }

    $mailServerEsc = ConvertTo-SfosXmlEscaped -Text $targetMailServer
    $usernameEsc = ConvertTo-SfosXmlEscaped -Text $targetUsername
    $senderAddressEsc = ConvertTo-SfosXmlEscaped -Text $targetSenderAddress
    $recepientEsc = ConvertTo-SfosXmlEscaped -Text $targetRecepient
    $managementInterfaceEsc = ConvertTo-SfosXmlEscaped -Text $targetManagementInterface

    $inner = @"
<Set operation="update">
  <Notification>
    <MailServer>$mailServerEsc</MailServer>
    <Port>$targetPort</Port>
    <NotificationServer>$targetNotificationServer</NotificationServer>
    <AuthenticationRequired>$targetAuthRequired</AuthenticationRequired>
    <Username>$usernameEsc</Username>
    $passwordXml
    <ConnectionSecurity>$targetConnectionSecurity</ConnectionSecurity>
    <SenderAddress>$senderAddressEsc</SenderAddress>
    <Recepient>$recepientEsc</Recepient>
    <ManagementInterface>$managementInterfaceEsc</ManagementInterface>
    <IPFamily>$targetIPFamily</IPFamily>
  </Notification>
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
        throw "Failed to update Notification: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Notification' -Action 'update'
}

#endregion

#region SNMPAgentConfiguration
# SNMPAgentConfiguration (SYSTEM > Administration > SNMP Agent Configuration) is the
# device-wide SNMP agent toggle. Wire root is <SNMPAgentConfiguration>, a singleton with no
# <Name> child (its own <Name> field is the agent's display name, not an identifier).
#
# Measured against the lab appliance (Get, live baseline):
# - Live fields: Location, Name, ContactPerson, Description, EnableAgent, ManagerPort,
#   AgentPort - matches the doc sample plus Description, which the sample carries but the
#   parameter table omits.
# - EnableAgent reads back lowercase 'false' [measured], matching the doc table's
#   'true'/'false' (not 'Enable'/'Disable' like most other boolean fields in this API).
# - AgentPort and ManagerPort are marked read-only in the doc sample's inline comment and
#   are absent from the parameter table entirely, so Set-SfosSNMPAgentConfiguration does not
#   expose them as parameters - sending a fixed port back on every update would either be
#   silently ignored or risk being rejected as an unexpected write to a read-only field.
#   Get-SfosSNMPAgentConfiguration still returns both, since they are real read values.
# - The doc table marks Location and ContactPerson 'Mandatory: Yes', but the live baseline
#   holds both empty - the firmware does not enforce that on this appliance [measured].

<#
.SYNOPSIS
    Retrieves the SNMP agent configuration from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the SNMPAgentConfiguration singleton (System >
    Administration > SNMP Agent Configuration). Use -AsXml to return the raw XML node
    instead of a PowerShell-friendly object.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPAgentConfiguration -Session $fw1 | Set-SfosSNMPAgentConfiguration -Session fw2.

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
    PSCustomObject (default) with Location, Name, ContactPerson, Description, EnableAgent,
    ManagerPort, AgentPort. System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    # Check whether the SNMP agent is enabled
    Get-SfosSNMPAgentConfiguration | Select-Object EnableAgent, AgentPort, ManagerPort

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall; all fields matched the saved baseline
    XML.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/SNMPAgentConfiguration/operations/SNMPAgentConfiguration.html

.LINK
    Set-SfosSNMPAgentConfiguration
#>
function Get-SfosSNMPAgentConfiguration {
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

    $inner = '<Get><SNMPAgentConfiguration></SNMPAgentConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving SNMPAgentConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPAgentConfiguration' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/SNMPAgentConfiguration')
    if (-not $node) {
        throw 'SNMPAgentConfiguration could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        Location      = [string]$node.Location
        Name          = [string]$node.Name
        ContactPerson = [string]$node.ContactPerson
        Description   = [string]$node.Description
        EnableAgent   = [string]$node.EnableAgent
        ManagerPort   = [string]$node.ManagerPort
        AgentPort     = [string]$node.AgentPort
    }
}

<#
.SYNOPSIS
    Updates the SNMP agent configuration on the Sophos Firewall.

.DESCRIPTION
    Updates the SNMPAgentConfiguration singleton (System > Administration > SNMP Agent
    Configuration) using the Sophos Firewall XML API. Reads the current settings first and
    resends every writable field, overriding only what the caller explicitly passed
    (read-modify-write) - omitting a field on this API clears it. AgentPort and ManagerPort
    are read-only on this entity (see the region header) and are not sent. Supports
    ShouldProcess; use -WhatIf to preview.

.PARAMETER Location
    Physical location of the appliance. If omitted, the current value is kept.

.PARAMETER Name
    Name to identify the SNMP agent. If omitted, the current value is kept.

.PARAMETER ContactPerson
    Contact information for the person responsible for the appliance. If omitted, the
    current value is kept.

.PARAMETER Description
    Description of the agent. If omitted, the current value is kept.

.PARAMETER EnableAgent
    'true' or 'false' to enable/disable the SNMP agent. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPAgentConfiguration -Session $fw1 | Set-SfosSNMPAgentConfiguration -Session fw2.

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
    # Change only the contact person, every other field is preserved
    Set-SfosSNMPAgentConfiguration -ContactPerson 'ops@example.test'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: the example above was executed against the lab firewall (changing
    ContactPerson from its baseline), confirmed via Get-SfosSNMPAgentConfiguration, then
    reverted to the baseline value and reconfirmed. The error path (an invalid EnableAgent
    value) was also reproduced client-side via -ValidateSet.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/SNMPAgentConfiguration/operations/SNMPAgentConfiguration.html

.LINK
    Get-SfosSNMPAgentConfiguration
#>
function Set-SfosSNMPAgentConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Location,
        [string]$Name,
        [string]$ContactPerson,
        [string]$Description,

        [ValidateSet('true', 'false')]
        [string]$EnableAgent,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosSNMPAgentConfiguration -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetLocation = if ($bp.ContainsKey('Location')) { $Location } else { $existing.Location }
    $targetName = if ($bp.ContainsKey('Name')) { $Name } else { $existing.Name }
    $targetContactPerson = if ($bp.ContainsKey('ContactPerson')) { $ContactPerson } else { $existing.ContactPerson }
    $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { $existing.Description }
    $targetEnableAgent = if ($bp.ContainsKey('EnableAgent')) { $EnableAgent } else { $existing.EnableAgent }

    # Measured: the firmware forces Name, Location AND ContactPerson to be non-empty on every
    # update - a request missing any of the three answers 400 with InvalidParams naming that
    # field, even when the stored value is currently empty. Fail fast client-side instead.
    if ([string]::IsNullOrEmpty($targetName) -or [string]::IsNullOrEmpty($targetLocation) -or [string]::IsNullOrEmpty($targetContactPerson)) {
        throw "SNMPAgentConfiguration requires Name, Location and ContactPerson (all firmware-mandatory on update, even when currently empty). Supply -Name, -Location and -ContactPerson."
    }

    if (-not $PSCmdlet.ShouldProcess("SNMPAgentConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    $locationEsc = ConvertTo-SfosXmlEscaped -Text $targetLocation
    $nameEsc = ConvertTo-SfosXmlEscaped -Text $targetName
    $contactPersonEsc = ConvertTo-SfosXmlEscaped -Text $targetContactPerson
    $descriptionEsc = ConvertTo-SfosXmlEscaped -Text $targetDescription

    $inner = @"
<Set operation="update">
  <SNMPAgentConfiguration>
    <Location>$locationEsc</Location>
    <Name>$nameEsc</Name>
    <ContactPerson>$contactPersonEsc</ContactPerson>
    <Description>$descriptionEsc</Description>
    <EnableAgent>$targetEnableAgent</EnableAgent>
  </SNMPAgentConfiguration>
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
        throw "Failed to update SNMPAgentConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPAgentConfiguration' -Action 'update'
}

#endregion

#region Time
# Time (SYSTEM > Administration > Time Configuration) is the device-wide date/time and NTP
# configuration. Wire root is <Time>, a singleton with no <Name> child.
#
# Measured against the lab appliance (Get, live baseline):
# - The live shape is narrower than the doc sample: only TimeZone and SetDateTime
#   (Date/Year,Month,Day and Time/HH,MM,SS) are present. PredefinedNTPServer,
#   CustomNTPServer/NTPServer and SyncNow - all documented, all "Mandatory: No" - are absent
#   from the Get response on this appliance, presumably because NTP sync is not configured.
#   Since there is nothing to read back for them, Set-SfosTime does not attempt to merge
#   them from the existing object; the NTP subtree and SyncNow are included in the update
#   only when the caller explicitly binds the corresponding parameter. SyncNow in particular
#   is a one-shot trigger, not a persisted value, so there is nothing to preserve either way.
# - The doc table lists SyncwithNTPServer as "Mandatory: Yes", but it does not appear on the
#   live object and is not implemented here - inventing a field the appliance never showed
#   would repeat the CountryHostGroup mistake. If a future measurement finds it, add it then.
# - Changing TimeZone causes a temporary management-interface outage [measured]: the update
#   itself times out client-side (the appliance restarts the service that serves the API/web
#   admin), and the firewall answers again 30-90 seconds later with the new zone already
#   applied. Not a lock-out like Set-SfosSpoofPrevention - it recovers on its own - but a
#   caller scripting Set-SfosTime -TimeZone should expect the call itself to throw a timeout
#   and should poll before treating the change as failed.

<#
.SYNOPSIS
    Retrieves the system date/time configuration from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the Time singleton (System > Administration >
    Time Configuration): time zone and current appliance clock, plus NTP settings when
    configured. Use -AsXml to return the raw XML node instead of a PowerShell-friendly
    object.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosTime -Session $fw1 | Set-SfosTime -Session fw2.

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
    PSCustomObject (default) with TimeZone, Year, Month, Day, HH, MM, SS,
    PredefinedNTPServer, NTPServer (string array). System.Xml.XmlElement when -AsXml is
    specified.

.EXAMPLE
    # Read the current appliance clock
    Get-SfosTime | Select-Object TimeZone, Year, Month, Day, HH, MM, SS

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall; TimeZone and SetDateTime matched the
    saved baseline XML (clock fields naturally differ by wall-clock time).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/TimeConfiguration/operations/SystemTimeConfiguration.html

.LINK
    Set-SfosTime
#>
function Get-SfosTime {
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

    $inner = '<Get><Time></Time></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving Time: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Time' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/Time')
    if (-not $node) {
        throw 'Time could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $ntpServers = @($node.SelectNodes('CustomNTPServer/NTPServer') | ForEach-Object { [string]$_.InnerText })

    return [PSCustomObject]@{
        TimeZone            = [string]$node.TimeZone
        Year                = [string]$node.SetDateTime.Date.Year
        Month               = [string]$node.SetDateTime.Date.Month
        Day                 = [string]$node.SetDateTime.Date.Day
        HH                  = [string]$node.SetDateTime.Time.HH
        MM                  = [string]$node.SetDateTime.Time.MM
        SS                  = [string]$node.SetDateTime.Time.SS
        PredefinedNTPServer = [string]$node.PredefinedNTPServer
        NTPServer           = $ntpServers
    }
}

<#
.SYNOPSIS
    Updates the system date/time configuration on the Sophos Firewall.

.DESCRIPTION
    Updates the Time singleton (System > Administration > Time Configuration) using the
    Sophos Firewall XML API. Reads the current settings first and resends TimeZone and the
    full SetDateTime block, overriding only what the caller explicitly passed
    (read-modify-write). PredefinedNTPServer/-NTPServer and -SyncNow have nothing to read
    back on this appliance (see the region header) and are included in the request only
    when the caller binds them. Supports ShouldProcess; use -WhatIf to preview.

    Changes the appliance clock. Not a lock-out risk like Set-SfosSpoofPrevention, but every
    call re-sends Year/Month/Day/HH/MM/SS - even a TimeZone-only change re-syncs the clock
    to whatever was read a moment earlier, which can drift the clock by a few seconds from
    wall-clock time. Changing -TimeZone also restarts the management service for 30-90
    seconds [measured] - see the region header - so the call itself is expected to time out;
    poll Get-SfosTime afterward rather than treating that timeout as a failure.

.PARAMETER TimeZone
    IANA time zone name (e.g. 'Europe/Berlin'). If omitted, the current value is kept.

.PARAMETER Year
    Year for the appliance clock. If omitted, the current value is kept.

.PARAMETER Month
    Month (1-12) for the appliance clock. If omitted, the current value is kept.

.PARAMETER Day
    Day (1-31) for the appliance clock. If omitted, the current value is kept.

.PARAMETER HH
    Hour (0-23) for the appliance clock. If omitted, the current value is kept.

.PARAMETER MM
    Minute (0-59) for the appliance clock. If omitted, the current value is kept.

.PARAMETER SS
    Second (0-59) for the appliance clock. If omitted, the current value is kept.

.PARAMETER PredefinedNTPServer
    'Enable' to use a predefined NTP server instead of a custom one. Sent only when bound -
    see .DESCRIPTION.

.PARAMETER NTPServer
    One or more custom NTP server addresses/hostnames. Sent only when bound - see
    .DESCRIPTION.

.PARAMETER SyncNow
    '1' to synchronize the clock with the NTP server immediately. A one-shot trigger, not a
    persisted value; sent only when bound.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosTime -Session $fw1 | Set-SfosTime -Session fw2.

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
    # Change only the time zone, the clock fields are preserved from the current reading
    Set-SfosTime -TimeZone 'Europe/Berlin'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live against the lab firewall with a real change: TimeZone was set to
    'Europe/London', the call itself timed out client-side, the appliance became reachable
    again after roughly 45 seconds with the new zone applied and the clock correctly
    recalculated (confirmed via Get-SfosTime), then TimeZone was set back to 'Europe/Berlin'
    with the same timeout-then-recover pattern, confirmed restored to the original value.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/TimeConfiguration/operations/SystemTimeConfiguration.html

.LINK
    Get-SfosTime
#>
function Set-SfosTime {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$TimeZone,

        [ValidateRange(1970, 2100)]
        [int]$Year,
        [ValidateRange(1, 12)]
        [int]$Month,
        [ValidateRange(1, 31)]
        [int]$Day,
        [ValidateRange(0, 23)]
        [int]$HH,
        [ValidateRange(0, 59)]
        [int]$MM,
        [ValidateRange(0, 59)]
        [int]$SS,

        [ValidateSet('Enable', '2')]
        [string]$PredefinedNTPServer,

        [string[]]$NTPServer,

        [ValidateSet('0', '1')]
        [string]$SyncNow,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosTime -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetTimeZone = if ($bp.ContainsKey('TimeZone')) { $TimeZone } else { $existing.TimeZone }
    $targetYear = if ($bp.ContainsKey('Year')) { $Year } else { $existing.Year }
    $targetMonth = if ($bp.ContainsKey('Month')) { $Month } else { $existing.Month }
    $targetDay = if ($bp.ContainsKey('Day')) { $Day } else { $existing.Day }
    $targetHH = if ($bp.ContainsKey('HH')) { $HH } else { $existing.HH }
    $targetMM = if ($bp.ContainsKey('MM')) { $MM } else { $existing.MM }
    $targetSS = if ($bp.ContainsKey('SS')) { $SS } else { $existing.SS }

    if (-not $PSCmdlet.ShouldProcess("Time on $($params.Firewall)", 'Update')) {
        return
    }

    $timeZoneEsc = ConvertTo-SfosXmlEscaped -Text $targetTimeZone

    $ntpXml = ''
    if ($bp.ContainsKey('PredefinedNTPServer')) {
        $ntpXml += "<PredefinedNTPServer>$PredefinedNTPServer</PredefinedNTPServer>"
    }
    if ($bp.ContainsKey('NTPServer')) {
        $serverXml = ($NTPServer | ForEach-Object { "<NTPServer>$(ConvertTo-SfosXmlEscaped -Text $_)</NTPServer>" }) -join ''
        $ntpXml += "<CustomNTPServer>$serverXml</CustomNTPServer>"
    }
    if ($bp.ContainsKey('SyncNow')) {
        $ntpXml += "<SyncNow>$SyncNow</SyncNow>"
    }

    $inner = @"
<Set operation="update">
  <Time>
    <TimeZone>$timeZoneEsc</TimeZone>
    <SetDateTime>
      <Date>
        <Year>$targetYear</Year>
        <Month>$targetMonth</Month>
        <Day>$targetDay</Day>
      </Date>
      <Time>
        <HH>$targetHH</HH>
        <MM>$targetMM</MM>
        <SS>$targetSS</SS>
      </Time>
    </SetDateTime>
    $ntpXml
  </Time>
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
        throw "Failed to update Time: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Time' -Action 'update'
}

#endregion

#region SNMPCommunity
# SNMPCommunity (SYSTEM > Administration > SNMP Community) defines an SNMP v1/v2c community
# string and the manager host(s) allowed to use it. Wire root is <SNMPCommunity>, identified
# by <Name> like every other entity in this module family. Empty on the lab appliance.
#
# Measured against the lab appliance:
# - Mandatory fields confirmed live: Name, CommunityString, one of AuthorizedHostIpv4/
#   AuthorizedHostIpv6, and one of AcceptQueries/SendTraps - the doc table marks both
#   AuthorizedHostIpv4 and AuthorizedHostIpv6 'Mandatory: Yes', but a create with only
#   AuthorizedHostIpv4 succeeded (201), matching the sample's "Specify either" comment, not
#   the table.
# - CommunityString is stored as a salted hash and read back as
#   <CommunityString hashform="mode1">$sfos$...</CommunityString>, the same mechanism already
#   documented for SSLBookmark's password. Get-SfosSNMPCommunity exposes the hash text and its
#   hashform attribute; Set-SfosSNMPCommunity resends them unchanged when the caller does not
#   pass -CommunityString, and the firewall re-salts on every write, same as SSLBookmark.
# - AuthorizedHostIpv4/AuthorizedHostIpv6 read back the literal string 'NULL' for whichever of
#   the pair was not set - Get-SfosSNMPCommunity normalises that to an empty string.
#   Set-SfosSNMPCommunity only emits whichever of the two carries a real value; sending the
#   unset side back as literal 'NULL' was not tested and is not risked, since 'NULL' is not a
#   valid address and AuthorizedHostIpv6's own validation excludes several address classes.
# - AcceptQueries/SendTraps are sent as 'True'/'False' (matching the doc sample) and read back
#   lowercase 'true'/'false' [measured] - the ValidateSet accepts the write-side casing only,
#   since that is what a caller supplies; Get's output is passed through as read.
# - Full CRUD cycle verified live: create, read back, update Description, read back, remove,
#   confirmed empty again. See the function .NOTES for the exact run.

<#
.SYNOPSIS
    Retrieves SNMPCommunity objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SNMPCommunity objects (System > Administration >
    SNMP Community). Use -AsXml to return the raw XML nodes instead of PowerShell-friendly
    objects.

.PARAMETER NameLike
    Optional name filter, substring match. Sent to the firewall as the server-side filter.

.PARAMETER DescriptionLike
    Optional description filter, substring match, applied client-side only.

.PARAMETER AuthorizedHostIpv4Like
    Optional IPv4 manager address filter, substring match, applied client-side only.

.PARAMETER AuthorizedHostIpv6Like
    Optional IPv6 manager address filter, substring match, applied client-side only.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPCommunity -Session $fw1 | New-SfosSNMPCommunity -Session fw2.

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
    PSCustomObject (default) with Name, CommunityString, CommunityStringHashForm, Description,
    AuthorizedHostIpv4, AuthorizedHostIpv6, AcceptQueries, SendTraps. System.Xml.XmlElement
    when -AsXml is specified.

.EXAMPLE
    # Retrieve all SNMP communities
    Get-SfosSNMPCommunity

.EXAMPLE
    # Filter by name (substring match)
    Get-SfosSNMPCommunity -NameLike 'Monitoring'

.NOTES
    Minimum supported PowerShell version: 5.1
    CommunityString is the stored hash, not the plaintext secret - see the region header.
    Verified live: executed against the lab firewall as part of the full create/read/update/
    remove cycle documented on Set-SfosSNMPCommunity.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/SNMPCommunity/operations/AddSNMPCommunity%26EditSNMPCommunity.html

.LINK
    New-SfosSNMPCommunity

.LINK
    Set-SfosSNMPCommunity

.LINK
    Remove-SfosSNMPCommunity
#>
function Get-SfosSNMPCommunity {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 100)]
        [string]$NameLike,

        [ValidateLength(1, 200)]
        [string]$DescriptionLike,

        [string]$AuthorizedHostIpv4Like,
        [string]$AuthorizedHostIpv6Like,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,
        [object]$Session,

        [switch]$AsXml
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    # Server-side pre-filter: only Name is known to work, everything else is applied
    # client-side below, combined with AND (see the project rules ?6).
    $filterXml = ''
    if ($NameLike) {
        $nameLikeEsc = ConvertTo-SfosXmlEscaped -Text $NameLike
        $filterXml = ('<key name="Name" criteria="like">{0}</key>' -f $nameLikeEsc)
    }

    $xmlFilterAdvanced = ''
    if ($filterXml) {
        $xmlFilterAdvanced = @"
<Filter>
    $filterXml
</Filter>
"@
    }

    $inner = @"
<Get>
  <SNMPCommunity>
    $xmlFilterAdvanced
  </SNMPCommunity>
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
        throw "Failed to retrieve SNMPCommunity objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPCommunity' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SNMPCommunity[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($DescriptionLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Description -like "*$DescriptionLike*" })
    }
    if ($AuthorizedHostIpv4Like) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.AuthorizedHostIpv4 -like "*$AuthorizedHostIpv4Like*" })
    }
    if ($AuthorizedHostIpv6Like) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.AuthorizedHostIpv6 -like "*$AuthorizedHostIpv6Like*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $result = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $communityStringNode = $node.SelectSingleNode('CommunityString')
        $authV4 = [string]$node.AuthorizedHostIpv4
        $authV6 = [string]$node.AuthorizedHostIpv6

        $result += [PSCustomObject]@{
            Name                    = [string]$node.Name
            CommunityString         = if ($communityStringNode) { [string]$communityStringNode.InnerText } else { '' }
            CommunityStringHashForm = if ($communityStringNode -and $communityStringNode.Attributes['hashform']) { [string]$communityStringNode.Attributes['hashform'].Value } else { '' }
            Description             = [string]$node.Description
            AuthorizedHostIpv4      = if ($authV4 -eq 'NULL') { '' } else { $authV4 }
            AuthorizedHostIpv6      = if ($authV6 -eq 'NULL') { '' } else { $authV6 }
            AcceptQueries           = [string]$node.AcceptQueries
            SendTraps               = [string]$node.SendTraps
        }
    }

    return $result
}

<#
.SYNOPSIS
    Creates a new SNMPCommunity object on the Sophos Firewall.

.DESCRIPTION
    Creates an SNMP community using the Sophos Firewall XML API. Requires exactly one of
    -AuthorizedHostIpv4/-AuthorizedHostIpv6, and at least one of -AcceptQueries/-SendTraps -
    see the region header for what was actually enforced live versus what the doc table
    claims.

.PARAMETER Name
    Name of the SNMP community (1-100 characters, no commas).

.PARAMETER CommunityString
    The community string (secret). Stored as a salted hash by the firewall.

.PARAMETER Description
    Optional description (max 200 characters).

.PARAMETER AuthorizedHostIpv4
    IPv4 address of the SNMP manager allowed to use this community. Specify this or
    -AuthorizedHostIpv6, not both.

.PARAMETER AuthorizedHostIpv6
    IPv6 address of the SNMP manager allowed to use this community. Specify this or
    -AuthorizedHostIpv4, not both.

.PARAMETER AcceptQueries
    'True' or 'False' - whether the agent accepts queries from the manager using this
    community. At least one of -AcceptQueries/-SendTraps is required.

.PARAMETER SendTraps
    'True' or 'False' - whether SNMP traps are sent using this community. At least one of
    -AcceptQueries/-SendTraps is required.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPCommunity -Session $fw1 | New-SfosSNMPCommunity -Session fw2.

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
    # Create a community that accepts queries from one IPv4 manager
    $secret = ConvertTo-SecureString 'public-secret' -AsPlainText -Force
    New-SfosSNMPCommunity -Name 'Monitoring' -CommunityString $secret -AuthorizedHostIpv4 '10.0.0.50' -AcceptQueries 'True'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall (see Set-SfosSNMPCommunity .NOTES for the
    full cycle including this create).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/SNMPCommunity/operations/AddSNMPCommunity%26EditSNMPCommunity.html

.LINK
    Get-SfosSNMPCommunity

.LINK
    Set-SfosSNMPCommunity

.LINK
    Remove-SfosSNMPCommunity
#>
function New-SfosSNMPCommunity {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [SecureString]$CommunityString,

        [ValidateLength(0, 200)]
        [string]$Description,

        [string]$AuthorizedHostIpv4,
        [string]$AuthorizedHostIpv6,

        [ValidateSet('True', 'False')]
        [string]$AcceptQueries,

        [ValidateSet('True', 'False')]
        [string]$SendTraps,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $AuthorizedHostIpv4 -and -not $AuthorizedHostIpv6) {
        throw "SNMPCommunity object '$Name' needs -AuthorizedHostIpv4 or -AuthorizedHostIpv6."
    }
    if (-not $PSBoundParameters.ContainsKey('AcceptQueries') -and -not $PSBoundParameters.ContainsKey('SendTraps')) {
        throw "SNMPCommunity object '$Name' needs -AcceptQueries or -SendTraps."
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CommunityString)
    try {
        $plainCommunityString = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
    }
    $communityStringEsc = ConvertTo-SfosXmlEscaped -Text $plainCommunityString

    $xmlDescription = ''
    if ($Description) {
        $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $xmlAuthV4 = ''
    if ($AuthorizedHostIpv4) {
        $xmlAuthV4 = "<AuthorizedHostIpv4>$(ConvertTo-SfosXmlEscaped -Text $AuthorizedHostIpv4)</AuthorizedHostIpv4>"
    }
    $xmlAuthV6 = ''
    if ($AuthorizedHostIpv6) {
        $xmlAuthV6 = "<AuthorizedHostIpv6>$(ConvertTo-SfosXmlEscaped -Text $AuthorizedHostIpv6)</AuthorizedHostIpv6>"
    }

    $xmlAcceptQueries = ''
    if ($PSBoundParameters.ContainsKey('AcceptQueries')) {
        $xmlAcceptQueries = "<AcceptQueries>$AcceptQueries</AcceptQueries>"
    }
    $xmlSendTraps = ''
    if ($PSBoundParameters.ContainsKey('SendTraps')) {
        $xmlSendTraps = "<SendTraps>$SendTraps</SendTraps>"
    }

    $inner = @"
<Set operation="add">
  <SNMPCommunity>
    <Name>$nameEsc</Name>
    <CommunityString>$communityStringEsc</CommunityString>
    $xmlDescription
    $xmlAuthV4
    $xmlAuthV6
    $xmlAcceptQueries
    $xmlSendTraps
  </SNMPCommunity>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("SNMPCommunity '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create SNMPCommunity object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPCommunity' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SNMPCommunity object on the Sophos Firewall.

.DESCRIPTION
    Updates an SNMP community using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). -CommunityString is the exception with a value to preserve: when not
    supplied, the stored hash (and its hashform attribute) is resent as-is, the same mechanism
    used for Set-SfosSSLBookmark.

.PARAMETER Name
    Name of the target SNMP community.

.PARAMETER CommunityString
    New community string. If omitted, the stored value is preserved (resent as its hash).

.PARAMETER Description
    Optional description. If omitted, the current value is kept.

.PARAMETER AuthorizedHostIpv4
    IPv4 address of the SNMP manager. If omitted, the current value is kept.

.PARAMETER AuthorizedHostIpv6
    IPv6 address of the SNMP manager. If omitted, the current value is kept.

.PARAMETER AcceptQueries
    'True' or 'False'. If omitted, the current value is kept.

.PARAMETER SendTraps
    'True' or 'False'. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPCommunity -Session $fw1 | Set-SfosSNMPCommunity -Session fw2.

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
    # Change only the description, every other field is preserved
    Set-SfosSNMPCommunity -Name 'Monitoring' -Description 'Updated description'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live against the lab firewall as a full cycle: New-SfosSNMPCommunity created
    'AdminModuleTest' with -AuthorizedHostIpv4 and -AcceptQueries; Get-SfosSNMPCommunity
    confirmed it; Set-SfosSNMPCommunity changed only -Description and Get-SfosSNMPCommunity
    confirmed the new description with every other field unchanged; Remove-SfosSNMPCommunity
    removed it and a final Get-SfosSNMPCommunity confirmed the entity list is empty again.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/SNMPCommunity/operations/AddSNMPCommunity%26EditSNMPCommunity.html

.LINK
    Get-SfosSNMPCommunity
#>
function Set-SfosSNMPCommunity {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [SecureString]$CommunityString,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateLength(0, 200)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$AuthorizedHostIpv4,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$AuthorizedHostIpv6,

        [ValidateSet('True', 'False')]
        [string]$AcceptQueries,

        [ValidateSet('True', 'False')]
        [string]$SendTraps,

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

        $existing = @(Get-SfosSNMPCommunity -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SNMPCommunity object '$Name' was not found."
        }

        $bp = $PSBoundParameters

        if ($bp.ContainsKey('CommunityString')) {
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CommunityString)
            try {
                $plainCommunityString = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            }
            finally {
                [Runtime.InteropServices.Marshal]::FreeBSTR($bstr)
            }
            $communityStringXml = "<CommunityString>$(ConvertTo-SfosXmlEscaped -Text $plainCommunityString)</CommunityString>"
        }
        else {
            $hashForm = if ($existing[0].CommunityStringHashForm) { " hashform=`"$($existing[0].CommunityStringHashForm)`"" } else { '' }
            $communityStringXml = "<CommunityString$hashForm>$($existing[0].CommunityString)</CommunityString>"
        }

        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetAuthV4 = if ($bp.ContainsKey('AuthorizedHostIpv4')) { $AuthorizedHostIpv4 } else { [string]$existing[0].AuthorizedHostIpv4 }
        $targetAuthV6 = if ($bp.ContainsKey('AuthorizedHostIpv6')) { $AuthorizedHostIpv6 } else { [string]$existing[0].AuthorizedHostIpv6 }
        $targetAcceptQueries = if ($bp.ContainsKey('AcceptQueries')) { $AcceptQueries } else { [string]$existing[0].AcceptQueries }
        $targetSendTraps = if ($bp.ContainsKey('SendTraps')) { $SendTraps } else { [string]$existing[0].SendTraps }

        if (-not $targetAuthV4 -and -not $targetAuthV6) {
            throw "SNMPCommunity object '$Name' needs -AuthorizedHostIpv4 or -AuthorizedHostIpv6."
        }

        if (-not $PSCmdlet.ShouldProcess("SNMPCommunity '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>"

        # Only whichever of the two AuthorizedHost* fields carries a real value is emitted -
        # the unset side reads back as the literal 'NULL', which is not a resendable address
        # (see the region header).
        $xmlAuthV4 = ''
        if ($targetAuthV4) {
            $xmlAuthV4 = "<AuthorizedHostIpv4>$(ConvertTo-SfosXmlEscaped -Text $targetAuthV4)</AuthorizedHostIpv4>"
        }
        $xmlAuthV6 = ''
        if ($targetAuthV6) {
            $xmlAuthV6 = "<AuthorizedHostIpv6>$(ConvertTo-SfosXmlEscaped -Text $targetAuthV6)</AuthorizedHostIpv6>"
        }

        $inner = @"
<Set operation="update">
  <SNMPCommunity>
    <Name>$nameEsc</Name>
    $communityStringXml
    $xmlDescription
    $xmlAuthV4
    $xmlAuthV6
    <AcceptQueries>$targetAcceptQueries</AcceptQueries>
    <SendTraps>$targetSendTraps</SendTraps>
  </SNMPCommunity>
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
            throw "Failed to update SNMPCommunity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPCommunity' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SNMPCommunity object from the Sophos Firewall.

.DESCRIPTION
    Removes an SNMP community using the Sophos Firewall XML API. Supports ShouldProcess; use
    -WhatIf to preview.

.PARAMETER Name
    Name of the target SNMP community.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPCommunity -Session $fw1 | Remove-SfosSNMPCommunity -Session fw2.

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
    # Remove a community
    Remove-SfosSNMPCommunity -Name 'Monitoring'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: part of the full cycle documented on Set-SfosSNMPCommunity.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/SNMPCommunity/operations/AddSNMPCommunity%26EditSNMPCommunity.html

.LINK
    Get-SfosSNMPCommunity
#>
function Remove-SfosSNMPCommunity {
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
        if (-not $PSCmdlet.ShouldProcess("SNMPCommunity '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <SNMPCommunity>
    <Name>$nameEsc</Name>
  </SNMPCommunity>
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
            throw "Error removing SNMPCommunity object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPCommunity' -Action 'remove' -Target $Name
    }
}

#endregion

#region SNMPv3User
# SNMPv3User (SYSTEM > Administration > SNMPv3 User) is an SNMPv3 USM user with
# authentication/privacy credentials. Wire root <SNMPv3User> is valid live but has no
# documentation page on this API version - the field set below was found by "provoke and
# read": submitting an incomplete Set and reading which field the firewall named next in
# <InvalidParams>, repeated until the create succeeded. Empty on the lab appliance.
#
# Measured field set (create, in the order the firewall demanded them):
# Name, Username, AuthenticationAlgorithm, AuthenticationPassword, EncryptionAlgorithm,
# EncryptionPassword, then at least one of AcceptQueries/SendTraps - the same "one of the two"
# rule as SNMPCommunity. There is no AuthorizedHost field on this entity at all (unlike
# SNMPCommunity) - Get never returns one, and none was accepted as a probe.
#
# - AuthenticationAlgorithm/EncryptionAlgorithm are a genuinely mixed enum, undocumented and
#   only partially mapped: 'MD5' as text is accepted for AuthenticationAlgorithm and reads
#   back as the numeric '1'; the numeric '2' is also accepted but no text form of it was found
#   ('SHA', 'SHA1', 'sha' were all rejected with 400 naming AuthenticationAlgorithm).
#   EncryptionAlgorithm accepts 'DES' and 'AES' as text (read back as '2' for either, so the
#   two text values do not map to two distinct codes in an obvious way) and the numeric values
#   '1'/'2'/'3' ('4' was rejected). No ValidateSet is applied for either parameter - the enum
#   is not fully known and a real firmware/build may accept values not seen here; this matches
#   the precedent set for Set-SfosApplicationClassificationAssignment.
# - EncryptionAlgorithm '3' reads back with EncryptionPassword empty (no hashform attribute)
#   even though a password was sent alongside it on the same request - consistent with '3'
#   meaning "no privacy", which then discards the value. Not fully confirmed against a
#   documented meaning for '3', since there is no documentation to confirm it against.
# - AuthenticationPassword/EncryptionPassword are stored as salted hashes, same mechanism as
#   SNMPCommunity's CommunityString and SSLBookmark's password on Get. Unlike those two,
#   RESENDING THE HASH ON UPDATE DOES NOT WORK on this entity [measured]: an update carrying
#   <AuthenticationPassword hashform="mode1">$sfos$...</AuthenticationPassword> - the exact
#   shape that works for SNMPCommunity - makes the firewall answer with no <SNMPv3User>
#   element and no <Status> anywhere in the response, not even a code-less one. The identical
#   hash text WITHOUT the hashform attribute is accepted (200/400 depending on the rest of the
#   request) but there is no way to confirm the firewall treats it as "preserve the existing
#   secret" rather than "hash this literal string as the new one" - dropping hashform is
#   exactly the signal that marks a value as plaintext everywhere else hashform is used.
#   Omitting the password element entirely was also tried and is rejected with 400 naming the
#   field, the same as at create. Because none of the three shapes is a confirmed-safe way to
#   preserve the existing secret, Set-SfosSNMPv3User makes both -AuthenticationPassword and
#   -EncryptionPassword mandatory on every call instead of attempting read-modify-write for
#   them - the one deliberate exception to this module's usual hash-resend pattern.
# - Full CRUD cycle verified live: create, read back, update a field, read back, remove,
#   confirmed empty again. See Set-SfosSNMPv3User's .NOTES for the exact run.

<#
.SYNOPSIS
    Retrieves SNMPv3User objects from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for SNMPv3User objects (System > Administration >
    SNMPv3 User). Use -AsXml to return the raw XML nodes instead of PowerShell-friendly
    objects.

.PARAMETER NameLike
    Optional name filter, substring match. Sent to the firewall as the server-side filter.

.PARAMETER UsernameLike
    Optional SNMPv3 username filter, substring match, applied client-side only.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPv3User -Session $fw1 | New-SfosSNMPv3User -Session fw2.

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
    PSCustomObject (default) with Name, Username, AuthenticationAlgorithm,
    AuthenticationPassword, AuthenticationPasswordHashForm, EncryptionAlgorithm,
    EncryptionPassword, EncryptionPasswordHashForm, AcceptQueries, SendTraps.
    System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    # Retrieve all SNMPv3 users
    Get-SfosSNMPv3User

.NOTES
    Minimum supported PowerShell version: 5.1
    See the region header for how this entity's field set was found (no documentation page
    exists for it on this API version).
    Verified live: executed against the lab firewall as part of the full cycle documented on
    Set-SfosSNMPv3User.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    New-SfosSNMPv3User

.LINK
    Set-SfosSNMPv3User

.LINK
    Remove-SfosSNMPv3User
#>
function Get-SfosSNMPv3User {
    [CmdletBinding()]
    param(
        [ValidateLength(1, 100)]
        [string]$NameLike,

        [string]$UsernameLike,

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
        $filterXml = ('<key name="Name" criteria="like">{0}</key>' -f $nameLikeEsc)
    }

    $xmlFilterAdvanced = ''
    if ($filterXml) {
        $xmlFilterAdvanced = @"
<Filter>
    $filterXml
</Filter>
"@
    }

    $inner = @"
<Get>
  <SNMPv3User>
    $xmlFilterAdvanced
  </SNMPv3User>
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
        throw "Failed to retrieve SNMPv3User objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPv3User' -Action 'get'

    $nodes = Select-Xml -Xml $XmlResponse -XPath '/Response/SNMPv3User[Name]' | ForEach-Object -Process {
        $_.Node
    }

    if ($NameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Name -like "*$NameLike*" })
    }
    if ($UsernameLike) {
        $nodes = @($nodes | Where-Object -FilterScript { $_.Username -like "*$UsernameLike*" })
    }

    if ($AsXml) {
        return @($nodes)
    }

    $result = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $authPwNode = $node.SelectSingleNode('AuthenticationPassword')
        $encPwNode = $node.SelectSingleNode('EncryptionPassword')

        $result += [PSCustomObject]@{
            Name                          = [string]$node.Name
            Username                      = [string]$node.Username
            AuthenticationAlgorithm       = [string]$node.AuthenticationAlgorithm
            AuthenticationPassword        = if ($authPwNode) { [string]$authPwNode.InnerText } else { '' }
            AuthenticationPasswordHashForm = if ($authPwNode -and $authPwNode.Attributes['hashform']) { [string]$authPwNode.Attributes['hashform'].Value } else { '' }
            EncryptionAlgorithm           = [string]$node.EncryptionAlgorithm
            EncryptionPassword             = if ($encPwNode) { [string]$encPwNode.InnerText } else { '' }
            EncryptionPasswordHashForm     = if ($encPwNode -and $encPwNode.Attributes['hashform']) { [string]$encPwNode.Attributes['hashform'].Value } else { '' }
            AcceptQueries                  = [string]$node.AcceptQueries
            SendTraps                      = [string]$node.SendTraps
        }
    }

    return $result
}

<#
.SYNOPSIS
    Creates a new SNMPv3User object on the Sophos Firewall.

.DESCRIPTION
    Creates an SNMPv3 USM user using the Sophos Firewall XML API. Requires at least one of
    -AcceptQueries/-SendTraps. See the region header for the undocumented
    AuthenticationAlgorithm/EncryptionAlgorithm value set.

.PARAMETER Name
    Name identifying the SNMPv3 user object (1-100 characters, no commas).

.PARAMETER SNMPUsername
    The SNMPv3 protocol username. Named -SNMPUsername rather than -Username to avoid
    colliding with the connection parameter of the same name.

.PARAMETER AuthenticationAlgorithm
    Authentication algorithm. 'MD5' is a confirmed text value; the numeric '2' is also
    accepted but has no known text form on this firmware - see the region header.

.PARAMETER AuthenticationPassword
    Authentication password/passphrase. Stored as a salted hash.

.PARAMETER EncryptionAlgorithm
    Privacy/encryption algorithm. 'DES' and 'AES' are confirmed text values; the numeric
    values '1'/'2'/'3' are also accepted - see the region header.

.PARAMETER EncryptionPassword
    Privacy/encryption password/passphrase. Stored as a salted hash.

.PARAMETER AcceptQueries
    'True' or 'False' - whether the agent accepts queries authenticated as this user. At
    least one of -AcceptQueries/-SendTraps is required.

.PARAMETER SendTraps
    'True' or 'False' - whether SNMP traps are sent authenticated as this user. At least one
    of -AcceptQueries/-SendTraps is required.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPv3User -Session $fw1 | New-SfosSNMPv3User -Session fw2.

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
    # Create an SNMPv3 user with MD5 authentication and DES privacy
    $authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
    $privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
    New-SfosSNMPv3User -Name 'MonitoringUser' -SNMPUsername 'monitor' -AuthenticationAlgorithm 'MD5' -AuthenticationPassword $authPw -EncryptionAlgorithm 'DES' -EncryptionPassword $privPw -AcceptQueries 'True'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall (see Set-SfosSNMPv3User .NOTES for the
    full cycle including this create).

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosSNMPv3User

.LINK
    Set-SfosSNMPv3User

.LINK
    Remove-SfosSNMPv3User
#>
function New-SfosSNMPv3User {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$SNMPUsername,

        [Parameter(Mandatory)]
        [string]$AuthenticationAlgorithm,

        [Parameter(Mandatory)]
        [SecureString]$AuthenticationPassword,

        [Parameter(Mandatory)]
        [string]$EncryptionAlgorithm,

        [Parameter(Mandatory)]
        [SecureString]$EncryptionPassword,

        [ValidateSet('True', 'False')]
        [string]$AcceptQueries,

        [ValidateSet('True', 'False')]
        [string]$SendTraps,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSBoundParameters.ContainsKey('AcceptQueries') -and -not $PSBoundParameters.ContainsKey('SendTraps')) {
        throw "SNMPv3User object '$Name' needs -AcceptQueries or -SendTraps."
    }

    $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name
    $snmpUsernameEsc = ConvertTo-SfosXmlEscaped -Text $SNMPUsername

    $bstrAuth = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AuthenticationPassword)
    try {
        $plainAuthPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrAuth)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeBSTR($bstrAuth)
    }
    $bstrEnc = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionPassword)
    try {
        $plainEncPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrEnc)
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeBSTR($bstrEnc)
    }

    $xmlAcceptQueries = ''
    if ($PSBoundParameters.ContainsKey('AcceptQueries')) {
        $xmlAcceptQueries = "<AcceptQueries>$AcceptQueries</AcceptQueries>"
    }
    $xmlSendTraps = ''
    if ($PSBoundParameters.ContainsKey('SendTraps')) {
        $xmlSendTraps = "<SendTraps>$SendTraps</SendTraps>"
    }

    $inner = @"
<Set operation="add">
  <SNMPv3User>
    <Name>$nameEsc</Name>
    <Username>$snmpUsernameEsc</Username>
    <AuthenticationAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $AuthenticationAlgorithm)</AuthenticationAlgorithm>
    <AuthenticationPassword>$(ConvertTo-SfosXmlEscaped -Text $plainAuthPassword)</AuthenticationPassword>
    <EncryptionAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $EncryptionAlgorithm)</EncryptionAlgorithm>
    <EncryptionPassword>$(ConvertTo-SfosXmlEscaped -Text $plainEncPassword)</EncryptionPassword>
    $xmlAcceptQueries
    $xmlSendTraps
  </SNMPv3User>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("SNMPv3User '$Name' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create SNMPv3User object '$Name': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPv3User' -Action 'create' -Target $Name
}

<#
.SYNOPSIS
    Updates an existing SNMPv3User object on the Sophos Firewall.

.DESCRIPTION
    Updates an SNMPv3 USM user using the Sophos Firewall XML API. Reads the current object
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write) - except -AuthenticationPassword/-EncryptionPassword, which are
    mandatory on every call. Unlike Set-SfosSNMPCommunity/Set-SfosSSLBookmark, resending the
    stored password hash does not work on this entity: with its hashform attribute the
    firewall answers with no <SNMPv3User> element and no <Status> at all, and without the
    attribute the value is accepted but is almost certainly re-hashed as a literal new secret
    rather than preserved. See the region header for the full measurement.

.PARAMETER Name
    Name of the target SNMPv3 user object.

.PARAMETER SNMPUsername
    New SNMPv3 protocol username. Named -SNMPUsername rather than -Username to avoid
    colliding with the connection parameter of the same name. If omitted, the current value
    is kept.

.PARAMETER AuthenticationAlgorithm
    New authentication algorithm - see the region header for the value set. If omitted, the
    current value is kept.

.PARAMETER AuthenticationPassword
    Authentication password. Mandatory on every update - see .DESCRIPTION for why there is no
    working way to preserve the stored value instead.

.PARAMETER EncryptionAlgorithm
    New privacy/encryption algorithm - see the region header for the value set. If omitted,
    the current value is kept.

.PARAMETER EncryptionPassword
    Privacy/encryption password. Mandatory on every update - see .DESCRIPTION for why there
    is no working way to preserve the stored value instead.

.PARAMETER AcceptQueries
    'True' or 'False'. If omitted, the current value is kept.

.PARAMETER SendTraps
    'True' or 'False'. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPv3User -Session $fw1 | Set-SfosSNMPv3User -Session fw2.

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
    # Change only the encryption algorithm; both passwords must still be supplied
    $authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
    $privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
    Set-SfosSNMPv3User -Name 'MonitoringUser' -EncryptionAlgorithm 'AES' -AuthenticationPassword $authPw -EncryptionPassword $privPw

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live against the lab firewall as a full cycle: New-SfosSNMPv3User created
    'AdminModuleTestV3' with MD5/DES and -AcceptQueries; Get-SfosSNMPv3User confirmed it;
    Set-SfosSNMPv3User changed only -SNMPUsername (with both passwords resupplied) and
    Get-SfosSNMPv3User confirmed the new username with every other field unchanged;
    Remove-SfosSNMPv3User removed it and a final Get-SfosSNMPv3User confirmed the entity list
    is empty again. The hash-resend path documented in .DESCRIPTION was independently
    reproduced against the live appliance before this cmdlet was changed to require both
    passwords on every update.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosSNMPv3User
#>
function Set-SfosSNMPv3User {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 100)]
        [ValidatePattern('^[^,]+$')]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SNMPUsername,

        [string]$AuthenticationAlgorithm,

        [Parameter(Mandatory)]
        [SecureString]$AuthenticationPassword,

        [string]$EncryptionAlgorithm,

        [Parameter(Mandatory)]
        [SecureString]$EncryptionPassword,

        [ValidateSet('True', 'False')]
        [string]$AcceptQueries,

        [ValidateSet('True', 'False')]
        [string]$SendTraps,

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

        $existing = @(Get-SfosSNMPv3User -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -NameLike $Name `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.Name -eq $Name })

        if ($existing.Count -eq 0) {
            throw "The SNMPv3User object '$Name' was not found."
        }

        $bp = $PSBoundParameters

        $targetSNMPUsername = if ($bp.ContainsKey('SNMPUsername')) { $SNMPUsername } else { [string]$existing[0].Username }
        $targetAuthAlgorithm = if ($bp.ContainsKey('AuthenticationAlgorithm')) { $AuthenticationAlgorithm } else { [string]$existing[0].AuthenticationAlgorithm }
        $targetEncAlgorithm = if ($bp.ContainsKey('EncryptionAlgorithm')) { $EncryptionAlgorithm } else { [string]$existing[0].EncryptionAlgorithm }
        $targetAcceptQueries = if ($bp.ContainsKey('AcceptQueries')) { $AcceptQueries } else { [string]$existing[0].AcceptQueries }
        $targetSendTraps = if ($bp.ContainsKey('SendTraps')) { $SendTraps } else { [string]$existing[0].SendTraps }

        # -AuthenticationPassword/-EncryptionPassword are mandatory here, unlike every other
        # hashed secret in this module - see the region header. Resending the stored hash with
        # its hashform attribute makes the firewall answer with no <SNMPv3User> element and no
        # <Status> at all (not even a code-less one), and the same hash text without the
        # attribute is accepted but then almost certainly re-hashed as a literal new secret
        # rather than preserved, since dropping hashform is exactly what signals "this is
        # plaintext" elsewhere in this API. Neither shape is safe, so there is nothing to
        # preserve here - the caller must supply both on every update.
        $bstrAuth = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AuthenticationPassword)
        try {
            $plainAuthPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrAuth)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstrAuth)
        }
        $authPasswordXml = "<AuthenticationPassword>$(ConvertTo-SfosXmlEscaped -Text $plainAuthPassword)</AuthenticationPassword>"

        $bstrEnc = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionPassword)
        try {
            $plainEncPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstrEnc)
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($bstrEnc)
        }
        $encPasswordXml = "<EncryptionPassword>$(ConvertTo-SfosXmlEscaped -Text $plainEncPassword)</EncryptionPassword>"

        if (-not $PSCmdlet.ShouldProcess("SNMPv3User '$Name' on $($params.Firewall)", 'Update')) {
            return
        }

        $inner = @"
<Set operation="update">
  <SNMPv3User>
    <Name>$nameEsc</Name>
    <Username>$(ConvertTo-SfosXmlEscaped -Text $targetSNMPUsername)</Username>
    <AuthenticationAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $targetAuthAlgorithm)</AuthenticationAlgorithm>
    $authPasswordXml
    <EncryptionAlgorithm>$(ConvertTo-SfosXmlEscaped -Text $targetEncAlgorithm)</EncryptionAlgorithm>
    $encPasswordXml
    <AcceptQueries>$targetAcceptQueries</AcceptQueries>
    <SendTraps>$targetSendTraps</SendTraps>
  </SNMPv3User>
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
            throw "Failed to update SNMPv3User object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPv3User' -Action 'update' -Target $Name
    }
}

<#
.SYNOPSIS
    Removes an SNMPv3User object from the Sophos Firewall.

.DESCRIPTION
    Removes an SNMPv3 USM user using the Sophos Firewall XML API. Supports ShouldProcess;
    use -WhatIf to preview.

.PARAMETER Name
    Name of the target SNMPv3 user object.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosSNMPv3User -Session $fw1 | Remove-SfosSNMPv3User -Session fw2.

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
    # Remove an SNMPv3 user
    Remove-SfosSNMPv3User -Name 'MonitoringUser'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: part of the full cycle documented on Set-SfosSNMPv3User.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosSNMPv3User
#>
function Remove-SfosSNMPv3User {
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
        if (-not $PSCmdlet.ShouldProcess("SNMPv3User '$Name' on $($params.Firewall)", 'Remove')) {
            return
        }

        $nameEsc = ConvertTo-SfosXmlEscaped -Text $Name

        $inner = @"
<Remove>
  <SNMPv3User>
    <Name>$nameEsc</Name>
  </SNMPv3User>
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
            throw "Error removing SNMPv3User object '$Name': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'SNMPv3User' -Action 'remove' -Target $Name
    }
}

#endregion

#region Messages
# Messages (SYSTEM > Administration > Messages) customizes the text shown to end users for
# SMTP rejections, login/session events, the admin login disclaimer and the default guest-user
# SMS. Wire root is <Messages>, a singleton with no <Name> child.
#
# Measured against the lab appliance:
# - Unlike every other singleton in this module, a Get answers with FOUR separate <Messages>
#   sibling elements, one per sub-block (<SMTP>, <Administration>, <SMSCustomization>,
#   <AuthenticationMessages>), not one <Messages> wrapping all four the way the doc sample
#   shows it for Set. Get-SfosMessages collects all four and returns one merged object.
# - The live SMTP block has 16 fields; the doc sample lists three more
#   (DataControlListRejection, SourceIPAddressRejection, DestinationIPAddressRejection) that
#   never appeared on a Get from this appliance. Not implemented, per the project rules ?5 - inventing
#   a field the appliance never showed is exactly how the CountryHostGroup defect happened.
# - Set is a genuine PARTIAL update, unlike almost every other entity in this API suite
#   [measured]: sending only <Messages><SMSCustomization><DefaultSMS>...</DefaultSMS>
#   </SMSCustomization></Messages> changed only that one field and left SMTP, Administration
#   and AuthenticationMessages - and every other field within AuthenticationMessages - byte
#   for byte unchanged. Set-SfosMessages therefore does NOT follow this module's usual
#   read-modify-write pattern: it sends only the fields the caller actually binds. A full
#   read-modify-write was tried first and rejected after measurement - see the next point.
# - Resending an untouched field is not harmless [measured]: the firewall trims trailing
#   whitespace from every text field it receives (see the next point), so a full
#   read-modify-write that resends the whole entity on every call silently strips trailing
#   whitespace from fields nobody asked to change - caught live when an unrelated -DefaultSMS
#   change lost the trailing newline on Administration/DisclaimerMessage, a field the call
#   never touched. Sending only bound fields confines the trimming to what the caller actually
#   changes.
# - Text fields are stored trimmed of trailing whitespace [measured]: the live baseline value
#   of AuthenticationMessages/NotAuthenticate carries a single trailing space (a pre-existing
#   Sophos default-text artifact, not something introduced by this module), and resending that
#   exact string verbatim came back with the trailing space silently dropped. Harmless for
#   this field, but any caller relying on exact trailing whitespace being preserved will lose
#   it on write.
# - A "Reset Admin Messages" operation is documented on the same page as the update operation
#   (parameters 'Message'/'ResetFlag', both arrays of strings, no working shape given). Every
#   shape tried against the live appliance - a bare field name, a field name nested inside its
#   own sub-block, operation="reset" instead of "update", and a dotted "Block/Field" path - was
#   accepted with code 200 and changed nothing (a silent no-op, the same signature already
#   documented elsewhere in this suite for GuestUser edit and IPSFullSignaturePack add). No
#   working shape was found, so no Reset-SfosMessages cmdlet is provided; use Set-SfosMessages
#   with the original text to revert a field instead.
# - Status lands flat at /Response/Messages/Status with a code attribute for both Get and Set
#   errors, confirmed by provoking a 501 (Description... actually a 501 field-length error) and
#   a 400 (multiple missing AcceptQueries/SendTraps-style validation failures do not apply
#   here, but an over-length value reproduced the same shape) - -ObjectName 'Messages' finds it
#   directly, no nested container.

<#
.SYNOPSIS
    Retrieves the customizable end-user messages from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the Messages singleton (System > Administration >
    Messages): SMTP rejection texts, the admin login disclaimer, the default guest-user SMS
    text, and authentication/session messages. Use -AsXml to return the raw XML nodes instead
    of a PowerShell-friendly object - see the region header for why this singleton returns
    four separate XML nodes rather than one.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosMessages -Session $fw1 | Set-SfosMessages -Session fw2.

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
    Returns the raw XML nodes (an array of the four <Messages> sub-block elements) instead of
    a PowerShell-friendly object.

.OUTPUTS
    PSCustomObject (default) with SMTP, Administration, SMSCustomization and
    AuthenticationMessages sub-objects, each carrying the matching leaf text fields.
    System.Xml.XmlElement[] when -AsXml is specified.

.EXAMPLE
    # Read the admin login disclaimer
    (Get-SfosMessages).Administration.DisclaimerMessage

.EXAMPLE
    # Read the default guest-user SMS text
    (Get-SfosMessages).SMSCustomization.DefaultSMS

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall; all fields matched the saved baseline
    XML.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/Messages/operations/ResetAdminMessages%26UpdateAdminMessages.html

.LINK
    Set-SfosMessages
#>
function Get-SfosMessages {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Messages is the Sophos API root element itself, a singleton with no singular child.')]
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

    $inner = '<Get><Messages></Messages></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving Messages: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Messages' -Action 'get'

    # Four separate <Messages> siblings, one per sub-block - see the region header.
    $nodes = @($XmlResponse.SelectNodes('/Response/Messages'))
    if (-not $nodes.Count) {
        throw 'Messages could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $nodes
    }

    $smtpNode = ($nodes | Where-Object -FilterScript { $_.SMTP } | Select-Object -First 1).SMTP
    $adminNode = ($nodes | Where-Object -FilterScript { $_.Administration } | Select-Object -First 1).Administration
    $smsNode = ($nodes | Where-Object -FilterScript { $_.SMSCustomization } | Select-Object -First 1).SMSCustomization
    $authNode = ($nodes | Where-Object -FilterScript { $_.AuthenticationMessages } | Select-Object -First 1).AuthenticationMessages

    return [PSCustomObject]@{
        SMTP                   = [PSCustomObject]@{
            SXLRejection                   = [string]$smtpNode.SXLRejection
            ProbableSpamRejection           = [string]$smtpNode.ProbableSpamRejection
            ProbableVirusOutbreakRejection  = [string]$smtpNode.ProbableVirusOutbreakRejection
            SpamRejection                   = [string]$smtpNode.SpamRejection
            VirusOutbreakRejection          = [string]$smtpNode.VirusOutbreakRejection
            EmailDomainRejection            = [string]$smtpNode.EmailDomainRejection
            SpamMailRejection               = [string]$smtpNode.SpamMailRejection
            MailHeaderRejection             = [string]$smtpNode.MailHeaderRejection
            MailVirusRejection              = [string]$smtpNode.MailVirusRejection
            IPAddressRejection              = [string]$smtpNode.IPAddressRejection
            OversizedMailRejection          = [string]$smtpNode.OversizedMailRejection
            UndersizedMailRejection         = [string]$smtpNode.UndersizedMailRejection
            DeliveryNotification            = [string]$smtpNode.DeliveryNotification
            AttachmentInfection              = [string]$smtpNode.AttachmentInfection
            RBLRejection                     = [string]$smtpNode.RBLRejection
            SuspectedInfection               = [string]$smtpNode.SuspectedInfection
        }
        Administration          = [PSCustomObject]@{
            DisclaimerMessage = [string]$adminNode.DisclaimerMessage
        }
        SMSCustomization        = [PSCustomObject]@{
            DefaultSMS = [string]$smsNode.DefaultSMS
        }
        AuthenticationMessages  = [PSCustomObject]@{
            Useraccountblocked                     = [string]$authNode.Useraccountblocked
            Useraccountdisabled                     = [string]$authNode.Useraccountdisabled
            Useraccountexpired                      = [string]$authNode.Useraccountexpired
            ClientlessUserLoginNotAllowed           = [string]$authNode.ClientlessUserLoginNotAllowed
            DataTransferExhausted                   = [string]$authNode.DataTransferExhausted
            DeactiveUser                             = [string]$authNode.DeactiveUser
            DeleteUser                               = [string]$authNode.DeleteUser
            DisconnectUser                           = [string]$authNode.DisconnectUser
            GuestUserValidityExpired                = [string]$authNode.GuestUserValidityExpired
            Loginnotallowedatthistime               = [string]$authNode.Loginnotallowedatthistime
            InvalidMachine                           = [string]$authNode.InvalidMachine
            Loginnotallowedatthisworkstation        = [string]$authNode.Loginnotallowedatthisworkstation
            SomeoneelseisloggedinfromsameIPAddress  = [string]$authNode.SomeoneelseisloggedinfromsameIPAddress
            LoggedOffSuccessfulMessage               = [string]$authNode.LoggedOffSuccessfulMessage
            LoggedOnSuccessfulMessage                = [string]$authNode.LoggedOnSuccessfulMessage
            LogoutNotification                       = [string]$authNode.LogoutNotification
            MaxLoginLimit                            = [string]$authNode.MaxLoginLimit
            NotAuthenticate                          = [string]$authNode.NotAuthenticate
            NotCurrentlyAllowed                      = [string]$authNode.NotCurrentlyAllowed
            Userpasswordexpired                      = [string]$authNode.Userpasswordexpired
            Userneedstoresetthepassword              = [string]$authNode.Userneedstoresetthepassword
            LoggedOffDueToSessionTimeOut             = [string]$authNode.LoggedOffDueToSessionTimeOut
            SurfingTimeExhausted                     = [string]$authNode.SurfingTimeExhausted
            SurfingTimeExpired                       = [string]$authNode.SurfingTimeExpired
        }
    }
}

<#
.SYNOPSIS
    Updates the customizable end-user messages on the Sophos Firewall.

.DESCRIPTION
    Updates the Messages singleton (System > Administration > Messages) using the Sophos
    Firewall XML API. Unlike every other Set-* in this module, this is a genuine PARTIAL
    update: only the fields the caller actually binds are sent, and every other field - even
    within the same sub-block - is left untouched on the firewall. See the region header for
    the measurement behind this and why the cmdlet deliberately does not read-modify-write the
    whole entity. At least one field parameter is required. Supports ShouldProcess; use
    -WhatIf to preview.

.PARAMETER SXLRejection
    SMTP: RBL rejection text. If omitted, the current value is kept.

.PARAMETER ProbableSpamRejection
    SMTP: probable-spam rejection text. If omitted, the current value is kept.

.PARAMETER ProbableVirusOutbreakRejection
    SMTP: probable virus outbreak rejection text. If omitted, the current value is kept.

.PARAMETER SpamRejection
    SMTP: spam rejection text. If omitted, the current value is kept.

.PARAMETER VirusOutbreakRejection
    SMTP: virus outbreak rejection text. If omitted, the current value is kept.

.PARAMETER EmailDomainRejection
    SMTP: sender domain policy rejection text. If omitted, the current value is kept.

.PARAMETER SpamMailRejection
    SMTP: sender address policy rejection text. If omitted, the current value is kept.

.PARAMETER MailHeaderRejection
    SMTP: MIME header policy rejection text. If omitted, the current value is kept.

.PARAMETER MailVirusRejection
    SMTP: virus rejection text. If omitted, the current value is kept.

.PARAMETER IPAddressRejection
    SMTP: sender IP policy rejection text. If omitted, the current value is kept.

.PARAMETER OversizedMailRejection
    SMTP: message-too-large rejection text. If omitted, the current value is kept.

.PARAMETER UndersizedMailRejection
    SMTP: message-too-small rejection text. If omitted, the current value is kept.

.PARAMETER DeliveryNotification
    SMTP: successful delivery notification text. If omitted, the current value is kept.

.PARAMETER AttachmentInfection
    SMTP: suspected-infected-attachment rejection text. If omitted, the current value is kept.

.PARAMETER RBLRejection
    SMTP: RBL rejection text (duplicate wording of -SXLRejection on this firmware). If
    omitted, the current value is kept.

.PARAMETER SuspectedInfection
    SMTP: suspected-virus rejection text. If omitted, the current value is kept.

.PARAMETER DisclaimerMessage
    Admin login disclaimer/warning banner text. If omitted, the current value is kept.

.PARAMETER DefaultSMS
    Default guest-user SMS text template. If omitted, the current value is kept.

.PARAMETER Useraccountblocked
    Authentication: account-blocked message. If omitted, the current value is kept.

.PARAMETER Useraccountdisabled
    Authentication: account-disabled message. If omitted, the current value is kept.

.PARAMETER Useraccountexpired
    Authentication: account-expired message. If omitted, the current value is kept.

.PARAMETER ClientlessUserLoginNotAllowed
    Authentication: clientless login not permitted message. If omitted, the current value is
    kept.

.PARAMETER DataTransferExhausted
    Authentication: data transfer quota exceeded message. If omitted, the current value is
    kept.

.PARAMETER DeactiveUser
    Authentication: account no longer active message. If omitted, the current value is kept.

.PARAMETER DeleteUser
    Authentication: user deleted/disconnected message. If omitted, the current value is kept.

.PARAMETER DisconnectUser
    Authentication: disconnected-by-admin message. If omitted, the current value is kept.

.PARAMETER GuestUserValidityExpired
    Authentication: guest user validity expired message. If omitted, the current value is
    kept.

.PARAMETER Loginnotallowedatthistime
    Authentication: login not permitted at this time message. If omitted, the current value
    is kept.

.PARAMETER InvalidMachine
    Authentication: login not permitted from this machine message. If omitted, the current
    value is kept.

.PARAMETER Loginnotallowedatthisworkstation
    Authentication: login denied by directory server for this workstation message. If
    omitted, the current value is kept.

.PARAMETER SomeoneelseisloggedinfromsameIPAddress
    Authentication: concurrent login from same IP message. If omitted, the current value is
    kept.

.PARAMETER LoggedOffSuccessfulMessage
    Authentication: sign-out confirmation message. If omitted, the current value is kept.

.PARAMETER LoggedOnSuccessfulMessage
    Authentication: sign-in confirmation message. If omitted, the current value is kept.

.PARAMETER LogoutNotification
    Authentication: pending-automatic-logout notification message. If omitted, the current
    value is kept.

.PARAMETER MaxLoginLimit
    Authentication: maximum login limit reached message. If omitted, the current value is
    kept.

.PARAMETER NotAuthenticate
    Authentication: invalid credentials message. If omitted, the current value is kept.

.PARAMETER NotCurrentlyAllowed
    Authentication: access not currently permitted message. If omitted, the current value is
    kept.

.PARAMETER Userpasswordexpired
    Authentication: directory server password expired message. If omitted, the current value
    is kept.

.PARAMETER Userneedstoresetthepassword
    Authentication: directory server password reset required message. If omitted, the current
    value is kept.

.PARAMETER LoggedOffDueToSessionTimeOut
    Authentication: session timed out message. If omitted, the current value is kept.

.PARAMETER SurfingTimeExhausted
    Authentication: surfing time quota exhausted message. If omitted, the current value is
    kept.

.PARAMETER SurfingTimeExpired
    Authentication: surfing time expired message. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosMessages -Session $fw1 | Set-SfosMessages -Session fw2.

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
    # Change only the default guest-user SMS text, every other field is preserved
    Set-SfosMessages -DefaultSMS 'Your Sophos guest account is ready.'

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live against the lab firewall as a full cycle: -DefaultSMS was changed from its
    baseline to a probe value with only that one parameter bound, confirmed via
    Get-SfosMessages to have changed nothing else (SMTP/Administration/AuthenticationMessages
    byte for byte identical), then set back to the exact baseline text and reconfirmed
    identical. -NotAuthenticate was probed the same way and reverted to the baseline text
    minus one trailing space the firewall silently trims on write (see the region header) - a
    one-character, functionally invisible difference from the pre-existing baseline value, not
    introduced by this cmdlet beyond what the write path itself does. An earlier version of
    this cmdlet performed a full read-modify-write and was caught doing exactly this kind of
    silent trimming to an UNTOUCHED field - resending Administration/DisclaimerMessage
    unchanged as part of an unrelated -DefaultSMS update lost its trailing newline - which is
    why this cmdlet sends only the bound fields instead. An over-length value (700 characters)
    was also sent and correctly rejected with code 501, confirmed unchanged via
    Get-SfosMessages.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/Messages/operations/ResetAdminMessages%26UpdateAdminMessages.html

.LINK
    Get-SfosMessages
#>
function Set-SfosMessages {
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Messages is the Sophos API root element itself, a singleton with no singular child.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Username/Password here are the standard connection parameters; Userpasswordexpired/Userneedstoresetthepassword are message text fields, not credentials.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Userpasswordexpired', Justification = 'Message text field, not a credential.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Userneedstoresetthepassword', Justification = 'Message text field, not a credential.')]
    param(
        [string]$SXLRejection,
        [string]$ProbableSpamRejection,
        [string]$ProbableVirusOutbreakRejection,
        [string]$SpamRejection,
        [string]$VirusOutbreakRejection,
        [string]$EmailDomainRejection,
        [string]$SpamMailRejection,
        [string]$MailHeaderRejection,
        [string]$MailVirusRejection,
        [string]$IPAddressRejection,
        [string]$OversizedMailRejection,
        [string]$UndersizedMailRejection,
        [string]$DeliveryNotification,
        [string]$AttachmentInfection,
        [string]$RBLRejection,
        [string]$SuspectedInfection,

        [string]$DisclaimerMessage,

        [string]$DefaultSMS,

        [string]$Useraccountblocked,
        [string]$Useraccountdisabled,
        [string]$Useraccountexpired,
        [string]$ClientlessUserLoginNotAllowed,
        [string]$DataTransferExhausted,
        [string]$DeactiveUser,
        [string]$DeleteUser,
        [string]$DisconnectUser,
        [string]$GuestUserValidityExpired,
        [string]$Loginnotallowedatthistime,
        [string]$InvalidMachine,
        [string]$Loginnotallowedatthisworkstation,
        [string]$SomeoneelseisloggedinfromsameIPAddress,
        [string]$LoggedOffSuccessfulMessage,
        [string]$LoggedOnSuccessfulMessage,
        [string]$LogoutNotification,
        [string]$MaxLoginLimit,
        [string]$NotAuthenticate,
        [string]$NotCurrentlyAllowed,
        [string]$Userpasswordexpired,
        [string]$Userneedstoresetthepassword,
        [string]$LoggedOffDueToSessionTimeOut,
        [string]$SurfingTimeExhausted,
        [string]$SurfingTimeExpired,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $bp = $PSBoundParameters

    $smtpFields = @(
        'SXLRejection', 'ProbableSpamRejection', 'ProbableVirusOutbreakRejection', 'SpamRejection',
        'VirusOutbreakRejection', 'EmailDomainRejection', 'SpamMailRejection', 'MailHeaderRejection',
        'MailVirusRejection', 'IPAddressRejection', 'OversizedMailRejection', 'UndersizedMailRejection',
        'DeliveryNotification', 'AttachmentInfection', 'RBLRejection', 'SuspectedInfection'
    )
    $adminFields = @('DisclaimerMessage')
    $smsFields = @('DefaultSMS')
    $authFields = @(
        'Useraccountblocked', 'Useraccountdisabled', 'Useraccountexpired', 'ClientlessUserLoginNotAllowed',
        'DataTransferExhausted', 'DeactiveUser', 'DeleteUser', 'DisconnectUser', 'GuestUserValidityExpired',
        'Loginnotallowedatthistime', 'InvalidMachine', 'Loginnotallowedatthisworkstation',
        'SomeoneelseisloggedinfromsameIPAddress', 'LoggedOffSuccessfulMessage', 'LoggedOnSuccessfulMessage',
        'LogoutNotification', 'MaxLoginLimit', 'NotAuthenticate', 'NotCurrentlyAllowed', 'Userpasswordexpired',
        'Userneedstoresetthepassword', 'LoggedOffDueToSessionTimeOut', 'SurfingTimeExhausted', 'SurfingTimeExpired'
    )

    # Messages is a confirmed partial-update entity (see the region header) - a request
    # carrying only the fields the caller actually bound changes only those fields and leaves
    # everything else, byte for byte, alone. This function deliberately does NOT read the
    # current object and resend it: doing so was tried first and its side effect was measured
    # live - the firewall trims trailing whitespace on every text field it receives, so
    # resending untouched fields silently stripped a trailing newline from
    # Administration/DisclaimerMessage that nobody asked to change. Sending only bound fields
    # confines that trimming to fields the caller is actually touching.
    $boundFieldXml = {
        param([string[]]$FieldNames)
        ($FieldNames | Where-Object -FilterScript { $bp.ContainsKey($_) } | ForEach-Object -Process {
                "<$_>$(ConvertTo-SfosXmlEscaped -Text $bp[$_])</$_>"
            }) -join ''
    }

    $smtpXml = & $boundFieldXml -FieldNames $smtpFields
    $adminXml = & $boundFieldXml -FieldNames $adminFields
    $smsXml = & $boundFieldXml -FieldNames $smsFields
    $authXml = & $boundFieldXml -FieldNames $authFields

    if (-not $smtpXml -and -not $adminXml -and -not $smsXml -and -not $authXml) {
        throw 'Set-SfosMessages needs at least one message field parameter.'
    }

    if (-not $PSCmdlet.ShouldProcess("Messages on $($params.Firewall)", 'Update')) {
        return
    }

    $smtpBlock = if ($smtpXml) { "<SMTP>$smtpXml</SMTP>" } else { '' }
    $adminBlock = if ($adminXml) { "<Administration>$adminXml</Administration>" } else { '' }
    $smsBlock = if ($smsXml) { "<SMSCustomization>$smsXml</SMSCustomization>" } else { '' }
    $authBlock = if ($authXml) { "<AuthenticationMessages>$authXml</AuthenticationMessages>" } else { '' }

    $inner = @"
<Set operation="update">
  <Messages>
    $smtpBlock
    $adminBlock
    $smsBlock
    $authBlock
  </Messages>
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
        throw "Failed to update Messages: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'Messages' -Action 'update'
}

#endregion

#region ApplianceAccess
# ApplianceAccess (SYSTEM > Administration > Device Access, "Local Service ACL" / "Admin
# Service Access" in the web admin) controls, per management-facing service, which firewall
# zones may reach it. Wire root is <ApplianceAccess>, a singleton with no <Name> child - one
# <ServiceName><ZoneName>...</ZoneName></ServiceName> block per service.
#
# No documentation page exists for this entity anywhere in the SFOS 22.0 API menu - the full
# menu index was searched for "ApplianceAccess" and "Local Service"/"Local ACL" and neither
# term appears, the same situation already documented for SNMPv3User elsewhere in this file.
#
# Measured against the lab appliance (Get, live baseline, confirmed unchanged on a second read
# taken while building this region):
# - 14 services, each holding zero or more <ZoneName> children: Https, SSH, CaptivePortal,
#   RadiusSSO, ClientAuthentication, Ping, DNS, SSLVPN, WebProxy, SMTPRelay, SNMP, VPNPortal,
#   RED, IPsec. Casing is exactly as shown on the wire - 'Https' (not 'HTTPS') and 'IPsec'
#   (not 'IPSec').
# - This is the field that actually carries HTTPS/SSH management access for the LAN zone: the
#   lab baseline has Https=[WiFi,LAN] and SSH=[LAN,DMZ,WiFi]. Removing LAN from either is the
#   fastest way to repeat the SpoofPrevention lock-out already paid for once in this suite -
#   FW1 has no out-of-band recovery path. See Set-SfosApplianceAccess's .NOTES: it was never
#   executed against the live firewall.
# - No <Set> was ever attempted against this entity, live or otherwise. The operation
#   attribute ('update'), the exact status XPath, and whether the API treats this as a genuine
#   full-replace like every other singleton in this module family are documentation-faithful
#   assumptions, not measurements. Set-SfosApplianceAccess follows the read-modify-write
#   contract used everywhere else in this module (the project rules ?5) as the safest default should
#   that assumption prove wrong.

<#
.SYNOPSIS
    Retrieves the appliance service access matrix (zones per management service) from the
    Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the ApplianceAccess singleton (SYSTEM >
    Administration > Device Access): which firewall zones may reach each of 14 management
    services (Https, SSH, CaptivePortal, RadiusSSO, ClientAuthentication, Ping, DNS, SSLVPN,
    WebProxy, SMTPRelay, SNMP, VPNPortal, RED, IPsec). Use -AsXml to return the raw XML node
    instead of a PowerShell-friendly object.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosApplianceAccess -Session $fw1 | Set-SfosApplianceAccess -Session fw2.

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
    PSCustomObject (default) with one string[] property per service: Https, SSH,
    CaptivePortal, RadiusSSO, ClientAuthentication, Ping, DNS, SSLVPN, WebProxy, SMTPRelay,
    SNMP, VPNPortal, RED, IPsec - each the list of zone names currently allowed to reach that
    service. System.Xml.XmlElement when -AsXml is specified.

.EXAMPLE
    # Which zones may reach the web admin console over HTTPS
    (Get-SfosApplianceAccess).Https

.NOTES
    Minimum supported PowerShell version: 5.1
    No documentation page exists for this entity - see the region header.
    Verified live: executed against the lab firewall; all 14 services and their zone lists
    matched the saved baseline XML.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Set-SfosApplianceAccess
#>
function Get-SfosApplianceAccess {
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

    $inner = '<Get><ApplianceAccess></ApplianceAccess></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving ApplianceAccess: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplianceAccess' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/ApplianceAccess')
    if (-not $node) {
        throw 'ApplianceAccess could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    $getZones = {
        param([System.Xml.XmlElement]$Parent, [string]$ServiceName)
        $serviceNode = $Parent.SelectSingleNode($ServiceName)
        if (-not $serviceNode) {
            return @()
        }
        return @($serviceNode.SelectNodes('ZoneName') | ForEach-Object -Process { [string]$_.InnerText })
    }

    return [PSCustomObject]@{
        Https                = & $getZones -Parent $node -ServiceName 'Https'
        SSH                  = & $getZones -Parent $node -ServiceName 'SSH'
        CaptivePortal        = & $getZones -Parent $node -ServiceName 'CaptivePortal'
        RadiusSSO            = & $getZones -Parent $node -ServiceName 'RadiusSSO'
        ClientAuthentication = & $getZones -Parent $node -ServiceName 'ClientAuthentication'
        Ping                 = & $getZones -Parent $node -ServiceName 'Ping'
        DNS                  = & $getZones -Parent $node -ServiceName 'DNS'
        SSLVPN               = & $getZones -Parent $node -ServiceName 'SSLVPN'
        WebProxy             = & $getZones -Parent $node -ServiceName 'WebProxy'
        SMTPRelay            = & $getZones -Parent $node -ServiceName 'SMTPRelay'
        SNMP                 = & $getZones -Parent $node -ServiceName 'SNMP'
        VPNPortal            = & $getZones -Parent $node -ServiceName 'VPNPortal'
        RED                  = & $getZones -Parent $node -ServiceName 'RED'
        IPsec                = & $getZones -Parent $node -ServiceName 'IPsec'
    }
}

<#
.SYNOPSIS
    Updates the appliance service access matrix (zones per management service) on the Sophos
    Firewall.

.DESCRIPTION
    Updates the ApplianceAccess singleton (SYSTEM > Administration > Device Access) using the
    Sophos Firewall XML API. Reads the current matrix first and resends all 14 services,
    overriding only the ones the caller explicitly passed (read-modify-write) - every service
    not bound keeps its current zone list unchanged. Supports ShouldProcess; use -WhatIf to
    preview.

    UNCONFIRMED: never executed against a live firewall - see the region header and this
    cmdlet's own .NOTES. Https and SSH carry the appliance's own management access; removing
    the zone that hosts the API/web admin session (typically the LAN zone) from either can
    make the appliance permanently unreachable with no way to revert the change remotely.
    Never remove the management zone from -Https or -SSH.

.PARAMETER Https
    Zone names allowed to reach the web admin console over HTTPS. If omitted, the current list is kept.

.PARAMETER SSH
    Zone names allowed to reach the appliance over SSH. If omitted, the current list is kept.

.PARAMETER CaptivePortal
    Zone names allowed to reach the captive portal. If omitted, the current list is kept.

.PARAMETER RadiusSSO
    Zone names allowed to reach the RADIUS single sign-on service. If omitted, the current list is kept.

.PARAMETER ClientAuthentication
    Zone names allowed to reach the client authentication service. If omitted, the current list is kept.

.PARAMETER Ping
    Zone names allowed to ping the appliance. If omitted, the current list is kept.

.PARAMETER DNS
    Zone names allowed to use the appliance as a DNS resolver. If omitted, the current list is kept.

.PARAMETER SSLVPN
    Zone names allowed to reach the SSL VPN service. If omitted, the current list is kept.

.PARAMETER WebProxy
    Zone names allowed to reach the web proxy. If omitted, the current list is kept.

.PARAMETER SMTPRelay
    Zone names allowed to use the appliance as an SMTP relay. If omitted, the current list is kept.

.PARAMETER SNMP
    Zone names allowed to query the appliance over SNMP. If omitted, the current list is kept.

.PARAMETER VPNPortal
    Zone names allowed to reach the VPN portal. If omitted, the current list is kept.

.PARAMETER RED
    Zone names allowed to reach the RED (Remote Ethernet Device) service. If omitted, the current list is kept.

.PARAMETER IPsec
    Zone names allowed to reach the IPsec service. If omitted, the current list is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosApplianceAccess -Session $fw1 | Set-SfosApplianceAccess -Session fw2.

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
    # Add DMZ to the zones allowed to ping the appliance, every other service is preserved
    Set-SfosApplianceAccess -Ping 'LAN', 'WiFi', 'DMZ'

.NOTES
    Minimum supported PowerShell version: 5.1
    UNCONFIRMED - never executed against the live firewall, by design (see .DESCRIPTION and
    the region header): this entity carries the appliance's own management access and FW1 has
    no out-of-band recovery path. The generated request XML was verified structurally by
    capturing it with Invoke-SfosApi shadowed in the calling session (no network call), merged
    against a real read of the lab baseline - confirmed to reproduce all 14 services and their
    zone lists unchanged except the one field actually overridden in the test call.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosApplianceAccess
#>
function Set-SfosApplianceAccess {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string[]]$Https,
        [string[]]$SSH,
        [string[]]$CaptivePortal,
        [string[]]$RadiusSSO,
        [string[]]$ClientAuthentication,
        [string[]]$Ping,
        [string[]]$DNS,
        [string[]]$SSLVPN,
        [string[]]$WebProxy,
        [string[]]$SMTPRelay,
        [string[]]$SNMP,
        [string[]]$VPNPortal,
        [string[]]$RED,
        [string[]]$IPsec,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosApplianceAccess -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $services = @('Https', 'SSH', 'CaptivePortal', 'RadiusSSO', 'ClientAuthentication', 'Ping', 'DNS', 'SSLVPN', 'WebProxy', 'SMTPRelay', 'SNMP', 'VPNPortal', 'RED', 'IPsec')

    $target = @{}
    foreach ($svc in $services) {
        $target[$svc] = if ($bp.ContainsKey($svc)) { @($bp[$svc]) } else { @($existing.$svc) }
    }

    if (-not $PSCmdlet.ShouldProcess("ApplianceAccess on $($params.Firewall)", 'Update')) {
        return
    }

    $blocksXml = ($services | ForEach-Object -Process {
            $svc = $_
            $zonesXml = ($target[$svc] | ForEach-Object -Process { "<ZoneName>$(ConvertTo-SfosXmlEscaped -Text $_)</ZoneName>" }) -join ''
            "<$svc>$zonesXml</$svc>"
        }) -join "`n    "

    $inner = @"
<Set operation="update">
  <ApplianceAccess>
    $blocksXml
  </ApplianceAccess>
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
        throw "Failed to update ApplianceAccess: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'ApplianceAccess' -Action 'update'
}

#endregion

#region AdminSettings
# AdminSettings (SYSTEM > Administration > Settings) is a singleton bundling six otherwise
# unrelated blocks: HostnameSettings, WebAdminSettings, LoginSecurity,
# PasswordComplexitySettings, LoginDisclaimer and DefaultConfigurationLanguage. Wire root is
# <AdminSettings>, no <Name> child.
#
# Individual operation pages exist for four of the six blocks - WebAdminSettings,
# LoginSecuritySettings, AdminPasswordComplexitySettings, LoginDisclaimerSettings - all
# reachable only under SYSTEM/Administration/AdminSettings/operations/, not under a page named
# after the entity itself. No page exists for HostnameSettings or DefaultConfigurationLanguage
# anywhere in the menu; both are implemented from the live Get shape alone.
#
# Measured against the lab appliance (Get, live baseline):
# - The live shape matches the sample XML on every documented block. One exception:
#   LoginSecuritySettings' sample additionally shows a top-level <LockSession> sibling of
#   <LogoutSession> - it never appears on this appliance's Get, so per the project rules ?5 it is not
#   implemented here (inventing a field the appliance never showed is the CountryHostGroup
#   mistake).
# - PasswordComplexitySettings/PasswordComplexity/MinimumPasswordLength: the doc table claims
#   "Only '8' allowed", but the live baseline holds 'Enable' and the sample XML shows
#   'Disable/Enable' - the table entry reads like a copy-paste of the neighbouring
#   MinimumPasswordLengthValue row. The live value and the sample agree with each other, so
#   Set-SfosAdminPasswordComplexity follows those, not the table.
# - CORRECTED: AdminSettings is NOT full-replace, unlike the rest of this API family. Measured
#   live with Set-SfosLoginDisclaimer: a <Set operation="update"> carrying only the
#   <LoginDisclaimer> block updated that field and left the other five blocks - including
#   WebAdminSettings/HTTPSport - untouched. AdminSettings is a partial-update singleton, one
#   block at a time. Every Set-* below therefore emits ONLY its own block, not all six;
#   read-modify-write still applies, but only within that one block, to preserve sibling
#   fields the caller did not bind (e.g. HostNameDesc when only -HostName is given). A block
#   with a single mandatory field (LoginDisclaimer, DefaultConfigurationLanguage) needs no
#   read at all - there is nothing else in the block to preserve.
# - HTTPSport and LoginSecurity/BlockLogin gate the appliance's own management access, and
#   FW1 has no out-of-band recovery path (see the ApplianceAccess region header for the same
#   constraint). Set-SfosWebAdminSettings and Set-SfosLoginSecurity are therefore still
#   UNCONFIRMED - the generated XML for both was verified structurally only, by shadowing
#   Invoke-SfosApi in the calling session (no network call). The one-block write narrows the
#   risk to each cmdlet's own fields: WebAdminSettings can no longer lock out via LoginSecurity
#   and vice versa, but each remains capable of locking out via its own field.
# - The status of an AdminSettings update was measured live and does NOT land nested under
#   AdminSettings: it lands FLAT and separately per block - /Response/HostnameSettings/Status,
#   /Response/WebAdminSettings/Status, /Response/LoginSecurity/Status,
#   /Response/PasswordComplexitySettings/Status, /Response/LoginDisclaimer/Status,
#   /Response/DefaultConfigurationLanguage/Status. Every Set-* below asserts against its own
#   block's flat path, not against 'AdminSettings'.
# - INCIDENT, historical: an earlier session's single live write -
#   Set-SfosAdminPasswordComplexity -MinimumPasswordLengthValue 11 against the baseline value
#   10, sent under the old full-replace assumption (all six blocks on the wire) - was accepted
#   by the firewall (all six blocks answered 200, confirming the status-path finding above),
#   and the firewall then stopped answering any further request for the rest of that session.
#   Whether the write caused the outage was never established. Nothing about that incident
#   points at any specific block; it predates this region's move to one-block writes.

<#
.SYNOPSIS
    Retrieves the SYSTEM > Administration > Settings singleton from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for the AdminSettings singleton: appliance hostname,
    web admin/portal HTTPS ports and certificate, admin login security (session timeout,
    login-attempt blocking), admin password complexity policy, the admin login disclaimer
    toggle, and the default configuration language. Use -AsXml to return the raw XML node
    instead of a PowerShell-friendly object.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosLoginDisclaimer -Session fw2.

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
    PSCustomObject (default) with HostName, HostNameDesc, LoginDisclaimer,
    DefaultConfigurationLanguage, and the nested sub-objects WebAdminSettings (Certificate,
    HTTPSport, UserPortalHTTPSPort, VPNPortalHTTPSPort, PortalRedirectMode,
    PortalCustomHostname), LoginSecurity (LogoutSession, BlockLogin, UnsucccessfulAttempt,
    Duration, ForMinutes) and PasswordComplexitySettings (PasswordComplexityCheck,
    MinimumPasswordLength, IncludeAlphabeticCharacters, IncludeNumericCharacter,
    IncludeSpecialCharacter, MinimumPasswordLengthValue). System.Xml.XmlElement when -AsXml is
    specified.

.EXAMPLE
    # Read the appliance hostname and the web admin HTTPS port
    Get-SfosAdminSettings | Select-Object HostName -ExpandProperty WebAdminSettings

.EXAMPLE
    # Read only the password complexity policy
    (Get-SfosAdminSettings).PasswordComplexitySettings

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall; all six blocks matched the saved
    baseline XML.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/AdminSettings/operations/WebAdminSettings.html

.LINK
    Set-SfosWebAdminSettings

.LINK
    Set-SfosLoginSecurity

.LINK
    Set-SfosAdminPasswordComplexity

.LINK
    Set-SfosLoginDisclaimer

.LINK
    Set-SfosHostname

.LINK
    Set-SfosDefaultLanguage
#>
function Get-SfosAdminSettings {
    # PSUseSingularNouns is suppressed on purpose: AdminSettings is the Sophos API's own
    # singleton element name, not a plural container with a singular child - see the project rules ?3.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'AdminSettings is the Sophos API root element itself, a singleton with no singular child.')]
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

    $inner = '<Get><AdminSettings></AdminSettings></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Error retrieving AdminSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminSettings' -Action 'get'

    $node = $XmlResponse.SelectSingleNode('/Response/AdminSettings')
    if (-not $node) {
        throw 'AdminSettings could not be retrieved from the firewall.'
    }

    if ($AsXml) {
        return $node
    }

    return [PSCustomObject]@{
        HostName                    = [string]$node.HostnameSettings.HostName
        HostNameDesc                = [string]$node.HostnameSettings.HostNameDesc
        WebAdminSettings             = [PSCustomObject]@{
            Certificate          = [string]$node.WebAdminSettings.Certificate
            HTTPSport            = [string]$node.WebAdminSettings.HTTPSport
            UserPortalHTTPSPort  = [string]$node.WebAdminSettings.UserPortalHTTPSPort
            VPNPortalHTTPSPort   = [string]$node.WebAdminSettings.VPNPortalHTTPSPort
            PortalRedirectMode   = [string]$node.WebAdminSettings.PortalRedirectMode
            PortalCustomHostname = [string]$node.WebAdminSettings.PortalCustomHostname
        }
        LoginSecurity                = [PSCustomObject]@{
            LogoutSession        = [string]$node.LoginSecurity.LogoutSession
            BlockLogin           = [string]$node.LoginSecurity.BlockLogin
            UnsucccessfulAttempt = [string]$node.LoginSecurity.BlockLoginSettings.UnsucccessfulAttempt
            Duration             = [string]$node.LoginSecurity.BlockLoginSettings.Duration
            ForMinutes           = [string]$node.LoginSecurity.BlockLoginSettings.ForMinutes
        }
        PasswordComplexitySettings  = [PSCustomObject]@{
            PasswordComplexityCheck     = [string]$node.PasswordComplexitySettings.PasswordComplexityCheck
            MinimumPasswordLength       = [string]$node.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLength
            IncludeAlphabeticCharacters = [string]$node.PasswordComplexitySettings.PasswordComplexity.IncludeAlphabeticCharacters
            IncludeNumericCharacter     = [string]$node.PasswordComplexitySettings.PasswordComplexity.IncludeNumericCharacter
            IncludeSpecialCharacter     = [string]$node.PasswordComplexitySettings.PasswordComplexity.IncludeSpecialCharacter
            MinimumPasswordLengthValue  = [string]$node.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLengthValue
        }
        LoginDisclaimer              = [string]$node.LoginDisclaimer
        DefaultConfigurationLanguage = [string]$node.DefaultConfigurationLanguage
    }
}

<#
.SYNOPSIS
    Updates the web admin/portal HTTPS ports, certificate and portal redirect mode on the
    Sophos Firewall.

.DESCRIPTION
    Updates the WebAdminSettings block of the AdminSettings singleton (SYSTEM >
    Administration > Settings > Web Admin Settings) using the Sophos Firewall XML API.
    AdminSettings is a partial-update singleton (see the region header): the request carries
    only the WebAdminSettings block, never the other five. Reads the block first and
    overrides only the fields the caller explicitly passed (read-modify-write within the
    block). Supports ShouldProcess; use -WhatIf to preview.

    UNCONFIRMED: never executed against a live firewall - see the region header and this
    cmdlet's own .NOTES. -HTTPSport in particular controls the port the current API/web admin
    session is reachable on; a wrong value can make the appliance unreachable with no way to
    revert the change remotely. The one-block write no longer risks LoginSecurity or the
    other blocks in the same call - the remaining risk is confined to this cmdlet's own
    fields.

.PARAMETER HTTPSport
    HTTPS port for the web admin console (1-65535). If omitted, the current value is kept.

.PARAMETER UserPortalHTTPSPort
    HTTPS port for the user portal (1-65535). If omitted, the current value is kept.

.PARAMETER VPNPortalHTTPSPort
    HTTPS port for the VPN portal (1-65535). If omitted, the current value is kept.

.PARAMETER Certificate
    Name of the certificate object used by the user portal and captive portal. If omitted,
    the current value is kept.

.PARAMETER PortalRedirectMode
    Hostname mode used for the captive portal etc.: 'ip', 'fqdn' or 'custom'. If omitted, the
    current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosWebAdminSettings -Session fw2.

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
    # Switch the captive portal hostname mode to fully qualified domain name
    Set-SfosWebAdminSettings -PortalRedirectMode 'fqdn'

.NOTES
    Minimum supported PowerShell version: 5.1
    UNCONFIRMED - never executed against the live firewall, by design (see .DESCRIPTION): a
    wrong -HTTPSport can make the appliance unreachable and FW1 has no out-of-band recovery
    path. The generated request XML was verified structurally by capturing it with
    Invoke-SfosApi shadowed in the calling session (no network call), merged against a real
    read of the lab baseline - confirmed to resend WebAdminSettings unchanged except the one
    field actually overridden in the test call, and confirmed to contain no other AdminSettings
    block (HostnameSettings, LoginSecurity, PasswordComplexitySettings, LoginDisclaimer,
    DefaultConfigurationLanguage) at all - see the region header for the measurement that made
    this a one-block write.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/AdminSettings/operations/WebAdminSettings.html

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosWebAdminSettings {
    # PSUseSingularNouns is suppressed on purpose: WebAdminSettings is the Sophos API's own
    # block name inside AdminSettings, not a plural container with a singular child.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'WebAdminSettings is the Sophos API block name itself, a singleton with no singular child.')]
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidateRange(1, 65535)]
        [int]$HTTPSport,

        [ValidateRange(1, 65535)]
        [int]$UserPortalHTTPSPort,

        [ValidateRange(1, 65535)]
        [int]$VPNPortalHTTPSPort,

        [string]$Certificate,

        [ValidateSet('ip', 'fqdn', 'custom')]
        [string]$PortalRedirectMode,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetHTTPSport = if ($bp.ContainsKey('HTTPSport')) { $HTTPSport } else { $existing.WebAdminSettings.HTTPSport }
    $targetUserPortalHTTPSPort = if ($bp.ContainsKey('UserPortalHTTPSPort')) { $UserPortalHTTPSPort } else { $existing.WebAdminSettings.UserPortalHTTPSPort }
    $targetVPNPortalHTTPSPort = if ($bp.ContainsKey('VPNPortalHTTPSPort')) { $VPNPortalHTTPSPort } else { $existing.WebAdminSettings.VPNPortalHTTPSPort }
    $targetCertificate = if ($bp.ContainsKey('Certificate')) { $Certificate } else { $existing.WebAdminSettings.Certificate }
    $targetPortalRedirectMode = if ($bp.ContainsKey('PortalRedirectMode')) { $PortalRedirectMode } else { $existing.WebAdminSettings.PortalRedirectMode }

    if (-not $PSCmdlet.ShouldProcess("AdminSettings WebAdminSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <WebAdminSettings>
      <Certificate>$(ConvertTo-SfosXmlEscaped -Text $targetCertificate)</Certificate>
      <HTTPSport>$targetHTTPSport</HTTPSport>
      <UserPortalHTTPSPort>$targetUserPortalHTTPSPort</UserPortalHTTPSPort>
      <VPNPortalHTTPSPort>$targetVPNPortalHTTPSPort</VPNPortalHTTPSPort>
      <PortalRedirectMode>$targetPortalRedirectMode</PortalRedirectMode>
      <PortalCustomHostname>$(ConvertTo-SfosXmlEscaped -Text $existing.WebAdminSettings.PortalCustomHostname)</PortalCustomHostname>
    </WebAdminSettings>
  </AdminSettings>
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
        throw "Failed to update AdminSettings WebAdminSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured live: the status lands FLAT at /Response/WebAdminSettings/Status, not nested
    # under AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebAdminSettings' -Action 'update'
}

<#
.SYNOPSIS
    Updates the admin login security policy (session timeout, failed-login blocking) on the
    Sophos Firewall.

.DESCRIPTION
    Updates the LoginSecurity block of the AdminSettings singleton (SYSTEM > Administration >
    Settings > Login Security) using the Sophos Firewall XML API. AdminSettings is a
    partial-update singleton (see the region header): the request carries only the
    LoginSecurity block, never the other five. Reads the block first and overrides only the
    fields the caller explicitly passed (read-modify-write within the block). Supports
    ShouldProcess; use -WhatIf to preview.

    UNCONFIRMED: never executed against a live firewall - see the region header and this
    cmdlet's own .NOTES. -BlockLogin/-UnsucccessfulAttempt/-Duration/-ForMinutes together
    control when the currently connected admin account itself gets locked out, and there is no
    out-of-band recovery path for FW1. The one-block write no longer risks WebAdminSettings or
    the other blocks in the same call - the remaining risk is confined to this cmdlet's own
    fields.

.PARAMETER LogoutSession
    Inactivity timeout in minutes before the admin session is logged out (1-120), or the
    literal string 'Disable'. If omitted, the current value is kept.

.PARAMETER BlockLogin
    'Enable' to block admin login after a configured number of failed attempts from the same
    IP address, 'Disable' to turn the block off. If omitted, the current value is kept.

.PARAMETER UnsucccessfulAttempt
    Allowed number of failed admin login attempts from the same IP address before blocking
    (1-5). Sophos's own wire spelling (three c's) is kept as-is. If omitted, the current value
    is kept.

.PARAMETER Duration
    Time span in minutes within which -UnsucccessfulAttempt failed logins trigger the block
    (1-120). If omitted, the current value is kept.

.PARAMETER ForMinutes
    Duration in minutes for which admin login is blocked once triggered (1-60). If omitted,
    the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosLoginSecurity -Session fw2.

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
    # Extend the admin session inactivity timeout to 30 minutes
    Set-SfosLoginSecurity -LogoutSession '30'

.NOTES
    Minimum supported PowerShell version: 5.1
    UNCONFIRMED - never executed against the live firewall, by design (see .DESCRIPTION): this
    block can lock out the currently connected admin account and FW1 has no out-of-band
    recovery path. The generated request XML was verified structurally by capturing it with
    Invoke-SfosApi shadowed in the calling session (no network call), merged against a real
    read of the lab baseline - confirmed to resend LoginSecurity unchanged except the one field
    actually overridden in the test call, and confirmed to contain no other AdminSettings block
    (HostnameSettings, WebAdminSettings, PasswordComplexitySettings, LoginDisclaimer,
    DefaultConfigurationLanguage) at all - see the region header for the measurement that made
    this a one-block write.
    LockSession, documented in the sample XML for this block, never appears on the lab
    appliance's Get and is not implemented - see the region header.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/AdminSettings/operations/LoginSecuritySettings.html

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosLoginSecurity {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [ValidatePattern('^(Disable|[0-9]{1,3})$')]
        [string]$LogoutSession,

        [ValidateSet('Enable', 'Disable')]
        [string]$BlockLogin,

        [ValidateRange(1, 5)]
        [int]$UnsucccessfulAttempt,

        [ValidateRange(1, 120)]
        [int]$Duration,

        [ValidateRange(1, 60)]
        [int]$ForMinutes,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetLogoutSession = if ($bp.ContainsKey('LogoutSession')) { $LogoutSession } else { $existing.LoginSecurity.LogoutSession }
    $targetBlockLogin = if ($bp.ContainsKey('BlockLogin')) { $BlockLogin } else { $existing.LoginSecurity.BlockLogin }
    $targetUnsucccessfulAttempt = if ($bp.ContainsKey('UnsucccessfulAttempt')) { $UnsucccessfulAttempt } else { $existing.LoginSecurity.UnsucccessfulAttempt }
    $targetDuration = if ($bp.ContainsKey('Duration')) { $Duration } else { $existing.LoginSecurity.Duration }
    $targetForMinutes = if ($bp.ContainsKey('ForMinutes')) { $ForMinutes } else { $existing.LoginSecurity.ForMinutes }

    if (-not $PSCmdlet.ShouldProcess("AdminSettings LoginSecurity on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <LoginSecurity>
      <LogoutSession>$targetLogoutSession</LogoutSession>
      <BlockLogin>$targetBlockLogin</BlockLogin>
      <BlockLoginSettings>
        <UnsucccessfulAttempt>$targetUnsucccessfulAttempt</UnsucccessfulAttempt>
        <Duration>$targetDuration</Duration>
        <ForMinutes>$targetForMinutes</ForMinutes>
      </BlockLoginSettings>
    </LoginSecurity>
  </AdminSettings>
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
        throw "Failed to update AdminSettings LoginSecurity: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured live: the status lands FLAT at /Response/LoginSecurity/Status, not nested under
    # AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LoginSecurity' -Action 'update'
}

<#
.SYNOPSIS
    Updates the admin password complexity policy on the Sophos Firewall.

.DESCRIPTION
    Updates the PasswordComplexitySettings block of the AdminSettings singleton (SYSTEM >
    Administration > Settings > Password Complexity Settings) using the Sophos Firewall XML
    API. AdminSettings is a partial-update singleton (see the region header): the request
    carries only the PasswordComplexitySettings block, never the other five. Reads the block
    first and overrides only the fields the caller explicitly passed (read-modify-write within
    the block). Only affects future password changes, not any password already set. Supports
    ShouldProcess; use -WhatIf to preview. Does not touch any access-gating field
    (HTTPSport, BlockLogin) - those live in other blocks, which this call no longer sends.

.PARAMETER PasswordComplexityCheck
    'Enable' to turn on password complexity enforcement, 'Disable' to turn it off. If omitted,
    the current value is kept.

.PARAMETER MinimumPasswordLength
    'Enable' to enforce -MinimumPasswordLengthValue, 'Disable' to turn the check off. If
    omitted, the current value is kept.

.PARAMETER MinimumPasswordLengthValue
    Minimum number of characters required in a password (5-20). If omitted, the current value
    is kept.

.PARAMETER IncludeAlphabeticCharacters
    'Enable' to require at least one upper- and one lower-case character. If omitted, the
    current value is kept.

.PARAMETER IncludeNumericCharacter
    'Enable' to require at least one numeric character. If omitted, the current value is kept.

.PARAMETER IncludeSpecialCharacter
    'Enable' to require at least one special character. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosAdminPasswordComplexity -Session fw2.

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
    # Raise the minimum required password length to 12 characters
    Set-SfosAdminPasswordComplexity -MinimumPasswordLengthValue 12

.NOTES
    Minimum supported PowerShell version: 5.1
    Refactored to a one-block write - see the region header. This cmdlet's request now
    carries only PasswordComplexitySettings; the other five AdminSettings blocks, including
    WebAdminSettings/HTTPSport and LoginSecurity/BlockLogin, are no longer sent and therefore
    cannot be affected by this call. Safe, live-testable write.
    HISTORICAL INCIDENT, predates this refactor: the one call once executed
    (-MinimumPasswordLengthValue 11 against the lab baseline of 10) was sent under the old
    full-replace assumption - all six AdminSettings blocks on the wire, not just this one. It
    was accepted by the firewall (all six blocks answered code 200 individually, confirming
    the flat per-block status path documented in the region header), and the firewall then
    stopped responding to any further request - including a plain Get-SfosAdminSettings sent
    seconds later - for the rest of that session. Whether this call caused the outage, or an
    unrelated lab event coincided with it, was never established. Nothing about the incident
    points at PasswordComplexitySettings specifically over the other five blocks that were
    also on the wire that time.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/AdminSettings/operations/AdminPasswordComplexitySettings.html

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosAdminPasswordComplexity {
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification = 'Username/Password here are the standard connection parameters; PasswordComplexityCheck/MinimumPasswordLength are Enable/Disable policy flags, not credentials.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'PasswordComplexityCheck', Justification = 'Enable/Disable policy flag, not a credential.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'MinimumPasswordLength', Justification = 'Enable/Disable policy flag, not a credential.')]
    param(
        [ValidateSet('Enable', 'Disable')]
        [string]$PasswordComplexityCheck,

        [ValidateSet('Enable', 'Disable')]
        [string]$MinimumPasswordLength,

        [ValidateRange(5, 20)]
        [int]$MinimumPasswordLengthValue,

        [ValidateSet('Enable', 'Disable')]
        [string]$IncludeAlphabeticCharacters,

        [ValidateSet('Enable', 'Disable')]
        [string]$IncludeNumericCharacter,

        [ValidateSet('Enable', 'Disable')]
        [string]$IncludeSpecialCharacter,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetPasswordComplexityCheck = if ($bp.ContainsKey('PasswordComplexityCheck')) { $PasswordComplexityCheck } else { $existing.PasswordComplexitySettings.PasswordComplexityCheck }
    $targetMinimumPasswordLength = if ($bp.ContainsKey('MinimumPasswordLength')) { $MinimumPasswordLength } else { $existing.PasswordComplexitySettings.MinimumPasswordLength }
    $targetMinimumPasswordLengthValue = if ($bp.ContainsKey('MinimumPasswordLengthValue')) { $MinimumPasswordLengthValue } else { $existing.PasswordComplexitySettings.MinimumPasswordLengthValue }
    $targetIncludeAlphabeticCharacters = if ($bp.ContainsKey('IncludeAlphabeticCharacters')) { $IncludeAlphabeticCharacters } else { $existing.PasswordComplexitySettings.IncludeAlphabeticCharacters }
    $targetIncludeNumericCharacter = if ($bp.ContainsKey('IncludeNumericCharacter')) { $IncludeNumericCharacter } else { $existing.PasswordComplexitySettings.IncludeNumericCharacter }
    $targetIncludeSpecialCharacter = if ($bp.ContainsKey('IncludeSpecialCharacter')) { $IncludeSpecialCharacter } else { $existing.PasswordComplexitySettings.IncludeSpecialCharacter }

    if (-not $PSCmdlet.ShouldProcess("AdminSettings PasswordComplexitySettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <PasswordComplexitySettings>
      <PasswordComplexityCheck>$targetPasswordComplexityCheck</PasswordComplexityCheck>
      <PasswordComplexity>
        <MinimumPasswordLength>$targetMinimumPasswordLength</MinimumPasswordLength>
        <IncludeAlphabeticCharacters>$targetIncludeAlphabeticCharacters</IncludeAlphabeticCharacters>
        <IncludeNumericCharacter>$targetIncludeNumericCharacter</IncludeNumericCharacter>
        <IncludeSpecialCharacter>$targetIncludeSpecialCharacter</IncludeSpecialCharacter>
        <MinimumPasswordLengthValue>$targetMinimumPasswordLengthValue</MinimumPasswordLengthValue>
      </PasswordComplexity>
    </PasswordComplexitySettings>
  </AdminSettings>
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
        throw "Failed to update AdminSettings PasswordComplexitySettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured live: the status lands FLAT at /Response/PasswordComplexitySettings/Status, not
    # nested under AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PasswordComplexitySettings' -Action 'update'
}

<#
.SYNOPSIS
    Updates the admin login disclaimer toggle on the Sophos Firewall.

.DESCRIPTION
    Updates the LoginDisclaimer field of the AdminSettings singleton (SYSTEM > Administration
    > Settings > Login Disclaimer) using the Sophos Firewall XML API. AdminSettings is a
    partial-update singleton (see the region header): the request carries only this one field,
    never any of the other five blocks - no read of the current settings is needed, since
    LoginDisclaimer has no sibling field to preserve. Supports ShouldProcess; use -WhatIf to
    preview.

    A safe write: this block does not touch HTTPSport, BlockLogin or any other access-gating
    field. Like every AdminSettings write it may cause a brief management-service restart (see
    Set-SfosTime's -TimeZone note for the same, measured, effect on a different singleton).

.PARAMETER LoginDisclaimer
    'Enable' to display a disclaimer/warning banner at admin login, 'Disable' to turn it off.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosLoginDisclaimer -Session fw2.

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
    # Turn on the admin login disclaimer banner
    Set-SfosLoginDisclaimer -LoginDisclaimer 'Enable'

.NOTES
    Minimum supported PowerShell version: 5.1
    Refactored to a one-block write - see the region header. This was the cmdlet used to
    measure that AdminSettings is a partial-update singleton: a request carrying only
    <LoginDisclaimer> left WebAdminSettings/HTTPSport and all other blocks unchanged. Safe,
    live-testable write; touches no access-gating field.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/SYSTEM/Administration/AdminSettings/operations/LoginDisclaimerSettings.html

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosLoginDisclaimer {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Enable', 'Disable')]
        [string]$LoginDisclaimer,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("AdminSettings LoginDisclaimer on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <LoginDisclaimer>$LoginDisclaimer</LoginDisclaimer>
  </AdminSettings>
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
        throw "Failed to update AdminSettings LoginDisclaimer: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured live: the status lands FLAT at /Response/LoginDisclaimer/Status, not nested
    # under AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LoginDisclaimer' -Action 'update'
}

<#
.SYNOPSIS
    Updates the appliance hostname and hostname description on the Sophos Firewall.

.DESCRIPTION
    Updates the HostnameSettings block of the AdminSettings singleton (SYSTEM >
    Administration > Settings > Hostname Settings) using the Sophos Firewall XML API.
    AdminSettings is a partial-update singleton (see the region header): the request carries
    only the HostnameSettings block, never the other five. Reads the block first and overrides
    only the fields the caller explicitly passed (read-modify-write within the block).
    Supports ShouldProcess; use -WhatIf to preview.

    A safe write: this block does not touch HTTPSport, BlockLogin or any other access-gating
    field. Like every AdminSettings write it may cause a brief management-service restart (see
    Set-SfosTime's -TimeZone note for the same, measured, effect on a different singleton).

.PARAMETER HostName
    Appliance hostname. If omitted, the current value is kept.

.PARAMETER HostNameDesc
    Free-text description of the appliance. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosHostname -Session fw2.

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
    # Set only the hostname description, the hostname itself is preserved
    Set-SfosHostname -HostNameDesc 'Lab firewall, do not change HostName'

.NOTES
    Minimum supported PowerShell version: 5.1
    Refactored to a one-block write - see the region header and Set-SfosLoginDisclaimer's
    .NOTES for the measurement that made this a one-block write (this cmdlet's block was not
    itself the one measured, but shares the same request shape and the same measured
    flat-per-block status path). Safe, live-testable write; touches no access-gating field.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosHostname {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$HostName,

        [string]$HostNameDesc,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = Get-SfosAdminSettings -Firewall $params.Firewall `
        -Port $params.Port `
        -Username $params.Username `
        -Password $params.Password `
        -SkipCertificateCheck:$params.SkipCertificateCheck

    $bp = $PSBoundParameters
    $targetHostName = if ($bp.ContainsKey('HostName')) { $HostName } else { $existing.HostName }
    $targetHostNameDesc = if ($bp.ContainsKey('HostNameDesc')) { $HostNameDesc } else { $existing.HostNameDesc }

    if (-not $PSCmdlet.ShouldProcess("AdminSettings HostnameSettings on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <HostnameSettings>
      <HostName>$(ConvertTo-SfosXmlEscaped -Text $targetHostName)</HostName>
      <HostNameDesc>$(ConvertTo-SfosXmlEscaped -Text $targetHostNameDesc)</HostNameDesc>
    </HostnameSettings>
  </AdminSettings>
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
        throw "Failed to update AdminSettings HostnameSettings: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured live: the status lands FLAT at /Response/HostnameSettings/Status, not nested
    # under AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HostnameSettings' -Action 'update'
}

<#
.SYNOPSIS
    Updates the default configuration language on the Sophos Firewall.

.DESCRIPTION
    Updates the DefaultConfigurationLanguage field of the AdminSettings singleton (SYSTEM >
    Administration > Settings) using the Sophos Firewall XML API. AdminSettings is a
    partial-update singleton (see the region header): the request carries only this one
    field, never any of the other five blocks - no read of the current settings is needed,
    since DefaultConfigurationLanguage has no sibling field to preserve. Supports
    ShouldProcess; use -WhatIf to preview.

    A safe write: this block does not touch HTTPSport, BlockLogin or any other access-gating
    field. Like every AdminSettings write it may cause a brief management-service restart (see
    Set-SfosTime's -TimeZone note for the same, measured, effect on a different singleton).

.PARAMETER DefaultConfigurationLanguage
    Default configuration language, e.g. 'German' or 'English'. No documentation page exists
    for this field and the full set of accepted values is unconfirmed - see the region header.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosAdminSettings -Session $fw1 | Set-SfosDefaultLanguage -Session fw2.

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
    # Switch the default configuration language to English
    Set-SfosDefaultLanguage -DefaultConfigurationLanguage 'English'

.NOTES
    Minimum supported PowerShell version: 5.1
    Refactored to a one-block write - see the region header and Set-SfosLoginDisclaimer's
    .NOTES for the measurement that made this a one-block write (this cmdlet's field was not
    itself the one measured, but shares the same request shape and the same measured
    flat-per-block status path). Touches no access-gating field (HTTPSport and the other
    blocks are preserved - verified live). BUT [measured]: changing the language triggers a
    management-interface restart, exactly like Set-SfosTime -TimeZone - the call itself times
    out client-side while the appliance rebuilds the web admin in the new language, and the
    firewall answers again some time later with the change applied. It is not a lock-out (the
    access fields are untouched) and it recovers on its own, but a caller should expect the
    call to throw a timeout and poll before treating it as failed. No ValidateSet is applied -
    no documentation page exists for this field, so the full set of accepted values is
    unconfirmed.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosDefaultLanguage {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$DefaultConfigurationLanguage,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("AdminSettings DefaultConfigurationLanguage on $($params.Firewall)", 'Update')) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <DefaultConfigurationLanguage>$(ConvertTo-SfosXmlEscaped -Text $DefaultConfigurationLanguage)</DefaultConfigurationLanguage>
  </AdminSettings>
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
        throw "Failed to update AdminSettings DefaultConfigurationLanguage: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Measured live: the status lands FLAT at /Response/DefaultConfigurationLanguage/Status,
    # not nested under AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultConfigurationLanguage' -Action 'update'
}

#endregion

#region LocalServiceACL
# LocalServiceACL (SYSTEM > Administration, no separate menu entry - rule-based control of
# which zones/hosts may reach which management services) has no documentation page in the
# SFOS 22.0 API menu navigation, but a field shape for it is documented [doc]: root
# <LocalServiceACL>, mandatory RuleName (max 60 chars, no comma) and Services/Service
# (at least one, from a fixed set of management service names), optional Description,
# IPFamily, SourceZone, Hosts/Host and Action (accept/drop). The lab appliance has zero rules
# configured, so this is not corroborated against a live sample the way most other entities in
# this file are - see Get-SfosLocalServiceACL's .NOTES.
#
# New-/Set-/Remove-SfosLocalServiceACL are implemented documentation-faithful and UNCONFIRMED
# against a live firewall. This entity controls admin/API/SSH/SNMP reachability by zone and
# source host; a wrong write here - especially Action=drop, or a rule that excludes the
# management source - can cut off the same access path the API itself uses, the same class of
# risk as Set-SfosSpoofPrevention's measured lock-out (see the project rules), except there is
# no known-good baseline rule on this appliance to fall back to and FW1 has no out-of-band
# recovery. No live write was attempted for this module; only the generated XML was verified
# against the documented schema (shadowed Invoke-SfosApi).

<#
.SYNOPSIS
    Retrieves Local Service ACL rules from the Sophos Firewall.

.DESCRIPTION
    Queries the Sophos Firewall XML API for LocalServiceACL objects (rules controlling which
    zones/source hosts may reach which management services). No documentation page exists for
    this entity on this API version, but its field shape is documented - see the region
    header. Use -AsXml to return the raw XML nodes instead of PowerShell-friendly objects.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it.

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
    PSCustomObject (default) with RuleName, Description, IPFamily, SourceZone, HostList,
    ServiceList, Action. System.Xml.XmlElement when -AsXml is specified. The lab appliance has
    zero rules configured, so this projection has not been corroborated against a live sample
    - see the region header.

.EXAMPLE
    # List any Local Service ACL rules (empty on an appliance with none configured)
    Get-SfosLocalServiceACL

.NOTES
    Minimum supported PowerShell version: 5.1
    Verified live: executed against the lab firewall, which has zero rules configured; the
    call returned an empty result via the documented code-less "No. of records Zero." status
    (the project rules ?5), not an error. The field projection itself is documentation-derived,
    not confirmed against a populated rule - see the region header.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    New-SfosLocalServiceACL

.LINK
    Set-SfosLocalServiceACL

.LINK
    Remove-SfosLocalServiceACL
#>
function Get-SfosLocalServiceACL {
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

    $inner = '<Get><LocalServiceACL></LocalServiceACL></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve LocalServiceACL objects: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LocalServiceACL' -Action 'get'

    $nodes = @($XmlResponse.SelectNodes('/Response/LocalServiceACL[RuleName]'))

    if ($AsXml) {
        return $nodes
    }

    $result = @()
    foreach ($node in $nodes) {
        if (-not $node) {
            continue
        }

        $hostList = @($node.SelectNodes('Hosts/Host') | ForEach-Object -Process { [string]$_.InnerText })
        $serviceList = @($node.SelectNodes('Services/Service') | ForEach-Object -Process { [string]$_.InnerText })

        $result += [PSCustomObject]@{
            RuleName    = [string]$node.RuleName
            Description = [string]$node.Description
            IPFamily    = [string]$node.IPFamily
            SourceZone  = [string]$node.SourceZone
            HostList    = $hostList
            ServiceList = $serviceList
            Action      = [string]$node.Action
        }
    }

    return $result
}

<#
.SYNOPSIS
    Creates a new Local Service ACL rule on the Sophos Firewall.

.DESCRIPTION
    Creates a LocalServiceACL rule using the Sophos Firewall XML API. Supports ShouldProcess;
    use -WhatIf to preview.

    UNCONFIRMED - never executed against a live firewall. See the region header for why: this
    entity controls admin/API/SSH/SNMP reachability and a wrong rule can cut off management
    access with no local recovery path on the lab appliance.

.PARAMETER RuleName
    Name of the rule, max 60 characters, no comma.

.PARAMETER Service
    One or more management services the rule applies to. At least one is required.

.PARAMETER Description
    Optional free-text description.

.PARAMETER IPFamily
    'IPv4' or 'IPv6'.

.PARAMETER SourceZone
    Zone the rule matches traffic from.

.PARAMETER SourceHost
    One or more source hosts/networks the rule matches.

.PARAMETER Action
    'accept' or 'drop'.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it.

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
    None. Throws an exception if the create fails.

.EXAMPLE
    # Allow HTTPS admin access from the LAN zone
    New-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Service HTTPS -SourceZone 'LAN' -Action accept

.NOTES
    Minimum supported PowerShell version: 5.1
    UNCONFIRMED - never executed live. See the region header.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosLocalServiceACL
#>
function New-SfosLocalServiceACL {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$RuleName,

        [Parameter(Mandatory)]
        [ValidateSet('HTTPS', 'SSH', 'DNS', 'DynamicRouting', 'Ping', 'Ping6', 'SSLVPN', 'UserPortal', 'WebProxy', 'VPNPortal', 'ADSSO', 'CaptivePortal', 'RadiusSSO', 'ClientAuthentication', 'ChromebookSSO', 'WirelessProtection', 'SMTPRelay', 'SNMP', 'RED', 'IPsec')]
        [string[]]$Service,

        [string]$Description,

        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [string]$SourceZone,

        [string[]]$SourceHost,

        [ValidateSet('accept', 'drop')]
        [string]$Action,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $ruleNameEsc = ConvertTo-SfosXmlEscaped -Text $RuleName

    $xmlDescription = ''
    if ($Description) {
        $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $Description)</Description>"
    }

    $xmlIPFamily = ''
    if ($IPFamily) {
        $xmlIPFamily = "<IPFamily>$IPFamily</IPFamily>"
    }

    $xmlSourceZone = ''
    if ($SourceZone) {
        $xmlSourceZone = "<SourceZone>$(ConvertTo-SfosXmlEscaped -Text $SourceZone)</SourceZone>"
    }

    $xmlHosts = ''
    if (@($SourceHost).Count -gt 0) {
        $hostXml = ($SourceHost | ForEach-Object -Process { "<Host>$(ConvertTo-SfosXmlEscaped -Text $_)</Host>" }) -join ''
        $xmlHosts = "<Hosts>$hostXml</Hosts>"
    }

    $serviceXml = ($Service | ForEach-Object -Process { "<Service>$(ConvertTo-SfosXmlEscaped -Text $_)</Service>" }) -join ''
    $xmlServices = "<Services>$serviceXml</Services>"

    $xmlAction = ''
    if ($Action) {
        $xmlAction = "<Action>$Action</Action>"
    }

    $inner = @"
<Set operation="add">
  <LocalServiceACL>
    <RuleName>$ruleNameEsc</RuleName>
    $xmlDescription
    $xmlIPFamily
    $xmlSourceZone
    $xmlHosts
    $xmlServices
    $xmlAction
  </LocalServiceACL>
</Set>
"@

    if (-not $PSCmdlet.ShouldProcess("LocalServiceACL rule '$RuleName' on $($params.Firewall)", 'Create')) {
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
        throw "Failed to create LocalServiceACL rule '$RuleName': $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LocalServiceACL' -Action 'create' -Target $RuleName
}

<#
.SYNOPSIS
    Updates an existing Local Service ACL rule on the Sophos Firewall.

.DESCRIPTION
    Updates a LocalServiceACL rule using the Sophos Firewall XML API. Reads the current rule
    first and resends every field, overriding only what the caller explicitly passed
    (read-modify-write). Supports ShouldProcess; use -WhatIf to preview.

    UNCONFIRMED - never executed against a live firewall. See the region header for why.

.PARAMETER RuleName
    Name of the target rule.

.PARAMETER Service
    One or more management services the rule applies to. If omitted, the current value is
    kept. At least one is required overall.

.PARAMETER Description
    Optional free-text description. If omitted, the current value is kept.

.PARAMETER IPFamily
    'IPv4' or 'IPv6'. If omitted, the current value is kept.

.PARAMETER SourceZone
    Zone the rule matches traffic from. If omitted, the current value is kept.

.PARAMETER SourceHost
    One or more source hosts/networks the rule matches. If omitted, the current value is kept.

.PARAMETER Action
    'accept' or 'drop'. If omitted, the current value is kept.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosLocalServiceACL -Session $fw1 | Set-SfosLocalServiceACL -Session fw2.

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
    # Change only the action, every other field is preserved
    Set-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Action drop

.NOTES
    Minimum supported PowerShell version: 5.1
    UNCONFIRMED - never executed live. See the region header.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosLocalServiceACL
#>
function Set-SfosLocalServiceACL {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$RuleName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('ServiceList')]
        [ValidateSet('HTTPS', 'SSH', 'DNS', 'DynamicRouting', 'Ping', 'Ping6', 'SSLVPN', 'UserPortal', 'WebProxy', 'VPNPortal', 'ADSSO', 'CaptivePortal', 'RadiusSSO', 'ClientAuthentication', 'ChromebookSSO', 'WirelessProtection', 'SMTPRelay', 'SNMP', 'RED', 'IPsec')]
        [string[]]$Service,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('IPv4', 'IPv6')]
        [string]$IPFamily,

        [Parameter(ValueFromPipelineByPropertyName)]
        [string]$SourceZone,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('HostList')]
        [string[]]$SourceHost,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('accept', 'drop')]
        [string]$Action,

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
        $ruleNameEsc = ConvertTo-SfosXmlEscaped -Text $RuleName

        $existing = @(Get-SfosLocalServiceACL -Firewall $params.Firewall `
                -Port $params.Port `
                -Username $params.Username `
                -Password $params.Password `
                -SkipCertificateCheck:$params.SkipCertificateCheck |
                Where-Object -FilterScript { $_.RuleName -eq $RuleName })

        if ($existing.Count -eq 0) {
            throw "The LocalServiceACL rule '$RuleName' was not found."
        }

        $bp = $PSBoundParameters
        $targetService = @( if ($bp.ContainsKey('Service')) { $Service } else { $existing[0].ServiceList } )
        $targetDescription = if ($bp.ContainsKey('Description')) { $Description } else { [string]$existing[0].Description }
        $targetIPFamily = if ($bp.ContainsKey('IPFamily')) { $IPFamily } else { [string]$existing[0].IPFamily }
        $targetSourceZone = if ($bp.ContainsKey('SourceZone')) { $SourceZone } else { [string]$existing[0].SourceZone }
        $targetSourceHost = @( if ($bp.ContainsKey('SourceHost')) { $SourceHost } else { $existing[0].HostList } )
        $targetAction = if ($bp.ContainsKey('Action')) { $Action } else { [string]$existing[0].Action }

        if (@($targetService).Count -eq 0) {
            throw "LocalServiceACL rule '$RuleName' needs at least one -Service."
        }

        if (-not $PSCmdlet.ShouldProcess("LocalServiceACL rule '$RuleName' on $($params.Firewall)", 'Update')) {
            return
        }

        $xmlDescription = "<Description>$(ConvertTo-SfosXmlEscaped -Text $targetDescription)</Description>"
        $xmlIPFamily = "<IPFamily>$targetIPFamily</IPFamily>"
        $xmlSourceZone = "<SourceZone>$(ConvertTo-SfosXmlEscaped -Text $targetSourceZone)</SourceZone>"

        $hostXml = ($targetSourceHost | ForEach-Object -Process { "<Host>$(ConvertTo-SfosXmlEscaped -Text $_)</Host>" }) -join ''
        $xmlHosts = "<Hosts>$hostXml</Hosts>"

        $serviceXml = ($targetService | ForEach-Object -Process { "<Service>$(ConvertTo-SfosXmlEscaped -Text $_)</Service>" }) -join ''
        $xmlServices = "<Services>$serviceXml</Services>"

        $xmlAction = "<Action>$targetAction</Action>"

        $inner = @"
<Set operation="update">
  <LocalServiceACL>
    <RuleName>$ruleNameEsc</RuleName>
    $xmlDescription
    $xmlIPFamily
    $xmlSourceZone
    $xmlHosts
    $xmlServices
    $xmlAction
  </LocalServiceACL>
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
            throw "Failed to update LocalServiceACL rule '$RuleName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LocalServiceACL' -Action 'update' -Target $RuleName
    }
}

<#
.SYNOPSIS
    Removes a Local Service ACL rule from the Sophos Firewall.

.DESCRIPTION
    Removes a LocalServiceACL rule using the Sophos Firewall XML API. Supports ShouldProcess;
    use -WhatIf to preview.

    The vendor documentation does not name an explicit delete operation for this entity; this
    cmdlet follows the project's standard <Remove> shape used by every other entity in this
    module. UNCONFIRMED - never executed against a live firewall. See the region header.

.PARAMETER RuleName
    Name of the target rule.

.PARAMETER Session
    A session object returned by Connect-SfosFirewall, or the name of a session
    registered with Connect-SfosFirewall -Name. Overrides the stored default
    connection context; any of -Firewall/-Port/-Username/-Password/
    -SkipCertificateCheck supplied explicitly still wins over it. Enables piping
    between firewalls, e.g. Get-SfosLocalServiceACL -Session $fw1 | Remove-SfosLocalServiceACL -Session fw2.

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
    # Remove a rule
    Remove-SfosLocalServiceACL -RuleName 'AllowLANHttps'

.NOTES
    Minimum supported PowerShell version: 5.1
    UNCONFIRMED - never executed live, and the delete operation shape itself is not
    documented for this entity - see the region header and .DESCRIPTION.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/API/

.LINK
    Get-SfosLocalServiceACL
#>
function Remove-SfosLocalServiceACL {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateLength(1, 60)]
        [ValidatePattern('^[^,]+$')]
        [string]$RuleName,

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
        if (-not $PSCmdlet.ShouldProcess("LocalServiceACL rule '$RuleName' on $($params.Firewall)", 'Remove')) {
            return
        }

        $ruleNameEsc = ConvertTo-SfosXmlEscaped -Text $RuleName

        $inner = @"
<Remove>
  <LocalServiceACL>
    <RuleName>$ruleNameEsc</RuleName>
  </LocalServiceACL>
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
            throw "Error removing LocalServiceACL rule '$RuleName': $($_.Exception.Message)"
        }

        $XmlResponse = [xml]$response.Content
        Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LocalServiceACL' -Action 'remove' -Target $RuleName
    }
}

#endregion
