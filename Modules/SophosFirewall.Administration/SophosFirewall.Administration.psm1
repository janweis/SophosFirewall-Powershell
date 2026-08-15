#requires -Version 5.1
#requires -Modules SophosFirewall.Core

<#
    SophosFirewall.Administration
    ==============================
    PowerShell module for the Sophos Firewall (SFOS) System > Administration area via the
    XML API: mail server notification settings, SNMP agent configuration, system date/time,
    SNMP communities, SNMPv3 users, customizable end-user messages, appliance service access
    (zones per management service), the admin settings singleton (hostname, web admin ports,
    login security, password complexity, login disclaimer, factory reset), and the
    Local Service ACL rule list (management access control by zone/source host).

    Total Functions: 29 - see README.md for the full cmdlet table.

    Requires SophosFirewall.Core (>= 1.3.0) for transport, session state and status
    evaluation. All XML building and entity parsing happens here; all HTTP(S) happens
    in Core.

    API reference:
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/
#>


#region Notification
# The Notification singleton (SYSTEM > Administration > Notification Settings) is the
# device-wide mail server used for system-generated notification e-mails. The wire root is
# <Notification>, a singleton with no <Name> child.
#
# The stored object holds MailServer, Port, NotificationServer, AuthenticationRequired,
# ConnectionSecurity, Password, Recepient (the API's own spelling), Username,
# ManagementInterface, IPFamily and SenderAddress. Subject, MailBody, Certificate,
# Oauth2Provider and IPSecTunnelStatusChangeNotification belong to the Test Notification
# Mail half of the same operation page and are not part of this cmdlet.
#
# <Password> always reads back empty, so Set-SfosNotification has no stored value to
# preserve and sends <Password> only when -SmtpPassword is supplied.
#
# -SmtpPort, -SmtpUsername and -SmtpPassword on Set-SfosNotification are the entity's own
# Port, Username and Password fields, renamed to avoid a name clash with the connection
# parameters of the same names. Get-SfosNotification keeps the API's own field names.

<#
.SYNOPSIS
    Retrieves the mail server notification settings from a Sophos Firewall.

.DESCRIPTION
    Returns the Notification singleton (System > Administration > Notification Settings):
    the mail server the firewall uses to send system-generated notification e-mails. Use
    this cmdlet to review the current configuration or to feed it into Set-SfosNotification.
    The cmdlet only reads; nothing on the firewall is changed. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    notification settings. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with MailServer, Port, NotificationServer,
    AuthenticationRequired, Username, Password, ConnectionSecurity, SenderAddress,
    Recepient, ManagementInterface and IPFamily. Returns System.Xml.XmlElement when -AsXml
    is used.

.EXAMPLE
    Get-SfosNotification

    Shows the current mail server notification settings.

.EXAMPLE
    Get-SfosNotification | Select-Object MailServer, SenderAddress, Recepient

    Shows only the mail server, sender address and recipient.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates the mail server notification settings on a Sophos Firewall.

.DESCRIPTION
    Sets the Notification singleton (System > Administration > Notification Settings): the
    mail server the firewall uses to send system-generated notification e-mails. The cmdlet
    reads the current settings first and sends every field back, overriding only what you
    pass. Fields you do not pass keep their current value. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account with
    administrative permission.

    -SmtpPassword is sent only when you pass it; the firewall never reports the stored
    password back, so there is no current value to keep.

.PARAMETER MailServer
    Optional. Mail server IPv4 or IPv6 address, or FQDN. If omitted, the current value is
    kept.

.PARAMETER SmtpPort
    Optional. Mail server port number. If omitted, the current value is kept.

.PARAMETER NotificationServer
    Optional. '1' sends notifications through the external mail server, '0' through the
    firewall itself. If omitted, the current value is kept.

.PARAMETER AuthenticationRequired
    Optional. Whether the mail server requires authentication: 'Disable', 'Enable', 'Oauth2'
    or '0'. If omitted, the current value is kept.

.PARAMETER SmtpUsername
    Optional. User name for mail server authentication. If omitted, the current value is
    kept.

.PARAMETER SmtpPassword
    Optional. Password for mail server authentication, as a SecureString. If omitted,
    nothing is sent and the stored password is left as is.

.PARAMETER ConnectionSecurity
    Optional. Transport security for the mail connection: 'None', 'STARTTLS' or 'SSLTLS'. If
    omitted, the current value is kept.

.PARAMETER SenderAddress
    Optional. E-mail address notifications are sent from. If omitted, the current value is
    kept.

.PARAMETER Recepient
    Optional. E-mail address notifications are sent to. If omitted, the current value is
    kept.

.PARAMETER ManagementInterface
    Optional. Management interface whose IP address is included in notification e-mails. If
    omitted, the current value is kept.

.PARAMETER IPFamily
    Optional. IP family of -ManagementInterface: 'IPv4' or 'IPv6'. If omitted, the current
    value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosNotification -SenderAddress 'firewall-alerts@example.test' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosNotification -SenderAddress 'firewall-alerts@example.test'

    Changes only the sender address; every other field is kept. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
# The SNMPAgentConfiguration singleton (SYSTEM > Administration > SNMP Agent Configuration)
# is the device-wide SNMP agent toggle. The wire root is <SNMPAgentConfiguration>, a
# singleton with no <Name> child of its own (its <Name> field is the agent's display name,
# not an identifier).
#
# The stored object holds Location, Name, ContactPerson, Description, EnableAgent,
# ManagerPort and AgentPort. EnableAgent reads back lowercase 'true'/'false'. ManagerPort
# and AgentPort are read-only, so Set-SfosSNMPAgentConfiguration does not expose them as
# parameters; Get-SfosSNMPAgentConfiguration still returns both.

<#
.SYNOPSIS
    Retrieves the SNMP agent configuration from a Sophos Firewall.

.DESCRIPTION
    Returns the SNMPAgentConfiguration singleton (System > Administration > SNMP Agent
    Configuration): whether the SNMP agent is enabled and its location, name, contact
    person and description. Use this cmdlet to review the current configuration or to feed
    it into Set-SfosSNMPAgentConfiguration. The cmdlet only reads; nothing on the firewall
    is changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the SNMP
    agent configuration. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with Location, Name, ContactPerson,
    Description, EnableAgent, ManagerPort and AgentPort. Returns System.Xml.XmlElement when
    -AsXml is used.

.EXAMPLE
    Get-SfosSNMPAgentConfiguration

    Shows the current SNMP agent configuration.

.EXAMPLE
    Get-SfosSNMPAgentConfiguration | Select-Object EnableAgent, AgentPort, ManagerPort

    Shows whether the SNMP agent is enabled and which ports it uses.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates the SNMP agent configuration on a Sophos Firewall.

.DESCRIPTION
    Sets the SNMPAgentConfiguration singleton (System > Administration > SNMP Agent
    Configuration). The cmdlet reads the current settings first and sends every writable
    field back, overriding only what you pass. Fields you do not pass keep their current
    value. AgentPort and ManagerPort are read-only and cannot be set. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

.PARAMETER Location
    Optional. Physical location of the appliance. If omitted, the current value is kept.

.PARAMETER Name
    Optional. Name that identifies the SNMP agent. If omitted, the current value is kept.

.PARAMETER ContactPerson
    Optional. Contact information for the person responsible for the appliance. If omitted,
    the current value is kept.

.PARAMETER Description
    Optional. Description of the agent. If omitted, the current value is kept.

.PARAMETER EnableAgent
    Optional. 'true' or 'false' to enable or disable the SNMP agent. If omitted, the current
    value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosSNMPAgentConfiguration -ContactPerson 'ops@example.test' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSNMPAgentConfiguration -ContactPerson 'ops@example.test'

    Changes only the contact person; every other field is kept. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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

    # The firmware requires Name, Location and ContactPerson to be non-empty on every update,
    # even when the stored value is currently empty. Checked here so the error names the
    # missing field before the request is sent.
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
# The Time singleton (SYSTEM > Administration > Time Configuration) is the device-wide
# date/time and NTP configuration. The wire root is <Time>, a singleton with no <Name>
# child.
#
# The stored object holds TimeZone and SetDateTime (Date/Year,Month,Day and
# Time/HH,MM,SS). PredefinedNTPServer, CustomNTPServer/NTPServer and SyncNow appear only
# once NTP sync is configured; Set-SfosTime does not merge them from the current object and
# includes the NTP subtree and SyncNow only when the caller passes the matching parameter.
# SyncNow is a one-shot trigger, not a stored value.

<#
.SYNOPSIS
    Retrieves the system date and time configuration from a Sophos Firewall.

.DESCRIPTION
    Returns the Time singleton (System > Administration > Time Configuration): the time
    zone, the current appliance clock and the NTP settings when configured. Use this cmdlet
    to review the current configuration or to feed it into Set-SfosTime. The cmdlet only
    reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the time
    configuration. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with TimeZone, Year, Month, Day, HH, MM,
    SS, PredefinedNTPServer and NTPServer (a string array). Returns System.Xml.XmlElement
    when -AsXml is used.

.EXAMPLE
    Get-SfosTime

    Shows the current time zone and appliance clock.

.EXAMPLE
    Get-SfosTime | Select-Object TimeZone, Year, Month, Day, HH, MM, SS

    Shows only the time zone and the clock fields.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates the system date and time configuration on a Sophos Firewall.

.DESCRIPTION
    Sets the Time singleton (System > Administration > Time Configuration). The cmdlet
    reads the current settings first and sends TimeZone and the full clock back, overriding
    only what you pass. Fields you do not pass keep their current value. NTP fields and
    -SyncNow are included only when you pass them. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

    Every call resends the clock fields, so a time-zone-only change also re-applies the
    clock reading taken a moment earlier. Changing the time zone briefly restarts the
    management service; the appliance becomes reachable again on its own a short time
    later, with the clock recalculated for the new zone.

.PARAMETER TimeZone
    Optional. IANA time zone name, for example 'Europe/Berlin'. If omitted, the current
    value is kept.

.PARAMETER Year
    Optional. Year for the appliance clock. If omitted, the current value is kept.

.PARAMETER Month
    Optional. Month, 1 to 12, for the appliance clock. If omitted, the current value is
    kept.

.PARAMETER Day
    Optional. Day, 1 to 31, for the appliance clock. If omitted, the current value is kept.

.PARAMETER HH
    Optional. Hour, 0 to 23, for the appliance clock. If omitted, the current value is
    kept.

.PARAMETER MM
    Optional. Minute, 0 to 59, for the appliance clock. If omitted, the current value is
    kept.

.PARAMETER SS
    Optional. Second, 0 to 59, for the appliance clock. If omitted, the current value is
    kept.

.PARAMETER PredefinedNTPServer
    Optional. 'Enable' to use a predefined NTP server instead of a custom one. Sent only
    when you pass it.

.PARAMETER NTPServer
    Optional. One or more custom NTP server addresses or host names. Sent only when you
    pass it.

.PARAMETER SyncNow
    Optional. '1' synchronizes the clock with the NTP server immediately. A one-shot
    trigger, not a stored value; sent only when you pass it.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosTime -TimeZone 'Europe/Berlin' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosTime -TimeZone 'Europe/Berlin'

    Changes the time zone; the clock fields are taken from the current reading. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
# An SNMPCommunity object (SYSTEM > Administration > SNMP Community) defines an SNMP v1/v2c
# community string and the manager host(s) allowed to use it. The wire root is
# <SNMPCommunity>, identified by <Name>.
#
# A create needs Name, CommunityString, one of AuthorizedHostIpv4/AuthorizedHostIpv6, and
# one of AcceptQueries/SendTraps.
#
# CommunityString is stored as a salted hash and read back as
# <CommunityString hashform="mode1">$sfos$...</CommunityString>. Get-SfosSNMPCommunity
# exposes the hash text and its hashform attribute; Set-SfosSNMPCommunity resends them
# unchanged when the caller does not pass -CommunityString, and the firewall re-salts on
# every write.
#
# AuthorizedHostIpv4/AuthorizedHostIpv6 read back the literal string 'NULL' for whichever of
# the pair is not set. Get-SfosSNMPCommunity normalises that to an empty string.
# Set-SfosSNMPCommunity sends only whichever of the two carries a real value.
#
# AcceptQueries/SendTraps are sent as 'True'/'False' and read back lowercase
# 'true'/'false'.

<#
.SYNOPSIS
    Retrieves SNMP community objects from a Sophos Firewall.

.DESCRIPTION
    Returns the SNMP community objects that are defined on the firewall. An SNMP community
    object holds an SNMP v1/v2c community string and the manager hosts allowed to use it.
    Use this cmdlet to review the existing objects or to feed them into another cmdlet
    through the pipeline. The cmdlet only reads; nothing on the firewall is changed. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

    You can combine several filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. If omitted,
    the name is not used to filter.

.PARAMETER DescriptionLike
    Optional. Returns only objects whose description contains the given text anywhere.
    Applied on the client. If omitted, the description is not used to filter.

.PARAMETER AuthorizedHostIpv4Like
    Optional. Returns only objects whose IPv4 manager address contains the given text
    anywhere. Applied on the client. If omitted, the address is not used to filter.

.PARAMETER AuthorizedHostIpv6Like
    Optional. Returns only objects whose IPv6 manager address contains the given text
    anywhere. Applied on the client. If omitted, the address is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the SNMP
    community objects. If omitted, the value from the current connection is used.

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
    objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per SNMP community, with the
    properties Name, CommunityString, CommunityStringHashForm, Description,
    AuthorizedHostIpv4, AuthorizedHostIpv6, AcceptQueries and SendTraps. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosSNMPCommunity

    Lists every SNMP community object on the firewall of the current connection.

.EXAMPLE
    Get-SfosSNMPCommunity -NameLike 'Monitoring'

    Lists all SNMP community objects whose name contains 'Monitoring'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Creates an SNMP community object on a Sophos Firewall.

.DESCRIPTION
    Creates an SNMP community: a community string and the manager host(s) allowed to use
    it, under System > Administration > SNMP Community. The object needs exactly one of
    -AuthorizedHostIpv4/-AuthorizedHostIpv6, and at least one of
    -AcceptQueries/-SendTraps. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER Name
    Required. Name of the SNMP community, 1 to 100 characters, no commas.

.PARAMETER CommunityString
    Required. The community string, as a SecureString. Stored as a salted hash on the
    firewall.

.PARAMETER Description
    Optional. Description of the community, up to 200 characters. If omitted, no
    description is set.

.PARAMETER AuthorizedHostIpv4
    Optional. IPv4 address of the SNMP manager allowed to use this community. Specify this
    or -AuthorizedHostIpv6, not both.

.PARAMETER AuthorizedHostIpv6
    Optional. IPv6 address of the SNMP manager allowed to use this community. Specify this
    or -AuthorizedHostIpv4, not both.

.PARAMETER AcceptQueries
    Optional. 'True' or 'False'. Whether the agent accepts queries from the manager using
    this community. At least one of -AcceptQueries/-SendTraps is required.

.PARAMETER SendTraps
    Optional. 'True' or 'False'. Whether SNMP traps are sent using this community. At least
    one of -AcceptQueries/-SendTraps is required.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    $secret = ConvertTo-SecureString 'public-secret' -AsPlainText -Force
    New-SfosSNMPCommunity -Name 'Monitoring' -CommunityString $secret -AuthorizedHostIpv4 '10.0.0.50' -AcceptQueries 'True' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    $secret = ConvertTo-SecureString 'public-secret' -AsPlainText -Force
    New-SfosSNMPCommunity -Name 'Monitoring' -CommunityString $secret -AuthorizedHostIpv4 '10.0.0.50' -AcceptQueries 'True'

    Creates a community that accepts queries from one IPv4 manager. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates an SNMP community object on a Sophos Firewall.

.DESCRIPTION
    Sets an existing SNMP community. The cmdlet reads the current object first and sends
    every field back, overriding only what you pass. Fields you do not pass keep their
    current value. When -CommunityString is not supplied, the stored hash is resent as is.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER Name
    Required. Name of the SNMP community to update.

.PARAMETER CommunityString
    Optional. New community string, as a SecureString. If omitted, the stored value is
    kept.

.PARAMETER Description
    Optional. Description of the community. If omitted, the current value is kept.

.PARAMETER AuthorizedHostIpv4
    Optional. IPv4 address of the SNMP manager. If omitted, the current value is kept.

.PARAMETER AuthorizedHostIpv6
    Optional. IPv6 address of the SNMP manager. If omitted, the current value is kept.

.PARAMETER AcceptQueries
    Optional. 'True' or 'False'. If omitted, the current value is kept.

.PARAMETER SendTraps
    Optional. 'True' or 'False'. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    System.String. Accepts a community name by property name from Get-SfosSNMPCommunity.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosSNMPCommunity -Name 'Monitoring' -Description 'Updated description' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosSNMPCommunity -Name 'Monitoring' -Description 'Updated description'

    Changes only the description; every other field is kept. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSNMPCommunity

.LINK
    New-SfosSNMPCommunity

.LINK
    Remove-SfosSNMPCommunity
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
    Removes an SNMP community object from a Sophos Firewall.

.DESCRIPTION
    Deletes an SNMP community. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Name
    Required. Name of the SNMP community to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    System.String. Accepts a community name by property name from Get-SfosSNMPCommunity.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosSNMPCommunity -Name 'Monitoring' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosSNMPCommunity -Name 'Monitoring'

    Removes the SNMP community. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
# An SNMPv3User object (SYSTEM > Administration > SNMPv3 User) is an SNMPv3 USM user with
# authentication and privacy credentials. The wire root is <SNMPv3User>, identified by
# <Name>. Unlike SNMPCommunity, this entity has no AuthorizedHost field.
#
# A create needs Name, Username, AuthenticationAlgorithm, AuthenticationPassword,
# EncryptionAlgorithm, EncryptionPassword, and at least one of AcceptQueries/SendTraps.
#
# AuthenticationAlgorithm and EncryptionAlgorithm mix numeric codes and text values ('MD5',
# 'DES', 'AES' alongside '1'/'2'/'3'). No ValidateSet is applied to either parameter, because
# the mapping between text and code is not fully known.
#
# AuthenticationPassword and EncryptionPassword are stored as salted hashes. Unlike
# SNMPCommunity, resending the stored hash on update does not preserve the secret on this
# entity, so Set-SfosSNMPv3User requires both passwords on every call rather than keeping
# the current value when they are omitted.

<#
.SYNOPSIS
    Retrieves SNMPv3 user objects from a Sophos Firewall.

.DESCRIPTION
    Returns the SNMPv3 user objects that are defined on the firewall. An SNMPv3 user object
    holds an SNMP v3 USM user name together with its authentication and privacy
    credentials. Use this cmdlet to review the existing objects or to feed them into
    another cmdlet through the pipeline. The cmdlet only reads; nothing on the firewall is
    changed. It needs an open connection from Connect-SfosFirewall, or the connection
    parameters supplied directly.

    You can combine both filters. The firewall itself evaluates at most one of them, so
    every filter you supply is applied again on the client. The result therefore always
    matches all filters you gave.

.PARAMETER NameLike
    Optional. Returns only objects whose name contains the given text anywhere. If omitted,
    the name is not used to filter.

.PARAMETER UsernameLike
    Optional. Returns only objects whose SNMPv3 user name contains the given text anywhere.
    Applied on the client. If omitted, the user name is not used to filter.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the SNMPv3
    user objects. If omitted, the value from the current connection is used.

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
    objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per SNMPv3 user, with the
    properties Name, Username, AuthenticationAlgorithm, AuthenticationPassword,
    AuthenticationPasswordHashForm, EncryptionAlgorithm, EncryptionPassword,
    EncryptionPasswordHashForm, AcceptQueries and SendTraps. Returns System.Xml.XmlElement
    when -AsXml is used, and an empty array when no object matches.

.EXAMPLE
    Get-SfosSNMPv3User

    Lists every SNMPv3 user object on the firewall of the current connection.

.EXAMPLE
    Get-SfosSNMPv3User -NameLike 'Monitoring'

    Lists all SNMPv3 user objects whose name contains 'Monitoring'.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Creates an SNMPv3 user object on a Sophos Firewall.

.DESCRIPTION
    Creates an SNMPv3 USM user with authentication and privacy credentials, under System >
    Administration > SNMPv3 User. The object needs at least one of
    -AcceptQueries/-SendTraps. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Name
    Required. Name that identifies the SNMPv3 user object, 1 to 100 characters, no commas.

.PARAMETER SNMPUsername
    Required. The SNMPv3 protocol user name.

.PARAMETER AuthenticationAlgorithm
    Required. Authentication algorithm. 'MD5' is a known text value; numeric codes are also
    accepted.

.PARAMETER AuthenticationPassword
    Required. Authentication password, as a SecureString. Stored as a salted hash.

.PARAMETER EncryptionAlgorithm
    Required. Privacy algorithm. 'DES' and 'AES' are known text values; numeric codes are
    also accepted.

.PARAMETER EncryptionPassword
    Required. Privacy password, as a SecureString. Stored as a salted hash.

.PARAMETER AcceptQueries
    Optional. 'True' or 'False'. Whether the agent accepts queries authenticated as this
    user. At least one of -AcceptQueries/-SendTraps is required.

.PARAMETER SendTraps
    Optional. 'True' or 'False'. Whether SNMP traps are sent authenticated as this user. At
    least one of -AcceptQueries/-SendTraps is required.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    $authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
    $privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
    New-SfosSNMPv3User -Name 'MonitoringUser' -SNMPUsername 'monitor' -AuthenticationAlgorithm 'MD5' -AuthenticationPassword $authPw -EncryptionAlgorithm 'DES' -EncryptionPassword $privPw -AcceptQueries 'True' -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    $authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
    $privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
    New-SfosSNMPv3User -Name 'MonitoringUser' -SNMPUsername 'monitor' -AuthenticationAlgorithm 'MD5' -AuthenticationPassword $authPw -EncryptionAlgorithm 'DES' -EncryptionPassword $privPw -AcceptQueries 'True'

    Creates an SNMPv3 user with MD5 authentication and DES privacy. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates an SNMPv3 user object on a Sophos Firewall.

.DESCRIPTION
    Sets an existing SNMPv3 USM user. The cmdlet reads the current object first and sends
    every field back, overriding only what you pass, except
    -AuthenticationPassword/-EncryptionPassword, which are required on every call because
    the stored password hash cannot be resent to preserve it on this entity. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

.PARAMETER Name
    Required. Name of the SNMPv3 user object to update.

.PARAMETER SNMPUsername
    Optional. New SNMPv3 protocol user name. If omitted, the current value is kept.

.PARAMETER AuthenticationAlgorithm
    Optional. New authentication algorithm. If omitted, the current value is kept.

.PARAMETER AuthenticationPassword
    Required. Authentication password, as a SecureString. Always sent, because there is no
    way to keep the stored value on this entity.

.PARAMETER EncryptionAlgorithm
    Optional. New privacy algorithm. If omitted, the current value is kept.

.PARAMETER EncryptionPassword
    Required. Privacy password, as a SecureString. Always sent, because there is no way to
    keep the stored value on this entity.

.PARAMETER AcceptQueries
    Optional. 'True' or 'False'. If omitted, the current value is kept.

.PARAMETER SendTraps
    Optional. 'True' or 'False'. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    System.String. Accepts a user name by property name from Get-SfosSNMPv3User.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    $authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
    $privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
    Set-SfosSNMPv3User -Name 'MonitoringUser' -EncryptionAlgorithm 'AES' -AuthenticationPassword $authPw -EncryptionPassword $privPw -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    $authPw = ConvertTo-SecureString 'AuthPass123!' -AsPlainText -Force
    $privPw = ConvertTo-SecureString 'PrivPass123!' -AsPlainText -Force
    Set-SfosSNMPv3User -Name 'MonitoringUser' -EncryptionAlgorithm 'AES' -AuthenticationPassword $authPw -EncryptionPassword $privPw

    Changes only the encryption algorithm; both passwords must still be supplied. The
    cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosSNMPv3User

.LINK
    New-SfosSNMPv3User

.LINK
    Remove-SfosSNMPv3User
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
    Removes an SNMPv3 user object from a Sophos Firewall.

.DESCRIPTION
    Deletes an SNMPv3 USM user. It needs an open connection from Connect-SfosFirewall, or
    the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER Name
    Required. Name of the SNMPv3 user object to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    System.String. Accepts a user name by property name from Get-SfosSNMPv3User.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosSNMPv3User -Name 'MonitoringUser' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosSNMPv3User -Name 'MonitoringUser'

    Removes the SNMPv3 user. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
# The Messages singleton (SYSTEM > Administration > Messages) customizes the text shown to
# end users for SMTP rejections, login and session events, the admin login disclaimer and
# the default guest-user SMS. The wire root is <Messages>, a singleton with no <Name> child.
#
# Unlike every other singleton in this module, a Get answers with four separate <Messages>
# sibling elements, one per sub-block (<SMTP>, <Administration>, <SMSCustomization>,
# <AuthenticationMessages>), not one <Messages> wrapping all four. Get-SfosMessages collects
# all four and returns one merged object. The SMTP block holds 16 fields.
#
# Set is a partial update: sending only one field leaves every other field, in every
# sub-block, unchanged. Set-SfosMessages therefore sends only the fields the caller actually
# passes rather than reading and resending the whole entity, because resending an untouched
# text field trims any trailing whitespace it carries.
#
# There is no working Reset operation for this entity, so no Reset-SfosMessages cmdlet is
# provided; use Set-SfosMessages with the original text to revert a field.
#
# Status lands flat at /Response/Messages/Status with a code attribute, for both Get and Set
# errors; -ObjectName 'Messages' finds it directly, with no nested container.

<#
.SYNOPSIS
    Retrieves the customizable end-user messages from a Sophos Firewall.

.DESCRIPTION
    Returns the Messages singleton (System > Administration > Messages): SMTP rejection
    texts, the admin login disclaimer, the default guest-user SMS text, and authentication
    and session messages. Use this cmdlet to review the current text or to feed it into
    Set-SfosMessages. The cmdlet only reads; nothing on the firewall is changed. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    Messages settings. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML elements sent by the firewall (one per sub-block) instead
    of a PowerShell object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with SMTP, Administration,
    SMSCustomization and AuthenticationMessages sub-objects, each carrying the matching
    text fields. Returns an array of System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosMessages

    Shows every customizable message.

.EXAMPLE
    (Get-SfosMessages).Administration.DisclaimerMessage

    Shows only the admin login disclaimer text.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates the customizable end-user messages on a Sophos Firewall.

.DESCRIPTION
    Sets the Messages singleton (System > Administration > Messages). Unlike every other
    Set-* in this module, this is a partial update: the cmdlet sends only the fields you
    pass, and every other field, including other fields in the same sub-block, is left
    unchanged on the firewall. At least one field parameter is required. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

.PARAMETER SXLRejection
    Optional. SMTP RBL rejection text. If omitted, the current value is kept.

.PARAMETER ProbableSpamRejection
    Optional. SMTP probable-spam rejection text. If omitted, the current value is kept.

.PARAMETER ProbableVirusOutbreakRejection
    Optional. SMTP probable virus outbreak rejection text. If omitted, the current value is
    kept.

.PARAMETER SpamRejection
    Optional. SMTP spam rejection text. If omitted, the current value is kept.

.PARAMETER VirusOutbreakRejection
    Optional. SMTP virus outbreak rejection text. If omitted, the current value is kept.

.PARAMETER EmailDomainRejection
    Optional. SMTP sender domain policy rejection text. If omitted, the current value is
    kept.

.PARAMETER SpamMailRejection
    Optional. SMTP sender address policy rejection text. If omitted, the current value is
    kept.

.PARAMETER MailHeaderRejection
    Optional. SMTP MIME header policy rejection text. If omitted, the current value is
    kept.

.PARAMETER MailVirusRejection
    Optional. SMTP virus rejection text. If omitted, the current value is kept.

.PARAMETER IPAddressRejection
    Optional. SMTP sender IP policy rejection text. If omitted, the current value is kept.

.PARAMETER OversizedMailRejection
    Optional. SMTP message-too-large rejection text. If omitted, the current value is kept.

.PARAMETER UndersizedMailRejection
    Optional. SMTP message-too-small rejection text. If omitted, the current value is kept.

.PARAMETER DeliveryNotification
    Optional. SMTP successful delivery notification text. If omitted, the current value is
    kept.

.PARAMETER AttachmentInfection
    Optional. SMTP suspected-infected-attachment rejection text. If omitted, the current
    value is kept.

.PARAMETER RBLRejection
    Optional. SMTP RBL rejection text. If omitted, the current value is kept.

.PARAMETER SuspectedInfection
    Optional. SMTP suspected-virus rejection text. If omitted, the current value is kept.

.PARAMETER DisclaimerMessage
    Optional. Admin login disclaimer and warning banner text. If omitted, the current value
    is kept.

.PARAMETER DefaultSMS
    Optional. Default guest-user SMS text template. If omitted, the current value is kept.

.PARAMETER Useraccountblocked
    Optional. Authentication message: account blocked. If omitted, the current value is
    kept.

.PARAMETER Useraccountdisabled
    Optional. Authentication message: account disabled. If omitted, the current value is
    kept.

.PARAMETER Useraccountexpired
    Optional. Authentication message: account expired. If omitted, the current value is
    kept.

.PARAMETER ClientlessUserLoginNotAllowed
    Optional. Authentication message: clientless login not permitted. If omitted, the
    current value is kept.

.PARAMETER DataTransferExhausted
    Optional. Authentication message: data transfer quota exceeded. If omitted, the current
    value is kept.

.PARAMETER DeactiveUser
    Optional. Authentication message: account no longer active. If omitted, the current
    value is kept.

.PARAMETER DeleteUser
    Optional. Authentication message: user deleted or disconnected. If omitted, the current
    value is kept.

.PARAMETER DisconnectUser
    Optional. Authentication message: disconnected by an administrator. If omitted, the
    current value is kept.

.PARAMETER GuestUserValidityExpired
    Optional. Authentication message: guest user validity expired. If omitted, the current
    value is kept.

.PARAMETER Loginnotallowedatthistime
    Optional. Authentication message: login not permitted at this time. If omitted, the
    current value is kept.

.PARAMETER InvalidMachine
    Optional. Authentication message: login not permitted from this machine. If omitted,
    the current value is kept.

.PARAMETER Loginnotallowedatthisworkstation
    Optional. Authentication message: login denied by the directory server for this
    workstation. If omitted, the current value is kept.

.PARAMETER SomeoneelseisloggedinfromsameIPAddress
    Optional. Authentication message: concurrent login from the same IP address. If
    omitted, the current value is kept.

.PARAMETER LoggedOffSuccessfulMessage
    Optional. Authentication message: sign-out confirmation. If omitted, the current value
    is kept.

.PARAMETER LoggedOnSuccessfulMessage
    Optional. Authentication message: sign-in confirmation. If omitted, the current value
    is kept.

.PARAMETER LogoutNotification
    Optional. Authentication message: pending automatic logout notification. If omitted,
    the current value is kept.

.PARAMETER MaxLoginLimit
    Optional. Authentication message: maximum login limit reached. If omitted, the current
    value is kept.

.PARAMETER NotAuthenticate
    Optional. Authentication message: invalid credentials. If omitted, the current value is
    kept.

.PARAMETER NotCurrentlyAllowed
    Optional. Authentication message: access not currently permitted. If omitted, the
    current value is kept.

.PARAMETER Userpasswordexpired
    Optional. Authentication message: directory server password expired. If omitted, the
    current value is kept.

.PARAMETER Userneedstoresetthepassword
    Optional. Authentication message: directory server password reset required. If
    omitted, the current value is kept.

.PARAMETER LoggedOffDueToSessionTimeOut
    Optional. Authentication message: session timed out. If omitted, the current value is
    kept.

.PARAMETER SurfingTimeExhausted
    Optional. Authentication message: surfing time quota exhausted. If omitted, the current
    value is kept.

.PARAMETER SurfingTimeExpired
    Optional. Authentication message: surfing time expired. If omitted, the current value
    is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosMessages -DefaultSMS 'Your Sophos guest account is ready.' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosMessages -DefaultSMS 'Your Sophos guest account is ready.'

    Changes only the default guest-user SMS text; every other field is kept. The cmdlet
    asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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

    # Messages is a partial-update entity (see the region header) - a request carrying only
    # the fields the caller actually bound changes only those fields and leaves everything
    # else, byte for byte, alone. This function deliberately does NOT read the current object
    # and resend it: the firewall trims trailing whitespace on every text field it receives,
    # so resending untouched fields would silently strip trailing whitespace from fields
    # nobody asked to change. Sending only bound fields confines that trimming to fields the
    # caller is actually touching.
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
# The ApplianceAccess singleton (SYSTEM > Administration > Device Access, "Local Service
# ACL" / "Admin Service Access" in the web admin) controls, per management-facing service,
# which firewall zones may reach it. The wire root is <ApplianceAccess>, a singleton with no
# <Name> child, holding one <ServiceName><ZoneName>...</ZoneName></ServiceName> block per
# service. This entity has no documentation page in the SFOS API reference.
#
# There are 14 services, each holding zero or more <ZoneName> children: Https, SSH,
# CaptivePortal, RadiusSSO, ClientAuthentication, Ping, DNS, SSLVPN, WebProxy, SMTPRelay,
# SNMP, VPNPortal, RED, IPsec. Casing on the wire is exactly as shown: 'Https', not 'HTTPS';
# 'IPsec', not 'IPSec'.
#
# The Https and SSH lists carry the appliance's own management access. Set-SfosApplianceAccess
# follows this module's usual read-modify-write pattern.

<#
.SYNOPSIS
    Retrieves the appliance service access matrix from a Sophos Firewall.

.DESCRIPTION
    Returns the ApplianceAccess singleton (SYSTEM > Administration > Device Access): which
    firewall zones may reach each of 14 management services (Https, SSH, CaptivePortal,
    RadiusSSO, ClientAuthentication, Ping, DNS, SSLVPN, WebProxy, SMTPRelay, SNMP, VPNPortal,
    RED, IPsec). Use this cmdlet to review the current matrix before changing it with
    Set-SfosApplianceAccess. The cmdlet only reads; nothing on the firewall is changed. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    appliance access settings. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with one string array property per service:
    Https, SSH, CaptivePortal, RadiusSSO, ClientAuthentication, Ping, DNS, SSLVPN, WebProxy,
    SMTPRelay, SNMP, VPNPortal, RED and IPsec, each the list of zone names currently allowed
    to reach that service. Returns System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosApplianceAccess

    Shows the full zone-per-service matrix.

.EXAMPLE
    (Get-SfosApplianceAccess).Https

    Shows which zones may reach the web admin console over HTTPS.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates which zones may reach each management service of a Sophos Firewall.

.DESCRIPTION
    Sets the device access matrix under SYSTEM > Administration > Device Access. For each of
    the 14 management services you pass the list of zones that are allowed to reach it. Use
    this cmdlet to open a service for an additional zone, or to close one that should no
    longer be reachable.

    The cmdlet reads the current matrix first and sends all 14 services back. Services you do
    not pass keep their current zone list, and a service you do pass is replaced by exactly
    the zones you name. The change takes effect immediately; no reload is needed. It needs an
    open connection from Connect-SfosFirewall, or the connection parameters supplied
    directly, and an account with administrative permission.

    The Https and SSH lists carry your own management access. If you remove the zone that
    your web admin or API session comes from, the appliance can no longer be reached over the
    network and the change cannot be undone remotely. Check the current matrix with
    Get-SfosApplianceAccess before you write, and use -WhatIf to preview the call.

.PARAMETER Https
    Optional. Zone names allowed to reach the web admin console over HTTPS. Replaces the
    current list. If omitted, the current list is kept.

.PARAMETER SSH
    Optional. Zone names allowed to reach the appliance over SSH. Replaces the current list.
    If omitted, the current list is kept.

.PARAMETER CaptivePortal
    Optional. Zone names allowed to reach the captive portal. Replaces the current list. If
    omitted, the current list is kept.

.PARAMETER RadiusSSO
    Optional. Zone names allowed to reach the RADIUS single sign-on service. Replaces the
    current list. If omitted, the current list is kept.

.PARAMETER ClientAuthentication
    Optional. Zone names allowed to reach the client authentication service. Replaces the
    current list. If omitted, the current list is kept.

.PARAMETER Ping
    Optional. Zone names allowed to ping the appliance. Replaces the current list. If
    omitted, the current list is kept.

.PARAMETER DNS
    Optional. Zone names allowed to use the appliance as a DNS resolver. Replaces the current
    list. If omitted, the current list is kept.

.PARAMETER SSLVPN
    Optional. Zone names allowed to reach the SSL VPN service. Replaces the current list. If
    omitted, the current list is kept.

.PARAMETER WebProxy
    Optional. Zone names allowed to reach the web proxy. Replaces the current list. If
    omitted, the current list is kept.

.PARAMETER SMTPRelay
    Optional. Zone names allowed to use the appliance as an SMTP relay. Replaces the current
    list. If omitted, the current list is kept.

.PARAMETER SNMP
    Optional. Zone names allowed to query the appliance over SNMP. Replaces the current list.
    If omitted, the current list is kept.

.PARAMETER VPNPortal
    Optional. Zone names allowed to reach the VPN portal. Replaces the current list. If
    omitted, the current list is kept.

.PARAMETER RED
    Optional. Zone names allowed to reach the RED (Remote Ethernet Device) service. Replaces
    the current list. If omitted, the current list is kept.

.PARAMETER IPsec
    Optional. Zone names allowed to reach the IPsec service. Replaces the current list. If
    omitted, the current list is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the current
    connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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
    you work with more than one at a time. Any connection parameter you pass explicitly still
    takes precedence. If omitted, the stored default connection is used.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the update.

.EXAMPLE
    Set-SfosApplianceAccess -Ping 'LAN','WiFi','DMZ' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosApplianceAccess -Ping 'LAN','WiFi','DMZ'

    Allows the LAN, WiFi and DMZ zones to ping the appliance. All other services keep their
    current zones. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    Set-SfosApplianceAccess -SNMP 'LAN' -Confirm:$false

    Restricts SNMP access to the LAN zone without asking for confirmation, for use in scripts.

.EXAMPLE
    Get-SfosApplianceAccess | Format-List

    Shows the current matrix. Run this before a change so you can restore the previous state.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
# The AdminSettings singleton (SYSTEM > Administration > Settings) bundles six otherwise
# unrelated blocks: HostnameSettings, WebAdminSettings, LoginSecurity,
# PasswordComplexitySettings, LoginDisclaimer and DefaultConfigurationLanguage. The wire root
# is <AdminSettings>, with no <Name> child.
#
# Unlike the rest of this API family, AdminSettings is not full-replace: a write carries only
# the one block being changed, and the other five are left untouched. Every Set-* below
# therefore emits only its own block; read-modify-write still applies, but only within that
# block, to preserve sibling fields the caller did not bind (for example HostNameDesc when
# only -HostName is given). A block with a single field (LoginDisclaimer,
# DefaultConfigurationLanguage) needs no read at all, since there is nothing else in the
# block to preserve.
#
# The status of an update does not land nested under AdminSettings. It lands flat and
# separately per block: /Response/HostnameSettings/Status, /Response/WebAdminSettings/Status,
# /Response/LoginSecurity/Status, /Response/PasswordComplexitySettings/Status,
# /Response/LoginDisclaimer/Status, /Response/DefaultConfigurationLanguage/Status. Every
# Set-* below asserts against its own block's flat path, not against 'AdminSettings'.
#
# DefaultConfigurationLanguage looks like a language setting but is a factory reset trigger;
# see Reset-SfosToFactoryDefaults.

<#
.SYNOPSIS
    Retrieves the administration settings from a Sophos Firewall.

.DESCRIPTION
    Returns the AdminSettings singleton (System > Administration > Settings): the appliance
    host name, the web admin and portal HTTPS ports and certificate, admin login security
    (session timeout, login-attempt blocking), the admin password complexity policy, and the
    admin login disclaimer toggle. Use this cmdlet to review the current configuration
    before changing one block with the matching Set-* cmdlet. The cmdlet only reads; nothing
    on the firewall is changed. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    administration settings. If omitted, the value from the current connection is used.

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
    Optional. Returns the raw XML element sent by the firewall instead of a PowerShell
    object.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject with HostName, HostNameDesc,
    LoginDisclaimer, DefaultConfigurationLanguage, and the nested sub-objects
    WebAdminSettings (Certificate, HTTPSport, UserPortalHTTPSPort, VPNPortalHTTPSPort,
    PortalRedirectMode, PortalCustomHostname), LoginSecurity (LogoutSession, BlockLogin,
    UnsucccessfulAttempt, Duration, ForMinutes) and PasswordComplexitySettings
    (PasswordComplexityCheck, MinimumPasswordLength, IncludeAlphabeticCharacters,
    IncludeNumericCharacter, IncludeSpecialCharacter, MinimumPasswordLengthValue). Returns
    System.Xml.XmlElement when -AsXml is used.

.EXAMPLE
    Get-SfosAdminSettings

    Shows every administration setting.

.EXAMPLE
    (Get-SfosAdminSettings).PasswordComplexitySettings

    Shows only the password complexity policy.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Reset-SfosToFactoryDefaults
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
    Updates the web admin and portal HTTPS settings on a Sophos Firewall.

.DESCRIPTION
    Sets the WebAdminSettings block of the AdminSettings singleton (System > Administration
    > Settings > Web Admin Settings). The cmdlet reads the block first and sends it back,
    overriding only the fields you pass; the other five AdminSettings blocks are not sent.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

    -HTTPSport controls the port the current API and web admin session is reachable on. A
    wrong value can make the appliance unreachable, with no way to revert the change
    remotely. Check the current value with Get-SfosAdminSettings before you write, and use
    -WhatIf to preview the call.

.PARAMETER HTTPSport
    Optional. HTTPS port for the web admin console, 1 to 65535. If omitted, the current
    value is kept.

.PARAMETER UserPortalHTTPSPort
    Optional. HTTPS port for the user portal, 1 to 65535. If omitted, the current value is
    kept.

.PARAMETER VPNPortalHTTPSPort
    Optional. HTTPS port for the VPN portal, 1 to 65535. If omitted, the current value is
    kept.

.PARAMETER Certificate
    Optional. Name of the certificate object used by the user portal and captive portal. If
    omitted, the current value is kept.

.PARAMETER PortalRedirectMode
    Optional. Host name mode used for the captive portal and related portals: 'ip', 'fqdn'
    or 'custom'. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosWebAdminSettings -PortalRedirectMode 'fqdn' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosWebAdminSettings -PortalRedirectMode 'fqdn'

    Switches the captive portal host name mode to fully qualified domain name. The cmdlet
    asks for confirmation before it writes.

.EXAMPLE
    Set-SfosWebAdminSettings -UserPortalHTTPSPort 8443 -Confirm:$false

    Changes the user portal HTTPS port without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    # Status lands flat at /Response/WebAdminSettings/Status, not nested under AdminSettings -
    # see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'WebAdminSettings' -Action 'update'
}

<#
.SYNOPSIS
    Updates the admin login security policy on a Sophos Firewall.

.DESCRIPTION
    Sets the LoginSecurity block of the AdminSettings singleton (System > Administration >
    Settings > Login Security): the admin session inactivity timeout and failed-login
    blocking. The cmdlet reads the block first and sends it back, overriding only the
    fields you pass; the other five AdminSettings blocks are not sent. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

    -BlockLogin, -UnsucccessfulAttempt, -Duration and -ForMinutes together control when the
    currently connected admin account itself is locked out. A value that locks out your own
    account leaves no way to sign back in until the block expires. Check the current values
    with Get-SfosAdminSettings before you write, and use -WhatIf to preview the call.

.PARAMETER LogoutSession
    Optional. Inactivity timeout in minutes before the admin session is logged out, 1 to
    120, or the literal string 'Disable'. If omitted, the current value is kept.

.PARAMETER BlockLogin
    Optional. 'Enable' blocks admin login after a configured number of failed attempts from
    the same IP address; 'Disable' turns the block off. If omitted, the current value is
    kept.

.PARAMETER UnsucccessfulAttempt
    Optional. Allowed number of failed admin login attempts from the same IP address before
    blocking, 1 to 5. If omitted, the current value is kept.

.PARAMETER Duration
    Optional. Time span in minutes within which -UnsucccessfulAttempt failed logins trigger
    the block, 1 to 120. If omitted, the current value is kept.

.PARAMETER ForMinutes
    Optional. Duration in minutes for which admin login is blocked once triggered, 1 to 60.
    If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosLoginSecurity -LogoutSession '30' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosLoginSecurity -LogoutSession '30'

    Extends the admin session inactivity timeout to 30 minutes. The cmdlet asks for
    confirmation before it writes.

.EXAMPLE
    Set-SfosLoginSecurity -LogoutSession '30' -Confirm:$false

    Extends the timeout without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    # Status lands flat at /Response/LoginSecurity/Status, not nested under AdminSettings -
    # see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LoginSecurity' -Action 'update'
}

<#
.SYNOPSIS
    Updates the admin password complexity policy on a Sophos Firewall.

.DESCRIPTION
    Sets the PasswordComplexitySettings block of the AdminSettings singleton (System >
    Administration > Settings > Password Complexity Settings). The cmdlet reads the block
    first and sends it back, overriding only the fields you pass; the other five
    AdminSettings blocks are not sent. The policy applies to future password changes only,
    not to any password already set. It needs an open connection from Connect-SfosFirewall,
    or the connection parameters supplied directly, and an account with administrative
    permission.

.PARAMETER PasswordComplexityCheck
    Optional. 'Enable' turns on password complexity enforcement; 'Disable' turns it off. If
    omitted, the current value is kept.

.PARAMETER MinimumPasswordLength
    Optional. 'Enable' enforces -MinimumPasswordLengthValue; 'Disable' turns the check off.
    If omitted, the current value is kept.

.PARAMETER MinimumPasswordLengthValue
    Optional. Minimum number of characters required in a password, 5 to 20. If omitted, the
    current value is kept.

.PARAMETER IncludeAlphabeticCharacters
    Optional. 'Enable' requires at least one upper-case and one lower-case character. If
    omitted, the current value is kept.

.PARAMETER IncludeNumericCharacter
    Optional. 'Enable' requires at least one numeric character. If omitted, the current
    value is kept.

.PARAMETER IncludeSpecialCharacter
    Optional. 'Enable' requires at least one special character. If omitted, the current
    value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosAdminPasswordComplexity -MinimumPasswordLengthValue 12 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosAdminPasswordComplexity -MinimumPasswordLengthValue 12

    Raises the minimum required password length to 12 characters. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    # Status lands flat at /Response/PasswordComplexitySettings/Status, not nested under
    # AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'PasswordComplexitySettings' -Action 'update'
}

<#
.SYNOPSIS
    Updates the admin login disclaimer toggle on a Sophos Firewall.

.DESCRIPTION
    Sets the LoginDisclaimer field of the AdminSettings singleton (System > Administration >
    Settings > Login Disclaimer). The request carries only this one field; no read of the
    current settings is needed, since LoginDisclaimer has no sibling field to preserve. It
    needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER LoginDisclaimer
    Required. 'Enable' displays a disclaimer and warning banner at admin login; 'Disable'
    turns it off.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosLoginDisclaimer -LoginDisclaimer 'Enable' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosLoginDisclaimer -LoginDisclaimer 'Enable'

    Turns on the admin login disclaimer banner. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    # Status lands flat at /Response/LoginDisclaimer/Status, not nested under AdminSettings -
    # see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'LoginDisclaimer' -Action 'update'
}

<#
.SYNOPSIS
    Updates the appliance host name and description on a Sophos Firewall.

.DESCRIPTION
    Sets the HostnameSettings block of the AdminSettings singleton (System > Administration
    > Settings > Hostname Settings). The cmdlet reads the block first and sends it back,
    overriding only the fields you pass; the other five AdminSettings blocks are not sent.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly, and an account with administrative permission.

.PARAMETER HostName
    Optional. Appliance host name. If omitted, the current value is kept.

.PARAMETER HostNameDesc
    Optional. Free-text description of the appliance. If omitted, the current value is
    kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosHostname -HostNameDesc 'Branch office firewall' -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosHostname -HostNameDesc 'Branch office firewall'

    Sets only the description; the host name itself is kept. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    # Status lands flat at /Response/HostnameSettings/Status, not nested under AdminSettings -
    # see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'HostnameSettings' -Action 'update'
}

<#
.SYNOPSIS
    Resets a Sophos Firewall to its factory default configuration.

.DESCRIPTION
    Resets the appliance to factory defaults and starts it up again with the language you
    choose as the default. The underlying API field is named DefaultConfigurationLanguage
    and looks like a language setting, but it triggers a full factory reset, not a language
    change. This erases the current configuration; the only way back is restoring the
    appliance from a backup taken beforehand. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

    The cmdlet asks for confirmation before it runs, unless -Confirm:$false is passed. Run
    it only against an appliance you deliberately intend to reset.

.PARAMETER DefaultLanguage
    Required. The language the reset appliance starts up in. Documented values: English,
    German, French, Italian, Spanish, Russian, Japanese, Korean, Hindi,
    Brazilian-Portuguese, Chinese-Simplified, Chinese-Traditional.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Reset-SfosToFactoryDefaults -DefaultLanguage German -WhatIf

    Shows what the call would do without sending it to the firewall.

.EXAMPLE
    Reset-SfosToFactoryDefaults -DefaultLanguage German

    Resets the appliance to factory defaults; it comes back up with German as the default
    language. The cmdlet asks for confirmation before it runs.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosAdminSettings
#>
function Reset-SfosToFactoryDefaults {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('English', 'German', 'French', 'Italian', 'Spanish', 'Russian', 'Japanese',
            'Korean', 'Hindi', 'Brazilian-Portuguese', 'Chinese-Simplified', 'Chinese-Traditional')]
        [string]$DefaultLanguage,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess($params.Firewall, "FACTORY-RESET the appliance to defaults (language '$DefaultLanguage')")) {
        return
    }

    $inner = @"
<Set operation="update">
  <AdminSettings>
    <DefaultConfigurationLanguage>$(ConvertTo-SfosXmlEscaped -Text $DefaultLanguage)</DefaultConfigurationLanguage>
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
        throw "Failed to factory-reset the appliance: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Status lands flat at /Response/DefaultConfigurationLanguage/Status, not nested under
    # AdminSettings - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'DefaultConfigurationLanguage' -Action 'update'
}

#endregion

#region LocalServiceACL
# A LocalServiceACL rule (SYSTEM > Administration, no separate menu entry) controls, per
# rule, which zones and source hosts may reach a set of management services. The wire root
# is <LocalServiceACL>. A rule needs a RuleName (max 60 characters, no comma) and at least
# one entry in Services/Service, drawn from a fixed set of management service names.
# Description, IPFamily, SourceZone, Hosts/Host and Action (accept/drop) are optional.

<#
.SYNOPSIS
    Retrieves Local Service ACL rules from a Sophos Firewall.

.DESCRIPTION
    Returns the LocalServiceACL rules that are defined on the firewall. Each rule controls
    which zones and source hosts may reach a set of management services. Use this cmdlet to
    review the existing rules or to feed them into another cmdlet through the pipeline. The
    cmdlet only reads; nothing on the firewall is changed. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the Local
    Service ACL rules. If omitted, the value from the current connection is used.

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
    objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per rule, with the properties
    RuleName, Description, IPFamily, SourceZone, HostList, ServiceList and Action. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no rule is
    configured.

.EXAMPLE
    Get-SfosLocalServiceACL

    Lists every Local Service ACL rule on the firewall of the current connection.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Creates a Local Service ACL rule on a Sophos Firewall.

.DESCRIPTION
    Creates a rule that controls which zones and source hosts may reach a set of management
    services, under System > Administration > Local Service ACL. This entity controls the
    same admin, API, SSH and SNMP access the current session uses. A rule that drops or
    excludes the zone or host you manage from can cut off management access, with no local
    way to undo it if there is no other path to the appliance. Check the effect with -WhatIf
    before you create a rule that could affect your own access. It needs an open connection
    from Connect-SfosFirewall, or the connection parameters supplied directly, and an
    account with administrative permission.

.PARAMETER RuleName
    Required. Name of the rule, up to 60 characters, no commas.

.PARAMETER Service
    Required. One or more management services the rule applies to.

.PARAMETER Description
    Optional. Free-text description of the rule. If omitted, no description is set.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'.

.PARAMETER SourceZone
    Optional. Zone the rule matches traffic from.

.PARAMETER SourceHost
    Optional. One or more source hosts or networks the rule matches.

.PARAMETER Action
    Optional. 'accept' or 'drop'.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    create.

.EXAMPLE
    New-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Service HTTPS -SourceZone 'LAN' -Action accept -WhatIf

    Shows what the call would create without sending it to the firewall.

.EXAMPLE
    New-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Service HTTPS -SourceZone 'LAN' -Action accept

    Creates a rule that allows HTTPS admin access from the LAN zone. The cmdlet asks for
    confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Updates a Local Service ACL rule on a Sophos Firewall.

.DESCRIPTION
    Sets an existing rule that controls which zones and source hosts may reach a set of
    management services. The cmdlet reads the current rule first and sends every field
    back, overriding only what you pass. This entity controls the same admin, API, SSH and
    SNMP access the current session uses. A change that drops or excludes the zone or host
    you manage from can cut off management access, with no local way to undo it if there is
    no other path to the appliance. Check the effect with -WhatIf before you change a rule
    that could affect your own access. It needs an open connection from
    Connect-SfosFirewall, or the connection parameters supplied directly, and an account
    with administrative permission.

.PARAMETER RuleName
    Required. Name of the rule to update.

.PARAMETER Service
    Optional. One or more management services the rule applies to. If omitted, the current
    value is kept.

.PARAMETER Description
    Optional. Free-text description of the rule. If omitted, the current value is kept.

.PARAMETER IPFamily
    Optional. 'IPv4' or 'IPv6'. If omitted, the current value is kept.

.PARAMETER SourceZone
    Optional. Zone the rule matches traffic from. If omitted, the current value is kept.

.PARAMETER SourceHost
    Optional. One or more source hosts or networks the rule matches. If omitted, the
    current value is kept.

.PARAMETER Action
    Optional. 'accept' or 'drop'. If omitted, the current value is kept.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    System.String. Accepts a rule name by property name from Get-SfosLocalServiceACL.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Action drop -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosLocalServiceACL -RuleName 'AllowLANHttps' -Action drop

    Changes only the action; every other field is kept. The cmdlet asks for confirmation
    before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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
    Removes a Local Service ACL rule from a Sophos Firewall.

.DESCRIPTION
    Deletes a rule that controls which zones and source hosts may reach a set of management
    services. This entity controls the same admin, API, SSH and SNMP access the current
    session uses. Removing a rule that currently permits the zone or host you manage from
    can cut off management access, with no local way to undo it if there is no other path
    to the appliance. Check the effect with -WhatIf before you remove a rule that could
    affect your own access. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and an account with administrative permission.

.PARAMETER RuleName
    Required. Name of the rule to remove.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    System.String. Accepts a rule name by property name from Get-SfosLocalServiceACL.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    removal.

.EXAMPLE
    Remove-SfosLocalServiceACL -RuleName 'AllowLANHttps' -WhatIf

    Shows what the call would remove without sending it to the firewall.

.EXAMPLE
    Remove-SfosLocalServiceACL -RuleName 'AllowLANHttps'

    Removes the rule. The cmdlet asks for confirmation before it writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

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

#region NetFlowConfiguration
# The NetFlowConfiguration singleton (SYSTEM > Administration > Netflow) holds the list of
# Netflow collector servers the appliance sends flow records to. The wire root is
# <NetFlowConfiguration>, with no <Name> child of its own; the servers sit underneath as
# repeated <Server> blocks, each with <ServerName>, <NetflowServer> and <NetflowServerPort>.
#
# The attribute table names the first field 'Name'; the wire element is 'ServerName',
# confirmed against a live object and matching the web admin field label. The table is
# wrong.
#
# On an appliance with nothing configured, a Get on NetFlowConfiguration is accepted (no
# 529) but returns no NetFlowConfiguration node at all - no empty element, no status - so
# Get-SfosNetFlowConfiguration returns an empty array rather than throwing. Once a server has
# been written, the same Get returns a NetFlowConfiguration node with one Server child per
# server.
#
# The server list is not append-only: an update that sends an empty NetFlowConfiguration
# body answers 200 and clears every server, confirmed by reading it back. There is no
# <Remove> for this entity - a Remove is accepted but returns no status at all, so clearing
# happens only through Set-SfosNetFlowConfiguration with empty arrays.
#
# The status of an update lands flat at /Response/NetFlowConfiguration/Status, since
# NetFlowConfiguration is itself the root element with no further wrapper.

<#
.SYNOPSIS
    Retrieves the Netflow server configuration from a Sophos Firewall.

.DESCRIPTION
    Returns the Netflow collector servers configured on the firewall (System >
    Administration > Netflow). Each server is returned with its name, target address and
    UDP port. Use this cmdlet to review the current list before changing it with
    Set-SfosNetFlowConfiguration. The cmdlet only reads; nothing on the firewall is changed.
    It needs an open connection from Connect-SfosFirewall, or the connection parameters
    supplied directly.

    On an appliance where no Netflow server has ever been configured, the firewall reports
    no data for this setting; the cmdlet returns an empty array in that case rather than an
    error.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs read permission for the
    administration settings. If omitted, the value from the current connection is used.

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
    objects.

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject. One object per configured Netflow server,
    with the properties ServerName, NetflowServer and NetflowServerPort. Returns
    System.Xml.XmlElement when -AsXml is used, and an empty array when no server is
    configured.

.EXAMPLE
    Get-SfosNetFlowConfiguration

    Lists every Netflow server configured on the firewall of the current connection.

.EXAMPLE
    Get-SfosNetFlowConfiguration -AsXml

    Returns the raw XML of the configured servers, for example to check a field that the
    standard output does not contain.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Set-SfosNetFlowConfiguration
#>
function Get-SfosNetFlowConfiguration {
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

    $inner = '<Get><NetFlowConfiguration></NetFlowConfiguration></Get>'

    try {
        $response = Invoke-SfosApi -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -InnerXml $inner -SkipCertificateCheck:$params.SkipCertificateCheck -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve NetFlowConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NetFlowConfiguration' -Action 'get'

    $serverNode = $XmlResponse.SelectSingleNode('/Response/NetFlowConfiguration/Server')

    if ($AsXml) {
        return @($serverNode | Where-Object { $_ })
    }

    $result = @()
    if ($serverNode) {
        # One Server wrapper holds every server. The three fields repeat inside it, one
        # repetition per Netflow server, and belong together by position. The documentation
        # sample shows a wrapper with a single field each, which reads as if the wrapper
        # repeated; on the wire it does not.
        $names = @($serverNode.SelectNodes('ServerName') | ForEach-Object -Process { $_.InnerText })
        $addresses = @($serverNode.SelectNodes('NetflowServer') | ForEach-Object -Process { $_.InnerText })
        $ports = @($serverNode.SelectNodes('NetflowServerPort') | ForEach-Object -Process { $_.InnerText })

        for ($i = 0; $i -lt $names.Count; $i++) {
            $result += [PSCustomObject]@{
                ServerName        = [string]$names[$i]
                NetflowServer     = [string]$(if ($i -lt $addresses.Count) { $addresses[$i] } else { '' })
                NetflowServerPort = [string]$(if ($i -lt $ports.Count) { $ports[$i] } else { '' })
            }
        }
    }

    return $result
}

<#
.SYNOPSIS
    Updates the Netflow server configuration on a Sophos Firewall.

.DESCRIPTION
    Sets the list of Netflow collector servers under System > Administration > Netflow. The
    three parameters are parallel arrays: the first entry of -ServerName, -NetflowServer and
    -NetflowServerPort together describe one server, the second entries describe the next
    server, and so on. The cmdlet reads the current list first; any of the three arrays you
    do not pass keeps its current values, so you can change only the port of one server
    while leaving the names and addresses of every server untouched. It needs an open
    connection from Connect-SfosFirewall, or the connection parameters supplied directly,
    and an account with administrative permission.

    The setting applies device-wide: there is one server list for the whole appliance, not
    one per zone or interface. Passing an empty array to all three parameters removes every
    configured server; there is no separate cmdlet to remove a single server or the whole
    list.

.PARAMETER ServerName
    Optional. Name of each Netflow server, one entry per server, 1 to 32 characters, no
    commas. If omitted, the current server names are kept. Pass an empty array together with
    empty -NetflowServer and -NetflowServerPort arrays to remove every configured server.

.PARAMETER NetflowServer
    Optional. IP address or domain name of each Netflow server, one entry per server. If
    omitted, the current server addresses are kept. Pass an empty array together with empty
    -ServerName and -NetflowServerPort arrays to remove every configured server.

.PARAMETER NetflowServerPort
    Optional. UDP port of each Netflow server, one entry per server, 1 to 65535. If omitted,
    the current server ports are kept. Pass an empty array together with empty -ServerName
    and -NetflowServer arrays to remove every configured server.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    Set-SfosNetFlowConfiguration -ServerName 'Collector1' -NetflowServer '10.0.0.50' -NetflowServerPort 2055 -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    Set-SfosNetFlowConfiguration -ServerName 'Collector1' -NetflowServer '10.0.0.50' -NetflowServerPort 2055

    Sets a single Netflow server. The cmdlet asks for confirmation before it writes.

.EXAMPLE
    Set-SfosNetFlowConfiguration -ServerName 'Collector1', 'Collector2' -NetflowServer '10.0.0.50', '10.0.0.51' -NetflowServerPort 2055, 2056 -Confirm:$false

    Sets two Netflow servers without asking for confirmation, for use in scripts.

.EXAMPLE
    Set-SfosNetFlowConfiguration -ServerName @() -NetflowServer @() -NetflowServerPort @()

    Removes every configured Netflow server. The cmdlet asks for confirmation before it
    writes.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosNetFlowConfiguration
#>
function Set-SfosNetFlowConfiguration {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateLength(1, 32)]
        [ValidatePattern('^[^,]+$')]
        [string[]]$ServerName,

        [string[]]$NetflowServer,

        [ValidateRange(1, 65535)]
        [int[]]$NetflowServerPort,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    $existing = @(Get-SfosNetFlowConfiguration -Firewall $params.Firewall `
            -Port $params.Port `
            -Username $params.Username `
            -Password $params.Password `
            -SkipCertificateCheck:$params.SkipCertificateCheck)

    $bp = $PSBoundParameters

    # Wrap the whole if/else, not just each branch: PowerShell collapses a one-element array
    # returned from an if/else assignment back to a scalar, and an index into that scalar
    # string reads a single character instead of a whole array entry.
    $targetServerName = @(if ($bp.ContainsKey('ServerName')) { $ServerName } else { @($existing | ForEach-Object -Process { $_.ServerName }) })
    $targetNetflowServer = @(if ($bp.ContainsKey('NetflowServer')) { $NetflowServer } else { @($existing | ForEach-Object -Process { $_.NetflowServer }) })
    $targetNetflowServerPort = @(if ($bp.ContainsKey('NetflowServerPort')) { $NetflowServerPort } else { @($existing | ForEach-Object -Process { $_.NetflowServerPort }) })

    if ($targetServerName.Count -ne $targetNetflowServer.Count -or $targetServerName.Count -ne $targetNetflowServerPort.Count) {
        throw "NetFlowConfiguration needs -ServerName, -NetflowServer and -NetflowServerPort with the same number of entries; one entry describes one Netflow server."
    }

    if (-not $PSCmdlet.ShouldProcess("NetFlowConfiguration on $($params.Firewall)", 'Update')) {
        return
    }

    # Send the shape the appliance stores: one Server wrapper whose three fields repeat, one
    # repetition per server. Sending one wrapper per server is accepted too, but the appliance
    # rewrites it into this form, and relying on that rewrite is not worth the risk.
    $serverXml = ''
    if ($targetServerName.Count -gt 0) {
        $namesXml = ''
        $addressesXml = ''
        $portsXml = ''
        for ($i = 0; $i -lt $targetServerName.Count; $i++) {
            $namesXml += "<ServerName>$(ConvertTo-SfosXmlEscaped -Text $targetServerName[$i])</ServerName>"
            $addressesXml += "<NetflowServer>$(ConvertTo-SfosXmlEscaped -Text $targetNetflowServer[$i])</NetflowServer>"
            $portsXml += "<NetflowServerPort>$(ConvertTo-SfosXmlEscaped -Text ([string]$targetNetflowServerPort[$i]))</NetflowServerPort>"
        }
        $serverXml = "<Server>$namesXml$addressesXml$portsXml</Server>"
    }

    $inner = @"
<Set operation="update">
  <NetFlowConfiguration>
    $serverXml
  </NetFlowConfiguration>
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
        throw "Failed to update NetFlowConfiguration: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Status lands flat at /Response/NetFlowConfiguration/Status - see the region header.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'NetFlowConfiguration' -Action 'update'
}
#endregion

# AdminPassword is a separate wire root, not part of the AdminSettings singleton: no
# <Name> child, and the status of an update lands flat at /Response/AdminPassword/Status.
# There is no Get for this entity - a <Get><AdminPassword> returns no element - and the
# account name itself is not writable through this operation, so it always targets the
# built-in admin account and this cmdlet has no -UserName parameter.

<#
.SYNOPSIS
    Changes the password of the built-in administrator account on a Sophos Firewall.

.DESCRIPTION
    Sets AdminPassword (System > Administration > Set Admin Password), the password of the
    appliance's built-in administrator account. The account name itself cannot be changed
    through this operation, so this cmdlet always targets that one account and has no
    parameter for the name. It needs an open connection from Connect-SfosFirewall, or the
    connection parameters supplied directly, and the account's current password for
    verification.

    Anyone who uses this account to sign in to the web admin console must use the new
    password there afterward.

.PARAMETER CurrentPassword
    Required. Current password of the built-in admin account, as a SecureString, up to 70
    characters.

.PARAMETER NewPassword
    Required. New password for the built-in admin account, as a SecureString.

.PARAMETER Firewall
    Optional. Host name or IP address of the firewall. If omitted, the value from the
    current connection is used.

.PARAMETER Port
    Optional. TCP port of the management API, usually 4444. If omitted, the value from the
    current connection is used.

.PARAMETER Username
    Optional. User name for the API login. The account needs administrative permission. If
    omitted, the value from the current connection is used.

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

.INPUTS
    None. This cmdlet does not accept pipeline input.

.OUTPUTS
    None. The cmdlet writes no output and raises an error if the firewall rejects the
    update.

.EXAMPLE
    $current = Read-Host -AsSecureString 'Current admin password'
    $new = Read-Host -AsSecureString 'New admin password'
    Set-SfosAdminPassword -CurrentPassword $current -NewPassword $new -WhatIf

    Shows what the call would change without sending it to the firewall.

.EXAMPLE
    $current = Read-Host -AsSecureString 'Current admin password'
    $new = Read-Host -AsSecureString 'New admin password'
    Set-SfosAdminPassword -CurrentPassword $current -NewPassword $new

    Changes the built-in admin account's password. The cmdlet asks for confirmation before
    it writes.

.EXAMPLE
    Set-SfosAdminPassword -CurrentPassword $current -NewPassword $new -Confirm:$false

    Changes the password without asking for confirmation, for use in scripts.

.LINK
    https://docs.sophos.com/nsg/sophos-firewall/22.0/api/

.LINK
    Get-SfosAdminSettings
#>
function Set-SfosAdminPassword {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [SecureString]$CurrentPassword,

        [Parameter(Mandatory)]
        [SecureString]$NewPassword,

        [string]$Firewall,
        [int]$Port,
        [string]$Username,
        [SecureString]$Password,
        [switch]$SkipCertificateCheck,

        [object]$Session
    )

    $params = Resolve-SfosParameters -BoundParameters $PSBoundParameters

    if (-not $PSCmdlet.ShouldProcess("built-in admin account on $($params.Firewall)", 'Change password')) {
        return
    }

    $currentBstr = $null
    $newBstr = $null
    $currentEscaped = $null
    $newEscaped = $null

    try {
        $currentBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CurrentPassword)
        $plainCurrent = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($currentBstr)

        # 70 characters is the documented maximum for CurrentPassword only; NewPassword
        # carries no documented limit and is therefore not validated here.
        if ($plainCurrent.Length -gt 70) {
            throw 'CurrentPassword exceeds the documented maximum length of 70 characters.'
        }

        $currentEscaped = ConvertTo-SfosXmlEscaped -Text $plainCurrent

        $newBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword)
        $plainNew = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($newBstr)
        $newEscaped = ConvertTo-SfosXmlEscaped -Text $plainNew
    }
    finally {
        if ($currentBstr -and $currentBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($currentBstr)
        }
        if ($newBstr -and $newBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($newBstr)
        }
        $plainCurrent = $null
        $plainNew = $null
    }

    $inner = @"
<Set operation="update">
  <AdminPassword>
    <CurrentPassword>$currentEscaped</CurrentPassword>
    <NewPassword>$newEscaped</NewPassword>
  </AdminPassword>
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
        throw "Failed to change the admin password: $($_.Exception.Message)"
    }

    $XmlResponse = [xml]$response.Content
    # Status lands flat at /Response/AdminPassword/Status, like every other block in this
    # API area - see the region header above Get-SfosAdminSettings.
    Assert-SfosApiReturnSuccess -Xml $XmlResponse -ObjectName 'AdminPassword' -Action 'update'
}
